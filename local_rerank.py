#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""local_rerank.py —— 在本机（家宽/公司网）实测重排 Cloudflare 优选 IP。

背景
----
JP/US 两台 VPS 上的 main.py 测的是「VPS → CF 边缘」这段路，而真正决定体验的是
「我 → CF 边缘」这段路。Cloudflare 是 anycast：同一个 IP 从不同地方进来，落到的
机房（colo）可能完全不同，拥塞程度也不同。所以 VPS 测出来的排序，对本地只算
「候选池」，不算「答案」。

为什么不调 curl（项目里 main.py 的做法）
----
本机 curl 的 Schannel 后端坏了（连 baidu 都报 SEC_E_NO_CREDENTIALS），而且
main.py 依赖 `--resolve` 把域名钉到某个 IP 上。这里改用 Python 的 ssl + 裸 socket：
自己建 TCP、自己带 SNI 握手、自己发 HTTP/1.1，不依赖任何外部二进制。

测什么（全部在本地发起）
----
  tcp   : 3 次 TCP 握手取中位数；失败 > 1/3 直接淘汰
  tls   : 到 speed.cloudflare.com 的 TLS 握手耗时
  ttfb  : 同一条连接上发 3 次 GET /cdn-cgi/trace，取中位数 + 标准差（抖动）
  colo  : 从 trace 里读出落地的 CF 机房代码（HKG/NRT/LAX/SIN…），这是解释
          「为什么同一个 IP 在不同网络下快慢差很多」的关键信息
  speed : GET /__down 限时限量测吞吐；先全量粗筛，再对前 N 名精测取中位数
          （1MB 级别的样本量出来的是噪声，20MB 才稳定）

计分与 main.py 同口径
--------------------
  score = w_speed * (speed / best_speed)
          / (1 + w_tcp*tcp/100 + w_http*ttfb/100 + w_jitter*jitter/100)
即：速度先归一化，延迟/抖动按「每 100ms 扣 1 倍权重」折算成惩罚项。

用法
----
  python local_rerank.py                          # 默认读 ip.txt / akile_jp_ip.txt / rnvps_ip.txt
  python local_rerank.py --top 10 --out ip_local.txt
  python local_rerank.py --inputs ip.txt --screen-secs 6 --final-secs 8
  python local_rerank.py --compare                # 额外输出与农场排序的 Spearman 相关性

输出
----
  控制台表格（按 score 排序）+ ip_local.txt（可直接当订阅源）+ local_rerank.json（全量明细）
"""

import argparse
import json
import os
import socket
import ssl
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

SNI = "speed.cloudflare.com"
TRACE_PATH = "/cdn-cgi/trace"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

DEFAULT_INPUTS = ["ip.txt", "akile_jp_ip.txt", "rnvps_ip.txt"]


# --------------------------------------------------------------------------
# 基础：解析输入
# --------------------------------------------------------------------------
def parse_nodes(paths):
    """返回 [(ip, port, tag, source)]，按 ip:port 去重（先出现的赢）。"""
    seen = set()
    nodes = []
    for path in paths:
        if not os.path.exists(path):
            print(f"[warn] 找不到输入文件，跳过：{path}")
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip().lstrip("\ufeff").strip()   # 干掉 BOM
                if not line or line.startswith("#"):
                    continue
                addr, _, tag = line.partition("#")
                addr = addr.strip()
                tag = (tag.strip() or "??").split()[0].upper()
                if ":" not in addr:
                    continue
                ip, _, port = addr.partition(":")
                key = f"{ip}:{port}"
                if key in seen:
                    continue
                seen.add(key)
                nodes.append((ip, int(port), tag, os.path.basename(path)))
    return nodes


def _ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE          # 只测连通与速度，不做证书校验
    ctx.set_alpn_protocols(["http/1.1"])     # 单流吞吐用 h1 足够，且实现简单
    return ctx


# --------------------------------------------------------------------------
# 单次连接的三个动作：握手 / 抓小响应 / 拉吞吐
# --------------------------------------------------------------------------
def tcp_probe(ip, port, timeout, probes):
    """多次 TCP 握手取中位数——单次连接噪声很大，最小值会系统性偏乐观。"""
    good = []
    for _ in range(probes):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                good.append((time.perf_counter() - start) * 1000.0)
        except OSError:
            pass
    if not good:
        return None, 0
    return statistics.median(good), len(good)


def _connect_tls(ip, port, timeout):
    """建 TCP 并完成 TLS 握手，返回 (tls_socket, 握手毫秒数)。"""
    raw = socket.create_connection((ip, port), timeout=timeout)
    raw.settimeout(timeout)
    t0 = time.perf_counter()
    try:
        ss = _ctx().wrap_socket(raw, server_hostname=SNI)
    except Exception:
        raw.close()
        raise
    return ss, (time.perf_counter() - t0) * 1000.0


def _recv_headers(ss, deadline):
    """读到 \\r\\n\\r\\n 为止，返回 (已读字节, 首字节到达时刻)。"""
    buf = b""
    first = None
    while b"\r\n\r\n" not in buf:
        if time.perf_counter() > deadline:
            break
        try:
            chunk = ss.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        if first is None:
            first = time.perf_counter()
        buf += chunk
        if len(buf) > 65536:                 # 防呆：别被异常对端喂爆内存
            break
    return buf, first


def _parse_http_head(buf):
    """极简 HTTP 响应头解析：返回 (status, headers, 头部之后剩余的 body 字节)。"""
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    headers = {}
    if lines:
        parts = lines[0].split(b" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return status, headers, body


def fetch_trace(ip, port, timeout, samples):
    """抓 /cdn-cgi/trace：拿 TTFB、抖动、colo，顺便确认对端真的是 CF。

    永远返回 dict（失败时 ok=False + error），方便把「为什么死」记下来。
    """
    ip = ip.strip()
    ttfb_list = []
    colo = None
    status = None
    server = ""
    tls_ms = None
    ss = None
    deadline = time.perf_counter() + timeout * samples + 3
    fail = {"ok": False, "error": "unknown"}

    for _ in range(samples):
        if ss is None:
            try:
                ss, tls_ms = _connect_tls(ip, port, timeout)
            except socket.timeout:
                return dict(fail, error="tls_timeout")
            except ssl.SSLError as e:
                return dict(fail, error=f"tls_error:{type(e).__name__}")
            except OSError as e:
                return dict(fail, error=f"tls_oserror:{type(e).__name__}")
        req = (f"GET {TRACE_PATH} HTTP/1.1\r\nHost: {SNI}\r\n"
               f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n")
        t0 = time.perf_counter()
        try:
            ss.sendall(req.encode())
            buf, first = _recv_headers(ss, min(deadline, t0 + timeout))
        except socket.timeout:
            return dict(fail, error="http_timeout")
        except (ssl.SSLError, OSError) as e:
            return dict(fail, error=f"http_{type(e).__name__}")
        if not buf:
            return dict(fail, error="empty_response")
        ttfb_list.append(((first or time.perf_counter()) - t0) * 1000.0)
        status, headers, body = _parse_http_head(buf)
        server = headers.get("server", server)
        # 把 body 读干净，否则下一条请求会和上一条的响应体串在一起
        try:
            need = int(headers.get("content-length", "0"))
        except ValueError:
            need = 0
        rest = need - len(body)
        while rest > 0:
            try:
                chunk = ss.recv(min(4096, rest))
            except (socket.timeout, ssl.SSLError, OSError):
                break
            if not chunk:
                break
            body += chunk
            rest -= len(chunk)
        for line in body.decode("utf-8", "replace").splitlines():
            if line.startswith("colo="):
                colo = line.split("=", 1)[1].strip()

    try:
        ss.close()
    except Exception:
        pass

    if not ttfb_list:
        return dict(fail, error="no_sample")
    return {
        "ok": True,
        "error": None,
        "tls_ms": tls_ms,
        "ttfb_ms": statistics.median(ttfb_list),
        "jitter_ms": statistics.pstdev(ttfb_list) if len(ttfb_list) >= 2 else None,
        "colo": colo,
        "status": status,
        "server": server,
        "is_cf": bool(colo) or "cloudflare" in (server or "").lower(),
    }


def fetch_down(ip, port, timeout, budget_secs, cap_bytes, attempts=3):
    """限时限量拉 /__down，返回 (Mbps, 字节数, 耗时秒, 末次状态)。

    CF 对同一来源的连续大样本请求会偶发 403（同一 IP 上一秒 403、下一秒 200），
    所以失败要多试几次，别把 403 当成「这个 IP 没速度」。
    """
    result = (0.0, 0, 0.0, "no_attempt")
    for i in range(attempts):
        result = _fetch_down_once(ip, port, timeout, budget_secs, cap_bytes)
        if result[1] > 0:
            return result
        if result[3].startswith("http_4"):     # 403/429：CF 对同源大流量限流，歇一下
            time.sleep(2.0 * (i + 1))
        else:
            time.sleep(0.2)
    return result


def _fetch_down_once(ip, port, timeout, budget_secs, cap_bytes):
    """一次下载测量，返回 (Mbps, 字节数, 耗时秒, 状态)。

    速度按「整个窗口的平均值」算：卡顿和慢启动都会被计入，而不是只算最顺的那几毫秒。
    """
    ss = None
    try:
        ss, _tls_ms = _connect_tls(ip, port, timeout)
        req = (f"GET /__down?bytes={cap_bytes} HTTP/1.1\r\nHost: {SNI}\r\n"
               f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        t_send = time.perf_counter()
        ss.sendall(req.encode())
        deadline = t_send + budget_secs
        buf, first = _recv_headers(ss, min(deadline, t_send + timeout))
        if not buf:
            return 0.0, 0, 0.0, "empty"
        status, _headers, body = _parse_http_head(buf)
        if status != 200:
            return 0.0, 0, 0.0, f"http_{status}"
        got = len(body)
        first_t = first or time.perf_counter()
        while got < cap_bytes:
            remain = deadline - time.perf_counter()
            if remain <= 0:
                break
            try:
                ss.settimeout(min(remain, 5.0))
                chunk = ss.recv(min(262144, cap_bytes - got))
            except socket.timeout:
                break                     # 卡住了：把这段停顿也算进平均速度里
            if not chunk:
                break
            got += len(chunk)
        elapsed = max(time.perf_counter() - first_t, 1e-6)
        elapsed = min(elapsed, budget_secs + 1.0)
        return (got * 8) / (elapsed * 1e6), got, elapsed, "ok"
    except socket.timeout:
        return 0.0, 0, 0.0, "timeout"
    except ssl.SSLError as e:
        return 0.0, 0, 0.0, f"tls_{type(e).__name__}"
    except OSError as e:
        return 0.0, 0, 0.0, f"os_{type(e).__name__}"
    finally:
        if ss is not None:
            try:
                ss.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# 三阶段流程
# --------------------------------------------------------------------------
def stage_probe(nodes, args):
    """阶段 1：TCP / TLS / TTFB / colo / 抖动（轻量，全部节点都测）。"""
    rows = {}

    def work(node):
        ip, port, tag, src = node
        tcp_ms, ok = tcp_probe(ip, port, args.connect_timeout, args.tcp_probes)
        row = {"ip": ip, "port": port, "tag": tag, "source": src,
               "tcp_ms": tcp_ms, "tcp_ok": ok, "tcp_probes": args.tcp_probes,
               "tls_ms": None, "ttfb_ms": None, "jitter_ms": None,
               "colo": None, "status": None, "is_cf": False, "error": None,
               "speed": 0.0, "speed_samples": [], "alive": False}
        if ok == 0:
            # 一次都没连上才算死。国际链路上丢 SYN 很常见，但只要连通过就算候选。
            row["error"] = "tcp_unreachable"
            return row
        info = fetch_trace(ip, port, args.trace_timeout, args.http_samples)
        for key in ("tls_ms", "ttfb_ms", "jitter_ms", "colo", "status", "is_cf"):
            row[key] = info.get(key)
        if not info.get("ok"):
            row["error"] = info.get("error")
            return row
        if not info.get("is_cf"):
            row["error"] = "not_cloudflare"
            return row
        row["alive"] = True
        return row

    total = len(nodes)
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(work, n): n for n in nodes}
        for fut in as_completed(futs):
            node = futs[fut]
            try:
                rows[f"{node[0]}:{node[1]}"] = fut.result()
            except Exception as e:
                rows[f"{node[0]}:{node[1]}"] = {
                    "ip": node[0], "port": node[1], "tag": node[2], "source": node[3],
                    "tcp_ms": None, "tcp_ok": 0, "tls_ms": None, "ttfb_ms": None,
                    "jitter_ms": None, "colo": None, "is_cf": False, "speed": 0.0,
                    "alive": False, "error": f"{type(e).__name__}: {e}"}
            done += 1
            print(f"\r  [1/3 探测] {done}/{total}   ", end="", flush=True)
    print()
    return [rows[f"{n[0]}:{n[1]}"] for n in nodes]


def latency_rank(rows):
    """按「本地到手延迟」先排一次：TTFB 为主，抖动和 TCP 次之。

    这一步只花 negligible 的流量（trace 只有几百字节），先砍掉一半候选，
    后面的吞吐测试就可以压低并发——并发一高，CF 会对同一个来源返回 403/429，
    测出来的全是 0，排序反而变成随机的。
    """
    def key(r):
        return ((r.get("ttfb_ms") or 9999.0)
                + 0.5 * (r.get("jitter_ms") or 200.0)
                + 0.3 * (r.get("tcp_ms") or 999.0))

    alive = [r for r in rows if r["alive"]]
    alive.sort(key=key)
    for r in alive:
        r["lat_key"] = round(key(r), 1)
    return alive


def stage_bw(shortlist, args):
    """阶段 2：短名单各测一次吞吐，选出进精测的名单。

    CF 的 speedtest 端点带一个「按来源 IP 计费」的令牌桶：并发一高就整片返回 403，
    过一会儿又恢复。所以这里并发压到 1~2，并且把整批 403 的节点在末尾重试一遍。
    """
    cap = int(args.bw_cap_mb * 1024 * 1024)
    print(f"  [2/3 吞吐] {len(shortlist)} 个短名单 × 最多 {args.bw_cap_mb:g}MB / "
          f"{args.bw_secs:g}s，并发 {args.bw_workers}")

    def run_pass(items, label):
        def work(row):
            time.sleep(args.pace)         # 全局节奏控制：别让请求打得太密
            return fetch_down(row["ip"], row["port"], args.trace_timeout,
                              args.bw_secs, cap)

        done = 0
        with ThreadPoolExecutor(max_workers=args.bw_workers) as ex:
            futs = {ex.submit(work, r): r for r in items}
            for fut in as_completed(futs):
                row = futs[fut]
                try:
                    row["speed_bw"], row["bw_bytes"], row["bw_secs"], \
                        row["bw_status"] = fut.result()
                except Exception:
                    row["speed_bw"] = 0.0
                    row["bw_status"] = "exception"
                done += 1
                print(f"\r  [2/3 吞吐{label}] {done}/{len(items)}   ", end="", flush=True)
        print()

    run_pass(shortlist, "")
    failed = [r for r in shortlist if (r.get("speed_bw") or 0) == 0]
    if failed:
        print(f"  其中 {len(failed)} 个没测出速度，等 8s 冷却后重试一轮…")
        time.sleep(8)
        run_pass(failed, "·重试")

    shortlist.sort(key=lambda r: r.get("speed_bw") or 0.0, reverse=True)
    return shortlist


def stage_final(rows, args):
    """阶段 3：对吞吐前 N 名多次取样取中位数（单次样本波动很大）。"""
    top = [r for r in rows if (r.get("speed_bw") or 0) > 0][:args.final_n]
    if not top:
        return []
    cap = int(args.final_cap_mb * 1024 * 1024)
    print(f"  [3/3 精测] {len(top)} 个节点 × {args.samples} 次 × 最多 "
          f"{args.final_cap_mb:g}MB / {args.final_secs:g}s，并发 {args.final_workers}")

    def work(row):
        vals, statuses = [], []
        for i in range(args.samples):
            speed, _got, _el, st = fetch_down(row["ip"], row["port"], args.trace_timeout,
                                              args.final_secs, cap)
            statuses.append(st)
            if speed > 0:
                vals.append(speed)
            time.sleep(args.pace)         # 给 CF 的限流桶一点恢复时间
        return vals, statuses

    done = 0
    with ThreadPoolExecutor(max_workers=args.final_workers) as ex:
        futs = {ex.submit(work, r): r for r in top}
        for fut in as_completed(futs):
            row = futs[fut]
            try:
                vals, statuses = fut.result()
            except Exception:
                vals, statuses = [], []
            row["final_status"] = statuses
            if not vals and (row.get("speed_bw") or 0) > 0:
                vals = [row["speed_bw"]]
                row["speed_note"] = "bw-only"
            row["speed_samples"] = [round(v, 3) for v in vals]
            row["speed"] = statistics.median(vals) if vals else 0.0
            done += 1
            print(f"\r  [3/3 精测] {done}/{len(top)}   ", end="", flush=True)
    print()
    # 没进精测的短名单成员，用吞吐那一次的结果兜底
    in_final = {id(r) for r in top}
    for r in rows:
        if id(r) not in in_final and not (r.get("speed") or 0):
            r["speed"] = r.get("speed_bw") or 0.0
            if r["speed"]:
                r["speed_samples"] = [round(r["speed"], 3)]
                r["speed_note"] = "bw-only"
    return top


def score(rows, args):
    """与 main.py 同口径的惩罚式打分。"""
    speeds = [r["speed"] for r in rows if r.get("speed")]
    best = max(speeds) if speeds else 1.0
    for r in rows:
        rel = (r["speed"] / best) if best else 0.0
        tcp = r.get("tcp_ms") or 999.0
        ttfb = r.get("ttfb_ms") or 999.0
        jit = r.get("jitter_ms") or 50.0
        penalty = (1.0
                   + args.w_tcp * tcp / 100.0
                   + args.w_http * ttfb / 100.0
                   + args.w_jitter * jit / 100.0)
        r["rel_speed"] = rel
        r["penalty"] = penalty
        r["score"] = args.w_speed * rel / penalty if penalty else 0.0
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


# --------------------------------------------------------------------------
# 输出与对比
# --------------------------------------------------------------------------
def print_table(rows, top_n):
    print()
    print(f"{'#':>2}  {'节点':<24} {'机房':<5} {'TCP':>7} {'TLS':>7} {'TTFB':>7} "
          f"{'抖动':>6} {'速度':>9} {'得分':>7}")
    print("-" * 92)
    for i, r in enumerate(rows[:top_n], 1):
        def f(v, unit="ms", fmt="%.0f"):
            return "  -  " if v is None else (fmt % v)
        print(f"{i:>2}  {r['ip']+':'+str(r['port'])+'#'+r['tag']:<24} "
              f"{(r.get('colo') or '-'):<5} "
              f"{f(r.get('tcp_ms')):>7} {f(r.get('tls_ms')):>7} {f(r.get('ttfb_ms')):>7} "
              f"{f(r.get('jitter_ms'), fmt='%.1f'):>6} "
              f"{f(r.get('speed'), fmt='%.2f'):>9} {r.get('score', 0):>7.4f}")
    print("-" * 92)
    print(f"注：速度单位 Mbps，TCP/TLS/TTFB/抖动单位 ms。共测 {len(rows)} 个节点。")


def spearman(xs, ys):
    """秩相关（不依赖 scipy）。"""
    def ranks(vs):
        order = sorted(range(len(vs)), key=lambda i: vs[i])
        out = [0.0] * len(vs)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and vs[order[j + 1]] == vs[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1
            for k in range(i, j + 1):
                out[order[k]] = avg
            i = j + 1
        return out
    rx, ry = ranks(xs), ranks(ys)
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = (sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry)) ** 0.5
    return num / den if den else None


def compare_with_farm(rows):
    """按来源文件分组，看「农场列表内的顺序」和「本地实测得分顺序」是否一致。"""
    print("\n【农场排序 vs 本地实测】Spearman 秩相关（越接近 0 说明农场顺序对本地越没参考价值）")
    by_src = {}
    for r in rows:
        by_src.setdefault(r["source"], []).append(r)
    for src, items in by_src.items():
        items = [r for r in items if r.get("speed")]
        if len(items) < 3:
            continue
        farm_rank = {id(r): i for i, r in enumerate(items)}
        xs = [farm_rank[id(r)] for r in items]
        ys = [r["score"] for r in items]
        rho = spearman(xs, ys)
        if rho is None:
            continue
        verdict = "相关性弱 → 本地重排确实能改变结论" if abs(rho) < 0.4 else "相关性不弱"
        print(f"  {src:<18} n={len(items):<3} rho={rho:+.3f}   {verdict}")


def main():
    ap = argparse.ArgumentParser(description="本地实测重排 Cloudflare 优选 IP")
    ap.add_argument("--inputs", default=",".join(DEFAULT_INPUTS),
                    help="逗号分隔的候选列表（默认 ip.txt,akile_jp_ip.txt,rnvps_ip.txt）")
    ap.add_argument("--top", type=int, default=10, help="最终输出几个（默认 10）")
    ap.add_argument("--out", default="ip.txt",
                    help="输出文件（默认 ip.txt：这台机器负责的那份订阅）")
    ap.add_argument("--json", default="local_rerank.json", help="明细 JSON")
    ap.add_argument("--compare", action="store_true", help="输出与农场排序的 Spearman 相关性")
    ap.add_argument("--workers", type=int, default=8, help="探测阶段并发（默认 8）")
    ap.add_argument("--bw-workers", type=int, default=2,
                    help="吞吐阶段并发（默认 2；调高会触发 CF 403/429）")
    ap.add_argument("--final-workers", type=int, default=2, help="精测并发（默认 2）")
    ap.add_argument("--tcp-probes", type=int, default=3, help="TCP 握手次数（默认 3）")
    ap.add_argument("--http-samples", type=int, default=3, help="trace 采样次数（默认 3）")
    ap.add_argument("--connect-timeout", type=float, default=2.0,
                    help="TCP 连接超时（默认 2.0s）")
    ap.add_argument("--trace-timeout", type=float, default=4.0,
                    help="TLS/trace 读超时（默认 4.0s；国际链路 TTFB 常到 1~2s）")
    ap.add_argument("--bw-secs", type=float, default=10.0)
    ap.add_argument("--bw-cap-mb", type=float, default=24.0)
    ap.add_argument("--shortlist", type=int, default=12,
                    help="按延迟挑多少个进吞吐测试（默认 12）")
    ap.add_argument("--final-secs", type=float, default=10.0)
    ap.add_argument("--final-cap-mb", type=float, default=24.0)
    ap.add_argument("--final-n", type=int, default=5,
                    help="按吞吐取前几名做多次精测（默认 5）")
    ap.add_argument("--samples", type=int, default=3, help="精测取样次数（默认 3）")
    ap.add_argument("--pace", type=float, default=1.5,
                    help="每次吞吐请求之间的最小间隔（默认 1.5s，调小容易触发 403）")
    ap.add_argument("--w-speed", type=float, default=3.0)
    ap.add_argument("--w-tcp", type=float, default=3.0)
    ap.add_argument("--w-http", type=float, default=3.0)
    ap.add_argument("--w-jitter", type=float, default=3.0)
    ap.add_argument("--min-mbps", type=float, default=1.0,
                    help="低于该速度视为不可用（默认 1.0 Mbps）")
    args = ap.parse_args()

    print("=" * 92)
    print("本地实测重排 Cloudflare 优选 IP")
    print(f"目标 SNI/域名：{SNI}   起点：本机直连（不走系统代理）")
    print("=" * 92)

    nodes = parse_nodes([p.strip() for p in args.inputs.split(",") if p.strip()])
    if not nodes:
        sys.exit("没有可测的节点，检查 --inputs")
    print(f"载入候选：{len(nodes)} 个（已按 ip:port 去重）")

    t_start = time.perf_counter()
    rows = stage_probe(nodes, args)
    alive = [r for r in rows if r["alive"]]
    dead = [r for r in rows if not r["alive"]]
    print(f"  探测通过 {len(alive)} 个，淘汰 {len(dead)} 个（TCP 不通 / 非 CF / TLS 被掐）")

    if not alive:
        sys.exit("探测阶段全军覆没：检查本机到 CF 443 的连通性")

    ranked = latency_rank(alive)
    print("  本地延迟前 5（TTFB / 抖动 / TCP）：")
    for r in ranked[:5]:
        print("    %-16s %-3s %-4s ttfb=%6.0fms jit=%6.1fms tcp=%6.0fms" % (
            r["ip"], r["tag"], r.get("colo") or "-",
            r.get("ttfb_ms") or -1, r.get("jitter_ms") or -1, r.get("tcp_ms") or -1))

    shortlist = ranked[:args.shortlist]
    stage_bw(shortlist, args)
    stage_final(shortlist, args)

    usable = [r for r in alive if (r.get("speed") or 0) >= args.min_mbps]
    dropped = [r for r in alive if (r.get("speed") or 0) < args.min_mbps]
    rows = score(usable, args)

    if not rows:
        # CF 的 speedtest 端点会按来源 IP 限流；整批 403 时宁可报错，也别用空结果
        # 覆盖上一次跑出来的 ip_local.txt。
        statuses = sorted({r.get("bw_status") for r in alive if r.get("bw_status")})
        print(f"\n没有节点通过 {args.min_mbps:g} Mbps 门槛，本次不写输出文件。")
        print(f"吞吐状态分布：{statuses[:8]}")
        print("如果大量出现 http_403/http_429，说明被 CF 限流了：等 10~30 分钟，"
              "或用 --bw-workers 1 --pace 3 再跑。")
        sys.exit(3)

    print_table(rows, args.top)
    if dropped:
        print(f"因速度低于 {args.min_mbps:g} Mbps 被丢弃：{len(dropped)} 个")

    if args.compare:
        compare_with_farm(rows)

    out_lines = [f"{r['ip']}:{r['port']}#{r['tag']}" for r in rows[:args.top]]
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out_lines) + "\n")
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "host": socket.gethostname(),
                   "sni": SNI,
                   "args": vars(args),
                   "nodes": rows,
                   "dropped": dropped,
                   "dead": dead}, f, ensure_ascii=False, indent=2)

    print(f"\n已写入 {args.out}（{len(out_lines)} 个）与 {args.json}")
    print(f"总耗时 {time.perf_counter() - t_start:.0f}s")


if __name__ == "__main__":
    main()
