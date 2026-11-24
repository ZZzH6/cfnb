#!/usr/bin/env bash
# 优选任务的统一启动器：加锁防重入、预检自愈、统一日志、记录耗时与退出码。
#
# 用法：
#   ./run.sh                # 正常跑（会改 DNS、推 GitHub）
#   ./run.sh --dry-run      # 只测速写文件，不动 DNS / 不推送
set -Eeuo pipefail
umask 077

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

LOG="$DIR/cron.log"
LOCK="/var/lock/cfnb.lock"
PYTHON="${CFNB_PYTHON:-/usr/bin/python3}"
CFG_DIR="/root/.config/cfnb"
CFG_BACKUP="$CFG_DIR/config.backup.json"
TOKEN_FILE="$CFG_DIR/github_token"

log() { printf '%s [run.sh] %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }

# 上一轮没跑完就跳过，避免两个进程同时写 cron.log / 抢 .git/index.lock
exec 9>"$LOCK"
if ! flock -n 9; then
    log "上一轮仍在运行，跳过本次"
    exit 0
fi

start=$(date +%s)
printf '\n===== %s 开始 (%s) =====\n' "$(date '+%F %T')" "${*:-no-args}" >> "$LOG"

# ---- 预检：缺文件就自愈，自愈不了就大声失败 ----
# 历史教训：config.json 被 git 操作弄丢后，程序静默退回占位默认值，
# 连续一周每天 3:00 空跑并退出 1，而没人知道。
if [ ! -s "$DIR/config.json" ]; then
    if [ -s "$CFG_BACKUP" ]; then
        cp -f "$CFG_BACKUP" "$DIR/config.json"
        chmod 600 "$DIR/config.json"
        log "config.json 缺失，已从 $CFG_BACKUP 自动恢复"
    else
        log "错误：config.json 缺失且没有备份，本次放弃"
        exit 2
    fi
fi

if ! "$PYTHON" -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' \
        "$DIR/config.json" >/dev/null 2>&1; then
    log "错误：config.json 不是合法 JSON，本次放弃"
    exit 2
fi

if [ ! -f "$DIR/git_sync.sh" ] && [ -s "$CFG_DIR/git_sync.sh" ]; then
    cp -f "$CFG_DIR/git_sync.sh" "$DIR/git_sync.sh"
    chmod 700 "$DIR/git_sync.sh"
    log "git_sync.sh 缺失，已从 $CFG_DIR/git_sync.sh 自动恢复"
fi

for f in main.py git_sync.sh; do
    if [ ! -f "$DIR/$f" ]; then
        log "错误：缺少 $f，本次放弃"
        exit 2
    fi
done

if [ ! -s "$TOKEN_FILE" ]; then
    log "警告：凭据文件 $TOKEN_FILE 缺失或为空，GitHub 推送很可能失败"
fi

# ---- 正式运行 ----
set +e
# nice -n 10：测速是 I/O 密集型，主动让出 CPU 给系统与 x-ui，别用负值抢优先级
nice -n 10 "$PYTHON" -u "$DIR/main.py" "$@" >> "$LOG" 2>&1
rc=$?
set -e

printf '===== %s 结束 rc=%d 用时 %ds =====\n' \
    "$(date '+%F %T')" "$rc" "$(( $(date +%s) - start ))" >> "$LOG"
exit "$rc"
