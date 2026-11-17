#!/usr/bin/env bash
# 优选任务的统一启动器：加锁防重入、统一日志、记录耗时与退出码。
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

# 上一轮没跑完就跳过，避免两个进程同时写 cron.log / 抢 .git/index.lock
exec 9>"$LOCK"
if ! flock -n 9; then
    printf '%s [run.sh] 上一轮仍在运行，跳过本次\n' "$(date '+%F %T')" >> "$LOG"
    exit 0
fi

start=$(date +%s)
printf '\n===== %s 开始 (%s) =====\n' "$(date '+%F %T')" "${*:-no-args}" >> "$LOG"

set +e
# nice -n 10：测速是 I/O 密集型，主动让出 CPU 给系统与 x-ui，别用负值抢优先级
nice -n 10 "$PYTHON" -u "$DIR/main.py" "$@" >> "$LOG" 2>&1
rc=$?
set -e

printf '===== %s 结束 rc=%d 用时 %ds =====\n' "$(date '+%F %T')" "$rc" "$(( $(date +%s) - start ))" >> "$LOG"
exit "$rc"
