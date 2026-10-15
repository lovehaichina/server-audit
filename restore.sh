#!/bin/bash
# ============================================================
#  恢复脚本：从 R2 上的 restic 快照恢复指定路径
#  用法：bash /root/restore.sh /etc/Caddyfile            # 恢复单个文件
#        bash /root/restore.sh /opt/family-points/data  # 恢复整个目录
#        TARGET=/tmp/rt bash /root/restore.sh /etc/Caddyfile  # 恢复到指定目录
# ============================================================
set -uo pipefail
set -a; . /root/.restic-env; set +a
export RESTIC_PASSWORD_FILE=/root/.restic-pass

SRC="${1:?用法: bash /root/restore.sh <要恢复的路径，如 /etc/Caddyfile>}"
TARGET="${TARGET:-/tmp/restore-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$TARGET"

echo "[..] 可用快照："
restic snapshots --compact

echo
echo "[..] 从最新快照恢复 $SRC 到 $TARGET"
restic restore latest --target "$TARGET" --include "$SRC"

echo
echo "[OK] 已恢复到：$TARGET"
echo "     核对无误后，再手动 cp 覆盖到原位置。"
