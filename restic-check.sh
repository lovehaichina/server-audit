#!/bin/bash
# ============================================================
#  仓库校验 + 保留策略清理
#  用法：bash /root/restic-check.sh          # 仅校验
#        bash /root/restic-check.sh prune    # 校验 + 清理旧快照
# ============================================================
set -uo pipefail
set -a; . /root/.restic-env; set +a
export RESTIC_PASSWORD_FILE=/root/.restic-pass
export RESTIC_CACHE_DIR=/var/lib/backrest/cache

echo "===== 快照列表 ====="
restic snapshots --compact

echo
echo "===== 完整性校验 ====="
restic check

if [ "${1:-}" = "prune" ]; then
  echo
  echo "===== 应用保留策略并清理 ====="
  restic forget \
    --keep-last 7 \
    --keep-daily 14 \
    --keep-weekly 8 \
    --keep-monthly 6 \
    --prune
fi
