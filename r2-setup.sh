#!/bin/bash
# ============================================================
#  luohai VPS 备份 · R2 凭据配置向导
#  你只需要修改下面 4 行，然后运行本脚本即可。
#  本脚本会自动：写入环境文件(600) → 初始化 restic 仓库 → 跑首次备份
# ============================================================
set -e

# ============ 请在这里填入你的 Cloudflare R2 信息 ============
R2_ACCOUNT_ID="在这里粘贴_AccountID"
R2_ACCESS_KEY="在这里粘贴_AccessKeyID"
R2_SECRET_KEY="在这里粘贴_SecretAccessKey"
R2_BUCKET="在这里粘贴_Bucket名称"
# ============================================================

REPO="s3:https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com/${R2_BUCKET}"

# 1) 写环境文件（root 私有）
cat > /root/.restic-env <<EOF
AWS_ACCESS_KEY_ID=${R2_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${R2_SECRET_KEY}
RESTIC_REPOSITORY=${REPO}
EOF
chmod 600 /root/.restic-env
echo "[OK] 凭据已写入 /root/.restic-env (600)"

# 2) 初始化仓库（已初始化则跳过）
export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY}"
export AWS_SECRET_ACCESS_KEY="${R2_SECRET_KEY}"
export RESTIC_REPOSITORY="${REPO}"
export RESTIC_PASSWORD_FILE=/root/.restic-pass

if restic snapshots >/dev/null 2>&1; then
  echo "[OK] 仓库已存在，跳过 init"
else
  echo "[..] 初始化 restic 仓库 ..."
  restic init
fi

echo
echo "[OK] 配置完成。现在可运行首次备份："
echo "     bash /root/backup-now.sh"
