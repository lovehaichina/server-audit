#!/bin/bash
# ============================================================
#  luohai VPS 全量备份脚本（restic → Cloudflare R2）
#  用法：bash /root/backup-now.sh            # 手动跑一次
#       由 cron / Backrest 调度自动执行
# ============================================================
set -uo pipefail

# 读取凭据（600，不入库、不写日志）
set -a
. /root/.restic-env
set +a
export RESTIC_PASSWORD_FILE=/root/.restic-pass
export RESTIC_CACHE_DIR=/var/lib/backrest/cache
# 降低内存占用：S3 并发调小
export RESTIC_PACK_SIZE=32
RESTIC_OPTS="-o s3.connections=4"

LOG=/var/log/restic-backup.log
say() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

say "===== 备份开始 ====="

# ---------- 备份路径清单 ----------
PATHS="
/etc/Caddyfile
/root/.local/share/caddy
/root/.config/caddy
/etc/strongswan
/root/vpn-certs
/root/vpn-add-user.sh
/root/vpn-del-user.sh
/root/vpn-credentials.txt
/usr/local/bin/server-audit.sh
/usr/local/bin/restic
/usr/local/bin/backrest
/etc/systemd/system
/etc/ssh/sshd_config
/etc/fail2ban
/root/.msmtprc
/root/.restic-pass
/var/spool/cron
/etc/firewalld
/etc/sysctl.conf
/etc/sysctl.d
/opt/family-points
/opt/SillyTavern/data
/opt/SillyTavern/config.yaml
/opt/SillyTavern/plugins
/opt/SillyTavern/default
/home/siyuan/SiYuan
/home/siyuan/.config/siyuan
/var/www/html
/var/log/server-audit
/var/lib/backrest/config
"

# 只保留真实存在的路径，避免 restic 报错中断
EXISTING=""
for p in $PATHS; do
  [ -e "$p" ] && EXISTING="$EXISTING $p"
done

restic $RESTIC_OPTS backup $EXISTING \
  --exclude=/opt/SillyTavern/node_modules \
  --exclude=/opt/SillyTavern/.git \
  --exclude=/opt/SillyTavern/src \
  --exclude=/opt/SillyTavern/public \
  --exclude=/opt/siyuan/siyuan-3.8.6-linux \
  --exclude=/etc/udev/hwdb.bin \
  --exclude=/etc/selinux \
  --exclude=/var/cache \
  --exclude=/var/tmp \
  --exclude=/tmp \
  --exclude=/root/.npm \
  --exclude=/root/.cache \
  --exclude=/root/.local/share/caddy/locks \
  --exclude='*.log' \
  --exclude='*.sock' \
  --tag auto --host luohai-vps 2>&1 | tee -a "$LOG"

RC=${PIPESTATUS[0]}
if [ $RC -eq 0 ]; then
  say "备份成功"
else
  say "备份失败，restic 退出码 $RC"
fi
exit $RC
