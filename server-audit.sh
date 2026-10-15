#!/bin/bash
# ============================================================
# server-audit.sh  服务器每日巡检脚本 v1.0
# 模块：①系统资源 ②关键服务 ③SSH安全 ④fail2ban ⑤端口审计
#       ⑥异常进程 ⑦Web站点 ⑧系统更新 ⑨网站文件变化
#       ⑩关键文件完整性 ⑪操作日志审计 ⑫Backrest备份
#       ⑬命令行操作统计 ⑭运维活动上下文 ⑮AI分析研判
# 输出：HTML 报告 → 邮件发送 YOUR_EMAIL@example.com
# 用法：首次运行自动建立基线；每日 cron 调用
# ============================================================

AUDIT_DIR=/var/log/server-audit
BASELINE_DIR=$AUDIT_DIR/baseline
TMP_DIR=$AUDIT_DIR/tmp
TODAY=$(date +%F)
NOW=$(date '+%F %T')
REPORT=$AUDIT_DIR/$TODAY.html
MAILTO=YOUR_EMAIL@example.com
MSMTP_CFG=/root/.msmtprc

mkdir -p "$AUDIT_DIR" "$BASELINE_DIR" "$TMP_DIR"
rm -f "$TMP_DIR"/* 2>/dev/null

OK=0; WARN=0; CRIT=0
AI_ITEMS=""   # AI 研判用：异常摘要收集
HTML=""

# ---------- 工具函数 ----------
h3() { HTML+="<h3 style=\"margin:18px 0 6px;font-size:15px;color:#111827;\">$1</h3>"; }
table() { HTML+="<table cellpadding=\"6\" cellspacing=\"0\" style=\"border-collapse:collapse;width:100%;background:#fff;font-size:13px;\">"; }
tclose() { HTML+="</table>"; }
row() { HTML+="<tr><td style=\"border:1px solid #e5e7eb;padding:6px 10px;color:#374151;\">$1</td><td style=\"border:1px solid #e5e7eb;padding:6px 10px;color:#374151;\">$2</td></tr>"; }
st_ok()   { OK=$((OK+1));   HTML+="<span style=\"color:#16a34a;font-weight:600;\">✅ 正常</span>"; }
st_warn() { WARN=$((WARN+1)); HTML+="<span style=\"color:#d97706;font-weight:600;\">⚠️ 关注</span>"; }
st_crit() { CRIT=$((CRIT+1)); HTML+="<span style=\"color:#dc2626;font-weight:600;\">🔴 异常</span>"; }

# ---------- ① 系统资源 ----------
res_load=$(uptime | sed 's/.*load average:/负载:/')
res_mem=$(free -m | awk '/Mem:/{printf "内存: 已用 %dMB / %dMB (%.0f%%)", $3, $2, $3/$2*100}')
res_disk=$(df -h / | tail -1 | awk '{printf "磁盘: 已用 %s / %s (%s)", $3, $2, $5}')
res_uptime=$(uptime -p | sed 's/up/运行时长:/')

h3 "① 系统资源 &nbsp; <span style=\"font-size:12px;color:#9ca3af;\">$(date '+%F %T')</span>"
table
row "负载 / 运行时长" "$(uptime | grep -o 'load average.*')&nbsp;·&nbsp;$res_uptime"
row "内存" "$(free -m | awk '/Mem:/{printf "已用 %dMB / %dMB (%.0f%%)", $3, $2, $3/$2*100}')"
row "磁盘 /" "$(df -h / | tail -1 | awk '{printf "已用 %s / %s (%s)", $3, $2, $5}')"
row "Swap" "$(free -m | awk '/Swap:/{printf "已用 %dMB / %dMB", $3, $2}')"
tclose
mem_pct=$(free -m | awk '/Mem:/{printf "%d", $3/$2*100}')
disk_pct=$(df -h / | tail -1 | awk '{gsub(/%/,"",$5); print $5}')
if [ "$mem_pct" -gt 85 ] || [ "$disk_pct" -gt 85 ]; then
  st_crit
  AI_ITEMS+="【① 系统资源】内存 ${mem_pct}% 或磁盘 ${disk_pct}% 使用率超过 85%；"
else st_ok; fi

# ---------- ② 关键服务 ----------
h3 "② 关键服务"
table
SERVICES="caddy fail2ban sshd siyuan family-points strongswan sillytavern backrest"
for svc in $SERVICES; do
  if systemctl is-active "$svc" >/dev/null 2>&1; then
    row "$svc" "$(systemctl show -p ActiveState,SubState --value "$svc" 2>/dev/null | tr '\n' ' ')"
  else
    row "$svc" "<b style=\"color:#dc2626;\">未运行</b>"
  fi
done
tclose
SVC_BAD=0
for svc in $SERVICES; do systemctl is-active "$svc" >/dev/null 2>&1 || SVC_BAD=$((SVC_BAD+1)); done
if [ "$SVC_BAD" -gt 0 ]; then
  st_crit
  BAD_LIST=""
  for svc in $SERVICES; do systemctl is-active "$svc" >/dev/null 2>&1 || BAD_LIST="$BAD_LIST $svc"; done
  AI_ITEMS+="【② 关键服务】以下服务未运行：${BAD_LIST}；"
else st_ok; fi

# ---------- ③ SSH 登录审计 ----------
h3 "③ SSH 登录审计（近24小时）"
table
SSH_FAIL=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep -c 'sshd.*Failed password')
SSH_ACC_LOG=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep 'sshd.*Accepted')
SSH_ACC_CNT=0; [ -n "$SSH_ACC_LOG" ] && SSH_ACC_CNT=$(echo "$SSH_ACC_LOG" | wc -l)
IP_LIST=$(echo "$SSH_ACC_LOG" | grep -oE 'from [0-9.]+' | awk '{print $2}' | sort -u | tr '\n' ' ')
# 历史成功登录 IP 基线比对
LIPBF="$BASELINE_DIR/login-ips.list"; LIPTF="$TMP_DIR/login-ips.list"
echo "$IP_LIST" | tr ' ' '\n' | sed '/^$/d' | sort > "$LIPTF"
NEW_IPS=""; OLD_IPS=""
if [ ! -f "$LIPBF" ]; then
  cp "$LIPTF" "$LIPBF"
  row "登录 IP 基线" "已建立（首次：$(tr '\n' ' ' < "$LIPTF")）"
else
  OLD_IPS=$(comm -12 "$LIPBF" "$LIPTF" | tr '\n' ' ')
  NEW_IPS=$(comm -13 "$LIPBF" "$LIPTF" | tr '\n' ' ')
fi
row "成功登录次数" "$SSH_ACC_CNT"
row "失败尝试次数" "$SSH_FAIL"
[ -n "$IP_LIST" ] && row "登录 IP 列表" "$IP_LIST"
[ -n "$OLD_IPS" ] && row "历史常见 IP" "$OLD_IPS"
[ -n "$NEW_IPS" ] && row "新出现 IP" "<b style=\"color:#d97706;\">$NEW_IPS</b>"
# IP 归属地查询：本地历史归属清单优先，未命中才调 ip-api.com，查到后更新清单
GEO_STR=""
GEO_FILE="$BASELINE_DIR/ip-geo.list"
if [ -n "$IP_LIST" ] && command -v curl >/dev/null 2>&1; then
  MISS_IPS=""; GEO_PARTS=""
  for ip in $IP_LIST; do
    hit=$(grep "^${ip}|" "$GEO_FILE" 2>/dev/null | head -1)
    if [ -n "$hit" ]; then
      cnt=$(echo "$hit" | cut -d'|' -f2); isp=$(echo "$hit" | cut -d'|' -f4)
      GEO_PARTS="${GEO_PARTS:+$GEO_PARTS }$ip(${cnt}/${isp})"
    else
      MISS_IPS="${MISS_IPS:+$MISS_IPS }$ip"
    fi
  done
  if [ -n "$MISS_IPS" ]; then
    IP_JSON=$(printf '%s' "$MISS_IPS" | tr ' ' '\n' | sed '/^$/d' | python3 -c 'import json,sys; ips=[l.strip() for l in sys.stdin if l.strip()]; print(json.dumps(ips))' 2>/dev/null)
    if [ -n "$IP_JSON" ]; then
      GEO_RAW=$(curl -s -m 15 -X POST "http://ip-api.com/batch?fields=query,country,regionName,isp" -H "Content-Type: application/json" -d "$IP_JSON" 2>/dev/null)
      NEW_GEO=$(echo "$GEO_RAW" | python3 -c '
import json,sys
try:
    d=json.load(sys.stdin)
    out=[]; lines=[]
    for i in d:
        q=i.get("query","")
        if not q: continue
        cnt=i.get("country",""); reg=i.get("regionName",""); isp=i.get("isp","")
        if cnt or isp:
            out.append("%s(%s/%s)" % (q, cnt, isp))
            lines.append("%s|%s|%s|%s" % (q, cnt, reg, isp))
    if lines:
        with open(sys.argv[1], "a", encoding="utf-8") as f:
            f.write("\n".join(lines)+"\n")
    print(" ".join(out))
except Exception:
    print("")' "$GEO_FILE" 2>/dev/null)
      [ -n "$NEW_GEO" ] && GEO_PARTS="${GEO_PARTS:+$GEO_PARTS }$NEW_GEO"
    fi
  fi
  GEO_STR="$GEO_PARTS"
fi
[ -n "$GEO_STR" ] && row "IP 来源归属" "$GEO_STR"
# 登录时间分布（按小时）
HOUR_DIST=$(echo "$SSH_ACC_LOG" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | cut -d: -f1 | sort | uniq -c | sort -rn | awk '{printf "%s时×%s ", $2, $1}' | tr '\n' ' ')
[ -n "$HOUR_DIST" ] && row "登录时间分布" "$HOUR_DIST"
# 登录时段相关操作（sudo 日志，弱关联标注）
SSH_SUDO=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep 'sudo.*COMMAND=' | sed 's/.*COMMAND=//' | head -5 | cut -c1-60 | tr '\n' '; ')
[ -n "$SSH_SUDO" ] && row "时段 sudo 操作（弱关联）" "$SSH_SUDO"
tclose
# 本次 IP 并入历史基线（下次不再当作新 IP）
if [ -f "$LIPBF" ]; then sort -u "$LIPBF" "$LIPTF" > "$LIPTF.new" 2>/dev/null && mv "$LIPTF.new" "$LIPBF"; fi
AI_SSH="近24h 成功登录 ${SSH_ACC_CNT} 次、失败 ${SSH_FAIL} 次${IP_LIST:+；登录IP：$IP_LIST}${OLD_IPS:+；历史常见IP（长期来源）：$OLD_IPS}${NEW_IPS:+；新出现IP：$NEW_IPS}${GEO_STR:+；来源归属：$GEO_STR}${HOUR_DIST:+；时间分布：$HOUR_DIST}${SSH_SUDO:+；时段sudo操作：$SSH_SUDO}"
if [ -n "$NEW_IPS" ] || [ "$SSH_FAIL" -gt 10 ]; then
  st_warn
  AI_ITEMS+="【③ SSH 登录审计（近24小时）】${AI_SSH}；"
else st_ok; fi

# ---------- ④ fail2ban ----------
h3 "④ fail2ban 封禁状态"
table
f2b_cur=$(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned:' | awk '{print $NF}')
f2b_tot=$(fail2ban-client status sshd 2>/dev/null | grep 'Total banned:' | awk '{print $NF}')
# 近24h 新增封禁：按日期前缀过滤
f2b_new24=$(grep '\[sshd\] Ban' /var/log/fail2ban.log 2>/dev/null | awk -v d="$(date -d '24 hours ago' '+%Y-%m-%d')" '$1 >= d' | wc -l)
row "当前封禁" "${f2b_cur:-0} 个"
row "累计封禁" "${f2b_tot:-0} 个"
row "近24h 新增封禁" "${f2b_new24} 个"
tclose
if [ "${f2b_cur:-0}" -gt 0 ] || [ "$f2b_new24" -gt 0 ]; then
  st_warn
  AI_ITEMS+="【④ fail2ban 封禁状态】当前封禁 ${f2b_cur:-0} 个，近24h 新增 ${f2b_new24} 个；"
else st_ok; fi

# ---------- ⑤ 端口审计 ----------
h3 "⑤ 监听端口（与基线对比）"
table
ss -tlnp 2>/dev/null | awk '{print $4}' | grep -v '^$' | sort -u > "$TMP_DIR/ports.txt"
if [ ! -f "$BASELINE_DIR/ports.list" ]; then
  cp "$TMP_DIR/ports.txt" "$BASELINE_DIR/ports.list"
  row "端口清单" "$(tr '\n' ' ' < "$TMP_DIR/ports.txt") （基线已建立）"
else
  new_ports=$(comm -13 "$BASELINE_DIR/ports.list" "$TMP_DIR/ports.txt")
  if [ -n "$new_ports" ]; then
    row "新增监听端口" "<b style=\"color:#d97706;\">$new_ports</b>"
    st_warn
    AI_ITEMS+="【⑤ 监听端口（与基线对比）】新增端口：$new_ports；"
  else
    row "端口清单" "$(tr '\n' ' ' < "$TMP_DIR/ports.txt")"
    st_ok
  fi
fi
tclose

# ---------- ⑥ 异常进程 ----------
h3 "⑥ 进程状态"
table
row "CPU Top5" "$(ps aux --sort=-%cpu 2>/dev/null | head -6 | awk 'NR==1{next}{printf "%s(%.0f%%) ", $11, $3}' | cut -c1-200)"
row "内存 Top5" "$(ps aux --sort=-%mem 2>/dev/null | head -6 | awk 'NR==1{next}{printf "%s(%.0f%%) ", $11, $4}' | cut -c1-200)"
zombie=$(ps aux 2>/dev/null | awk '$8 ~ /^Z/ {c++} END {print c+0}')
row "僵尸进程" "$zombie 个"
tclose
if [ "$zombie" -gt 0 ]; then
  st_warn
  AI_ITEMS+="【⑥ 进程状态】僵尸进程 ${zombie} 个；"
else st_ok; fi

# ---------- ⑦ Web 站点 ----------
h3 "⑦ Web 站点健康与证书"
table
WEB_BAD=0
# 站点清单：替换为你的域名（格式 "域名|期望HTTP状态码"）
for entry in "example.com|200" "www.example.com|301"; do
  domain=${entry%%|*}; expect=${entry##*|}
  # 重试防瞬时抖动：状态码为空/000/与预期不符时最多重试 2 次（间隔 3s）
  code=""
  for attempt in 1 2 3; do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "https://$domain/" 2>/dev/null)
    if [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" = "$expect" ]; then break; fi
    [ "$attempt" -lt 3 ] && sleep 3
  done
  ms=$(curl -sk -o /dev/null -w '%{time_total}' --max-time 10 "https://$domain/" 2>/dev/null)
  loc=""
  if [ "$code" = "301" ] || [ "$code" = "302" ]; then
    loc=$(curl -sk -o /dev/null -w '%{redirect_url}' --max-time 10 "https://$domain/" 2>/dev/null)
  fi
  expire=$(timeout 10 openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  days=""
  if [ -n "$expire" ]; then
    epo=$(date -d "$expire" +%s 2>/dev/null)
    [ -n "$epo" ] && days=$(( (epo - $(date +%s)) / 86400 ))
  fi
  if [ "$code" = "$expect" ]; then
    row "$domain" "HTTP $code${loc:+ → $loc} · ${ms}s · 证书${days:+剩 ${days} 天}"
    if [ -n "$days" ] && [ "$days" -lt 30 ]; then WARN=$((WARN+1)); fi
  else
    row "$domain" "<b style=\"color:#dc2626;\">HTTP $code（预期 $expect）异常</b>"
    WEB_BAD=$((WEB_BAD+1))
  fi
done
tclose
if [ "$WEB_BAD" -gt 0 ]; then
  st_crit
  AI_ITEMS+="【⑦ Web 站点健康与证书】${WEB_BAD} 个站点响应与预期不符（含证书）；"
else st_ok; fi

# ---------- ⑧ 系统更新 ----------
h3 "⑧ 系统安全更新"
table
sec_updates=$(dnf list --security updates -q 2>/dev/null | grep -cE '^[a-zA-Z0-9_.+-]+\.')
row "待装安全更新" "$sec_updates 个"
tclose
if [ "$sec_updates" -gt 0 ]; then
  st_warn
  AI_ITEMS+="【⑧ 系统安全更新】待装安全更新 ${sec_updates} 个；"
else st_ok; fi

# ---------- ⑨ 网站文件变化 ----------
snapshot_dir() {
  local dir="$1" name="$2"
  local bf="$BASELINE_DIR/snap-$name.txt"
  local tf="$TMP_DIR/snap-$name.txt"
  # 排除应用内部状态目录（如思源 .siyuan），避免正常运行临时文件误报
  ( cd "$dir" && find . -type d -name .siyuan -prune -o -type f -printf '%P|%s\n' 2>/dev/null | sort ) > "$tf"
  local total=$(wc -l < "$tf")
  if [ ! -f "$bf" ]; then
    cp "$tf" "$bf"
    row "「$name」($dir)" "基线已建立：$total 个文件"
    return
  fi
  local added=$(comm -13 <(cut -d'|' -f1 "$bf") <(cut -d'|' -f1 "$tf"))
  local deleted=$(comm -23 <(cut -d'|' -f1 "$bf") <(cut -d'|' -f1 "$tf"))
  local changed=$(join -t'|' -j1 <(sort "$bf") <(sort "$tf") 2>/dev/null | awk -F'|' '$2!=$3{print $1}')
  local suspect=""
  local norm_cnt=0
  if [ -n "$added" ]; then
    while IFS= read -r f; do
      case "$f" in
        *.html|*.htm|*.js|*.css|*.svg|*.png|*.jpg|*.jpeg|*.webp|*.gif|*.ico|*.txt|*.xml|*.json|*.woff|*.woff2|*.ttf|*.otf|*.eot|*.mp4|*.webm|*.pdf|*.gz|*.zip|*.md|*.map|*.avif|*.sy|*.sqlite|*.sqlite3|*.db) norm_cnt=$((norm_cnt+1)) ;;
        *) suspect="$suspect $f" ;;
      esac
    done <<< "$added"
  fi
  local msg="共 $total 个文件"
  if [ -n "$deleted" ] || [ -n "$changed" ] || [ -n "$suspect" ] || [ "$norm_cnt" -gt 0 ]; then
    msg+="<br>新增白名单文件 $norm_cnt 个（发布更新）"
    [ -n "$deleted" ] && msg+="<br>删除 ${deleted} 个：$(echo "$deleted" | head -5 | tr '\n' ' ')"
    [ -n "$changed" ] && msg+="<br>大小变化 ${changed} 个：$(echo "$changed" | head -5 | tr '\n' ' ')"
    [ -n "$suspect" ] && msg+="<br><b style=\"color:#dc2626;\">可疑新增：$suspect</b>"
    row "「$name」($dir)" "$msg"
    if [ -n "$suspect" ]; then
      CRIT=$((CRIT+1))
      AI_ITEMS+="【⑨ 网站文件变化监控】「$name」可疑新增：$suspect；"
    else
      WARN=$((WARN+1))
      AI_ITEMS+="【⑨ 网站文件变化监控】「$name」文件有增删改（共 $total 文件）；"
    fi
  else
    row "「$name」($dir)" "$msg（无变化）"
    OK=$((OK+1))
  fi
}
h3 "⑨ 网站文件变化监控"
table
snapshot_dir /var/www/html www-html
snapshot_dir /home/siyuan/SiYuan siyuan-workspace
tclose

# ---------- ⑩ 关键文件完整性 ----------
h3 "⑩ 关键文件完整性（md5 基线）"
table
KEYFILES=(/etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/Caddyfile /root/.msmtprc /etc/crontab /etc/hosts /root/.bashrc)
BF="$BASELINE_DIR/keyfiles.md5"
TF="$TMP_DIR/keyfiles.md5"
for f in "${KEYFILES[@]}"; do [ -f "$f" ] && md5sum "$f"; done | sort > "$TF"
if [ ! -f "$BF" ]; then
  cp "$TF" "$BF"
  row "关键文件指纹" "基线已建立（${#KEYFILES[@]} 个文件）"
  OK=$((OK+1))
else
  if diff -q "$BF" "$TF" >/dev/null 2>&1; then
    row "关键文件指纹" "全部一致"
    OK=$((OK+1))
  else
    changed_files=$(diff "$BF" "$TF" | grep '^[<>]' | awk '{print $NF}' | sed 's|.*/||' | sort -u | tr '\n' ' ')
    row "关键文件指纹" "<b style=\"color:#dc2626;\">以下文件发生变化：$changed_files</b>"
    CRIT=$((CRIT+1))
    AI_ITEMS+="【⑩ 关键文件完整性（md5 基线）】关键文件变化：$changed_files；"
  fi
fi
# cron 目录 + systemd 目录指纹
CRONBF="$BASELINE_DIR/cron.md5"; CRONTF="$TMP_DIR/cron.md5"
md5sum /etc/crontab /etc/cron.d/* /var/spool/cron/* 2>/dev/null | sort > "$CRONTF"
if [ ! -f "$CRONBF" ]; then cp "$CRONTF" "$CRONBF";
elif ! diff -q "$CRONBF" "$CRONTF" >/dev/null 2>&1; then
  row "cron 任务" "<b style=\"color:#d97706;\">计划任务有变更</b>"
  WARN=$((WARN+1))
  AI_ITEMS+="【⑩ 关键文件完整性（md5 基线）】cron 计划任务变更；"
else
  row "cron 任务" "无变更"
fi
# VPN（strongswan）配置指纹
SWBF="$BASELINE_DIR/swanctl.md5"; SWTF="$TMP_DIR/swanctl.md5"
{ [ -d /etc/swanctl ] && find /etc/swanctl -type f -exec md5sum {} + 2>/dev/null; [ -f /etc/strongswan.conf ] && md5sum /etc/strongswan.conf; } | sort > "$SWTF"
if [ ! -s "$SWTF" ]; then
  row "VPN(strongswan) 配置" "未发现配置文件（隧道未配置）"
elif [ ! -f "$SWBF" ]; then
  cp "$SWTF" "$SWBF"
  row "VPN(strongswan) 配置" "基线已建立"
else
  if diff -q "$SWBF" "$SWTF" >/dev/null 2>&1; then
    row "VPN(strongswan) 配置" "无变化"
    OK=$((OK+1))
  else
    row "VPN(strongswan) 配置" "<b style=\"color:#dc2626;\">配置已变更！</b>"
    CRIT=$((CRIT+1))
    AI_ITEMS+="【⑩ 关键文件完整性（md5 基线）】VPN(strongswan) 配置变更；"
  fi
fi
tclose

# ---------- ⑪ 操作日志审计 ----------
h3 "⑪ 操作日志审计（近24小时）"
table
JQ=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null)
sudo_log=$(echo "$JQ" | grep -E 'sudo.*COMMAND|sudo\[' | tail -8 | sed 's/.*sudo[^:]*: *//' | cut -c1-140 | tr '\n' ' ')
acc_log=$(echo "$JQ" | grep -E 'useradd|usermod|userdel|groupadd|groupdel|passwd' | grep -v 'Failed' | tail -6 | cut -c1-140 | tr '\n' ' ')
err_cnt=$(echo "$JQ" | grep -cE 'kernel:.*(error|critical)|systemd.*(Failed|error)')
sysd_bf="$BASELINE_DIR/systemd.list"
ls /etc/systemd/system/*.service 2>/dev/null | sort > "$TMP_DIR/systemd.list"
if [ ! -f "$sysd_bf" ]; then cp "$TMP_DIR/systemd.list" "$sysd_bf"; sysd_new=0
else sysd_new=$(comm -13 "$sysd_bf" "$TMP_DIR/systemd.list" | wc -l); fi
row "sudo / su 操作" "${sudo_log:-近24h无}"
row "账户/密码变更" "${acc_log:-近24h无}"
row "系统错误日志" "$err_cnt 条"
row "新增 systemd 服务" "$sysd_new 个"
[ -n "$sysd_new" ] && [ "$sysd_new" -gt 0 ] && row "新服务列表" "$(comm -13 "$sysd_bf" "$TMP_DIR/systemd.list" | tr '\n' ' ')"
# 新装软件包（rpm 基线对比）
PKGBF="$BASELINE_DIR/rpm-packages.txt"; PKGTF="$TMP_DIR/rpm-packages.txt"
rpm -qa 2>/dev/null | sort > "$PKGTF"
if [ ! -f "$PKGBF" ]; then
  cp "$PKGTF" "$PKGBF"
  row "新装软件包" "基线已建立（$(wc -l < "$PKGTF") 个包）"
else
  new_pkgs=$(comm -13 "$PKGBF" "$PKGTF" | head -12 | tr '\n' ' ')
  if [ -n "$new_pkgs" ]; then
    row "新装软件包" "<b style=\"color:#d97706;\">$new_pkgs</b>"
    WARN=$((WARN+1))
    AI_ITEMS+="【⑪ 操作日志审计（近24小时）】新装软件包：$new_pkgs；"
  else
    row "新装软件包" "无新增"
  fi
fi
# 用户账户列表
USRBF="$BASELINE_DIR/users.txt"; USRTF="$TMP_DIR/users.txt"
awk -F: '$3==0 || $3>=1000 {print $1}' /etc/passwd 2>/dev/null | sort > "$USRTF"
if [ ! -f "$USRBF" ]; then
  cp "$USRTF" "$USRBF"
  row "用户账户" "基线已建立：$(tr '\n' ' ' < "$USRTF")"
else
  new_users=$(comm -13 "$USRBF" "$USRTF" | tr '\n' ' ')
  if [ -n "$new_users" ]; then
    row "用户账户" "<b style=\"color:#dc2626;\">新增用户：$new_users</b>"
    CRIT=$((CRIT+1))
    AI_ITEMS+="【⑪ 操作日志审计（近24小时）】新增用户账户：$new_users；"
  else
    row "用户账户" "无新增"
  fi
fi
tclose
if [ "$sysd_new" -gt 0 ] || [ "$err_cnt" -gt 5 ]; then
  st_warn
  AI_ITEMS+="【⑪ 操作日志审计（近24小时）】新增 systemd 服务 ${sysd_new} 个，系统错误日志 ${err_cnt} 条；"
else st_ok; fi

# ---------- ⑫ Backrest 备份（R2） ----------
h3 "⑫ Backrest 备份（R2）"
table
if command -v restic >/dev/null 2>&1 && [ -f /root/.restic-env ] && [ -f /root/.restic-pass ]; then
  BK_OUT=$( { set -a; . /root/.restic-env; set +a; export RESTIC_PASSWORD_FILE=/root/.restic-pass RESTIC_CACHE_DIR=/var/lib/backrest/cache; timeout 90 restic snapshots --compact 2>&1; } )
  # restic 输出按时间升序，取最后一个快照主行（Tags 续行以空格开头不匹配）
  BK_SNAP_LINE=$(echo "$BK_OUT" | grep -E '^[0-9a-f]{8}[[:space:]]' | tail -1)
  if [ -z "$BK_SNAP_LINE" ]; then
    row "最近快照" "<b style=\"color:#dc2626;\">查询失败：$(echo "$BK_OUT" | tail -1 | cut -c1-80)</b>"
    st_crit
    AI_ITEMS+="【⑫ Backrest 备份（R2）】R2 仓库查询失败（restic）：$(echo "$BK_OUT" | tail -1 | cut -c1-60)；"
  else
    BK_TIME=$(echo "$BK_SNAP_LINE" | awk '{print $2, $3}')
    BK_SIZE=$(echo "$BK_SNAP_LINE" | awk '{print $(NF-1), $NF}')
    BK_EPOCH=$(date -d "$BK_TIME" +%s 2>/dev/null)
    BK_AGE=999
    [ -n "$BK_EPOCH" ] && BK_AGE=$(( ( $(date +%s) - BK_EPOCH ) / 86400 ))
    BK_ERR24=$(journalctl -u backrest --since "24 hours ago" --no-pager 2>/dev/null | grep -cE 'ERROR|task failed')
    row "最近快照" "$BK_TIME · $BK_SIZE"
    row "快照距今" "$BK_AGE 天"
    row "backrest 近24h 错误" "$BK_ERR24 条"
    if [ "$BK_ERR24" -gt 0 ]; then
      st_warn
      AI_ITEMS+="【⑫ Backrest 备份（R2）】最近快照 $BK_TIME（$BK_SIZE），但 backrest 近24h 有 $BK_ERR24 条错误（备份通知可能失败）；"
    elif [ "$BK_AGE" -ge 7 ]; then
      st_crit
      AI_ITEMS+="【⑫ Backrest 备份（R2）】最近快照距今 ${BK_AGE} 天，备份疑似中断；"
    elif [ "$BK_AGE" -ge 2 ]; then
      st_warn
      AI_ITEMS+="【⑫ Backrest 备份（R2）】最近快照距今 ${BK_AGE} 天，接近过期；"
    else
      st_ok
    fi
  fi
else
  row "Backrest 备份" "restic/凭据缺失，无法检查"
  st_warn
fi
tclose

# ---------- ⑬ 命令行操作统计 ----------
h3 "⑬ 命令行操作统计（近24h）"
table
SUDO_LOG=$(journalctl --since "24 hours ago" --no-pager 2>/dev/null | grep 'sudo.*COMMAND=' || true)
CMD_CNT=0
[ -n "$SUDO_LOG" ] && CMD_CNT=$(echo "$SUDO_LOG" | wc -l)
CMD_LIST=$(echo "$SUDO_LOG" | sed 's/.*COMMAND=//' | sed 's/[[:space:]]*$//' | grep -v '^$')
CMD_TOP=$(echo "$CMD_LIST" | grep -v '^$' | sort | uniq -c | sort -rn | head -6 | awk '{$1="";sub(/^ /,"");print $0}' | cut -c1-70 | tr '\n' '; ')
CMD_SUS=$(echo "$CMD_LIST" | grep -E 'rm -rf /|chmod 777|iptables|nft |systemctl stop|systemctl disable|useradd|userdel|passwd |curl .*\||wget .*\||nc -l|nc -e|ssh -R|scp |reboot|shutdown|mkfs|dd if=' | head -4 | tr '\n' '; ' || true)
HIS_TAIL=$(tail -8 /root/.bash_history 2>/dev/null | sed -E 's/sk-[a-zA-Z0-9]{16,}/sk-***/g; s/(password|passwd|secret|token|api[_-]?key)[=: ][^ ;&|]*/\1=***/Ig' | cut -c1-60 | tr '\n' '; ')
row "sudo 操作条数（近24h）" "${CMD_CNT:-0}"
[ -n "$CMD_TOP" ] && row "sudo 高频操作" "$CMD_TOP"
[ -n "$CMD_SUS" ] && row "可疑命令" "<b style=\"color:#d97706;\">$CMD_SUS</b>"
row "root 历史尾部（无时间戳）" "${HIS_TAIL:-（空）}"
tclose
CMD_AI="近24h sudo 操作 ${CMD_CNT:-0} 条${CMD_TOP:+，主要：$CMD_TOP}${CMD_SUS:+；命中可疑命令：$CMD_SUS}"
# 脱敏后再交给 AI（去掉明文密钥/口令）
CMD_AI_SAN=$(echo "$CMD_AI" | sed -E 's/sk-[a-zA-Z0-9]{16,}/sk-***/g; s/(password|passwd|secret|token|api[_-]?key)[=: ][^ ;&|]*/\1=***/Ig')
if [ -n "$CMD_SUS" ]; then
  st_warn
  AI_ITEMS+="【⑬ 命令行操作统计】${CMD_AI_SAN}；"
else
  st_ok
fi

# ---------- ⑭ 运维活动上下文（供 AI 综合研判甄别，避免误报） ----------
OPS_CTX=""
# Backrest 近24h 任务类型（备份/清理/检查/还原）
BR_ACT=$(journalctl --since "24 hours ago" --no-pager -u backrest 2>/dev/null | grep -oE '"task": "[a-z]+' | awk -F'"' '{print $4}' | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}' | tr '\n' ' ')
[ -n "$BR_ACT" ] && OPS_CTX+="Backrest备份任务：${BR_ACT}；"
# siyuan 工作区写入特征：内容批量变化但时间戳几乎未更新 = 还原/回滚特征（restic 还原保留原时间戳）
WS_WR=0
[ -d /home/siyuan/SiYuan ] && WS_WR=$(find /home/siyuan/SiYuan -type f -mmin -1440 2>/dev/null | wc -l)
OPS_CTX+="siyuan工作区近24h仅 ${WS_WR} 个文件时间戳更新（若内容批量变化而时间戳未更新，是备份还原/回滚特征，非写入型入侵）；"
# 登录时段（深夜维护窗口）
[ -n "$HOUR_DIST" ] && OPS_CTX+="SSH登录集中在 ${HOUR_DIST}；"
# 无新增服务/用户（无持久化痕迹）
if [ "${sysd_new:-0}" -eq 0 ]; then OPS_CTX+="近24h无新增systemd服务、无新增用户账户（无持久化后门痕迹）；"; fi

# ---------- ⑮ AI 分析研判（DeepSeek，言简意赅） ----------
AI_OVERALL=""
AI_CARD=""
DSK_FILE=/root/.deepseek_key
if [ -z "$AI_ITEMS" ]; then AI_ITEMS="全部模块正常（✅ $OK · ⚠️ $WARN · 🔴 $CRIT）"; fi
# 命令行操作统计并入 AI 研判（有操作才发，避免空转 tokens）
if [ "$CMD_CNT" -gt 0 ] || [ -n "$CMD_SUS" ]; then AI_ITEMS="${AI_ITEMS}【⑬ 命令行操作统计】${CMD_AI_SAN}；"; fi
if command -v curl >/dev/null 2>&1 && [ -s "$DSK_FILE" ]; then
  {
    echo "你是服务器运维研判助手。基于巡检结果做研判，输出格式："
    echo "第一行：总体研判（风险等级+一句话结论）。"
    echo "之后必须逐条对应每条异常研判，一条都不许遗漏，每行三部分、用分号分隔，顺序为："
    echo "【模块名（必须原样保留）】潜在风险与问题；结论；进一步建议。"
    echo "每条研判要切实发挥价值：分析到位、结论明确、建议可执行，字数不超过 1000 字；"
    echo "不要逐字复述巡检数据，聚焦分析、判断与处置建议。"
    echo "巡检结果：$AI_ITEMS"
    if [ -n "$OPS_CTX" ]; then
      echo ""
      echo "【运维活动上下文（仅供参考甄别，请勿把它当作异常输出研判行）】$OPS_CTX"
      echo "请结合上下文综合研判：上述异常是否可能由正常运维操作（备份、还原测试、深夜维护）导致。"
      echo "若能合理解释，请在结论中标注“疑似运维操作所致”，并给出核实确认建议，避免误报为入侵；"
      echo "若无法解释或存在矛盾，再判定为真实风险。"
    fi
  } > "$TMP_DIR/ai_prompt.txt"
  python3 - "$TMP_DIR/ai_prompt.txt" > "$TMP_DIR/ai_body.json" <<'PYEOF'
import json, sys
prompt = open(sys.argv[1], encoding="utf-8").read()
print(json.dumps({
    "model": "deepseek-flash",
    "messages": [{"role": "user", "content": prompt}],
    "max_tokens": 10000, "temperature": 0.3, "stream": False,
    "thinking": {"type": "disabled"}
}, ensure_ascii=False))
PYEOF
  RESP=$(curl -s -m 90 https://api.deepseek.com/chat/completions \
    -H "Authorization: Bearer $(cat "$DSK_FILE")" \
    -H "Content-Type: application/json" --data @"$TMP_DIR/ai_body.json" 2>/dev/null)
  AI_OVERALL=$(echo "$RESP" | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin)["choices"][0]["message"]["content"])
except Exception:
    print("")' 2>/dev/null)
fi
if [ -n "$AI_OVERALL" ]; then
  AI_OVERALL1=$(echo "$AI_OVERALL" | sed -n '1p' | cut -c1-300)
  AI_DETAILS=$(echo "$AI_OVERALL" | tail -n +2 | grep -oE '【[^】]+】.*' | head -12 || true)
  AI_CARD="<div style=\"margin-top:12px;padding:12px 16px;border-radius:8px;background:#eff6ff;border:1px solid #bfdbfe;font-size:14px;color:#1e40af;\"><b>🤖 AI 总体研判</b>：${AI_OVERALL1}</div>"
fi

# ---------- 汇总与邮件 ----------
SUMMARY="✅ 正常 $OK · ⚠️ 关注 $WARN · 🔴 异常 $CRIT"
if [ "$CRIT" -gt 0 ]; then TITLE="【服务器巡检】$TODAY · 🔴 需处理（$CRIT）"; STATUS_COLOR="#dc2626";
elif [ "$WARN" -gt 0 ]; then TITLE="【服务器巡检】$TODAY · ⚠️ 有异常（$WARN）"; STATUS_COLOR="#d97706";
else TITLE="【服务器巡检】$TODAY · ✅ 正常"; STATUS_COLOR="#16a34a"; fi
# RFC 2047 编码标题（msmtp 不会自动编码非 ASCII Subject，直接发送会乱码）
SUBJECT_ENC="=?UTF-8?B?$(printf '%s' "$TITLE" | base64 -w0)?="

REPORT_HTML="<html><head><meta charset=\"utf-8\"></head><body style=\"margin:0;padding:20px;background:#f3f4f6;font-family:system-ui,'Microsoft YaHei',sans-serif;\">
<div style=\"max-width:860px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;box-shadow:0 1px 3px rgba(0,0,0,.1);\">
<h2 style=\"margin:0 0 4px;color:#111827;\">服务器每日巡检报告</h2>
<div style=\"color:#6b7280;font-size:13px;margin-bottom:14px;\">主机 YOUR_SERVER_IP · 生成时间 $NOW</div>
<div style=\"padding:12px 16px;border-radius:8px;background:#f9fafb;border:1px solid #e5e7eb;font-size:15px;color:#374151;\">巡检结果：<b style=\"color:$STATUS_COLOR;\">$SUMMARY</b></div>
${AI_CARD}
$HTML
<div style=\"margin-top:20px;padding-top:12px;border-top:1px solid #e5e7eb;color:#9ca3af;font-size:12px;\">本报告由 /usr/local/bin/server-audit.sh 自动生成 · 报告存档 /var/log/server-audit/（保留30天）</div>
</div></body></html>"

# AI 分项研判插入对应章节（h3 之后）
if [ -n "$AI_DETAILS" ]; then
  printf '%s\n' "$AI_DETAILS" > "$TMP_DIR/ai_details.txt"
  python3 - "$REPORT_HTML" "$TMP_DIR/ai_details.txt" > "$TMP_DIR/report_ai.html" <<'PYEOF'
import re, sys
html = sys.argv[1]
for line in open(sys.argv[2], encoding="utf-8"):
    m = re.match(r"【([^】]+)】\s*(.*)", line.strip())
    if not m:
        continue
    mod, txt = m.group(1).strip(), m.group(2).strip()
    pat = re.compile(r"(<h3[^>]*>" + re.escape(mod) + r"</h3>)")
    div = ('<div style="margin:6px 0 10px;padding:8px 12px;border-radius:6px;background:#fefce8;'
           'border:1px solid #fde68a;font-size:13px;color:#854d0e;"><b>🤖 AI 研判</b>：' + txt + '</div>')
    html = pat.sub(lambda x: x.group(1) + div, html)
sys.stdout.write(html)
PYEOF
  REPORT_HTML=$(cat "$TMP_DIR/report_ai.html")
fi

# HTML 折叠换行：避免单行超 SMTP 998 字节限制
FOLDED=$(echo "$REPORT_HTML" | sed 's/></>\n</g')
echo "$FOLDED" > "$REPORT"

# 邮件组装
MAIL_FILE="$TMP_DIR/mail.txt"
{
  echo "From: YOUR_EMAIL@example.com"
  echo "To: $MAILTO"
  echo "Subject: $SUBJECT_ENC"
  echo "MIME-Version: 1.0"
  echo "Content-Type: text/html; charset=utf-8"
  echo "Content-Transfer-Encoding: 8bit"
  echo ""
  echo "$FOLDED"
} > "$MAIL_FILE"

SEND_OK=1
if [ -f "$MSMTP_CFG" ]; then
  if msmtp -a qq "$MAILTO" < "$MAIL_FILE" 2>>"$AUDIT_DIR/send-errors.log"; then SEND_OK=0; fi
else
  if command -v msmtp >/dev/null 2>&1 && msmtp -a qq "$MAILTO" < "$MAIL_FILE" 2>>"$AUDIT_DIR/send-errors.log"; then SEND_OK=0; fi
fi
if [ "$SEND_OK" -ne 0 ]; then
  echo "[$NOW] 邮件发送失败，报告保留于 $REPORT" >> "$AUDIT_DIR/send-errors.log"
fi

# 30天轮转
find "$AUDIT_DIR" -maxdepth 1 -name '*.html' -mtime +30 -delete 2>/dev/null

if [ "$SEND_OK" -eq 0 ]; then
  echo "[$NOW] 巡检完成: $SUMMARY · 邮件发送成功"
else
  echo "[$NOW] 巡检完成: $SUMMARY · 邮件发送失败（详见 send-errors.log）"
fi
exit 0
