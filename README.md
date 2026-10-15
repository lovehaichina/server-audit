# 服务器巡检安全脚本 (Server Audit)

一套**开箱即用的 VPS 每日巡检 + 安全扫描**脚本：系统状态、服务健康、安全态势、登录审计、命令操作统计，**AI 自动研判**并生成 HTML 报告，通过邮箱推送到你手上。

> 无人值守的服务器管家：每天早上自动体检一遍服务器，把"有没有被入侵、哪个服务挂了、谁登过服务器、磁盘还够不够"这些问题，浓缩成一份带 AI 结论的报告发到你邮箱。

---

## 为什么需要它？

- **VPS 无人值守**：服务挂了、被扫描了、磁盘满了，等你发现往往已经晚了。
- **登录审计靠人肉**：谁在什么时候从哪个 IP 登过服务器、做过什么操作，没有系统化记录与比对。
- **日志太多看不完**：几十 MB 的日志没人逐行看，需要 AI 把"异常"拎出来讲人话。
- **安全工具太分散**：fail2ban、登录审计、服务健康、备份检查散落在不同工具里，没有一个统一入口。

## 功能特性

- **系统状态巡检**：CPU、内存、磁盘、负载、SWAP、进程数，异常自动告警。
- **服务健康检查**：systemd 服务存活、关键端口、**网站可达性**（HTTP 状态码逐站点探测）。
- **安全扫描**：fail2ban 封禁统计、SSH 登录审计（**历史成功登录 IP 清单比对** + ip-api.com 归属查询）、异常登录模式识别。
- **命令操作审计**：对当天 bash 操作做脱敏统计（自动遮蔽 `sk-`/`password=` 等敏感串），送 AI 分析"做了什么 → 潜在风险 → 结论 → 建议"。
- **AI 综合研判**：接入 DeepSeek API，汇总全部巡检结果给出**总体结论 + 异常章节专项研判**（风险、问题、结论、建议四段式）。
- **HTML 报告 + 邮件推送**：自动生成可视化 HTML 报告，经 msmtp 发到你邮箱（QQ 邮箱等 SMTP 均可）。
- **网站文件变化巡检**：监控多个站点的文件/服务变化，纳入例行巡检范围。
- **备份状态检查**：若使用 restic + Cloudflare R2 备份，自动检查备份快照健康与还原脚本可用性。
- **每日定时**：cron 一键接入，`0 30 7 * * *` 每天自动执行。

## 快速开始

### 环境要求

| 项 | 要求 |
|---|---|
| 系统 | Linux（CentOS/Ubuntu/Debian 均可） |
| 依赖 | `curl`、`msmtp`、`python3`（用于 AI 研判时） |
| 权限 | root（读取日志、systemd、fail2ban 需要） |

### 安装

```bash
# 1. 上传脚本到服务器
install -m 755 server-audit.sh /usr/local/bin/server-audit.sh

# 2. （可选）AI 研判：写入 DeepSeek API Key
echo '你的_DeepSeek_API_Key' > /root/.deepseek_key && chmod 600 /root/.deepseek_key

# 3. 配置邮件发送（msmtp + QQ 邮箱示例）
cat > /root/.msmtprc <<'EOF'
defaults
auth on
tls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account qq
host smtp.qq.com
port 465
from 你的QQ邮箱@qq.com
user 你的QQ邮箱@qq.com
password 你的SMTP授权码
EOF
chmod 600 /root/.msmtprc

# 4. 加入每日定时任务（每天 7:30 巡检）
echo "30 7 * * * /usr/local/bin/server-audit.sh >> /var/log/server-audit/cron-run.log 2>&1" | crontab -

# 5. 立即试跑一次
bash /usr/local/bin/server-audit.sh
```

> 报告默认输出到 `/var/log/server-audit/`，收件邮箱在脚本顶部 `MAILTO=` 配置。

### 配套脚本（备份体系，可选）

| 脚本 | 用途 |
|---|---|
| `r2-setup.sh` | 一键配置 Cloudflare R2 作为 restic 备份仓库（填写占位符后运行） |
| `backup-now.sh` | 手动全量备份（restic → R2，含关键目录清单） |
| `restic-check.sh` | 检查备份快照健康与完整性 |
| `restore.sh` | 交互式还原备份（列出快照 → 选择 → 还原） |

## 配置说明

| 项 | 位置 | 说明 |
|---|---|---|
| 收件邮箱 | `server-audit.sh` 顶部 `MAILTO=` | 报告发送目标 |
| AI 密钥 | `/root/.deepseek_key` | DeepSeek API Key（600 权限） |
| SMTP | `/root/.msmtprc` | msmtp 配置（QQ/163/Gmail 均可用） |
| 备份凭据 | `/root/.restic-env`、`/root/.restic-pass` | restic/R2 凭据，**不入库** |
| 巡检范围 | 脚本内 `WEBSITES`、`SERVICES` 等变量 | 自定义站点/服务清单 |

> 所有凭据均为**外部文件引用**，脚本与仓库中不含任何明文密钥。

## 目录结构

```
server-audit/
├── server-audit.sh   # 主巡检脚本（全部逻辑，单文件）
├── backup-now.sh     # 手动全量备份（restic → R2）
├── r2-setup.sh       # Cloudflare R2 备份仓库一键配置
├── restic-check.sh   # 备份快照健康检查
└── restore.sh        # 交互式还原工具
```

## 常见问题

**Q：必须配置 AI 研判吗？**
不是。未配置 `/root/.deepseek_key` 时脚本自动跳过 AI 环节，其余巡检照常执行。

**Q：报告是中文的吗？**
是。HTML 报告全中文，标题经 RFC 2047 编码，邮件客户端不会乱码。

**Q：IP 归属查询失败怎么办？**
脚本内置历史归属清单缓存（先查本地清单，未命中才请求 ip-api.com），外部 API 不可用时静默降级为"无归属信息"，不影响整体巡检。

**Q：能监控多个网站吗？**
能。在脚本内 `WEBSITES` 变量列出站点即可，逐个探测 HTTP 状态码并纳入报告。

## License

[GPL-3.0](LICENSE) © 2026 luohai
