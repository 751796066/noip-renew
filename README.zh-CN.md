# noip-renew（HTTP 版自动确认）

No-IP 免费动态域名每 30 天要手动点一次「Confirm」，超时就进赎回期、再超时删除。
这个 fork 用 GitHub Actions 定时替你点确认。

## 和上游的区别

| 上游 loblab/noip-renew (1.2) | 本 fork |
| --- | --- |
| Selenium 3 写法（`find_element_by_*`，新版 Selenium 已移除） | 纯 HTTP 表单 POST，不装浏览器 |
| 密码必须 base64 传参 | 直接读密码 |
| 自己改本机 crontab | GitHub Actions cron |
| 不处理 No-IP 的邮箱二次验证 | 支持 2FA + 「信任设备 30 天」Cookie 复用 |
| 站点改版即失效 | 运行时扫描页面，自动识别「Confirm」按钮/表单 |

## 运行逻辑

1. 载入 `NOIP_COOKIES` 里的信任设备 Cookie；有效则跳过 2FA 直接进后台。
2. 无效则登录：`POST /login` → 需要时 `POST /2fa/verify`（自动勾选 `trust_device=1`）。
   验证码来源优先级：`NOIP_2FA_CODE` → `NOIP_2FA_WAIT_FILE` → IMAP 读信箱。
3. 读取后台与 DNS 记录页，识别免费主机名（当前为 `orbi752.mynetgear.com`）。
4. 页面上出现 Confirm 控件（第 23 天起出现，窗口 7 天）就提交；没出现就输出
   `RESULT=NOTHING_TO_CONFIRM` 并正常退出。

## 需要的 Secrets

| 名称 | 内容 |
| --- | --- |
| `NOIP_USERNAME` | No-IP 登录名 |
| `NOIP_PASSWORD` | No-IP 密码 |
| `NOIP_COOKIES` | 信任设备的 Cookie（base64 后的 JSON），用于跳过邮箱验证码 |
| `NOIP_IMAP_USER` / `NOIP_IMAP_PASS` | QQ 邮箱地址 + IMAP 授权码；Cookie 失效时脚本自己去收件箱读那 6 位验证码，不需要人工填 |

设置方式：`gh secret set NOIP_COOKIES --repo <你>/noip-renew --body "$(base64 -w0 noip-cookies.json)"`

## 定时

`.github/workflows/noip-renew.yml`：每 3 天 03:00 UTC 跑一次，也可在 Actions 页面手动
`Run workflow`。日志里的 `RESULT=` 和 `artifacts/` 附件（各页面 HTML）用于排错。

## 无人值守怎么处理验证码

- 验证码邮件标题固定为 `No-IP Verification Code: 123456`，脚本优先从标题取（正文兜底）。
- 只认**本次登录之后到达**的邮件（登录时刻 -5 秒起算），并且优先跳过 20 分钟外的旧信，
  防止把上一轮已经用过的码再提交一次（No-IP 一码一用）。
- 邮件通常 30 秒内到达，脚本最多轮询约 2 分钟。
- No-IP 偶尔会在 `POST /2fa/verify` 中途掐断 TLS 连接。这种情况不会拿同一个码重放，
  而是**重开一轮会话、取一个新码**再审，最多 3 轮。

## 已知边界

- 信任 Cookie 有效期 30 天。到期后若没有配置 IMAP，任务会以「2FA code unavailable」
  失败——届时重新跑一次登录、更新 `NOIP_COOKIES` 即可。
- 确认按钮只在到期前 7 天出现，平时运行时看到 `NOTHING_TO_CONFIRM` 是正常的。
- 该脚本只做「确认」，不做动态 DNS 更新；IP 同步仍由路由器/DUC 负责。
