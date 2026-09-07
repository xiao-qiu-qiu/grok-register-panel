# Windows 本机运行

Windows 跑批不依赖 Xvfb，也不需要 SSH 到 Linux 上的 `127.0.0.1:82xx` mixed 口。
代理必须是 **本机进程能拨通** 的 HTTP/SOCKS URL。

## 安装

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

会创建 `.venv`、安装 `requirements.txt`、执行 `python -m camoufox fetch`。
再编辑 `config.json`（邮箱服务、默认 proxy）。

## 跑批 / 面板

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_windows_batch.ps1 -Count 1 -Workers 1
powershell -ExecutionPolicy Bypass -File scripts\run_windows_panel.ps1
```

默认环境：

- `GROK_HEADLESS=1`（有头模式设 `GROK_HEADED=1`）
- `PYTHONUTF8=1`
- `GROK_USE_XVFB=0`

面板令牌：启动脚本会把 `MONITOR_TOKEN` 写入项目根目录的 `.env.monitor`（已 gitignore），下次启动复用同一串。浏览器「访问令牌」必须与控制台打印的 `token=` 一致；换浏览器或清站点数据后重新粘贴一次即可。不要把 `.env.monitor` 提交进仓库。

代理池在面板里导入，或写 `proxies.txt` / `config.json` 的 `proxy`。支持 `http://` 与 `socks5://`。
不要沿用另一台机器上的 loopback 端口。

可选：本机另起 mihomo/clash，把 mixed 口填进代理池。若已放置
`bin\mihomo-windows-amd64.exe` 与 `log\mihomo-windows.yaml`（含凭据，勿提交）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_windows_mihomo.ps1
```

## Playwright Node

不要把 `PLAYWRIGHT_NODEJS_PATH` 指到 bash 版 `scripts/playwright-node`。
运行时会解析 `node.exe` 或 Playwright 自带 Node，并用带引号的
`NODE_OPTIONS --require "..."` 注入 `scripts/playwright-epipe-guard.js`。
