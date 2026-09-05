# SecAutoMind — 快速运行指南

> **SecAutoMind** 是一个**多智能体驱动的靶场自主攻防推演平台**，面向授权靶场与教学场景。
> 集成 90 个 YAML 工具配方（覆盖 100+ 底层安全工具），支持人机协同审计、自动化报告生成。

本目录是**已编译、可直接运行**的分发包。接收方按以下步骤即可启动。

---

## 1. 系统要求

| 项 | 要求 |
|---|---|
| 操作系统 | Windows 10/11 / Windows Server 2019+ (x64) |
| 内存 | 8 GB+ 推荐 |
| 磁盘 | ≥ 500 MB 可用空间 |
| Python | **3.10+** （仅在使用安全工具/MCP 时需要） |
| 浏览器 | Chrome / Edge / Firefox 最新版 |
| 网络 | 默认监听 `127.0.0.1:8080`（不开外网） |

> Linux/macOS 本包不直接支持（二进制是 Windows 版），需要源码重新编译。

---

## 2. 一键启动

### 2.1 最简启动（仅主服务）

1. 解压本目录到任意位置，**路径不要有中文和空格**（推荐 `C:\SecAutoMind\`）
2. 双击 `start.bat`
3. 等浏览器自动打开 `http://127.0.0.1:8080/`
4. 首次启动会生成随机 admin 密码，**在控制台窗口里打印，并同时写入 `data/admin_initial_password.txt`**（可直接打开该文件查看，GUI 无控制台也不受影响）
5. 用 `admin` + 那个密码登录

### 2.2 完整启动（主服务 + 安全工具 + MCP）

主服务只依赖 Go 二进制，可以独立跑。但要使用 `arjun / bloodhound / mcp` 等需要 Python 的功能：

```bat
REM 1. 准备 Python 3.10+ 环境
python --version

REM 2. 重建 venv（首次运行）
setup_venv.bat

REM 3. 启动主服务
start.bat
```

---

## 3. 常用命令

| 操作 | 命令 |
|---|---|
| 启动 | `start.bat` |
| 停止 | `stop.bat` 或 `taskkill /F /IM secautomind-ai.exe` |
| 查看日志 | 控制台窗口（默认 `log.output: stdout`）；如需落盘改 `config.yaml` 的 `log.output` 为文件路径（如 `server.out.log`） |
| 修改配置 | 直接编辑 `config.yaml`，**修改后重启**才生效 |
| 桌面快捷方式 | `install-shortcut.ps1` (PowerShell) |

---

## 4. 默认账号

- 用户名：`admin`
- 密码：**首次启动时在控制台打印一次**（形如 `Initial admin password: xxxxxxxx`），同时**已自动写入 `data/admin_initial_password.txt`**（仅首次初始化生成，可直接打开该文件查看，GUI 无控制台也不受影响）
- **首次运行向导**：首次启动后访问 `http://127.0.0.1:<port>/`，页面会引导用上述一次性初始密码设置**管理员专属密码**（完成后 `data/admin_initial_password.txt` 自动删除，之后用你设置的密码登录）。跳过向导也可直接以初始密码登录。
- 密码丢失（文件误删或忘记）：运行 `secautomind-ai.exe -config config.yaml --reset-admin-password` 交互式重置后重启
- 修改密码：登录后 → 右上角"设置"→"用户管理"

> 💡 控制台输出不可见（如后台/无窗口启动）时无需担心——`data/admin_initial_password.txt` 始终提供首次密码。

---

## 5. 目录结构

```
SecAutoMind/
├── secautomind-ai.exe        # 主服务 (~154MB Go 编译产物, v1.7.25)
├── config.yaml               # 主配置
├── config.example.yaml       # 配置模板 (config.yaml 缺失时会自动拷贝)
├── start.bat                 # 启动脚本
├── stop.bat                  # 停止脚本
├── setup_venv.bat            # 重建 venv (按需)
├── install-shortcut.ps1      # 创建桌面快捷方式
├── README.md                 # 项目说明
├── README_CN.md              # 项目说明（中文）
├── requirements.txt          # Python 依赖（用于安全工具）
├── web/                      # 前端 (HTML + JS + CSS + i18n)
├── internal/ cmd/            # Go 源码 (仅供参考，编译用)
├── agents/ roles/            # Agent 与角色定义
├── skills/                   # Skill 库 (23 个攻防技能包)
├── tools/                    # 工具库 (90 个 YAML 工具定义)
├── mcp-servers/              # MCP 服务 (pent_claude_agent, reverse_shell)
├── plugins/                  # 浏览器/Burp 插件源码
├── knowledge_base/           # 知识库 (SQL Injection / Prompt Injection)
└── docs/                     # 完整文档 (中英双语)
```

> 注：venv（Python 虚拟环境，约 110MB）**不包含在本包**。需要时运行 `setup_venv.bat` 自动重建。

---

## 6. 常见问题

### Q: 启动后浏览器没自动打开
A: 手动访问 `http://127.0.0.1:8080/`。

### Q: 端口 8080 被占用
A: 编辑 `config.yaml` 中 `server.port`，改完后重启。

### Q: 报错 "missing python"
A: 仅在调用需要 Python 的工具时出现。运行 `setup_venv.bat` 重建 venv。

### Q: 报 "TLS certificate" 错误
A: 配置默认 `tls_enabled: true`。用 `start.bat --http` 走 HTTP 即可（已在脚本里默认启用）。

### Q: 怎么彻底卸载
A: 删除整个目录即可（数据存于 `data/conversations.db`，可一并删除）。

### Q: 可以部署到公网吗
A: 可以，但务必修改 admin 密码 + 改 `server.host` 为 `0.0.0.0` + 配置 TLS。

### Q: 怎么在钉钉 / 飞书 / Telegram 里和智能体对话
A: 机器人通道默认关闭，属可选扩展。以钉钉为例：在钉钉开放平台创建企业内部应用拿到 Client ID / Client Secret，然后二选一注入——① 填入 `config.yaml` 的 `robots.dingtalk`（该文件已被 `.gitignore` 忽略，勿提交真实密钥）；② 环境变量 `DING_APP_KEY` / `DING_APP_SECRET`（+ 可选 `DINGTALK_ENABLED=true`），优先级高于配置文件。凭证缺失时仅禁用该通道并告警，主系统全部功能不受影响。详细步骤见 `docs/zh-CN/robot.md`。

---

## 7. 验证包完整性

启动后浏览器能看到：
- ✅ 左上角 logo (紫色 SecAutoMind + AI)
- ✅ 4 个分组菜单 (工作台 / 安全作业 / 能力中心 / 平台管理)
- ✅ 默认 dashboard 有 KPI 卡片

如果页面打不开或 404，检查：
1. 防火墙是否拦截 8080
2. 控制台窗口（或 `config.yaml` 指定的日志文件）末尾是否有 ERROR
3. 浏览器开发者工具 Network 是否有 401（多半是 admin 密码没拿到）

---

## 8. 许可与免责

- **License**: Apache License 2.0（见 `LICENSE`）
- **安全免责**: 本平台**仅用于已授权靶场**。在未授权系统上使用需自行承担法律责任。
- **完整免责声明**: 见 `SECURITY.md`

---

**版本**: v1.7.25
**构建时间**: 2026-09-03（已含引导密码落盘与 shell 流式执行修复）
**分发包制作**: 2026-09-03
