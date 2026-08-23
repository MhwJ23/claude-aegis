<p align="center">
  <img src="assets/logo.png" alt="claude-aegis logo" width="132" />
</p>

# claude-aegis

在**原生 Windows** 上，用真正的操作系统级沙箱 —— **AppContainer** —— 运行
**Claude Code**（或任意 Windows 程序）。免管理员权限、无需 WSL、无需 Docker。

> English guide: [README.md](README.md) · [English](README.md)

[![CI](https://github.com/MhwJ23/claude-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/MhwJ23/claude-aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/MhwJ23/claude-aegis)](https://github.com/MhwJ23/claude-aegis/releases)

---

## claude-aegis 是什么？

它把 **Claude Code**（或你运行的任何程序）关进 Windows 的 **AppContainer**——
也就是 Windows 商店应用用的那种系统级隔离。由你决定它能读/写哪些文件夹、能访问
哪些网站、能启动哪些程序；其余一律拦截，每次操作都写进审计日志。无需管理员权限、
无需 WSL、无需 Docker。

## 面向谁？

| 你是… | 用这个 | 得到什么 |
|---|---|---|
| **开发者 / 极客** | [CLI](#cli) | 一条命令、可脚本化、可进 CI |
| **企业 / 安全 / 非极客** | [GUI](#gui) | 图形配置、审计日志、合规友好 |

**为什么重要：** Claude Code 自带的沙箱只支持 macOS(Seatbelt) 和 Linux/WSL2
(bubblewrap)。原生 Windows 上沙箱**官方不支持**。没有 OS 级隔离时，`deny` 规则
只能拦住 Claude 内置的 Read 工具，拦不住 `Bash(cat ~/.ssh/id_rsa)`。
claude-aegis 正是填补这个空白。

---

## 安装

从 [GitHub Releases](https://github.com/MhwJ23/claude-aegis/releases) 下载最新版：

- **`claude-aegis_*_x64-setup.exe`** —— 一键 Windows 安装包（非技术用户推荐；
  一次装好 CLI、代理和 GUI）。
- **`claude-aegis-v*.zip`** —— 便携版二进制（`claude-aegis.exe`、
  `claude-aegis-proxy.exe`、`claude-aegis-gui.exe`），解压即用。

需要 Windows 10 1703+（LPAC）。无需管理员权限。

---

## 能做什么

四类控制，由 Windows AppContainer（LowBox/LPAC）机制强制执行：

1. **文件** —— 读 / 写 / 隐藏 三档白名单。默认全部不可见，只放行清单内的路径。
2. **网络** —— 域名白名单，由沙箱内的 loopback CONNECT 代理执行（不做 MITM，
   TLS 原样透传）。
3. **进程** —— 可执行程序白名单，只允许启动清单内的二进制。
4. **权限** —— AppContainer 身份本身就是权限边界（AppContainer 令牌天然受限）。

全程**免管理员**（AppContainer 无需提权）。

---

## CLI

编译二进制：

```bash
cargo build --release -p claude-aegis -p claude-aegis-proxy
```

生成配置，然后运行：

```bash
# 1. 在当前目录生成 claude-aegis.toml
claude-aegis init

# 2. 在沙箱内运行 claude（或配置里的 command）
claude-aegis run --config claude-aegis.toml -- -p "总结这个仓库"
```

顺带写审计日志：

```bash
claude-aegis run --config claude-aegis.toml \
  --audit-log "$LOCALAPPDATA\claude-aegis\audit.log" -- -p "hi"
```

### 配置（`claude-aegis.toml`）

```toml
profile = "claude-aegis"      # AppContainer 身份
command = "claude"            # 裸名字（从 PATH 解析）或完整路径

[files]
read  = ["C:\\projects"]      # 沙箱可读目录
write = ["C:\\projects"]      # 沙箱可写目录（隐含可读）

[network]
domains = ["api.anthropic.com"]   # 域名白名单；为空 = 不设域名过滤

[process]
allow = ["git.exe", "node.exe"]   # 可执行程序白名单；为空 = 全部放行
```

---

## GUI

GUI 是「配置 + 启动 + 审计」控制台（Tauri，静态前端，构建无需 Node）。
「运行」会在独立控制台窗口里启动沙箱程序，GUI 侧实时看审计日志。

构建：

```bash
cargo build -p claude-aegis-gui
```

运行 `claude-aegis-gui.exe`（`claude-aegis-proxy.exe` 需与它同目录）。在窗口里
可以编辑配置、用原生文件夹对话框选目录、启动沙箱、查看实时着色审计日志。

---

## 审计日志

每次运行都会向 `%LOCALAPPDATA%\claude-aegis\audit.log` 追加 JSON 行：

```json
{"access":"read_execute","event":"grant","path":"D:\\aegis\\claude-aegis-proxy.exe","ts":1787469295}
{"command":"D:\\aegis\\claude-aegis-proxy.exe","event":"launch","pid":29020,"profile":"claude-aegis","ts":1787469295}
{"addr":"127.0.0.1:64571","event":"proxy_start","ts":1787469295}
{"event":"net","host":"api.anthropic.com","allowed":true,"ts":1787469295}
{"code":0,"event":"exit","pid":31280,"ts":1787469296}
```

事件类型：`launch`、`exit`、`grant`、`proxy_start`、`proxy_stop`、`net`。
日志**只由可信的宿主进程写入** —— 代理的 `net` 判定先写到自己的 stdout，
再由宿主重定向进日志文件，因此沙箱程序永远拿不到自己审计日志的写权限。

---

## 安全模型 —— 说点实在的

- **是真正的 OS 沙箱，不是策略文件。** AppContainer 由 Windows 内核强制执行，
  不是 Claude 的工具代码。
- **不能替代独立安全审计。** 任何沙箱都不是证明。把它当作纵深防御的一层。
- **域名白名单已强制，但按主机名匹配。** 代理运行时，沙箱程序**没有直连网络**
  （不授予 internetClient），所有流量必须走代理，无法绕过白名单。过滤按主机名、
  不按 IP，也不检查加密载荷；能到达白名单域名的载荷仍可经该连接外传。
- **Windows 默认授予 AppContainer 对某些位置的读权限**（如 `%TEMP%` 和系统目录）。
  「默认拒绝」因此不覆盖 `%TEMP%`——别把秘密放 %TEMP% 还指望沙箱替你藏住。
- **代理与沙箱共享同一身份。** 代理和被沙箱的程序跑在同一个 AppContainer
  （同 SID），这正是「免管理员 loopback 架构」成立的前提。代理是我们自己的小二进制。
- **审计是「可察觉篡改」，不是「不可篡改」。** 沙箱程序写不了审计文件，
  但本项目不会把日志送到中央采集器。

## 架构

```
claude-aegis/
├── crates/
│   ├── core/     # AppContainer 引擎（文件 / 网络 / 进程 / 权限）
│   ├── cli/      # `claude-aegis`（init、run）
│   └── proxy/    # loopback CONNECT 代理 + 域名白名单
├── gui/          # Tauri GUI（配置 + 审计控制台）
└── spike/        # 设计笔记与验证实验（见 spike/FINDINGS.md）
```

引擎封装 [`rappct`](https://github.com/cpjet64/rappct) 并直接调用 AppContainer
Win32 API（具体常量和踩坑记录见 `spike/FINDINGS.md`）。

## 从源码构建

要求：Windows 上的 Rust（stable，MSVC 目标）。GitHub Actions 在
`windows-latest` 上构建与测试。

```bash
cargo build --workspace        # core + cli + proxy + gui
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

## 许可证

[Apache-2.0](LICENSE)。
