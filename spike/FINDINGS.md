# Spike 发现（阶段 0 — 机制验证已通过）

> 本文件记录阶段 0 的关键结论和踩坑，任何新会话接手前先读这里。
> 最后更新：2026-08-22

## ✅ 结论

**文件隔离验证通过**：普通进程能读秘密文件（exit code 0），AppContainer 进程读同一文件被拒绝（"拒绝访问"，exit code 1）。

- AppContainer 隔离在本机（Windows 11 24H2）**完全可用**。
- **零安装**：只用系统自带 `csc.exe`（.NET Framework 4.8 C# 编译器）+ 内置 Win32 API，无需管理员权限。

## 🔑 关键技术参数（务必沿用，都是踩坑换来的）

1. **`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009`**
   - ⚠️ 不是 `0x20011`！`0x20011` 会报 ERROR_BAD_LENGTH(24)，是错误值。
2. **`SECURITY_CAPABILITIES` 结构 = 24 字节（x64）**，字段顺序：
   - `AppContainerSid`(IntPtr, 8) + `Capabilities`(IntPtr, 8) + `CapabilityCount`(uint, 4) + `Reserved`(uint, 4)
3. **`STARTUPINFOEX.cb = 112`**（x64），`sizeof(STARTUPINFO) = 104`。
4. **capability SID 用 `CreateWellKnownSid(类型=85, WinCapabilityInternetClientSid)`**，再构造 `SID_AND_ATTRIBUTES`：
   - `Sid = capSid`，`Attributes = SE_GROUP_ENABLED = 0x00000004`
   - ⚠️ **不要用 `DeriveCapabilitySidsFromName`**——它返回的 `Attributes` 字段是垃圾值（0xDB17...），会导致 CreateProcess 报 ERROR_INVALID_PARAMETER(87)。
5. **调用序列**（顺序不可乱）：
   ```
   CreateAppContainerProfile → CreateWellKnownSid(85) → 构造 SID_AND_ATTRIBUTES
   → 构造 SECURITY_CAPABILITIES → InitializeProcThreadAttributeList(两次，先拿大小)
   → UpdateProcThreadAttribute(0x20009) → CreateProcess(EXTENDED_STARTUPINFO_PRESENT=0x80000)
   → WaitForSingleObject → GetExitCodeProcess
   ```

## 📁 可复用代码

- `spike/VerifyIsolation.cs` —— 完整可工作的 C# 验证程序（文件隔离对照实验）。
  - 编译：`csc.exe -nologo -out:VerifyIsolation.exe VerifyIsolation.cs`（在 spike 目录，用 `-` 前缀避免 Git Bash 路径转换）
- `spike/TestAttrScan.cs` —— Attribute 常量扫描（找 0x20009 用的）。
- `spike/debug-*.ps1` —— PowerShell P/Invoke 版（已弃用，PowerShell 封送有坑，用 C#）。

## ⚠️ 已知坑

- Git Bash 里 `csc.exe` 参数要用 `-` 前缀（`-nologo`），不能用 `/nologo`（会被当路径）。
- PowerShell 5.1 读无 BOM UTF-8 脚本会乱码 → spike 脚本/代码全用英文。
- `GetLastWin32Error` 在 P/Invoke 成功后是残留值（如 122），判断成败看 `ok` 返回值，不看 err。

## 🔜 下一步（阶段 0 第二层：端到端验证）

把真实的 Claude Code 关进 AppContainer，验证能否启动、连 API、跑子进程：

- **claude.exe 路径**（npm 安装）：`C:\Users\Michael Jordan\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe`
- 方法：复用 VerifyIsolation.cs 的 AppContainer 启动逻辑，把 `cmd.exe /c type ...` 换成 `claude.exe -p "say hi"`（或 headless 模式），观察它能否在沙箱里跑起来。
- **注意**：AppContainer 默认无网络能力，需要给它加 `internetClient`/`internetClientServer` capability 才能连 Anthropic API（本验证已用 internetClient）。

## 📌 对阶段 1（Rust 实现）的指导

正式产品用 Rust + rappct 时，上述常量值和调用序列**完全适用**——rappct 底层就是同一套 Win32 API。核心数值直接搬运：`0x20009`、`SECURITY_CAPABILITIES=24`、`CreateWellKnownSid(85)`、`SE_GROUP_ENABLED=0x4`。

---

## ✅ 端到端验证（阶段 0 第二层）—— 启动已通过

- **claude.exe 是自包含 PE 二进制（337MB，Bun 编译）**，不依赖外部 node。路径：`C:\Users\Michael Jordan\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe`
- **验证结果**：授权路径后，claude.exe 在 AppContainer 里成功运行 `--version`，输出 `2.1.240 (Claude Code)`，exit 0。✅ 可复用代码：`spike/EndToEnd.cs`

### 端到端验证的额外踩坑（重要）

1. **路径遍历问题**：AppContainer 访问用户目录深处的文件，需要授权**路径链每一级**的遍历权限。实测只授权 claude-code 目录不够，还需授权 `C:\Users\Michael Jordan`（用户目录）RX，让 AppContainer 能遍历到 claude.exe。→ 这是真实产品设计的核心难点（授权范围 vs 安全性的平衡）。
2. **ConvertSidToStringSid 必须 `CharSet.Unicode`**：不指定会用 ANSI 版 + `PtrToStringAuto` 解码，导致 SID 字符串乱码。修正：`CharSet=CharSet.Unicode` + `Marshal.PtrToStringUni`。
3. **icacls 授权语法**：`icacls "路径" /grant *S-1-15-2-xxx:(OI)(CI)RX`（SID 和权限**不加引号**，SID 前加 `*`）。exit 0 = 成功。
4. **cmd.exe 引号嵌套易错**：带空格路径（"Michael Jordan"）用 cmd.exe /c 包裹时引号转义极易错（报"文件名语法不正确"）。**可靠做法**：`CreateProcess(lpApplicationName=完整路径, ...)` 直接启动，绕开 cmd.exe。
5. **stdout 继承 OK**：claude.exe 在 AppContainer 里的 stdout 能直接继承到父进程控制台（没设置 STARTF_USESTDHANDLES 时）。

### ✅ 端到端验证第二层：连 API 干活 —— 已通过

- 复用 `EndToEnd.cs`，跑 `claude.exe -p "Reply with exactly: OK"`，结果：成功连上 Anthropic API，回复 `OK`，exit 0。✅
- **`internetClient` capability 足够**连 api.anthropic.com（无需 internetClientServer / localhost）。
- 认证凭证从 `~/.claude` 正常读取（已授权 M）。
- 完整验证链（已跑通）：`CreateAppContainerProfile → 授权路径(icacls) → CreateWellKnownSid(85) → SECURITY_CAPABILITIES → UpdateProcThreadAttribute(0x20009) → CreateProcess(claude.exe -p) → 连 API → 回复 OK`。

**🎉 阶段 0 全部通过 → 可进入阶段 1（Rust 核心库）。**

---

## 🎉 阶段 1 实弹验证（本机 Rust 编译运行）—— 成功

本机装 Rust 1.98 + MSVC（D 盘），`cargo build` 通过，`claude-aegis` CLI 真实把 claude.exe 关进 AppContainer，连 API 回复成功。

### 关键 bug：rappct 的 launch_in_container 在 Win11 24H2 报 FILE_NOT_FOUND

- **症状**：rappct 0.13.3 的 `launch_in_container` 在 Windows 11 24H2（build 26100）上，CreateProcessW 报 ERROR_FILE_NOT_FOUND (2)，最简的 cmd.exe 也失败。
- **根因**：`CreateAppContainerProfile` 的 `pszDescription` 传 NULL 会导致它失败，然后 fallback 到 `DeriveAppContainerSidFromAppContainerName`——而 **Derive 和 Create 返回不同的 SID**，SECURITY_CAPABILITIES 用了错误的 SID。spike 的 C# 传了非空 `"spike"` 所以成功。
- **解决**：绕开 rappct 的 launch 和 SDDL 往返，直接用 windows crate 调 `CreateAppContainerProfile`（**desc 必须非空**）+ `CreateWellKnownSid(WinCapabilityInternetClientSid=85)`，手动构建 SECURITY_CAPABILITIES + attribute list + `CreateProcessW`（手动 extern 声明 `#[link_name = "CreateProcessW"]`）。
- **验证**：`claude-aegis --exe claude.exe --grant ... -- -p hi` → claude 在沙箱里回复 "Hi! What can I help you with today?" ✅

### 其他踩坑

- `InitializeProcThreadAttributeList` / `CreateWellKnownSid` 第一次调用（探测大小）返回 ERROR_INSUFFICIENT_BUFFER(122)，必须忽略（不能 `?`）。
- `LocalAlloc` 返回 `Result<HLOCAL>`；`LocalFree` 需要 `Option<HLOCAL>`。
- Git Bash 把 `/c` 转成 `C:/`——测试 cmd.exe 参数要用 `MSYS_NO_PATHCONV=1`。
- windows crate 0.62.2 的 `CreateProcessW` 用泛型 `Param<PCWSTR>`，手动 `#[link_name]` 声明更稳。

---

## 🎯 阶段 2 关键发现：AppContainer 的 loopback 网络隔离（决定域名代理架构）

> 实弹验证（`crates/core/examples/loopback_probe.rs` 探针 + 沙箱内 curl）+ 联网研究双重确认。

### 结论：`internetClient` 不授予 loopback，但**同 SID 进程间 loopback 可以互通**

1. **AppContainer → 宿主进程的 loopback 被 WFP 阻断**：仅带 `internetClient`(S-1-15-3-1) 的沙箱进程，连接宿主在 127.0.0.1 的监听器，SYN 被 WFP 的 AppContainer Loopback Filter 静默丢弃（curl 卡在 `Trying 127.0.0.1:...`，不报"拒绝连接"）。`privateNetworkClientServer`(S-1-15-3-3) 同样**不**授予 loopback。
2. **loopback 豁免需要管理员**：`CheckNetIsolation LoopbackExempt -a -p=<SID>` 或 `NetworkIsolationSetAppContainerConfig`（rappct 的 `net` feature 封装了这个），写入防火墙服务（MPSSVC），非提升权限调用返回 ACCESS_DENIED。
3. **同 SID（同一 AppContainer）多进程 loopback 可以互通**（本机实弹确认）：两个分别用 `CreateProcessW` 关进**同一个 profile 名**（同 SID）的进程，一个 bind 127.0.0.1、一个 connect 127.0.0.1，连接成功（探针输出 `CONNECTED` + `ACCEPTED`）。无需豁免、无需管理员。

### 架构决策（据此定稿）

- **域名代理跑在沙箱内部**（与 claude.exe 同一个 AppContainer / 同 SID），监听 127.0.0.1，claude 通过 `HTTPS_PROXY=http://127.0.0.1:PORT` 走代理。代理自身用 `internetClient` 出网、按域名白名单放行。
- 这样全程**免管理员**，符合项目"免 admin"核心卖点。
- 代价：代理和 claude 共享同一能力令牌（代理必须小、可信），但代理是本项目自己的二进制，可接受。

### 其它踩坑（阶段 2 排查时）

- 后台/嵌套 `cmd //c` 调用 `build.bat` 会**吞掉 cargo 输出**；要调试编译错误，直接 `export RUSTUP_HOME/D...` 后从 bash 直接跑 `cargo`（纯 Rust 目标可脱离 vcvars 链接）。
- `cargo build --example X` 在 workspace 根需要 `-p <crate>` 指定包。
- 非提升权限的 `netstat`/`Get-NetTCPConnection` **看不到** AppContainer 的 loopback 监听器（但端口确实被占用，二次 bind 报 10048）。
- 当前 CLI `launch()` 不等待子进程、进程退出会杀死线程内代理 → 阶段 2 必须改成"启动代理进程(同容器) → 启动 claude → 等 claude 退出 → 杀代理"。

---

## ✅ 阶段 2 完成：CLI 完整化（配置文件 + 完整命令 + 域名代理接回 launch）

> 实弹验证全部通过：`claude-aegis run` 把 claude.exe 关进沙箱、经域内代理连 API 回复 OK。

### 交付内容

- **配置文件** `claude-aegis.toml`（TOML，serde）：`profile` / `command` / `[files].read/write` / `[network].domains` / `[process].allow`。`crates/core/src/config.rs`。
- **CLI**（clap derive）：`claude-aegis init`（脚手架生成配置）、`claude-aegis run --config <path> [--dir <项目>] [-- <args>]`（加载配置 → 授权 → 起代理 → 启动 → 等退出 → 杀代理）。`crates/cli/src/main.rs`。
- **代理接回 launch**：代理作为独立进程跑在沙箱内部（同 SID），CLI 选空闲 loopback 端口、启动代理、把 `HTTPS_PROXY=http://127.0.0.1:PORT` 注入 claude（`NO_PROXY=127.0.0.1,localhost`）。核心库 `launch()` 返回 `Child`（含 `wait()`/`kill()`）。

### 关键踩坑（阶段 2 实弹排查）

1. **ACL 授权在大目录上极慢（~30s/个）**：`SetNamedSecurityInfoW`（rappct 用）和 `icacls` 在 `C:\Users\<用户>`、`AppData` 这类海量目录上都 ~28-30s——本质是 ACL **继承传播**（把继承 ACE 重算到整棵子树），与 API 无关。
   - **解决**：幂等检查。授权前用 `GetEffectiveRightsFromAclW` 读 ACL 判断是否已授权，已授权就跳过（读很快）。首轮 ~60s（授权用户目录+AppData），之后每次 ~0.5s。
   - ⚠️ **坑**：`GetEffectiveRightsFromAclW` 返回的是**具体权限**（generic 已映射成 specific，如 `GENERIC_EXECUTE`→`FILE_TRAVERSE=0x20`），不是 generic 位。检查必须用具体位 `0x20`，不能用 `0x20000000`。
2. **祖先 traverse 授权不能带继承**：`grant_traverse` 用 `ResourcePath::File`（rappct 里 `grfInheritance=0`）授权目录，避免向子树传播。叶子授权（项目目录）才需要 `(OI)(CI)` 继承。
3. **命令 exe 授权 best-effort**：`System32`/`Program Files` 里的二进制 AppContainer 本来就可读（ALL APPLICATION PACKAGES），改其 ACL 会 access-denied——忽略，靠 `CreateProcessW` 失败兜底。
4. **`build_cmdline` 必须给含空格的参数加引号**（`-p "Reply with exactly: OK"` 这种会被拆散）。
5. **本机 claude 的 `ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic`**（不是 api.anthropic.com）——域名白名单必须匹配 claude 实际连的 API 域名，否则代理正确返回 403。测试时 `domains=["deepseek.com"]` 通过、`domains=["anthropic.com"]` 正确拦截，双向都验证了白名单。

### 端到端验证结果（exit 0）

- `claude-aegis run --config claude.toml -- -p "Reply with exactly: OK"` → 沙箱内 claude 经域内代理回复 `OK` ✅
- 代理白名单：放行 `deepseek.com` 时正常转发；放行 `anthropic.com` 时正确拦截（claude 实际连 deepseek.com）✅
- `cargo test --workspace` 全绿、`cargo clippy` 无警告、`cargo fmt` 干净。

---

## ✅ 阶段 3/4 完成：Tauri GUI + 审计日志 + 发布（2026-08-23）

> 交付：`gui/`（Tauri v2 静态前端）、core 审计日志、proxy net 审计、README 中英、CI/release workflow、Apache-2.0。

### 🔑 关键设计：审计日志"防篡改"（最重要的架构决策）

- **问题**：审计日志由两部分写——宿主进程写 `launch/exit/grant/proxy_stop`（成功），代理进程写 `proxy_start/net`。代理跑在沙箱内，对审计文件**没有写权限**，那些行会**静默丢失**。
- **不能简单授权**：代理和 claude **共享同一 AppContainer SID**（阶段 2 架构），给审计文件授权写 = claude 也能写/截断自己的审计日志 → 违背"合规审计"初衷。
- **正解**：代理把审计行写到 **stdout**（`--audit` 标志），**宿主机**在 `CreateProcessW` 里把代理 stdout 重定向到审计文件（append 模式，`STARTF_USESTDHANDLES` + `SetHandleInformation(HANDLE_FLAG_INHERIT)` + `bInheritHandles=1`）。沙箱进程全程**拿不到审计文件的写权限**。
- 落点：core `launch.rs` 的 `launch_appcontainer(..., stdout_path: Option<&Path>)` + `Sandbox::launch_with_stdout()`；`audit.rs` 的 `AuditLog::append/read_tail`（JSONL，`ts`=unix 秒）。

### 🔑 Tauri v2 静态前端（免 Node）踩坑

1. **免 bundler 配置**：`tauri.conf.json` → `build.frontendDist = "../src"`（直指静态目录）、`devUrl/before*Command` 省略；`app.withGlobalTauri = true` 暴露 `window.__TAURI__.core.invoke(cmd, args)`。前端是纯 HTML/CSS/JS，**构建全程无 Node**。
2. **`[lib] name` 必须显式声明**：默认 lib crate 名是 `claude_aegis_gui`，但 `main.rs` 按 Tauri 惯例引用 `claude_aegis_gui_lib`。需在 `Cargo.toml` 加 `[lib] name = "claude_aegis_gui_lib"`，否则报 E0433。
3. **capabilities 文件**：`src-tauri/capabilities/default.json` 给 `main` 窗口 `core:default` 权限（自定义 command 不设权限也可 invoke，但官方模板都带 `core:default`）。
4. **图标**：用 Pillow（本机 Python 3.13 + PIL 12.3）生成 `icon.png`(512) + `icon.ico`(多尺寸)。生成脚本 `.tools/gen-icon.py`（gitignored），产物 `gui/src-tauri/icons/` 已提交。
5. **GUI 作为根 workspace 成员** + `default-members` 排除，避免裸 `cargo build` 拖入 tauri；CI 用 `--workspace` 全量构建。
6. **GUI「运行」在新控制台窗口**：core `launch` 加 `new_console` 参数 → `CREATE_NEW_CONSOLE(0x10)`（在 `Win32::System::Threading`，不在 `Console`）。`run_sandbox` 走同步 Tauri 命令（自带线程池，不卡 UI）。
7. **`rfd`** 做原生目录选择（`pick_folder` 命令），比 `tauri-plugin-dialog` 简单（无需 capability 配置）。

### ⚠️ 其它踩坑

- **孤儿代理进程锁死 target exe**：阶段 2 残留的 4 个 `claude-aegis-proxy.exe` 锁着 `target/debug/claude-aegis-proxy.exe`，导致 `cargo build` 报"拒绝访问"删除文件失败。本会话用独立 `CARGO_TARGET_DIR=/d/aegis-target` 绕过；用户需自行清理残留进程。
- **serde_json/tauri 依赖树经代理下载**：需 `export HTTPS_PROXY/HTTP_PROXY=http://127.0.0.1:65532` 才能从 crates.io 拉取。
- **测试共用临时文件**会并行互相干扰（read_tail 读到别的测试的行）→ 每个测试用独立临时文件名。
- **Windows crate 常量路径**：`CREATE_NEW_CONSOLE`/`STARTF_USESTDHANDLES` 在 `Win32::System::Threading`；`SetHandleInformation`/`HANDLE_FLAG_INHERIT` 在 `Win32::Foundation`。

### ✅ 端到端验证结果

- `cargo build --workspace`、`cargo test --workspace`（8 测试）、`cargo clippy --workspace -- -D warnings`、`cargo fmt --check` 全绿。
- 审计冒烟：`claude-aegis run --audit-log <p> -- /c exit 0`（cmd.exe）→ audit.log 出现 `grant/launch/proxy_start/launch/exit/proxy_stop` 完整链路，`proxy_start` 由代理经 stdout 重定向写入 ✅
- GUI 冒烟：启动 `claude-aegis-gui.exe` → 窗口标题 `claude-aegis`、句柄非零、响应正常 ✅
