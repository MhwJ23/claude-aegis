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
