# PLAN.md — claude-aegis：Claude Code Windows 原生沙箱

> 本文件是本项目的**唯一权威计划**。任何新会话只要读此文件，即可无缝接手继续执行。
> 最后更新：2026-08-22

---

## 1. 一句话定位

给 **Claude Code** 在 **原生 Windows**（非 WSL/Docker）上提供 **OS 级沙箱隔离**（基于 AppContainer），填补官方战略放弃、社区只有"最低权限雏形"的安全空白。

## 2. 成功标准（用户明确的四合一目标，缺一不可）

1. **高 star / 大量真实采用** —— 易用、好装、传播性强
2. **技术严格正确** —— 经得起安全审查，不是"玩具沙箱"
3. **硬核作品展示** —— Rust + Windows 底层安全 API，有技术深度
4. **商业 / 企业价值** —— 企业友好（合规、审计、配置化），有被真实采用的潜力

## 3. 问题与机会

- **官方缺失**：Claude Code 沙箱仅支持 macOS(Seatbelt) / Linux·WSL2(bubblewrap)，官方文档明确 *"On Windows, sandboxing is not supported"*。
- **官方放弃**：Windows/WSL2 大量 bug 被 `closed not planned`（[#39955](https://github.com/anthropics/claude-code/issues/39955)）；原生沙箱请求 [#46740](https://github.com/anthropics/claude-code/issues/46740) 长期 stale。
- **真实漏洞**：无 OS 级隔离时，`deny` 规则只能拦内置 Read 工具，拦不住 `Bash(cat ~/.ssh/id_rsa)`。
- **社区空白**：现有方案要么绕道（WSL/Docker），要么是最低权限雏形（[fmuecke/claude-win-sandbox](https://github.com/fmuecke/claude-win-sandbox)，作者自认"not 100% protection"）。**没有任何人**用 AppContainer 做了真正的文件系统白名单 + 网络域名白名单。

## 4. 目标用户（GitHub 上按人群分类呈现）

| 人群 | 使用形态 | 诉求 |
|---|---|---|
| 开发者 / 极客 | **CLI** | 一条命令、可脚本化、可进 CI |
| 企业 / 安全 / 非极客 | **GUI** | 图形配置、审计日志、合规友好 |

## 5. 技术方案（已定，勿改）

- **隔离机制**：Windows **AppContainer**（LowBox/LPAC）——免管理员权限的 OS 级隔离，Windows 8+ 可用，Win10 1703+ 支持 LPAC。
- **正式实现语言**：**Rust**，底层用 [rappct](https://github.com/cpjet64/rappct) crate（AppContainer/LPAC 工具箱，v0.13.3 stable，免 admin）。
- **四类控制**（核心能力，全部要做）：
  1. **文件**：读 / 写 / 隐藏 三档白名单（默认全不可见，只放行清单）
  2. **网络**：域名白名单（本地 loopback CONNECT 代理，不 MITM）
  3. **进程**：可执行程序白名单（只允许 git / node / npm / cargo 等）
  4. **权限**：进程降权（Low Integrity Level / restricted token）

## 6. 交付形态（两个独立产物）

- **CLI**（第一批交付）：`cc-aegis run --dir <项目>` 等命令。
- **GUI**（第二批交付）：图形界面，面向企业/非极客用户。
- 两者**分开**，GitHub README 顶部按人群导航，明确"开发者用 CLI，企业用 GUI"。

## 7. 分阶段计划（先验证，再全做）

- **阶段 0 — Spike（零安装验证）✅ 全部通过**：用系统自带 `csc.exe`（C#）+ Win32 API 调 AppContainer，两层验证全部通过：
  - ✅ 机制验证：文件隔离通过（普通进程读秘密 exit 0，AppContainer 进程被拒 exit 1）
  - ✅ 端到端验证：claude.exe 关进 AppContainer 能启动（--version）、连 API（-p 回复 OK）、正常退出
  - **结论：技术路线完全可行，进入阶段 1**。详见 `claude-aegis/spike/FINDINGS.md`
- **阶段 1 — Rust 核心库**：用 rappct 实现四类控制，配单元测试 + 隔离测试。
- **阶段 2 — CLI 完整化**：配置加载、命令行参数、错误处理、`init`/`run` 子命令。
- **阶段 3 — GUI（第二批）**：图形配置界面（技术栈届时再定，候选 Tauri）。
- **阶段 4 — 发布**：README（中英双语）、CI（GitHub Actions Windows runner 编译）、License、发布到 GitHub。

## 8. 架构（monorepo，Cargo workspace）

```
claude-aegis/
├── PLAN.md
├── README.md
├── LICENSE
├── .github/workflows/ci.yml        # Windows runner 编译 + 隔离测试
├── crates/
│   ├── core/                       # AppContainer 隔离引擎（四类控制）
│   ├── cli/                        # CLI 前端
│   └── proxy/                      # loopback CONNECT 域名白名单代理
└── gui/                            # GUI（第二批）
```

## 9. 风险与诚实应对

| 风险 | 应对 |
|---|---|
| **claude.exe（Bun 二进制）在 AppContainer 里跑不起来**（最大风险） | 阶段 0 spike 优先验证；失败则降级为"渐进式隔离" |
| AppContainer 白名单语义与官方"默认可读"相反 | 阶段 1 设计"读/写/隐藏"三档 ACL 处理 |
| rappct 编译需要 MSVC + Windows SDK | 交给 GitHub CI 的 Windows runner（自带完整工具链） |
| 无法声称"绝对安全" | 文档诚实标注"不能替代独立安全审计" |

## 10. 已确认项（2026-08-22 定稿）

- [x] **项目命名**：`claude-aegis`
- [x] **许可证**：Apache-2.0
- [x] **GUI 技术栈**：Tauri

## 11. 环境与执行约束（已确认，勿违背）

- **本机零安装**：验证用自带 PowerShell；编译用 GitHub CI；本机不装 Rust/MSVC。
- **兜底**：若 CI 迭代痛苦到卡死，再考虑装 Rust/MSVC，**装到 D 盘**。
- **GitHub 上传**：用户有账号，用 `gh auth login` 授权后由我建仓库并推送。
- **用户本人不用此工具**，成品也不用 —— 这是纯"做成功开源项目"。
- **换会话不丢**：所有决策已写入本文件 + 长期记忆（memory）。
