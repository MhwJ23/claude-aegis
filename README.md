<p align="center">
  <img src="assets/logo.png" alt="claude-aegis logo" width="132" />
</p>

# claude-aegis

Run **Claude Code** (or any Windows program) inside a real OS-level sandbox —
**AppContainer**, on **native Windows** — no admin rights, no WSL, no Docker.

> 中文说明见 [README.zh.md](README.zh.md) · [中文](README.zh.md)

[![CI](https://github.com/MhwJ23/claude-aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/MhwJ23/claude-aegis/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/MhwJ23/claude-aegis)](https://github.com/MhwJ23/claude-aegis/releases)

---

## What is claude-aegis?

It puts **Claude Code** (or anything else you run) inside a Windows
**AppContainer** — the same OS-level isolation Windows Store apps use. You decide
which folders it can read or write, which websites it can reach, and which
programs it can start; everything else is blocked, and every action is written
to an audit log. No administrator rights, no WSL, no Docker.

## Who is this for?

| You are… | Use this | What you get |
|---|---|---|
| **Developer / power user** | [CLI](#cli) | One command, scriptable, CI-friendly |
| **Enterprise / security / non-geek** | [GUI](#gui) | Graphical config, audit log, compliance-friendly |

**Why it matters:** Claude Code's own sandbox only supports macOS (Seatbelt) and
Linux/WSL2 (bubblewrap). On native Windows, sandboxing is officially *not
supported*. When there is no OS-level isolation, `deny` rules only block
Claude's built-in Read tool — they can't stop `Bash(cat ~/.ssh/id_rsa)`.
claude-aegis closes that gap.

---

## Install

Download the latest release from
[GitHub Releases](https://github.com/MhwJ23/claude-aegis/releases):

- **`claude-aegis_*_x64-setup.exe`** — a one-click Windows installer (recommended
  for non-technical users; installs the CLI, proxy, and GUI).
- **`claude-aegis-v*.zip`** — portable binaries (`claude-aegis.exe`,
  `claude-aegis-proxy.exe`, `claude-aegis-gui.exe`); unzip and run.

Requires Windows 10 1703+ (LPAC). No administrator rights needed.

---

## What it does

Four controls, enforced by the Windows AppContainer (LowBox/LPAC) mechanism:

1. **Files** — read / write / hide whitelists. Everything is hidden by default;
   only the listed paths are visible.
2. **Network** — a domain allow-list enforced by an in-container loopback
   CONNECT proxy (no MITM; TLS passes through untouched).
3. **Processes** — an executable allow-list for binaries the sandbox may launch.
4. **Privilege** — the AppContainer identity *is* the privilege boundary (an
   AppContainer token is inherently restricted).

All of it is **admin-free** (AppContainer requires no elevation).

---

## CLI

Build the binaries:

```bash
cargo build --release -p claude-aegis -p claude-aegis-proxy
```

Scaffold a config, then run:

```bash
# 1. create a claude-aegis.toml in the current directory
claude-aegis init

# 2. run claude (or whatever `command` says) inside the sandbox
claude-aegis run --config claude-aegis.toml -- -p "summarize this repo"
```

Write an audit trail while you're at it:

```bash
claude-aegis run --config claude-aegis.toml \
  --audit-log "$LOCALAPPDATA\claude-aegis\audit.log" -- -p "hi"
```

### Configuration (`claude-aegis.toml`)

```toml
profile = "claude-aegis"      # AppContainer identity
command = "claude"            # bare name (PATH) or full path

[files]
read  = ["C:\\projects"]      # dirs the sandbox may read
write = ["C:\\projects"]      # dirs the sandbox may write (implies read)

[network]
domains = ["api.anthropic.com"]   # domain allow-list; empty = no filter

[process]
allow = ["git.exe", "node.exe"]   # executable allow-list; empty = allow all
```

---

## GUI

The GUI is a config + launch + audit console (Tauri, static frontend, no Node
needed to build). "Run" launches the sandboxed program in its own console
window while the GUI watches the audit log.

Build it:

```bash
cargo build -p claude-aegis-gui
```

Run `claude-aegis-gui.exe` (the `claude-aegis-proxy.exe` binary must sit next
to it). From the window you can edit the config, pick directories with a
native folder dialog, launch the sandbox, and watch a live, color-coded audit
log.

---

## Audit log

Every run appends JSON-lines to `%LOCALAPPDATA%\claude-aegis\audit.log`:

```json
{"access":"read_execute","event":"grant","path":"D:\\aegis\\claude-aegis-proxy.exe","ts":1787469295}
{"command":"D:\\aegis\\claude-aegis-proxy.exe","event":"launch","pid":29020,"profile":"claude-aegis","ts":1787469295}
{"addr":"127.0.0.1:64571","event":"proxy_start","ts":1787469295}
{"event":"net","host":"api.anthropic.com","allowed":true,"ts":1787469295}
{"code":0,"event":"exit","pid":31280,"ts":1787469296}
```

Events: `launch`, `exit`, `grant`, `proxy_start`, `proxy_stop`, `net`.
The log is written **only by the trusted host process** — the proxy's `net`
decisions are written to its stdout and redirected into the file, so the
sandboxed program never gets write access to its own audit trail.

---

## Security model — honest version

- **It's a real OS sandbox, not a policy file.** AppContainer is enforced by
  the Windows kernel, not by Claude's tool code.
- **Not a substitute for a security audit.** No sandbox is a proof. Treat this
  as one layer of a defense-in-depth strategy.
- **The domain allow-list is enforced, but hostname-based.** When the proxy is
  running, the sandboxed program has *no direct internet* (`internetClient` is
  withheld from it), so all traffic must go through the proxy — it cannot bypass
  the allow-list. The filter matches hostnames, not IPs, and does not inspect
  encrypted payloads; a payload that reaches an allow-listed domain still
  exfiltrates over that connection.
- **Windows grants AppContainers read access to some locations by default**
  (e.g. `%TEMP%` and system directories). "Default deny" therefore does not
  cover `%TEMP%` — don't keep secrets there and expect the sandbox to hide them.
- **The proxy shares the sandbox's identity.** The proxy and the sandboxed
  program run in the same AppContainer (same SID), which is what makes the
  admin-free loopback architecture work. The proxy is our own small binary.
- **Audit is tamper-evident, not tamper-proof.** The sandboxed program cannot
  write the audit file, but nothing here ships it to a central collector.

## Architecture

```
claude-aegis/
├── crates/
│   ├── core/     # AppContainer engine (files / network / process / privilege)
│   ├── cli/      # `claude-aegis` (init, run)
│   └── proxy/    # loopback CONNECT proxy with domain allow-list
├── gui/          # Tauri GUI (config + audit console)
└── spike/        # design notes & validation experiments (see spike/FINDINGS.md)
```

The engine wraps [`rappct`](https://github.com/cpjet64/rappct) and calls the
AppContainer Win32 APIs directly (see `spike/FINDINGS.md` for the exact
constants and the pitfalls they document).

## Building from source

Requirements: Rust (stable, MSVC target) on Windows. The GitHub Actions
workflow builds and tests on `windows-latest`.

```bash
cargo build --workspace        # core + cli + proxy + gui
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

## License

[Apache-2.0](LICENSE).
