// claude-aegis GUI — vanilla JS, talks to the Rust backend via the global
// Tauri API (withGlobalTauri exposes window.__TAURI__ without a bundler).

"use strict";

const invoke = (cmd, args = {}) => window.__TAURI__.core.invoke(cmd, args);

let auditPath = "";

// --- Form <-> Config object -------------------------------------------------

function buildConfig() {
  return {
    profile: value("profile") || "claude-aegis",
    command: value("command") || "claude",
    files: {
      read: dirItems("read-dirs"),
      write: dirItems("write-dirs"),
    },
    network: {
      domains: csv(value("domains")),
    },
    process: {
      allow: csv(value("allow")),
    },
  };
}

function populate(config) {
  setValue("profile", config.profile || "");
  setValue("command", config.command || "");
  renderDirList("read-dirs", config.files?.read || []);
  renderDirList("write-dirs", config.files?.write || []);
  setValue("domains", (config.network?.domains || []).join(", "));
  setValue("allow", (config.process?.allow || []).join(", "));
}

function value(id) {
  return document.getElementById(id).value.trim();
}

function setValue(id, v) {
  document.getElementById(id).value = v;
}

function csv(text) {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function dirItems(id) {
  return [...document.querySelectorAll(`#${id} li .dir-path`)].map((el) => el.textContent);
}

// --- Directory list UI ------------------------------------------------------

function renderDirList(id, paths) {
  const ul = document.getElementById(id);
  ul.innerHTML = "";
  for (const p of paths) {
    ul.appendChild(dirRow(p));
  }
}

function dirRow(path) {
  const li = document.createElement("li");
  const span = document.createElement("span");
  span.className = "dir-path";
  span.textContent = path;
  const btn = document.createElement("button");
  btn.className = "dir-remove";
  btn.title = "Remove";
  btn.textContent = "×";
  btn.addEventListener("click", () => li.remove());
  li.append(span, btn);
  return li;
}

async function addDir(target) {
  const path = await invoke("pick_folder");
  if (!path) return;
  document.getElementById(`${target}-dirs`).appendChild(dirRow(path));
}

// --- Audit log --------------------------------------------------------------

function fmtTime(ts) {
  if (!ts) return "";
  return new Date(ts * 1000).toLocaleString();
}

function fmtDetail(o) {
  switch (o.event) {
    case "launch":
      return `${o.command} (pid ${o.pid})`;
    case "exit":
      return `pid ${o.pid} exited with code ${o.code}`;
    case "grant":
      return `${o.access} -> ${o.path}`;
    case "net":
      return `${o.allowed ? "ALLOW" : "DENY"} ${o.host}`;
    case "proxy_start":
      return `listening on ${o.addr}`;
    case "proxy_stop":
      return "proxy stopped";
    default:
      return JSON.stringify(o);
  }
}

function renderAudit(lines) {
  const el = document.getElementById("audit-log");
  el.innerHTML = "";
  if (!lines.length) {
    const empty = document.createElement("div");
    empty.className = "audit-empty";
    empty.textContent = "No events yet.";
    el.appendChild(empty);
    return;
  }
  for (const line of lines) {
    let obj;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    el.appendChild(renderRow(obj));
  }
  el.scrollTop = el.scrollHeight;
}

function renderRow(obj) {
  const row = document.createElement("div");
  row.className = "log-row";

  const time = document.createElement("span");
  time.className = "log-time";
  time.textContent = fmtTime(obj.ts);

  const tag = document.createElement("span");
  tag.className = "log-tag tag-" + (obj.event || "unknown");
  tag.textContent = obj.event || "unknown";

  const detail = document.createElement("span");
  detail.className = "log-detail";
  detail.textContent = fmtDetail(obj);

  if (obj.event === "net" && obj.allowed === false) {
    row.classList.add("row-deny");
  }

  row.append(time, tag, detail);
  return row;
}

async function refreshAudit() {
  try {
    const lines = await invoke("tail_audit", { path: auditPath, n: 500 });
    renderAudit(lines);
  } catch (e) {
    console.error("tail_audit failed", e);
  }
}

// --- Status -----------------------------------------------------------------

function setStatus(text, cls) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = "status " + (cls || "");
}

// --- Actions ----------------------------------------------------------------

async function load() {
  try {
    const path = value("config-path") || null;
    const config = await invoke("load_config", { path });
    populate(config);
    setStatus("Loaded", "ok");
  } catch (e) {
    setStatus("Load failed", "error");
    console.error(e);
  }
}

async function save() {
  try {
    const path = value("config-path");
    if (!path) {
      setStatus("Enter a config path", "error");
      return;
    }
    await invoke("save_config", { path, config: buildConfig() });
    setStatus("Saved", "ok");
  } catch (e) {
    setStatus("Save failed", "error");
    console.error(e);
  }
}

async function run() {
  const btn = document.getElementById("btn-run");
  btn.disabled = true;
  setStatus("Running...", "running");
  try {
    const result = await invoke("run_sandbox", { config: buildConfig(), dir: null });
    setStatus(`Exited (code ${result.code})`, result.code === 0 ? "ok" : "error");
  } catch (e) {
    setStatus("Run failed", "error");
    console.error(e);
  } finally {
    btn.disabled = false;
    refreshAudit();
  }
}

async function clearLog() {
  try {
    await invoke("clear_audit", { path: auditPath });
    refreshAudit();
  } catch (e) {
    console.error(e);
  }
}

// --- Bootstrap --------------------------------------------------------------

function wire() {
  document.getElementById("btn-load").addEventListener("click", load);
  document.getElementById("btn-save").addEventListener("click", save);
  document.getElementById("btn-run").addEventListener("click", run);
  document.getElementById("btn-refresh").addEventListener("click", refreshAudit);
  document.getElementById("btn-clear").addEventListener("click", clearLog);

  for (const btn of document.querySelectorAll(".btn-add")) {
    btn.addEventListener("click", () => addDir(btn.dataset.target));
  }
}

async function boot() {
  wire();
  try {
    auditPath = await invoke("audit_path");
    document.getElementById("audit-path").textContent = auditPath;
    const path = value("config-path") || null;
    const config = await invoke("load_config", { path });
    populate(config);
  } catch (e) {
    console.error("boot: no config loaded yet", e);
  }
  refreshAudit();
  setInterval(refreshAudit, 1500);
}

boot();
