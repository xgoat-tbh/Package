# SysPy

A small, dependency-free remote administration toolkit.

SysPy has two halves:

| Half | File | Runs on | Purpose |
|------|------|---------|---------|
| Agent | `agent.py` | the target machine | connects out, executes commands |
| Controller | `controller.py` | your machine | web dashboard that drives agents |

Everything else in `syspy/` is shared plumbing (transport, crypto, protocol).

## Why it has no dependencies

The agent has to run on a machine where nothing is installed. So the entire
project uses only the Python standard library:

* MQTT 3.1.1 client is implemented in `syspy/mqtt.py`
* WebSocket server is implemented in `syspy/ws.py`
* HTTP router is implemented in `syspy/httpd.py`
* Encryption is SHA-256 in counter mode + HMAC-SHA-256 (`syspy/crypto.py`)

## Running

    python controller.py          # opens http://127.0.0.1:8787
    python agent.py               # on the target

## Building a distribution kit

    python build_dist.py

Produces `dist/` and `SysPy.zip`. See `README.txt` inside for victim instructions.

## Security model

* All agent traffic is sealed with an encrypt-then-MAC envelope.
* Key material is derived from `PASSPHRASE` with PBKDF2-HMAC-SHA-256.
* A replay filter rejects duplicated nonces.
* The dashboard binds to loopback and requires a password.
