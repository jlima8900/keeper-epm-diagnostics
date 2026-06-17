# keeper-epm-diagnostics

Two small **read-only** tools that help explain why a Keeper Endpoint Privilege
Manager (EPM) elevation isn't working, and produce a clean, sanitized report you
can attach to a support case.

They never change anything, and they redact identities and secrets by default.

## The two tools

| Tool | Runs on | Tells you |
|---|---|---|
| **`epm_endpoint_check.ps1`** | the Windows endpoint | Is the agent healthy on the box? Service, ports, plugins, scheduled tasks, logs. |
| **`epm_device_diag.py`** | your admin machine | What the backend thinks: is an *enforce* policy actually reaching this device? approvals? events? |

Rule of thumb: the `.ps1` says what's **actually happening on the box**; the
`.py` says what **should** be happening.

## Quick start

**On the Windows endpoint** (no Keeper login needed) — run from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\epm_endpoint_check.ps1
```

**On your admin machine** (needs Keeper Commander):

```bash
pip install keepercommander
keeper login
python epm_device_diag.py --machine HOST-01
```

## What the output looks like

Both tools end with the part that matters: a plain-English list of findings.

**Endpoint check** (condensed):

```
  host       : HOST-01
  2. WINDOWS SERVICE    : Running
  3. /health            : "Healthy"
  4. PORTS 6888/6889/8675 : listening
  5. PLUGIN BINARIES    : KeeperApproval.exe  <-- MISSING
  6. SCHEDULED TASKS    : NONE under \Keeper Security\

  FINDINGS
  1. Plugin binary missing: KeeperApproval.exe (corrupt install -> reinstall).
  2. No scheduled tasks under '\Keeper Security\' -- user-session components
     cannot launch (reinstall recreates them).
```

**Device diagnostic** — the per-device verdict:

```
  --- verdict for this device ---
    online .................. YES
    in a machine collection . NO
    reached by any policy ... YES
    enforce elevation policy  NO  <-- likely root cause
```

## Reports & output

- **Where they go** — by default the report prints to the screen. Add
  `--output report.txt` (`-Output report.txt` for the `.ps1`) to also write a
  file; it lands in your current directory unless you give a full path.
- **Format** — plain UTF-8 text, or JSON with `--format json`. **Not
  compressed** — open or attach the file directly.
- **Text vs JSON** — the text report is a readable summary; a couple of
  high-volume lists (the application-collection inventory, audit events) are
  sampled so it stays readable. `--format json` is the **complete** export —
  every collection, every policy that reaches the device, full approval detail.

## Options

`epm_endpoint_check.ps1`:

| Flag | Effect |
|---|---|
| `-Region eu` | region for the connectivity test (`com`/`eu`/`us`/`com.au`/`jp`) |
| `-Output report.txt` | also write the report to a file |
| `-Live` | capture a window: press Enter, reproduce the elevation, see exactly what the agent did (or didn't do) |
| `-Raw` | show identities unredacted (internal use) |

`epm_device_diag.py`:

| Flag | Effect |
|---|---|
| `--machine HOST` | focus a device by name |
| `--days 14` | audit-event lookback (default 7) |
| `--output report.txt` | also write the report to a file |
| `--format json` | machine-readable output |
| `--no-redact` | show identities/keys unredacted (internal use) |

## Catching it live (`-Live`)

When the complaint is "nothing happens when I try to elevate," a one-shot check
isn't enough — you need to watch the moment it fails. `-Live` records a
baseline, waits while you reproduce the elevation, then shows exactly what the
agent did (or didn't do) in that window:

```
PS> .\epm_endpoint_check.ps1 -Live

  LIVE CAPTURE -- reproduce the issue now
  baseline at : 09:14:02
  >>> Reproduce the elevation NOW, then press Enter: 

  WHAT HAPPENED DURING YOUR 23s WINDOW
  new log lines            : 0
  keeper event-log entries : 0
  scheduled tasks fired    : 0

  LIVE VERDICT
  The agent observed NOTHING during your reproduction.
  => the request is NOT reaching the agent (Task Scheduler / user-session
     layer). Matches 'agent history shows no requests'.
```

If those counters are **all zero**, the request never reached the agent — so
the problem is the user-session/Task Scheduler layer, not your policy. If they
move, the agent is reacting and you focus on the policy/approval decision
instead. Run it elevated, ideally in the affected user's session.

## Good to know

- **Read-only and sanitized** — nothing is changed; identities and secrets are
  masked unless you pass `--no-redact` / `-Raw`.
- **Lockout-safe** — the Python tool stops and asks you to `keeper login` rather
  than risk submitting a bad password.
- **PowerShell** — runs on Windows PowerShell 5.1 or 7; run it elevated.
- `/health` is the reliable liveness check; `/registration` and `/api/plugins`
  can return `403` (token-gated) even when the agent is fine.

## License

MIT — see [LICENSE](LICENSE). Not an official Keeper Security product; provided
as-is, no warranty.
