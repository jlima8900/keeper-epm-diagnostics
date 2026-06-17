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
