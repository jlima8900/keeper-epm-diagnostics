# keeper-epm-diagnostics

Two small **read-only** tools that help explain why a Keeper Endpoint Privilege
Manager (EPM) elevation isn't working, and produce a clean, sanitized report you
can attach to a support case.

They never change anything, and they redact identities and secrets by default.

## The two tools

| Tool | Runs on | Tells you |
|---|---|---|
| **`epm_endpoint_check.ps1`** | the Windows endpoint | Is the agent healthy on the box? Services, ports, plugins, the user-session launcher, logs, and whether policies are actually **enforcing**. |
| **`epm_device_diag.py`** | your admin machine | What the backend thinks: is an *enforce* policy actually reaching this device? approvals? events? |

Rule of thumb: the `.ps1` says what's **actually happening on the box**; the
`.py` says what **should** be happening.

## Step-by-step

### On the Windows endpoint (the machine with the problem)

No Keeper login and no Python needed — just PowerShell.

1. Get the script onto the machine — **use the raw file, not the GitHub web
   page** (saving the page gives you HTML, which won't run). Easiest, in
   PowerShell:
   ```powershell
   Invoke-WebRequest https://raw.githubusercontent.com/jlima8900/keeper-epm-diagnostics/master/epm_endpoint_check.ps1 -OutFile C:\temp\epm_endpoint_check.ps1
   ```
   Or on the file's GitHub page click **Raw**, then save as plain text. (No
   internet on the box? Download it elsewhere and copy it over.)
2. Open PowerShell **as administrator**: click **Start**, type `PowerShell`,
   right-click it, choose **Run as administrator**.
3. Go to the folder where you put the file:
   ```powershell
   cd C:\temp
   ```
4. Run it:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\epm_endpoint_check.ps1
   ```
5. Read the **SUMMARY** at the top — it lists what's wrong. To save/share it,
   add `-Output report.txt` and send that file.

*(To capture a live reproduction, add `-Live` and follow the on-screen prompt.)*

### On your admin machine (the tenant view)

```bash
pip install keepercommander          # once
keeper login                         # start a Keeper session
python epm_device_diag.py --machine HOST-01
```

The device's verdict is at the top of the output; add `--output report.txt` to save it.

## What the output looks like

Both tools lead with a **SUMMARY** of findings, then the detail below.

**Endpoint check** (`epm_endpoint_check.ps1`, condensed) — a healthy agent whose
elevation policy simply isn't enforcing:

```
==============================================================================
  SUMMARY -- HOST-01
==============================================================================
  1 finding(s) -- act on these first:
    1. Policy evaluations return EnforcementDisabled -- check enforce mode +
       policy scope on the tenant (this is NOT an endpoint problem).
  Full detail follows below.
  ...
  2. WINDOWS SERVICES (Keeper)
       Keeper Endpoint Privilege Manager : Running
       Keeper Watchdog Service           : Running
  5. PLUGIN BINARIES
       exe files found : 9   (keeperAgent, KeeperApi, KeeperClient,
                              KeeperMessage, KeeperPolicy, KeeperUSession all present)
  6. USER-SESSION LAUNCHER (process + tasks)
       session process running : KeeperClient, KeeperUSession
  8b. POLICY ENFORCEMENT (from recent log)
       policy evaluations (recent) : 112
         -> EnforcementDisabled    : 112
         -> ApplicablePolicies=0   : 27
       => endpoint healthy; set the policy to ENFORCE and confirm its scope
          covers this device + user + apps (a tenant-side fix, not a reinstall).
```

A genuinely healthy, enforcing box instead reports `No blocking issues found`.

**Device diagnostic** (`epm_device_diag.py`) — the per-device verdict:

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
| `-Bundle` | build a support bundle (report + recent KeeperLogger logs + `currentPolicies.json`) as one `.zip` in `C:\temp` (change with `-BundlePath`) |
| `-Live` | capture a window: press Enter, reproduce the elevation, see exactly what the agent did (or didn't do) |
| `-Json` | machine-readable output |
| `-Raw` | show identities unredacted (internal use) |

`epm_device_diag.py`:

| Flag | Effect |
|---|---|
| `--machine HOST` | focus device(s) by name (substring) |
| `--agent <UID>` | focus a single agent by UID |
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
  can return `403` (`SelectiveAuth` needs an authenticated Admin session, so a
  plain probe is denied) even when the agent is perfectly fine.

## License

MIT — see [LICENSE](LICENSE). Not an official Keeper Security product; provided
as-is, no warranty.
