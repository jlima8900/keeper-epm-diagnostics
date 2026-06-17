# keeper-epm-diagnostics

**Read-only** diagnostics for [Keeper Endpoint Privilege Manager
(EPM)](https://docs.keeper.io/en/keeperpam/endpoint-privilege-manager),
producing sanitized reports you can attach to a support case. Neither tool makes
any change — they only read.

There are two tools, because EPM problems split across two machines:

| Tool | Runs on | Needs Keeper login? | Answers |
|---|---|---|---|
| **`epm_device_diag.py`** | admin workstation | yes (Commander session) | tenant view: is an enforce policy reaching the device? approvals? audit events? |
| **`epm_endpoint_check.ps1`** | the Windows endpoint | **no** ("keeperless") | local view: service health, ports, plugin binaries, scheduled tasks, policy sync, logs, DNS, EDR |

Run them together: the `.py` tells you what the backend thinks should happen,
the `.ps1` tells you what's actually true on the box.

## What it's for

Two of the most common EPM elevation complaints are hard to triage from the
Admin Console alone:

| Symptom | What the report tells you |
|---|---|
| **Applications not appearing in the Admin Console** | Whether application collections exist, whether the device is in any collection, whether an **enforce** elevation policy actually *reaches* the device, and whether that policy's `ApplicationCheck` covers it. |
| **Agent history shows no requests** | Whether the agent is registered and online, whether there are any approval requests for it, and recent `approval_request_status_changed` audit events scoped to the device. |

It also prints an **endpoint-side checklist** of the things the backend API
*cannot* see (log files, local health endpoints, scheduled tasks, plugin
binaries, port/DNS reachability) so whoever has hands on the machine has a
single list to work through.

## Requirements

- Python 3.8+
- [`keepercommander`](https://pypi.org/project/keepercommander/) installed and
  an **active Keeper session** (`keeper login`) with EPM admin rights.

```
pip install keepercommander
keeper login
```

## Usage — tenant side (`epm_device_diag.py`, on the admin workstation)

```bash
python epm_device_diag.py                          # summary of all agents
python epm_device_diag.py --machine HOST-01        # focus device(s) by name substring
python epm_device_diag.py --agent <AGENT_UID>      # focus a single agent UID
python epm_device_diag.py --days 14                # audit-event lookback (default 7)
python epm_device_diag.py --output report.txt      # also write a utf-8 file
python epm_device_diag.py --format json            # machine-readable dump
python epm_device_diag.py --no-redact              # show identities + keys (internal use)
```

It reads your Commander config from `~/.keeper/config.json`
(`C:\Users\<you>\.keeper\config.json` on Windows).

## Usage — endpoint side (`epm_endpoint_check.ps1`, on the Windows endpoint)

No Keeper login, no Python, no Commander — pure PowerShell, so it runs on a
clean endpoint. Run it from an **elevated** PowerShell (the localhost health
endpoints return 401/403 without admin). Works on Windows PowerShell 5.1 and
PowerShell 7.

```powershell
powershell -ExecutionPolicy Bypass -File .\epm_endpoint_check.ps1 -Region eu
.\epm_endpoint_check.ps1 -Region eu -Output endpoint_report.txt
.\epm_endpoint_check.ps1 -Raw          # show identities (internal use only)
.\epm_endpoint_check.ps1 -Live         # time-boxed capture (see below)
```

### `-Live` — capture a reproduction in real time

A static check tells you the state *now*; `-Live` captures a **time window
around a reproduction**. It records a baseline, prompts you to *reproduce the
elevation attempt now*, waits for you to press Enter, then reports everything
that changed in that window: new KeeperLogger log lines, Keeper-related Windows
event-log entries, `\Keeper Security\` scheduled-task runs, and registration
state.

This is the strongest test for "nothing happens when I try to elevate": if the
window shows **no new log lines, no events, and no task runs**, the request
never reached the agent — pointing at the user-session / Task Scheduler layer
rather than policy. Run it elevated, as the affected user's session where
possible.

It checks the service, ports 6888/6889/8675, plugin binaries, the
`\Keeper Security\` scheduled tasks, `currentPolicies.json`, the latest
KeeperLogger log, `.NET 8`, DNS/egress to the Keeper router, EDR presence, and
local Administrators membership — then prints a findings list and suggested
(manual) remediation. `-Region` accepts `com | eu | us | com.au | jp`.

> **Note on the health endpoints.** `https://localhost:6889/health` is an
> unauthenticated liveness probe and is the reliable signal. Depending on the
> agent build, `/api/Keeper/registration` and `/api/plugins` may return **403**
> even from an elevated session (they are token-gated) — the tool labels that
> as *auth-gated, not necessarily broken*, so don't read a 403 as a failure on
> its own. The install path is `...\Endpoint Privilege Manager\` (the tool also
> checks the `...Management\` spelling some docs use).

## Privacy / sanitization

By **default** the report redacts:

- identities — emails, usernames, SIDs, domains
- justification free-text (reduced to a length)
- all cryptographic key material

Pass `--no-redact` only for internal use; if you combine it with `--output` the
tool warns you that the file contains unredacted data. Always review a report
before sharing it externally.

## Safety

- **Read-only.** No collection/agent/policy is created, modified, or deleted.
- **Fail-closed login.** If your Keeper session has expired the tool stops and
  asks you to run `keeper login` — it never submits an empty password, so it
  cannot trigger an account lockout.

## Validation

Both tools have been run end-to-end against live infrastructure:

- `epm_device_diag.py` — against a live tenant, including the audit-event path
  (events returned, statuses decoded, identities masked) and the policy-reach
  verdict logic.
- `epm_endpoint_check.ps1` — on a live Windows Server 2022 endpoint running the
  EPM agent (PowerShell 5.1), all 12 sections plus the findings/remediation
  output.

The audit-event section of the Python tool drives Commander's own report
engine; if that query ever fails on a different tenant it degrades gracefully
and points you at `epm report event` in an interactive Commander session.

## License

MIT — see [LICENSE](LICENSE).

> Not an official Keeper Security product. Provided as-is, no warranty.
