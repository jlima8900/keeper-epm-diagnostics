# Scenarios these tools detect

A checklist of the situations the diagnostics recognise and the verdict each one
produces. Use it to see whether your symptom is already covered before reading a
full report. Each tool leads with a **SUMMARY** that lists only the findings that
matched.

> Rule of thumb: the endpoint checks (`epm_endpoint_check.ps1` / `.sh`) report
> what's **actually happening on the box**; `epm_device_diag.py` reports what the
> tenant **thinks should** be happening. When the two disagree, that gap is the
> answer.

---

## `epm_endpoint_check.ps1` — Windows endpoint

| # | Scenario | What you'd see | Verdict the tool gives |
|---|---|---|---|
| 1 | **Agent not installed** | No install dir under `C:\Program Files\Keeper Security\`, no Keeper services | "agent may not be installed" |
| 2 | **Service stopped / not running** | A Keeper service is present but not `Running` | Flags the specific service + expected state |
| 3 | **Main EPM service missing** | Keeper services exist but the core EPM service isn't among them | Flags a partial/broken install |
| 4 | **Corrupt / incomplete install** | One of the core component `.exe`s is missing from `plugins\bin` | "clean reinstall" |
| 5 | **Health endpoint unreachable** | `/health` does not respond | Flags the agent as not responding (run elevated first) |
| 6 | **Agent not registered** | `/registration` reports `IsRegistered != true` | Flags enrolment incomplete |
| 7 | **403/401 on `/registration` or `/api/plugins`** | Probe denied | **Not an error** — `SelectiveAuth` needs an authenticated admin session; the tool says so explicitly |
| 8 | **A listening port is down** | Expected local port not listening | Flags the port |
| 9 | **Core plugin not running** | `KeeperAPI` / `KeeperPolicy` reports not-running | Flags the core plugin |
| 10 | **User-session launcher absent** | `KeeperClient` / `KeeperUSession` not running **and** no Keeper scheduled task | Flags the user-session layer |
| 11 | **Scheduled task disabled** | A Keeper scheduled task is `Disabled` | Flags it |
| 12 | **Policy file not synced** | `currentPolicies.json` missing or ~empty | "policy sync may not have completed" |
| 13 | **Plugin failed security validation** | Log line "Plugin failed security validation" | Flags it with the log path |
| 14 | **Policy reaches the box but isn't enforcing** | Many evaluations return `EnforcementDisabled` / `ApplicablePolicies=0` | "endpoint healthy; set the policy to ENFORCE and confirm scope — **tenant-side fix, not a reinstall**" |
| 15 | **Agent can't launch onto the user's desktop** | `UserSessionLauncher LAUNCH_FAILED ... on user desktop` (approval popup and/or approved app) | Flags the launch failure; tells you to check `qwinsta` (console vs `rdp-tcp`, `Active` vs `Disc`) before escalating |
| 16 | **...and the agent sees no active user session** | The above **plus** `WindowsUserDetection: Found 0 active user session(s)` | **Strong signal**: the Keeper popup and approved apps will never appear — a console-vs-RDP / disconnected-session targeting problem. Routes you: if the user is on `rdp-tcp`/`Disc`, retest on the **active console**; if the user is Active on the console and the agent still sees 0 sessions, **escalate to engineering** with these log lines |
| 17 | **Live capture: nothing happened** (`-Live`) | During the reproduction window: 0 new log lines, 0 events, 0 tasks fired | The request never reached the agent — it's the **user-session / Task Scheduler** layer, not the policy |
| 18 | **.NET 8 runtime not found** | No system-wide .NET 8 | Informational — the agent may bundle its own; only a concern if the service won't start |

**Symptom → scenario shortcuts**

- *"Only the Windows UAC prompt shows, never the Keeper approval popup"* → **#15/#16** (the popup can't render onto the user's session).
- *"The app was approved but never actually starts"* → **#15/#16** (approval succeeds, launch into the desktop fails).
- *"Nothing happens at all when I try to elevate"* → run with `-Live` → **#17**.
- *"Elevation is allowed when it shouldn't be / blocked when it shouldn't be"* → **#14** (policy scope/enforce mode, tenant-side).

---

## `epm_endpoint_check.sh` — Linux endpoint (Debian/Ubuntu)

| # | Scenario | Verdict the tool gives |
|---|---|---|
| 1 | **Non-Debian distro** (RHEL/Rocky/etc.) | Notes the Keeper EPM Linux agent ships as `.deb` only — it likely isn't installed here |
| 2 | **Agent package absent** | `keeper-privilege-manager` not in `dpkg` → agent absent or installed another way |
| 3 | **Agent installed, service not active** | "elevation/policy enforcement will not work" |
| 4 | **`keeperagent` missing** | Partial/abnormal install |
| 5 | **`sudo` is governed by EPM** | keepersudo present + service active → plain `sudo` fails closed (`"use keepersudo"`); tells you to elevate via `keepersudo`/`keeperagent` and how to recover (`keeperagent dpkg --purge keeper-privilege-manager` — stopping the service alone does **not** restore `sudo`) |
| 6 | **keepersudo present but service inactive** | Governance may currently be off |
| 7 | **Backend unreachable** | Region endpoint `:443` blocked → no policy/approval sync |
| 8 | **Residual secrets in the bundle** | Secret-scan flags lines that may be unredacted before you share |

---

## `epm_device_diag.py` — admin / tenant view

| # | Scenario | Verdict the tool gives |
|---|---|---|
| 1 | **Device offline** | "no live requests will arrive" |
| 2 | **Agent disabled** | "agent will not enforce" |
| 3 | **Not in a machine collection** | Shown in the per-device verdict |
| 4 | **No policy reaches the device** | Shown in the per-device verdict |
| 5 | **No *enforce* elevation policy reaching it** | `enforce elevation policy NO <-- likely root cause` |
| 6 | **Policy present but status not `enforce`** | "not enforcing" per policy |

---

## How a real case maps across the tools

A typical "elevation isn't working" investigation:

1. **`.py` first** — does the tenant even send an *enforce* policy to this device? If not, stop here (scenario py-#5).
2. **`.ps1`/`.sh` on the box** — is the agent healthy, registered, and synced? If healthy but `EnforcementDisabled` (ps1-#14), it's a tenant scope/enforce fix.
3. **If the agent is healthy and policy is enforcing but the popup/app never appears** — look at ps1-#15/#16: the agent can't reach the user's interactive desktop. Confirm with `qwinsta`, and route console-vs-RDP issues to environment vs engineering accordingly.
