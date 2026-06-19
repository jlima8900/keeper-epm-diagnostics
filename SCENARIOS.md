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
| 15 | **Agent can't launch onto the user's desktop — but it DID resolve the user** | `WTS_SESSION_SELECTED` / `Found 1 active user session`, then `WindowsTaskSchedulerLauncher SCHTASKS_ERROR` ("cannot find the file specified") + `PROCESS_DETECTION_FAILED` + `USER_DESKTOP_TASK_LAUNCH_RESULT ... Launched: False` → `LAUNCH_FAILED ... on user desktop` | The agent's Task Scheduler launcher couldn't spawn the process even though session targeting is fine (it found the logged-on user; **reproduces from the console too**, so it's *not* an RDP issue). **Before escalating, rule out the environment with #19–#22** (AppLocker/WDAC, Defender ASR/quarantine, Mark-of-the-Web, the `-ProbeSchtasks` test). If app-control/EDR/MOTW are clean **and** the schtasks probe works, *then* it's an **agent-side launch defect → escalate to Keeper engineering** with the launcher failure chain (+ any WinTrust `CRYPT_E_FILE_ERROR 0x80092003`). |
| 16 | **Agent can't launch AND genuinely saw 0 active sessions** | `LAUNCH_FAILED` with `Found 0 active user session(s)` and **no** `WTS_SESSION_SELECTED` in the window | Nobody was logged on, or a real session-targeting gap. Confirm with `qwinsta` during a repro: if the user shows `Active` (console *or* `rdp-tcp`) yet the agent still sees 0 → engineering; otherwise just reproduce while the user is actively logged on. (Note: idle/overnight `Found 0` lines are normal — only count it when it coincides with a repro.) |
| 17 | **Live capture: nothing happened** (`-Live`) | During the reproduction window: 0 new log lines, 0 events, 0 tasks fired | The request never reached the agent — it's the **user-session / Task Scheduler** layer, not the policy |
| 18 | **.NET 8 runtime not found** | No system-wide .NET 8 | Informational — the agent may bundle its own; only a concern if the service won't start |
| 19 | **AppLocker / WDAC blocking the launch** | AppLocker enforcing, or `Microsoft-Windows-AppLocker` / `CodeIntegrity` block events in the last 48h | App-control is refusing the agent's launched process → matches "schtasks cannot find the file." Allow the EPM bin dir + approved apps |
| 20 | **Defender ASR / quarantine blocking the launch** | ASR rules in Block mode, or Defender block/threat events (ID 1121 / 1116 / 1117) | A child-process-creation ASR rule or a quarantined target breaks the scheduled-task launch. Review the events around the repro time |
| 21 | **Target exe is Mark-of-the-Web blocked / unreadable** (`-TargetExe`) | `Zone.Identifier` stream present, or the file can't be read by this account | MOTW makes SmartScreen/WDAC refuse it (Unblock it); an unreadable path matches the agent's WinTrust `CRYPT_E_FILE_ERROR` (mapped/network/OneDrive path or ACLs) |
| 22 | **Task Scheduler launches don't work here** (`-ProbeSchtasks`) | The create+run+delete probe fails | The exact mechanism the agent uses is broken in this context → that *is* the "system cannot find the file specified" failure. Distinguishes an environment/policy block from an agent bug |

**Symptom → scenario shortcuts**

- *"Only the Windows UAC prompt shows, never the Keeper approval popup"* → **#15/#16** (the popup process never spawns onto the user's session).
- *"The app was approved but the Launch button / app never actually starts"* → **#15/#16** (approval succeeds, the agent's launch into the desktop fails). If it fails the same way from **both RDP and the physical console**, it's #15 (agent launcher defect → engineering), not a session-targeting issue.
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
