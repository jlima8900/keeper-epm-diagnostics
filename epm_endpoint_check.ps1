<#
.SYNOPSIS
    Keeper EPM endpoint diagnostic collector -- READ ONLY, no Keeper login required.

.DESCRIPTION
    Runs ON a Windows endpoint that has the Keeper Endpoint Privilege Manager
    agent installed and reports the LOCAL health signals the backend cannot see:
    service health, listening ports, plugin binaries, scheduled tasks, policy
    sync state, logs, .NET runtime, DNS/egress, EDR presence, local admin
    membership, and the app-control / launch-blocker posture (AppLocker, WDAC
    Code Integrity, Defender ASR, Mark-of-the-Web) that can make the agent's
    scheduled-task user-desktop launch fail.

    It needs NO Keeper session and NO Python/Commander -- pure PowerShell, so it
    runs on a clean endpoint. It makes NO changes (read-only); any fix is only
    printed as a suggestion.

    Pair it with epm_device_diag.py, which runs on the admin workstation and
    reports the tenant-side view (policies/collections/approvals/audit).

.PARAMETER Region
    Keeper region host suffix for the connectivity test: com | eu | us | com.au | jp
    Default: com

.PARAMETER Output
    Also write the report to this file (UTF-8).

.PARAMETER Raw
    Show identities (usernames / emails / SIDs) unredacted. Internal use only.

.PARAMETER TargetExe
    A file path (e.g. the approved app, or KeeperApproval.exe) to inspect for a
    Mark-of-the-Web / Zone.Identifier block and Authenticode signature. Helps
    explain a "schtasks could not launch it" failure.

.PARAMETER ProbeSchtasks
    Opt-in ACTIVE test: create + run + delete a harmless no-op scheduled task to
    prove whether Task Scheduler launches work at all in this context (this is the
    mechanism the EPM agent uses for user-desktop launches). This is the ONLY check
    that writes anything; the temp task is removed immediately. Off by default.

.EXAMPLE
    # Run elevated (health endpoints need admin):
    powershell -ExecutionPolicy Bypass -File .\epm_endpoint_check.ps1 -Region eu

.EXAMPLE
    .\epm_endpoint_check.ps1 -Region eu -Output endpoint_report.txt

.NOTES
    Not an official Keeper Security product. Provided as-is, no warranty.
#>

[CmdletBinding()]
param(
    [string]$Region = "com",
    [string]$Output,
    [switch]$Raw,
    [switch]$Json,
    [switch]$Live,
    [switch]$Bundle,
    [string]$BundlePath = "C:\temp",
    [string]$TargetExe,
    [switch]$ProbeSchtasks
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"   # avoid CLIXML/progress noise over SSH/remoting
$script:Lines    = New-Object System.Collections.Generic.List[string]
$script:Result   = [ordered]@{}
$script:Findings = New-Object System.Collections.Generic.List[string]

# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
function Emit([string]$s = "") { $script:Lines.Add($s) }            # buffered; flushed at end
function EmitLive([string]$s = "") { Write-Host $s; $script:Lines.Add($s) }  # also shown immediately (prompts)

function Flush-Report {
    # assemble a summary-first report, print it, and optionally write it to a file
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add("=" * 78)
    $out.Add("  SUMMARY -- " + $env:COMPUTERNAME + $(if ($Raw) { "  (UNREDACTED)" } else { "" }))
    $out.Add("=" * 78)
    if ($script:Findings.Count -eq 0) {
        $out.Add("  No blocking issues found by the local checks.")
    } else {
        $out.Add("  " + $script:Findings.Count + " finding(s) -- act on these first:")
        $n = 1; foreach ($f in $script:Findings) { $out.Add("    $n. $f"); $n++ }
    }
    $out.Add("  Full detail follows below.")
    $out.Add("")
    foreach ($l in $script:Lines) { $out.Add($l) }
    $text = $out -join "`r`n"
    Write-Host $text
    if ($Output) {
        try {
            $text | Out-File -FilePath $Output -Encoding utf8
            if ($Raw) { Write-Warning "$Output contains UNREDACTED identities." } else { Write-Host "`nWrote report to $Output" }
        } catch { Write-Warning ("Could not write " + $Output + ": " + $_.Exception.Message) }
    }
    if ($Bundle) { New-Bundle $text }
}

function New-Bundle([string]$reportText) {
    # Collect a support bundle: this report + recent KeeperLogger logs +
    # currentPolicies.json, zipped into one file to hand to Keeper support.
    # NOTE: the raw logs are NOT redacted -- only share with the vendor.
    try {
        $paths = Get-EpmPaths
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $name  = "epm-bundle-" + $env:COMPUTERNAME + "-" + $stamp
        if (-not (Test-Path $BundlePath)) { New-Item -ItemType Directory -Path $BundlePath -Force | Out-Null }
        $work = Join-Path $env:TEMP $name
        if (Test-Path $work) { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $work -Force | Out-Null

        # 1. the report
        $reportText | Out-File (Join-Path $work "report.txt") -Encoding utf8

        # 2. currentPolicies.json
        $cp = Get-ChildItem $paths.PluginBin -Recurse -Filter "currentPolicies.json" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cp) { Copy-Item $cp.FullName (Join-Path $work "currentPolicies.json") -ErrorAction SilentlyContinue }

        # 3. recent KeeperLogger logs (last 3 days)
        if (Test-Path $paths.LogDir) {
            $logDest = Join-Path $work "logs"
            New-Item -ItemType Directory -Path $logDest -Force | Out-Null
            Get-ChildItem $paths.LogDir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-3) } |
                Copy-Item -Destination $logDest -ErrorAction SilentlyContinue
        }

        $zip = Join-Path $BundlePath ($name + ".zip")
        if (Test-Path $zip) { Remove-Item $zip -Force -ErrorAction SilentlyContinue }
        Compress-Archive -Path (Join-Path $work "*") -DestinationPath $zip -Force
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue

        Write-Host ""
        Write-Host ("  Support bundle: " + $zip)
        Write-Host  "  (contains the report, recent KeeperLogger logs, and currentPolicies.json"
        Write-Host  "   -- logs are RAW/unredacted; share only with Keeper support.)"
    } catch {
        Write-Warning ("Could not build bundle: " + $_.Exception.Message)
    }
}
function Section([string]$t) {
    Emit ""
    Emit ("=" * 78)
    Emit ("  " + $t)
    Emit ("=" * 78)
}
function Item([string]$label, $value, [string]$flag = "") {
    $v = if ($null -eq $value -or $value -eq "") { "(none)" } else { $value }
    $line = "  {0,-26} {1}" -f ($label + " :"), $v
    if ($flag) { $line += "   <-- $flag" }
    Emit $line
}
function Flag([string]$s) { $script:Findings.Add($s) }

# --------------------------------------------------------------------------- #
# sanitization (on by default)
# --------------------------------------------------------------------------- #
function Mask([string]$s) {
    if ($Raw -or [string]::IsNullOrEmpty($s)) { return $s }
    if ($s -match '^S-1-') { return 'S-1-***' }
    if ($s -match '^(.)(.*)@(.).*?(\.[^.]+)$') { return "$($Matches[1])***@$($Matches[3])***$($Matches[4])" }
    if ($s.Contains('\')) {                       # DOMAIN\user
        $p = $s.Split('\'); return "$($p[0])\$(Mask $p[-1])"
    }
    if ($s.Length -le 3) { return '***' }
    return $s.Substring(0,2) + '***' + $s.Substring($s.Length-1,1)
}

# --------------------------------------------------------------------------- #
# self-signed localhost cert bypass (works on PS 5.1 and PS 7)
# --------------------------------------------------------------------------- #
$script:IwrExtra = @{}
if ($PSVersionTable.PSVersion.Major -ge 6) {
    $script:IwrExtra = @{ SkipCertificateCheck = $true }
} else {
    try {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class KeeperTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@ -ErrorAction SilentlyContinue
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object KeeperTrustAll
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    } catch {}
}

function Invoke-LocalApi([string]$url) {
    try {
        return Invoke-RestMethod -Uri $url -TimeoutSec 6 @script:IwrExtra
    } catch {
        return @{ __error = $_.Exception.Message }
    }
}

function Test-Admin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-EpmPaths {
    $cands = @(
        "C:\Program Files\Keeper Security\Endpoint Privilege Management",
        "C:\Program Files\Keeper Security\Endpoint Privilege Manager"
    )
    $base = $null
    foreach ($c in $cands) { if (Test-Path $c) { $base = $c; break } }
    if (-not $base) { $base = $cands[0] }
    $pluginBin = Join-Path $base "Plugins\bin"
    return [pscustomobject]@{
        Base      = $base
        PluginBin = $pluginBin
        LogDir    = Join-Path $pluginBin "KeeperLogger\Log"
    }
}

function Invoke-LiveCapture {
    $paths  = Get-EpmPaths
    $logDir = $paths.LogDir

    Section "LIVE CAPTURE -- reproduce the issue now"
    if (-not (Test-Path $logDir)) {
        Emit "  WARNING: log dir not found ($logDir); still capturing events + tasks."
    }

    # ----- baseline -----
    $t0 = Get-Date
    $baseLines = @{}
    if (Test-Path $logDir) {
        foreach ($f in Get-ChildItem $logDir -File -ErrorAction SilentlyContinue) {
            $baseLines[$f.FullName] = @(Get-Content $f.FullName -ErrorAction SilentlyContinue).Count
        }
    }
    $baseReg = (Invoke-LocalApi "https://localhost:6889/api/Keeper/registration").IsRegistered
    EmitLive ("  baseline at : " + $t0.ToString("HH:mm:ss"))
    EmitLive ""
    EmitLive "  >>> Reproduce the elevation NOW:"
    EmitLive "      as the demoted standard user, try to install/run something that"
    EmitLive "      should raise the Keeper elevation prompt."
    EmitLive ""
    [void](Read-Host "  Press Enter the moment you have finished the attempt")
    $t1 = Get-Date
    $elapsed = [int]($t1 - $t0).TotalSeconds

    Section ("WHAT HAPPENED DURING YOUR " + $elapsed + "s WINDOW")

    # ----- new log lines (handles rotation: new files counted from 0) -----
    $newLog = New-Object System.Collections.Generic.List[string]
    if (Test-Path $logDir) {
        foreach ($f in Get-ChildItem $logDir -File -ErrorAction SilentlyContinue) {
            $b = 0; if ($baseLines.ContainsKey($f.FullName)) { $b = $baseLines[$f.FullName] }
            $all = @(Get-Content $f.FullName -ErrorAction SilentlyContinue)
            if ($all.Count -gt $b) { for ($i = $b; $i -lt $all.Count; $i++) { $newLog.Add($all[$i]) } }
        }
    }
    Item "new log lines" $newLog.Count
    if ($newLog.Count -gt 0) {
        Emit "  --- log lines written during the window (last 80) ---"
        foreach ($l in ($newLog | Select-Object -Last 80)) { Emit ("    " + $l) }
    }

    # ----- Keeper-related Windows events in the window -----
    $evCount = 0
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = @('Application','System'); StartTime = $t0; EndTime = $t1 } -ErrorAction SilentlyContinue |
              Where-Object { $_.ProviderName -match 'Keeper' -or $_.Message -match 'Keeper' }
        $evCount = @($ev).Count
        Item "keeper event-log entries" $evCount
        foreach ($e in (@($ev) | Select-Object -First 20)) {
            Emit ("    [" + $e.TimeCreated.ToString("HH:mm:ss") + "] " + $e.ProviderName + ": " + (($e.Message -split "`n")[0]))
        }
    } catch { Item "event log" "query unavailable" }

    # ----- scheduled tasks that fired during the window -----
    $ranTasks = New-Object System.Collections.Generic.List[string]
    try {
        foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'Keeper' -or $_.TaskPath -match 'Keeper' })) {
            $lr = ($t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue).LastRunTime
            if ($lr -and $lr -ge $t0) { $ranTasks.Add($t.TaskName + " @ " + $lr.ToString("HH:mm:ss")) }
        }
    } catch {}
    Item "scheduled tasks fired" $ranTasks.Count
    foreach ($r in $ranTasks) { Emit ("    " + $r) }

    # ----- registration change -----
    $nowReg = (Invoke-LocalApi "https://localhost:6889/api/Keeper/registration").IsRegistered
    if ($baseReg -ne $nowReg) { Item "registration changed" ("$baseReg -> $nowReg") }

    Section "LIVE VERDICT"
    if ($newLog.Count -eq 0 -and $evCount -eq 0 -and $ranTasks.Count -eq 0) {
        Emit "  The agent observed NOTHING during your reproduction:"
        Emit "    no new log lines, no Keeper events, no scheduled-task runs."
        Emit "  => the elevation request is NOT reaching the agent. The interception /"
        Emit "     user-session layer (Task Scheduler -> KeeperClient/keeperAgent) is the"
        Emit "     prime suspect, and this matches 'agent history shows no requests'."
        Emit "  Next: re-run WITHOUT -Live for the full static check and confirm the"
        Emit "     \Keeper Security\ tasks exist and the plugin binaries are present."
        Flag "Live capture: agent reacted to nothing during the reproduction window."
    } else {
        Emit "  The agent DID react during the window (see above): the request is"
        Emit "  reaching the agent. Focus on the policy/approval decision -- grep the"
        Emit "  new log lines for 'policy' / 'approval' / 'denied' and cross-check the"
        Emit "  tenant-side report (epm_device_diag.py)."
    }
}

# =========================================================================== #
Section "KEEPER EPM ENDPOINT CHECK  (read-only$(if(-not $Raw){''}else{' -- UNREDACTED'}))"
Emit ("  generated  : " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
Emit ("  host       : " + $env:COMPUTERNAME)
Emit ("  user       : " + (Mask "$env:USERDOMAIN\$env:USERNAME"))
Emit ("  PowerShell : " + $PSVersionTable.PSVersion.ToString())
$isAdmin = Test-Admin
Emit ("  elevated   : " + $isAdmin)
if (-not $isAdmin) {
    Emit "  WARNING: not elevated -- localhost health endpoints will return 401/403."
    Emit "           Re-run from an Administrator PowerShell for full results."
    Flag "Run elevated: health endpoints unavailable without admin."
}

# ----- live capture short-circuits the static sweep -----
if ($Live) {
    Invoke-LiveCapture
    Flush-Report
    return
}

# --------------------------------------------------------------------------- #
Section "1. INSTALL LOCATION"
$baseCandidates = @(
    "C:\Program Files\Keeper Security\Endpoint Privilege Management",
    "C:\Program Files\Keeper Security\Endpoint Privilege Manager"
)
$base = $null
foreach ($c in $baseCandidates) { if (Test-Path $c) { $base = $c; break } }
Item "install dir" $(if ($base) { $base } else { "NOT FOUND" })
if (-not $base) {
    Flag "EPM install directory not found under 'C:\Program Files\Keeper Security\'."
    $base = $baseCandidates[0]
}
$pluginBin = Join-Path $base "Plugins\bin"
Item "plugins\bin" (Test-Path $pluginBin)
$script:Result["install_dir"] = $base

# --------------------------------------------------------------------------- #
Section "2. WINDOWS SERVICES (Keeper)"
try {
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Keeper" -or $_.DisplayName -match "Keeper" }
    if ($svc) {
        $mainSeen = $false
        foreach ($s in $svc) {
            Item $s.DisplayName $s.Status ($(if ($s.Status -ne "Running") { "NOT RUNNING" } else { "" }))
            if ($s.DisplayName -match "Endpoint Privilege" -or $s.Name -match "Endpoint") {
                $mainSeen = $true
                if ($s.Status -ne "Running") { Flag "Service '$($s.DisplayName)' is $($s.Status) (expected Running)." }
            }
        }
        if (-not $mainSeen) { Flag "Keeper EPM service not found among the Keeper services." }
    } else {
        Item "Keeper services" "NONE FOUND" "agent may not be installed"
        Flag "No Keeper services found -- agent may not be installed."
    }
} catch { Item "service query" ("error: " + $_.Exception.Message) }

# --------------------------------------------------------------------------- #
Section "3. SERVICE HEALTH (localhost API -- needs elevation)"
$health = Invoke-LocalApi "https://localhost:6889/health"
$reg    = Invoke-LocalApi "https://localhost:6889/api/Keeper/registration"
$plugs  = Invoke-LocalApi "https://localhost:6889/api/plugins"

if ($health.__error) { Item "/health" ("FAIL: " + $health.__error) "service not responding"; Flag "Health endpoint unreachable: $($health.__error)" }
else { Item "/health" ($health | ConvertTo-Json -Compress -Depth 4) }

if ($reg.__error) {
    $note = if ($reg.__error -match '403|401') { "needs an authenticated Admin session (SelectiveAuth); a plain probe is denied -- not broken" } else { "endpoint not responding" }
    Item "/registration" ("unavailable: " + $reg.__error) $note
}
else {
    $isReg = $reg.IsRegistered
    Item "IsRegistered" $isReg ($(if ($isReg -ne $true) { "NOT REGISTERED" } else { "" }))
    if ($isReg -ne $true) { Flag "Agent reports IsRegistered != true." }
}

if ($plugs.__error) {
    $note = if ($plugs.__error -match '403|401') { "needs an authenticated Admin session (SelectiveAuth); a plain probe is denied -- not broken" } else { "endpoint not responding" }
    Item "/api/plugins" ("unavailable: " + $plugs.__error) $note
}
else {
    $plist = if ($plugs.plugins) { $plugs.plugins } else { $plugs }
    foreach ($pl in $plist) {
        $nm = $pl.name; $st = $pl.status
        if ($nm) {
            $bad = ($st -ne "Running")
            Item ("plugin:" + $nm) $st ($(if ($bad) { "not running" } else { "" }))
            if ($bad -and ($nm -in @("KeeperAPI","KeeperPolicy"))) { Flag "Core plugin '$nm' is '$st' (expected Running)." }
        }
    }
}

# --------------------------------------------------------------------------- #
Section "4. LOCAL PORTS (6888 HTTP / 6889 HTTPS / 8675 MQTT)"
foreach ($port in 6888,6889,8675) {
    $listening = $false
    try {
        $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        $listening = [bool]$conn
    } catch {
        $listening = [bool]((netstat -an | Select-String ":$port\s" | Select-String "LISTENING"))
    }
    Item ("port " + $port) $listening ($(if (-not $listening) { "NOT listening" } else { "" }))
    if (-not $listening) { Flag "Port $port is not listening." }
}

# --------------------------------------------------------------------------- #
Section "5. PLUGIN BINARIES"
# Core components of the elevation / user-session chain. This minimal set is
# present in every build validated to date (1.1.0.327 and 2.0.0.82). The full
# component set is build-dependent and grows across versions -- 1.1 ships ~31
# EXEs, 2.0 ships ~44 (adding KeeperUpdater/KeeperUpdaterPrompt for self-update,
# keeper-agentic-snapshot-writer + KeeperOperatorApproval for agent governance,
# and incremental-inventory binaries). Do NOT treat the wider set as required;
# only this core list gates "corrupt install". (Earlier builds were thought to
# lack KeeperApproval.exe -- that was build-specific; it IS present in 1.1/2.0.)
$critical = @("keeperAgent","KeeperApi","KeeperClient","KeeperMessage","KeeperPolicy","KeeperUSession")
$present = @()
try { $present = @(Get-ChildItem $pluginBin -Recurse -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -Expand BaseName -Unique) } catch {}
Item "exe files found" $present.Count
foreach ($c in $critical) {
    $ok = $present -contains $c
    Item $c $ok ($(if (-not $ok) { "MISSING" } else { "" }))
    if (-not $ok) { Flag "Core component missing: $c.exe (corrupt install -> clean reinstall)." }
}
$extra = @($present | Where-Object { $critical -notcontains $_ } | Sort-Object)
if ($extra.Count -gt 0) { Item "other components" ($extra -join ", ") }

# --------------------------------------------------------------------------- #
Section "6. USER-SESSION LAUNCHER (process + tasks)"
# The session component (KeeperClient/KeeperUSession) can be launched by a
# standing scheduled task ('\KeeperClient Startup') OR dynamically by a job
# trigger. So the real signal is: is the PROCESS running? A missing scheduled
# task alone is NOT a problem if the process is up.
$proc = @()
try { $proc = @(Get-Process -Name "KeeperClient","KeeperUSession" -ErrorAction SilentlyContinue) } catch {}
$tasks = @()
try { $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -match 'Keeper' -or $_.TaskPath -match 'Keeper' }) } catch {}

if ($proc.Count -gt 0) {
    Item "session process running" (($proc | Select-Object -Expand ProcessName -Unique) -join ", ")
} else {
    Item "session process running" "NO" "KeeperClient/KeeperUSession not running"
}
if ($tasks.Count -gt 0) {
    foreach ($t in $tasks) {
        Item ($t.TaskPath + $t.TaskName) $t.State ($(if ($t.State -eq "Disabled") { "DISABLED" } else { "" }))
        if ($t.State -eq "Disabled") { Flag "Scheduled task '$($t.TaskName)' is Disabled." }
    }
} else {
    Item "Keeper scheduled tasks" "none (this build may launch via a job trigger instead)"
}
# Only a real problem if NEITHER the process is running NOR a task exists
if ($proc.Count -eq 0 -and $tasks.Count -eq 0) {
    Flag "User-session launcher absent: KeeperClient/KeeperUSession not running and no Keeper scheduled task."
}

# --------------------------------------------------------------------------- #
Section "7. POLICY SYNC STATE"
$cp = $null
try {
    $cp = Get-ChildItem -Path $pluginBin -Recurse -Filter "currentPolicies.json" -ErrorAction SilentlyContinue |
          Select-Object -First 1
} catch {}
if ($cp) {
    Item "currentPolicies.json" $cp.FullName
    Item "  last written" $cp.LastWriteTime
    Item "  size (bytes)" $cp.Length ($(if ($cp.Length -le 2) { "looks empty" } else { "" }))
} else {
    Item "currentPolicies.json" "NOT FOUND" "no synced policy file"
    Flag "currentPolicies.json not found -- policy sync may not have completed."
}

# --------------------------------------------------------------------------- #
Section "8. LOGS (KeeperLogger)"
$logDir = Join-Path $pluginBin "KeeperLogger\Log"
Item "log dir" ($(if (Test-Path $logDir) { $logDir } else { "NOT FOUND ($logDir)" }))
if (Test-Path $logDir) {
    $latest = Get-ChildItem -Path $logDir -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Item "latest log" $latest.Name
        Item "  modified" $latest.LastWriteTime
        Item "  CAPTURED ERRORS ARE IN" $latest.FullName        # <-- where to look / collect from
        try {
            $tail = Get-Content $latest.FullName -Tail 2000 -ErrorAction SilentlyContinue
            $merge = $tail | Select-String "policy merge complete|policies\s*=|merged.*polic" | Select-Object -Last 1
            if (-not $merge) { $merge = $tail | Select-String "polic" | Select-Object -Last 1 }
            $secfail = $tail | Select-String "Plugin failed security validation|security validation failed" | Select-Object -Last 1
            $mline = if ($merge) { $merge.Line.Trim() } else { "no 'policy' lines in last 2000" }
            if ($mline.Length -gt 200) { $mline = $mline.Substring(0,200) + " ..." }
            Item "  latest policy log line" $mline

            # surface captured errors/warnings (count only -- benign errors are normal;
            # this tells the user WHERE to read them, it does not auto-flag)
            $errs  = @($tail | Select-String "\[ERR\]|\[FTL\]|\[ERROR\]|Exception")
            $warns = @($tail | Select-String "\[WRN\]|\[WARN")
            Item "  errors / warnings (last 2000 lines)" ("$($errs.Count) error(s), $($warns.Count) warning(s)")
            if ($errs.Count -gt 0) {
                Emit "  most recent error lines (full text in the log file above):"
                foreach ($e in ($errs | Select-Object -Last 3)) {
                    $el = $e.Line.Trim()
                    if ($el.Length -gt 180) { $el = $el.Substring(0, 180) + " ..." }
                    Emit ("    " + $el)
                }
            }
            if ($secfail) {
                Item "  SECURITY VALIDATION" $secfail.Line.Trim() "plugin failed validation"
                Flag "Log shows 'Plugin failed security validation' -- see $($latest.FullName)"
            }

            # user-session launch failures: the agent cannot place the Keeper popup
            # OR the approved app onto the user's interactive desktop. This explains
            # BOTH "no Keeper popup (only UAC)" and "approved app never starts".
            #
            # Two DIFFERENT root causes -- the detection separates them, because the
            # next step is opposite:
            #   (A) the agent never resolved an active user session (it really saw 0)
            #       -> session targeting / nobody-logged-on. Confirm with qwinsta.
            #   (B) the agent DID resolve the active user (e.g. "Selected user X in
            #       session N", "Found 1 active user session") but the launch still
            #       failed via WindowsTaskSchedulerLauncher (schtasks error +
            #       PROCESS_DETECTION_FAILED + Launched: False). The session is fine;
            #       the agent's own user-desktop launcher is broken on this box.
            #       This is an AGENT defect -> Keeper engineering, NOT an environment
            #       or RDP/console issue (it reproduces from console too).
            $launchFail = @($tail | Select-String "LAUNCH_FAILED|Failed to launch .* on user desktop|LAUNCH_APPROVAL_NON_ELEVATED_FAILED|WINDOWS_LAUNCH_FAILED")
            $schFail    = @($tail | Select-String "PROCESS_DETECTION_FAILED|SCHTASKS_ERROR|USER_DESKTOP_TASK_LAUNCH_RESULT.*Launched: False")
            $sawUser    = @($tail | Select-String "Found [1-9][0-9]* active user session|WTS_SESSION_SELECTED|SESSION_LOOKUP_SUCCESS")
            $noUser     = @($tail | Select-String "Found 0 active user session")
            $sigReadErr = @($tail | Select-String "SIGNATURE_VERIFICATION_FAILED.*CRYPT_E_FILE_ERROR|0x80092003")
            if ($launchFail.Count -gt 0 -or $schFail.Count -gt 0) {
                Item "  USER-SESSION LAUNCH FAILURES" "$($launchFail.Count) launch-failed, $($schFail.Count) task-scheduler/detection failure(s)"
                foreach ($lf in (($launchFail + $schFail) | Select-Object -Last 4)) {
                    $ll = $lf.Line.Trim(); if ($ll.Length -gt 180) { $ll = $ll.Substring(0,180) + " ..." }
                    Emit ("    " + $ll)
                }
                if ($schFail.Count -gt 0 -and $sawUser.Count -gt 0) {
                    Emit "  Agent DID resolve the active user session, but its Task Scheduler launcher could not spawn the process."
                    if ($sigReadErr.Count -gt 0) { Emit "  Also: WinTrust signature read failed (CRYPT_E_FILE_ERROR 0x80092003) -- agent could not read the target .exe to verify it." }
                    Flag "Agent's user-desktop launcher (WindowsTaskSchedulerLauncher) FAILED to spawn the process even though it correctly resolved the logged-on user (schtasks 'cannot find the file specified' + PROCESS_DETECTION_FAILED + Launched: False). The Keeper approval popup and approved apps never start. This is NOT a session/RDP-targeting problem (the agent saw the user; it reproduces from the console too) -> AGENT-SIDE LAUNCH DEFECT. ESCALATE to Keeper engineering with the WindowsTaskSchedulerLauncher SCHTASKS_ERROR + PROCESS_DETECTION_FAILED + USER_DESKTOP_TASK_LAUNCH_RESULT 'Launched: False' lines (and any WinTrust CRYPT_E_FILE_ERROR)."
                } elseif ($noUser.Count -gt 0 -and $sawUser.Count -eq 0) {
                    Emit "  Agent reports NO active user session in this window."
                    Flag "Agent CANNOT launch on the user's interactive desktop AND reports 0 active user sessions -> nobody was logged on, or a session-targeting problem. Confirm with 'qwinsta' during a repro: if the user shows Active (console OR rdp-tcp) and the agent still sees 0, escalate to Keeper engineering; otherwise reproduce while the user is actively logged on."
                } else {
                    Flag "Agent logged UserSessionLauncher LAUNCH_FAILED 'on user desktop' -> Keeper popup / approved app could not start in the user's session. Check whether the agent resolved the logged-on user (WTS_SESSION_SELECTED) just before the failure: if yes -> agent launcher defect (engineering); if it saw 0 sessions -> confirm the user was logged on (qwinsta)."
                }
            }
        } catch {}
    }
} else {
    Flag "KeeperLogger log directory not found (check 'Management' vs 'Manager' in the path)."
}

# --------------------------------------------------------------------------- #
Section "8b. POLICY ENFORCEMENT (from recent log)"
# Distinguishes a healthy agent whose policies are in MONITOR/disabled (a
# tenant-side config issue) from an actual endpoint failure.
$plog = $null
try { $plog = Get-ChildItem $logDir -File -Filter "KeeperLogger2*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 } catch {}
if ($plog) {
    $lt = Get-Content $plog.FullName -Tail 5000 -ErrorAction SilentlyContinue
    $evals    = @($lt | Select-String "POLICY\.EVALUATION|policy_evaluation|PolicyEvaluationOrchestrator").Count
    $disabled = @($lt | Select-String "EnforcementDisabled").Count
    $applic0  = @($lt | Select-String "ApplicablePolicies: 0").Count
    $reg      = $lt | Select-String "Total policies in registry" | Select-Object -Last 1
    Item "policy evaluations (recent)" $evals
    Item "  -> EnforcementDisabled" $disabled
    Item "  -> ApplicablePolicies=0" $applic0
    if ($reg) {
        $rl = ($reg.Line -replace '.*(Total policies in registry.*)', '$1').Trim()
        if ($rl.Length -gt 160) { $rl = $rl.Substring(0, 160) + " ..." }
        Item "  registry state" $rl
    }
    if ($disabled -gt 0) {
        Emit "  The agent IS evaluating requests, but enforcement is OFF / no policy applies."
        Emit "  => endpoint healthy; this points TENANT-SIDE. Set the elevation policy to"
        Emit "     ENFORCE (not monitor) and confirm its scope (machine/user/app collections)"
        Emit "     covers this device + the user + the apps being tested."
        Flag "Policy evaluations return EnforcementDisabled -- check enforce mode + policy scope on the tenant (this is NOT an endpoint problem)."
    }
} else {
    Item "policy enforcement" "no KeeperLogger log to analyze"
}

# --------------------------------------------------------------------------- #
Section "9. .NET RUNTIME (.NET 8)"
$net8 = $false
try { $rt = & dotnet --list-runtimes 2>$null; if ($rt -match "Microsoft\.NETCore\.App 8\.") { $net8 = $true } } catch {}
if (-not $net8) {
    foreach ($shared in @("C:\Program Files\dotnet\shared\Microsoft.NETCore.App",
                          "C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App")) {
        if (Test-Path $shared) {
            if (Get-ChildItem $shared -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "8.*" }) { $net8 = $true; break }
        }
    }
}
if ($net8) { Item ".NET 8 runtime" "present (system-wide)" }
else { Item ".NET 8 runtime" "not found on PATH or in shared runtimes -- the agent may bundle its own; only a concern if the service fails to start" }

# --------------------------------------------------------------------------- #
Section "10. CONNECTIVITY (Keeper router: $Region)"
$kp = "connect.keepersecurity.$Region"
try {
    $dnsSrv = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.ServerAddresses } | Select-Object -Expand ServerAddresses) -join ", "
    if ($dnsSrv) { Item "configured DNS servers" $dnsSrv }
} catch {}
try {
    $dns = Resolve-DnsName -Name $kp -ErrorAction SilentlyContinue
    if ($dns) { Item "DNS $kp" (($dns | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress) }
    else { Item "DNS $kp" "RESOLVE FAILED" "DNS failure"; Flag "DNS resolution failed for $kp (check DNS servers above / egress)." }
} catch { Item "DNS $kp" ("error: " + $_.Exception.Message) }
try {
    $tnc = Test-NetConnection -ComputerName $kp -Port 443 -WarningAction SilentlyContinue
    Item "TCP 443 $kp" $tnc.TcpTestSucceeded ($(if (-not $tnc.TcpTestSucceeded) { "cannot reach :443" } else { "" }))
    if (-not $tnc.TcpTestSucceeded) { Flag "Cannot reach $kp on 443." }
} catch { Item "TCP 443 $kp" ("error: " + $_.Exception.Message) }

# --------------------------------------------------------------------------- #
Section "11. EDR PRESENCE (may block process launch from EPM dir)"
$edr = @{ "CrowdStrike" = "csagent|CSFalcon"; "SentinelOne" = "Sentinel"; "Sophos" = "Sophos"; "Defender" = "WinDefend|Sense" }
foreach ($name in $edr.Keys) {
    $found = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $edr[$name] -or $_.DisplayName -match $name }
    if ($found) { Item $name "present" "ensure EPM dir is excluded from real-time scanning" }
}

# --------------------------------------------------------------------------- #
Section "11b. APP-CONTROL & LAUNCH BLOCKERS (why a schtasks user-desktop launch can fail)"
Emit "  The agent launches the approval popup + approved apps by creating a scheduled"
Emit "  task. App-control (AppLocker/WDAC), Defender ASR, or a Mark-of-the-Web block can"
Emit "  make that step fail with 'the system cannot find the file specified' even though"
Emit "  the agent resolved the user correctly. Checking the usual culprits:"

# --- AppLocker: enforcement + recent block events --------------------------- #
try {
    $alSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    $alPol = $null
    try { $alPol = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue } catch {}
    if ($alPol -and $alPol.RuleCollections) {
        $modes = ($alPol.RuleCollections | ForEach-Object { "$($_.RuleCollectionType)=$($_.EnforcementMode)" }) -join ", "
        Item "AppLocker policy" $modes
        if ($modes -match "Enabled") { Flag "AppLocker is ENFORCING ($modes) -- it can block the agent's launched process. Confirm the EPM bin dir + the approved app are allowed." }
    } else {
        Item "AppLocker policy" ("none effective" + $(if ($alSvc) { " (AppIDSvc: $($alSvc.Status))" } else { "" }))
    }
    $alBlocks = @()
    foreach ($lg in @('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script')) {
        try { $alBlocks += @(Get-WinEvent -FilterHashtable @{ LogName = $lg; Id = @(8004,8007); StartTime = (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue) } catch {}
    }
    Item "AppLocker BLOCK events (48h)" $alBlocks.Count
    if ($alBlocks.Count -gt 0) {
        foreach ($b in ($alBlocks | Select-Object -First 4)) { Emit ("    " + $b.TimeCreated.ToString("MM-dd HH:mm") + "  " + (($b.Message -split "`n")[0])) }
        Flag "AppLocker logged $($alBlocks.Count) BLOCK event(s) in the last 48h -- a blocked launch matches 'schtasks could not find the file'. Allow the EPM bin dir + approved apps."
    }
} catch { Item "AppLocker" ("query error: " + $_.Exception.Message) }

# --- WDAC / Code Integrity: enforcement + recent block events --------------- #
try {
    $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($dg) {
        $ciState = switch ($dg.CodeIntegrityPolicyEnforcementStatus) { 0 {"Off"} 1 {"Audit"} 2 {"Enforced"} default {"unknown"} }
        Item "WDAC / Code Integrity" $ciState
        if ($dg.CodeIntegrityPolicyEnforcementStatus -eq 2) { Flag "WDAC Code Integrity is ENFORCED -- an unsigned/disallowed approved app or launcher helper would be blocked. Check CodeIntegrity/Operational blocks below." }
    }
    $ciBlocks = @()
    try { $ciBlocks = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = @(3077,3033); StartTime = (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue) } catch {}
    Item "CodeIntegrity BLOCK events (48h)" $ciBlocks.Count
    if ($ciBlocks.Count -gt 0) {
        foreach ($b in ($ciBlocks | Select-Object -First 4)) { Emit ("    " + $b.TimeCreated.ToString("MM-dd HH:mm") + "  " + (($b.Message -split "`n")[0])) }
        Flag "Code Integrity logged $($ciBlocks.Count) BLOCK event(s) in 48h -- the launched process may be disallowed by WDAC."
    }
} catch { Item "WDAC" ("query error: " + $_.Exception.Message) }

# --- Defender: real-time/ASR posture + recent ASR/threat events ------------- #
try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) { Item "Defender real-time" $mp.RealTimeProtectionEnabled ($(if ($mp.IsTamperProtected) { "tamper-protected" } else { "" })) }
    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    if ($pref -and $pref.AttackSurfaceReductionRules_Ids) {
        $blockAsr = 0
        for ($i=0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
            if ($pref.AttackSurfaceReductionRules_Actions[$i] -eq 1) { $blockAsr++ }
        }
        Item "Defender ASR rules in Block mode" $blockAsr
        if ($blockAsr -gt 0) { Flag "Defender has $blockAsr ASR rule(s) in BLOCK mode -- some block child-process creation and can break the agent's scheduled-task launch. Review ASR events (ID 1121) around the repro time." }
    }
    if ($pref -and ($pref.ExclusionPath -or $pref.ExclusionProcess)) {
        $epmExcluded = @($pref.ExclusionPath) -match "Keeper"
        Item "Defender EPM-dir excluded" ($(if ($epmExcluded) { "yes" } else { "no" }))
    }
    $defEvents = @()
    try { $defEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1121,1116,1117); StartTime = (Get-Date).AddDays(-2) } -ErrorAction SilentlyContinue) } catch {}
    Item "Defender block/threat events (48h)" $defEvents.Count
    if ($defEvents.Count -gt 0) {
        foreach ($b in ($defEvents | Select-Object -First 4)) { Emit ("    " + $b.TimeCreated.ToString("MM-dd HH:mm") + "  id=" + $b.Id + "  " + (($b.Message -split "`n")[0])) }
        Flag "Defender logged $($defEvents.Count) block/threat event(s) in 48h (ASR 1121 / detection 1116/1117) -- a quarantined or ASR-blocked target explains the launch failure."
    }
} catch { Item "Defender" ("query error (Defender module/cmdlets may be absent): " + $_.Exception.Message) }

# --- Target exe: Mark-of-the-Web + signature -------------------------------- #
if ($TargetExe) {
    if (Test-Path -LiteralPath $TargetExe) {
        Item "target exe" $TargetExe
        $motw = $null
        try { $motw = Get-Item -LiteralPath $TargetExe -Stream Zone.Identifier -ErrorAction SilentlyContinue } catch {}
        if ($motw) {
            Item "  Mark-of-the-Web" "PRESENT (file is flagged downloaded-from-internet)"
            Flag "Target exe has a Mark-of-the-Web / Zone.Identifier block -- SmartScreen/WDAC/AppLocker may refuse to run it. Clear it: right-click > Properties > Unblock (or 'Unblock-File `"$TargetExe`"')."
        } else { Item "  Mark-of-the-Web" "none" }
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $TargetExe -ErrorAction SilentlyContinue
            if ($sig) { Item "  signature" ("$($sig.Status)" + $(if ($sig.SignerCertificate) { " (" + $sig.SignerCertificate.Subject.Split(',')[0] + ")" } else { "" })) }
        } catch {}
        # is the file actually readable by THIS context? (the WinTrust CRYPT_E_FILE_ERROR symptom)
        try { [void][System.IO.File]::OpenRead($TargetExe).Close(); Item "  readable by this account" "yes" }
        catch { Item "  readable by this account" "NO"; Flag "This account cannot read $TargetExe (matches the agent's WinTrust CRYPT_E_FILE_ERROR). Check the path (mapped/network/OneDrive?) and ACLs." }
    } else { Item "target exe" "NOT FOUND: $TargetExe" }
} else {
    Emit "  (pass -TargetExe '<path to approved app>' to check Mark-of-the-Web + signature + readability)"
}

# --- schtasks: context + optional active launch probe ----------------------- #
$whoami = $null
try { $whoami = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; Item "current context" $whoami } catch {}
if ($ProbeSchtasks) {
    # The EPM agent runs as SYSTEM, so the meaningful test is whether a SYSTEM-context
    # scheduled task can be created + run here. /RU SYSTEM reproduces the agent's own
    # context regardless of who launched this script (requires admin to create).
    $tn = "KeeperDiagProbe_" + (Get-Random)
    $probeOk = $false; $probeErr = ""; $ranOk = $false
    try {
        $r1 = & schtasks.exe /Create /TN $tn /TR "cmd.exe /c exit" /SC ONCE /ST 23:59 /RU SYSTEM /F 2>&1
        $created = ($LASTEXITCODE -eq 0)
        $r2 = & schtasks.exe /Run /TN $tn 2>&1
        $ranOk = ($LASTEXITCODE -eq 0)
        $r3 = & schtasks.exe /Query /TN $tn 2>&1
        if ($created -and $ranOk) { $probeOk = $true } else { $probeErr = (@($r1) + @($r2) + @($r3) -join " | ").Trim() }
    } catch { $probeErr = $_.Exception.Message }
    finally { & schtasks.exe /Delete /TN $tn /F 2>&1 | Out-Null }
    Item "schtasks SYSTEM-context probe" ($(if ($probeOk) { "OK -- a SYSTEM scheduled task created + ran (the agent's launch path works here)" } else { "FAILED" }))
    if (-not $probeOk) {
        if ($whoami -and $whoami -notmatch "SYSTEM" -and $probeErr -match "Access is denied|denied") {
            Emit "  (run elevated; creating a /RU SYSTEM task needs admin)"
        }
        Flag "schtasks SYSTEM-context probe FAILED ($probeErr) -- the agent uses Task Scheduler (as SYSTEM) to launch on the user desktop, so the same block stops it. This is the mechanism behind 'the system cannot find the file specified'. ENVIRONMENT finding: whitelist schtasks/Task Scheduler for SYSTEM (app-control/EDR), not an agent bug."
    }
} else {
    Emit "  (pass -ProbeSchtasks to actively test a SYSTEM-context scheduled-task launch -- the agent's exact mechanism)"
}

# --------------------------------------------------------------------------- #
Section "12. LOCAL ADMINISTRATORS (criteria 1: demotion check)"
try {
    $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($members) {
        foreach ($m in $members) { Item "member" (Mask $m.Name) }
        Emit "  (the demoted standard user should NOT appear above)"
    } else { Item "administrators" "could not enumerate" }
} catch { Item "administrators" ("error: " + $_.Exception.Message) }

# --------------------------------------------------------------------------- #
Section "FINDINGS"
if ($script:Findings.Count -eq 0) {
    Emit "  No blocking issues detected by the local checks."
    Emit "  If elevation still fails, capture today's KeeperLogger log and the"
    Emit "  tenant-side report (epm_device_diag.py on the admin workstation)."
} else {
    $i = 1
    foreach ($f in $script:Findings) { Emit ("  {0}. {1}" -f $i, $f); $i++ }
}

Section "SUGGESTED REMEDIATION (apply manually -- this tool changes nothing)"
Emit @"
  - Tasks missing/disabled -> reinstall the EPM agent (recreates \Keeper Security\ tasks).
  - Binaries missing       -> install is corrupt; clean reinstall.
  - Not registered         -> force re-register (recreates tasks):
      curl -X POST "https://localhost:6889/api/Keeper/register?token=<token>&force=true" --insecure
  - DNS/443 fails           -> open egress to connect.keepersecurity.${Region}:443; recheck proxy/EDR.
  - After any fix           -> restart the Keeper endpoint service, then log the user out and back in.
"@

# --------------------------------------------------------------------------- #
Flush-Report
if ($Json) {
    $script:Result["host"] = $env:COMPUTERNAME
    $script:Result["findings"] = $script:Findings
    $script:Result | ConvertTo-Json -Depth 6
}
