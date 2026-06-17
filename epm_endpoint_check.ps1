<#
.SYNOPSIS
    Keeper EPM endpoint diagnostic collector -- READ ONLY, no Keeper login required.

.DESCRIPTION
    Runs ON a Windows endpoint that has the Keeper Endpoint Privilege Manager
    agent installed and reports the LOCAL health signals the backend cannot see:
    service health, listening ports, plugin binaries, scheduled tasks, policy
    sync state, logs, .NET runtime, DNS/egress, EDR presence, and local admin
    membership.

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
    [switch]$Live
)

$ErrorActionPreference = "Continue"
$script:Lines    = New-Object System.Collections.Generic.List[string]
$script:Result   = [ordered]@{}
$script:Findings = New-Object System.Collections.Generic.List[string]

# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
function Emit([string]$s = "") { Write-Host $s; $script:Lines.Add($s) }
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
    Emit ("  baseline at : " + $t0.ToString("HH:mm:ss"))
    Emit ""
    Emit "  >>> Reproduce the elevation NOW:"
    Emit "      as the demoted standard user, try to install/run something that"
    Emit "      should raise the Keeper elevation prompt."
    Emit ""
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
        foreach ($t in Get-ScheduledTask -TaskPath "\Keeper Security\*" -ErrorAction SilentlyContinue) {
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
    Section "FINDINGS"
    if ($script:Findings.Count -eq 0) { Emit "  (none flagged)" }
    else { $i = 1; foreach ($f in $script:Findings) { Emit ("  {0}. {1}" -f $i, $f); $i++ } }
    if ($Output) {
        try {
            $script:Lines -join "`r`n" | Out-File -FilePath $Output -Encoding utf8
            Write-Host "`nWrote capture to $Output"
        } catch { Write-Warning ("Could not write " + $Output + ": " + $_.Exception.Message) }
    }
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
Section "2. WINDOWS SERVICE"
try {
    $svc = Get-Service -Name "Keeper*" -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -match "Endpoint" -or $_.Name -match "Endpoint" }
    if (-not $svc) { $svc = Get-Service -Name "KeeperEndpointService" -ErrorAction SilentlyContinue }
    if ($svc) {
        foreach ($s in $svc) {
            Item $s.Name $s.Status ($(if ($s.Status -ne "Running") { "NOT RUNNING" } else { "" }))
            if ($s.Status -ne "Running") { Flag "Service '$($s.Name)' is $($s.Status) (expected Running)." }
        }
    } else {
        Item "KeeperEndpointService" "NOT FOUND" "service missing"
        Flag "Keeper endpoint service not found -- agent may not be installed."
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
    $note = if ($reg.__error -match '403|401') { "auth-gated (token needed); not necessarily broken" } else { "endpoint not responding" }
    Item "/registration" ("unavailable: " + $reg.__error) $note
}
else {
    $isReg = $reg.IsRegistered
    Item "IsRegistered" $isReg ($(if ($isReg -ne $true) { "NOT REGISTERED" } else { "" }))
    if ($isReg -ne $true) { Flag "Agent reports IsRegistered != true." }
}

if ($plugs.__error) {
    $note = if ($plugs.__error -match '403|401') { "auth-gated (token needed); not necessarily broken" } else { "endpoint not responding" }
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
$bins = @("KeeperClient\KeeperClient.exe","keeperAgent\keeperAgent.exe",
          "KeeperMessage\KeeperMessage.exe","KeeperApproval\KeeperApproval.exe")
foreach ($b in $bins) {
    $full = Join-Path $pluginBin $b
    $ok = Test-Path $full
    Item $b $ok ($(if (-not $ok) { "MISSING" } else { "" }))
    if (-not $ok) { Flag "Plugin binary missing: $b (corrupt install -> clean reinstall)." }
}

# --------------------------------------------------------------------------- #
Section "6. SCHEDULED TASKS (\Keeper Security\)"
try {
    $tasks = Get-ScheduledTask -TaskPath "\Keeper Security\*" -ErrorAction SilentlyContinue
    if (-not $tasks) {
        Item "tasks" "NONE FOUND" "no tasks under \Keeper Security\"
        Flag "No scheduled tasks under '\Keeper Security\' -- user-session components cannot launch (reinstall recreates them)."
    } else {
        foreach ($t in $tasks) {
            $state = $t.State
            Item $t.TaskName $state ($(if ($state -eq "Disabled") { "DISABLED" } else { "" }))
            if ($state -eq "Disabled") { Flag "Scheduled task '$($t.TaskName)' is Disabled." }
        }
    }
} catch { Item "scheduled tasks" ("error: " + $_.Exception.Message) }

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
        try {
            $tail = Get-Content $latest.FullName -Tail 2000 -ErrorAction SilentlyContinue
            $merge = $tail | Select-String "policy merge complete|policies\s*=|merged.*polic" | Select-Object -Last 1
            if (-not $merge) { $merge = $tail | Select-String "polic" | Select-Object -Last 1 }
            $secfail = $tail | Select-String "Plugin failed security validation|security validation failed" | Select-Object -Last 1
            $mline = if ($merge) { $merge.Line.Trim() } else { "no 'policy' lines in last 2000" }
            if ($mline.Length -gt 200) { $mline = $mline.Substring(0,200) + " ..." }
            Item "  latest policy log line" $mline
            if ($secfail) {
                Item "  SECURITY VALIDATION" $secfail.Line.Trim() "plugin failed validation"
                Flag "Log shows 'Plugin failed security validation'."
            }
        } catch {}
    }
} else {
    Flag "KeeperLogger log directory not found (check 'Management' vs 'Manager' in the path)."
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
    $dns = Resolve-DnsName -Name $kp -ErrorAction SilentlyContinue
    if ($dns) { Item "DNS $kp" (($dns | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress) }
    else { Item "DNS $kp" "RESOLVE FAILED" "DNS failure"; Flag "DNS resolution failed for $kp." }
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
if ($Output) {
    try {
        $script:Lines -join "`r`n" | Out-File -FilePath $Output -Encoding utf8
        if (-not $Raw) { Write-Host "`nWrote report to $Output" }
        else { Write-Warning "$Output contains UNREDACTED identities." }
    } catch { Write-Warning ("Could not write " + $Output + ": " + $_.Exception.Message) }
}
if ($Json) {
    $script:Result["host"] = $env:COMPUTERNAME
    $script:Result["findings"] = $script:Findings
    $script:Result | ConvertTo-Json -Depth 6
}
