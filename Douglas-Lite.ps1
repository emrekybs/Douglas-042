<#
    Douglas-Lite - fast live-system triage snapshot for Windows

    A single-pass collector that dumps the output of ~70 built-in Windows
    commands into one plain-text report. No parameters, no analysis, no
    scoring - just a fast, readable snapshot of what the machine looks
    like right now.

    For full incident response with detection rules, risk scoring, timeline
    and an HTML report, use Douglas-042.ps1 instead.

    USAGE
        .\Douglas-Lite.ps1

    Requires Administrator. Output: REPORT_<hostname>_<timestamp>.txt

    NOTE ON LIVE-SYSTEM IMPACT
    Running this touches file access times and Prefetch. If forensic
    soundness matters, image the disk first.

#>

$ErrorActionPreference = 'Continue'

$banner = @'

    ____                    __                 __    _ __
   / __ \____  __  ______ _/ /___ ______      / /   (_) /____
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ /   / / __/ _ \
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /___/ / /_/  __/
/_____/\____/\__,_/\__, /_/\__,_/____/     /_____/_/\__/\___/
                  /____/
'@

Write-Host $banner -ForegroundColor Cyan
Write-Host '        Fast live-system triage snapshot' -ForegroundColor White
Write-Host '        Single text report  |  no analysis  |  run and read' -ForegroundColor DarkGray
Write-Host ''

# --- Administrator check ---
$isAdmin = ([Security.Principal.WindowsPrincipal] `
            [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
if (-not $isAdmin) {
    Write-Host '  [x] Douglas-Lite must be run with Administrator rights.' -ForegroundColor Red
    Write-Host '      Example: Start-Process powershell -Verb RunAs' -ForegroundColor DarkGray
    exit 1
}

# --- Host identity ---
# NOTE: the old version parsed `ipconfig` text, which breaks on localised
# Windows. Get-NetIPAddress is language independent.
$hostName = $env:COMPUTERNAME
$ipList = @()
try {
    $ipList = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
        Select-Object -ExpandProperty IPAddress)
} catch {
    try { $ipList = @((Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.IPEnabled }).IPAddress |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) } catch { }
}
$ipText = if ($ipList.Count) { $ipList -join ', ' } else { 'unknown' }

$stamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$report = Join-Path (Get-Location).Path "REPORT_${hostName}_${stamp}.txt"

Write-Host "  Host      : $hostName ($ipText)"
Write-Host "  Started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Output    : $report"
Write-Host ''
Write-Host '  Collecting... this usually takes under a minute.' -ForegroundColor DarkGray
Write-Host ''

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

$script:sectionNo = 0

function Section {
    <# Section header. Also prints progress to the console so the operator
       can see the script is alive rather than staring at a frozen prompt. #>
    param([string]$Title)
    $script:sectionNo++
    Write-Host ("  [{0,2}] {1}" -f $script:sectionNo, $Title) -ForegroundColor DarkCyan
    ''
    '=' * 100
    "  $Title"
    '=' * 100
}

function Sub {
    param([string]$Title)
    ''
    "--- $Title ---"
}

function Safe {
    <# Runs a collection block and, if it fails, records WHY in the report.
       The old version silenced every error, so a missing section looked
       identical to an empty one. #>
    param([string]$Label, [scriptblock]$Block)
    Sub $Label
    try {
        $out = & $Block 2>&1
        if ($null -eq $out -or (@($out).Count -eq 0)) { '  (no data)' }
        else { $out }
    } catch {
        "  [collection failed] $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
#  Collection
# ---------------------------------------------------------------------------

$data = {

Section 'GENERAL INFORMATION'
Safe 'System summary' { systeminfo }
Safe 'Operating system' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, CSName,
                      InstallDate, LastBootUpTime | Format-List
}
Safe 'Time zone' { Get-TimeZone }
Safe 'Group policy result' { gpresult.exe /z }
Safe 'BitLocker / encryption status' { manage-bde.exe -status }

Section 'ACCOUNTS AND GROUPS'
Safe 'Local users' { Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet, Description -AutoSize }
Safe 'Enabled local users' { Get-LocalUser | Where-Object Enabled -eq $true | Format-Table Name, LastLogon, PasswordLastSet -AutoSize }
Safe 'Local groups' { Get-LocalGroup | Format-Table Name, Description -AutoSize }
Safe 'Administrators group members' { Get-LocalGroupMember -Group 'Administrators' | Format-Table Name, ObjectClass, PrincipalSource -AutoSize }
Safe 'Password and lockout policy' { net accounts }
Safe 'Logged on sessions' { query user }

Section 'PATCHES AND HOTFIXES'
Safe 'Installed hotfixes' { Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn, InstalledBy -AutoSize }
Safe 'Release ID' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName, ReleaseId, DisplayVersion, CurrentBuild, UBR | Format-List }

Section 'HARDWARE'
Safe 'BIOS' { Get-CimInstance Win32_BIOS | Format-List Manufacturer, Name, SerialNumber, Version, ReleaseDate }
Safe 'Processor' { Get-CimInstance Win32_Processor | Format-List Name, NumberOfCores, NumberOfLogicalProcessors, SocketDesignation }
Safe 'Computer system' { Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer, Model, SystemType, TotalPhysicalMemory, Domain, PartOfDomain }
Safe 'Logical disks' {
    Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, FileSystem,
        @{L='FreeGB';E={'{0:N1}' -f ($_.FreeSpace/1GB)}},
        @{L='SizeGB';E={'{0:N1}' -f ($_.Size/1GB)}} | Format-Table -AutoSize
}

Section 'FIREWALL'
Safe 'Firewall profiles' { Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked -AutoSize }
Safe 'Current profile configuration' { netsh advfirewall show currentprofile }
Safe 'Allowed inbound rules (enabled)' {
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop |
        Select-Object -First 100 DisplayName, Profile, Program | Format-Table -AutoSize
}

Section 'NETWORK'
Safe 'IP configuration' { Get-NetIPAddress | Where-Object AddressFamily -eq 'IPv4' | Format-Table InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin -AutoSize }
Safe 'Active adapters' { Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table Name, InterfaceDescription, MacAddress, LinkSpeed -AutoSize }
Safe 'Routing table' { Get-NetRoute -AddressFamily IPv4 | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias -AutoSize }
Safe 'DNS servers' { Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table InterfaceAlias, ServerAddresses -AutoSize }
Safe 'TCP connections with owning process' {
    Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
        $p = $null
        try { $p = Get-Process -Id $_.OwningProcess -ErrorAction Stop } catch { }
        [PSCustomObject]@{
            LocalAddress  = "$($_.LocalAddress):$($_.LocalPort)"
            RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
            State         = $_.State
            PID           = $_.OwningProcess
            Process       = if ($p) { $p.ProcessName } else { '?' }
            Path          = if ($p) { $p.Path } else { $null }
        }
    } | Sort-Object State, RemoteAddress | Format-Table -AutoSize -Wrap
}
Safe 'Listening ports' {
    Get-NetTCPConnection -State Listen -ErrorAction Stop | ForEach-Object {
        $p = $null
        try { $p = Get-Process -Id $_.OwningProcess -ErrorAction Stop } catch { }
        [PSCustomObject]@{
            Local   = "$($_.LocalAddress):$($_.LocalPort)"
            PID     = $_.OwningProcess
            Process = if ($p) { $p.ProcessName } else { '?' }
            Path    = if ($p) { $p.Path } else { $null }
        }
    } | Sort-Object Local | Format-Table -AutoSize -Wrap
}
Safe 'UDP endpoints' { Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime | Format-Table -AutoSize }
Safe 'ARP cache' { Get-NetNeighbor -AddressFamily IPv4 | Where-Object State -ne 'Unreachable' | Format-Table IPAddress, LinkLayerAddress, State -AutoSize }
Safe 'Hosts file' { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" }
Safe 'Hosts file timestamps' { Get-Item "$env:SystemRoot\System32\drivers\etc\hosts" | Format-List CreationTime, LastWriteTime, LastAccessTime }
Safe 'DNS client cache' { Get-DnsClientCache | Select-Object Entry, Name, Data, Type | Format-Table -AutoSize }
Safe 'Proxy settings' { Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyEnable, ProxyServer, AutoConfigURL | Format-List }
Safe 'netsh portproxy rules' { netsh interface portproxy show all }
Safe 'Mapped drives / net use' { net use }

Section 'PROCESSES'
Safe 'Process list with command line' {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
        Sort-Object Name | Format-Table -AutoSize -Wrap
}
Safe 'Process list with owner' {
    Get-Process -IncludeUserName -ErrorAction Stop |
        Select-Object Id, ProcessName, UserName, Path, StartTime |
        Sort-Object ProcessName | Format-Table -AutoSize -Wrap
}
Safe 'Processes running from user-writable paths' {
    Get-CimInstance Win32_Process |
        Where-Object { $_.ExecutablePath -match '(?i)\\(AppData|Temp|ProgramData|Users\\Public|Downloads)\\' } |
        Select-Object ProcessId, Name, ExecutablePath, CommandLine | Format-List
}
Safe 'Top 10 by CPU' { Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, WorkingSet | Format-Table -AutoSize }
Safe 'Top 10 by memory' { Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name, Id, @{L='WS_MB';E={[math]::Round($_.WorkingSet/1MB,1)}} | Format-Table -AutoSize }
Safe 'Process instance counts' { Get-Process | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize }

Section 'PERSISTENCE'
Safe 'Startup commands' { Get-CimInstance Win32_StartupCommand | Format-Table Name, Command, User, Location -AutoSize -Wrap }
Safe 'Run key (HKLM)' { Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List }
Safe 'Run key (HKCU)' { Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List }
Safe 'RunOnce keys' {
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        if (Test-Path $k) { "[$k]"; Get-ItemProperty $k | Format-List }
    }
}
Safe 'Startup folders' {
    foreach ($p in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
                     "$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (Test-Path $p) { "[$p]"; Get-ChildItem $p -Force | Format-Table Name, Length, LastWriteTime -AutoSize }
    }
}
Safe 'Scheduled tasks (enabled)' {
    Get-ScheduledTask | Where-Object State -ne 'Disabled' |
        Select-Object TaskPath, TaskName, State,
            @{L='Action';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '}} |
        Sort-Object TaskPath | Format-Table -AutoSize -Wrap
}
Safe 'WMI event filters' { Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Format-Table Name, Query -AutoSize -Wrap }
Safe 'WMI event consumers' { Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Format-List Name, CommandLineTemplate, ScriptText }
Safe 'WMI filter-to-consumer bindings' { Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Format-Table Filter, Consumer -AutoSize -Wrap }

Section 'SERVICES'
Safe 'Services with binary path' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName |
        Sort-Object Name | Format-Table -AutoSize -Wrap
}
Safe 'Running services' { Get-Service | Where-Object Status -eq 'Running' | Format-Table Name, DisplayName, StartType -AutoSize }
Safe 'Services with unquoted paths containing spaces' {
    Get-CimInstance Win32_Service |
        Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s.+\\' } |
        Select-Object Name, PathName | Format-Table -AutoSize -Wrap
}

Section 'DRIVERS'
Safe 'Loaded drivers' { Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' | Select-Object Name, DisplayName, PathName, StartMode | Sort-Object Name | Format-Table -AutoSize -Wrap }

Section 'INSTALLED SOFTWARE'
# NOTE: the old version used Win32_Product, which triggers an MSI consistency
# check (and can silently reconfigure/repair packages) on every enumeration.
# Reading the uninstall keys is fast and side-effect free.
Safe 'Installed programs (uninstall registry keys)' {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty $paths -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName | Format-Table -AutoSize
}

Section 'SECURITY POSTURE'
Safe 'Defender status' { Get-MpComputerStatus | Format-List AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureVersion }
Safe 'Defender exclusions' { Get-MpPreference | Select-Object -ExpandProperty ExclusionPath }
Safe 'Defender exclusion registry' { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions' -Recurse -ErrorAction SilentlyContinue | Format-Table PSPath -AutoSize }
Safe 'Defender threat history' { Get-MpThreatDetection | Select-Object -First 30 InitialDetectionTime, ThreatID, ProcessName, Resources | Format-Table -AutoSize -Wrap }
Safe 'Audit policy' { auditpol /get /category:* }
Safe 'Shadow copies' { Get-CimInstance Win32_ShadowCopy | Format-Table ID, InstallDate, VolumeName -AutoSize }

Section 'SMB AND SHARES'
Safe 'SMB shares' { Get-SmbShare | Format-Table Name, Path, Description -AutoSize }
Safe 'SMB share permissions' { Get-SmbShareAccess -Name * -ErrorAction SilentlyContinue | Format-Table Name, AccountName, AccessRight, AccessControlType -AutoSize }
Safe 'SMB sessions' { Get-SmbSession | Format-Table ClientComputerName, ClientUserName, NumOpens -AutoSize }
Safe 'SMB open files' { Get-SmbOpenFile | Format-Table ClientComputerName, ClientUserName, Path -AutoSize -Wrap }
Safe 'SMB client connections' { Get-SmbConnection | Format-Table ServerName, ShareName, UserName, Dialect -AutoSize }

Section 'REMOTE ACCESS'
Safe 'RDP status' {
    $v = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
    if ($v -eq 0) { 'RDP is ENABLED' } else { 'RDP is disabled' }
}
Safe 'RDP sessions' { qwinsta }
Safe 'RDP connection history (per user)' {
    Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue |
        ForEach-Object { [PSCustomObject]@{ Server = $_.PSChildName
            UsernameHint = (Get-ItemProperty $_.PSPath).UsernameHint } } | Format-Table -AutoSize
}
Safe 'PowerShell session configurations' { Get-PSSessionConfiguration | Format-Table Name, PSVersion, Permission -AutoSize -Wrap }
Safe 'WinRM listeners' { winrm enumerate winrm/config/listener }

Section 'USER ACTIVITY'
Safe 'USB device history' {
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue |
        Select-Object FriendlyName, PSChildName | Format-Table -AutoSize
}
# NOTE: Get-History only returns the *current* session, so inside a script it
# is always empty. PSReadLine keeps the real on-disk history.
Safe 'PowerShell console history (PSReadLine, all users)' {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $h = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if (Test-Path $h) {
            ''
            "[$($_.Name)]"
            Get-Content $h -Tail 200 -ErrorAction SilentlyContinue
        }
    }
}
Safe 'Kerberos sessions' { klist sessions }
Safe 'Recently modified files in user profiles (top 50)' {
    Get-ChildItem 'C:\Users' -Recurse -File -Force -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, Length, LastWriteTime |
        Format-Table -AutoSize -Wrap
}
Safe 'Prefetch entries' {
    Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Format-Table Name, CreationTime, LastWriteTime -AutoSize
}

Section 'SUSPICIOUS FILE LOCATIONS'
# NOTE: the old version recursed all of C:\ for *.exe, which can run for
# hours. These are the directories that hold the overwhelming majority of
# real findings.
Safe 'Executables written in user-writable paths (last 14 days)' {
    $cut = (Get-Date).AddDays(-14)
    $paths = @("$env:TEMP", "$env:ProgramData", "$env:APPDATA", "$env:LOCALAPPDATA",
               'C:\Users\Public', "$env:SystemRoot\Temp")
    # NOT: foreach bir ifade degildir, dogrudan pipe edilemez.
    # Sonuclar once toplanir, sonra siralanir.
    $found = foreach ($p in $paths) {
        if (-not (Test-Path $p)) { continue }
        Get-ChildItem $p -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cut -and
                           $_.Extension -match '(?i)^\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$' } |
            Select-Object FullName, Length, LastWriteTime
    }
    $found | Sort-Object LastWriteTime -Descending | Format-Table -AutoSize -Wrap
}
Safe 'Named pipes' { Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Select-Object Name | Sort-Object Name | Format-Table -AutoSize }

Section 'EVENT LOGS'
Safe 'Available logs' { Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object RecordCount -gt 0 | Sort-Object RecordCount -Descending | Select-Object -First 25 LogName, RecordCount, IsEnabled, LogMode | Format-Table -AutoSize }
Safe 'Security log - last 40' { Get-WinEvent -LogName Security -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, @{L='Message';E={($_.Message -split "`n")[0]}} -AutoSize -Wrap }
Safe 'System log - last 40' { Get-WinEvent -LogName System -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, ProviderName, @{L='Message';E={($_.Message -split "`n")[0]}} -AutoSize -Wrap }
Safe 'Application log - last 40' { Get-WinEvent -LogName Application -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, ProviderName, @{L='Message';E={($_.Message -split "`n")[0]}} -AutoSize -Wrap }
Safe 'New service installs (System 7045)' { Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 40 -ErrorAction SilentlyContinue | Format-Table TimeCreated, @{L='Message';E={($_.Message -replace "`r?`n",' ')}} -AutoSize -Wrap }
Safe 'Event log cleared (System 104 / Security 1102)' {
    Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, @{L='Message';E={($_.Message -replace "`r?`n",' ')}} -AutoSize -Wrap
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 20 -ErrorAction SilentlyContinue |
        Format-Table TimeCreated, @{L='Message';E={($_.Message -replace "`r?`n",' ')}} -AutoSize -Wrap
}

Section 'END OF REPORT'
"Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"Host      : $hostName ($ipText)"
"Sections  : $script:sectionNo"

}

# ---------------------------------------------------------------------------
#  Write report
# ---------------------------------------------------------------------------

$sw = [Diagnostics.Stopwatch]::StartNew()
$header = @(
    ('=' * 100)
    "  DOUGLAS-LITE TRIAGE REPORT"
    "  Host      : $hostName ($ipText)"
    "  Collected : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') (local)"
    "  Operator  : $env:USERDOMAIN\$env:USERNAME"
    ('=' * 100)
)

try {
    $header  | Out-File -FilePath $report -Encoding UTF8
    & $data  | Out-File -FilePath $report -Encoding UTF8 -Append
    $sw.Stop()
    $sizeKB = [math]::Round((Get-Item $report).Length / 1KB, 1)
    Write-Host ''
    Write-Host "  Done in $([math]::Round($sw.Elapsed.TotalSeconds,1)) s  |  $sizeKB KB" -ForegroundColor Green
    Write-Host "  Report: $report" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  For detection rules, risk scoring and an HTML report, use Douglas-042.ps1' -ForegroundColor DarkGray
    Write-Host ''
} catch {
    Write-Host ''
    Write-Host "  [x] Could not write the report: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
