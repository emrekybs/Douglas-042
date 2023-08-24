param(
[Parameter(Mandatory=$False)]
[Switch]$a
)

$banner = @"

    ____                    __                 ____  __ __ ___ 
   / __ \____  __  ______ _/ /___ ______      / __ \/ // /|__ \
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ / / / // /___/ /
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /_/ /__  __/ __/ 
/_____/\____/\__,_/\__, /_/\__,_/____/      \____/  /_/ /____/ 
                  /____/                                       ⠀⠀⠀

          +----DEFENSE BY OFFENSE BLUE TEAM----+     
               
                      "ву ємяє кувѕ"
   
      +------𝐈𝐧𝐜𝐢𝐝𝐞𝐧𝐭 𝐑𝐞𝐬𝐩𝐨𝐧𝐬𝐞 & 𝐓𝐡𝐫𝐞𝐚𝐭 𝐇𝐮𝐧𝐭𝐢𝐧𝐠------+ 



"@

    Write-Host $banner -ForegroundColor Red
    $ErrorActionPreference= 'silentlycontinue'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host '𝘿𝙤𝙪𝙜𝙡𝙖𝙨-042 you must run it with Administrator privileges'
    Exit 1
}

$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$blue = (gi env:\Computername).Value
Write-Host "Collecting data for $blue ($ip) | $(Get-Date -Format dd/MM/yyyy-H:mm:ss)"

$data = {
"==== GENERAL INFORMATION ===="
#Get-ComputerInfo | Format-List -Property CsDNSHostName, CsDomain, OsName, OsVersion, OsBuildNumber, OsArchitecture, OsUptime, OsLocalDateTime, TimeZone, OsSerialNumber, OsMuiLanguages, OsHotFixes, WindowsRegisteredOrganization, WindowsRegisteredOwner, WindowsSystemRoot, OsPagingFiles, CsManufacturer, CsModel, CsName, CsProcessors, CsNetworkAdapters, BiosBIOSVersion, BiosSeralNumber, BiosFirmwareType, CsDomainRole, OsStatus, OsSuites, LogonServer, DeviceGuardSmartStatus, DeviceGuardRequiredSecurityProperties, DeviceGuardAvailableSecurityProperties, DeviceGuardSecurityServicesConfigured, DeviceGuardSecurityServicesRunning, DeviceGuardCodeIntegrityPolicyEnforcementStatus, DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus
systeminfo
"------------------------------------------------------------------------------------------------------------------------------------
"

"--- Group policy settings ---"
gpresult.exe -z
"----------------------------------------
"

"--- Encryption information ---"
manage-bde.exe -status
"----------------------------------------
"
"==== ACCOUNT AND GROUP INFORMATION ===="
"--- LOCAL USER ---"
Get-LocalUser
"----------------------------------------
"
"--- Enabled Local User ---"
Get-LocalUser | ? Enabled -eq "True"
"----------------------------------------
"
"--- Local Group ---"
Get-LocalGroup
"----------------------------------------
"
"--- Local Group Administrator ---"
Get-LocalGroup Administrators
"----------------------------------------
"
"--- Account Settings  ---"
net accounts
"----------------------------------------
"


"==== OS BUILD AND HOTFIXES ===="
"--- Hotfixes ---"
Get-HotFix
"----------------------------------------
"
"--- Operating System ---"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, Servicepackmajorversion, BuildNumber, CSName, LastBootUpTime
Get-ItemProperty "HKLM:\SOFTWARE\MICROSOFT\windows NT\CurrentVersion" | Select-Object ReleaseId
"----------------------------------------
"


"==== HARDWARE QUERIES ===="
"--- Bios Information ---"
gcim -ClassName Win32_BIOS | fl Manufacturer, Name, SerialNumber, Version;
"-----------------------------------------------------------------------------
"
"--- Processor Information ---"
gcim -ClassName Win32_Processor | fl caption, Name, SocketDesignation;
"-----------------------------------------------------------------------------
"
"--- Information Manufacturer, SystemFamily,Model,SystemType ---"
gcim -ClassName Win32_ComputerSystem | fl Manufacturer, Systemfamily, Model, SystemType
"----------------------------------------
"
"---Information About Logical Disk Drives---"
gcim  -ClassName Win32_LogicalDisk
gcim  -ClassName Win32_LogicalDisk |Select -Property DeviceID, DriveType, @{L='FreeSpaceGB';E={"{0:N2}" -f ($_.FreeSpace /1GB)}}, @{L="Capacity";E={"{0:N2}" -f ($_.Size/1GB)}} | fl
"----------------------------------------
"

"==== FIREWALL INFORMATION ===="
"--- Configuration of the Windows Firewall: ---"
netsh advfirewall show currentprofile
"----------------------------------------
"
"--- Firewall Profile ---"
Get-NetFirewallProfile
"----------------------------------------
"
"--- Firewall Settings ---"
Get-NetFirewallSetting
"----------------------------------------
"
"--- Inactive Firewall ---"
Get-NetFirewallRule | Where-Object { $_.Enabled -ne $true }
"----------------------------------------
"
"==== NETWORK INFORMATION ===="
"--- Active Network Interfaces ---"
Get-NetAdapter | ? status -eq "up" |  Get-NetIPAddress | Select IPAddress,InterfaceIndex, InterfaceAlias, AddressFamily,PrefixOrigin |Sort InterfaceAlias | Format-Table -Wrap
"----------------------------------------
"
"--- Active TCP connections Remote IP ---"
(Get-NetTCPConnection).remoteaddress | Sort-Object -Unique
"----------------------------------------
"
"--- List UDP endpoints ---"
Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize
"----------------------------------------
"
"--- Network Ipv6 addresses  ---"
Get-NetIPAddress -AddressFamily IPv6  | ft Interfacealias, IPv6Address
"----------------------------------------
"
"--- Shows TCP connections on the Internet ---"
Get-NetTCPConnection -AppliedSetting Internet | select-object -property remoteaddress, remoteport, creationtime | Sort-Object -Property creationtime | format-table -autosize
"----------------------------------------
"

"==== CHECK HOST FILE ===="
"--- DNS cache ---"
Get-DnsClientCache
"----------------------------------------
"
"----DNS cache Success----"
Get-DnsClientCache -Status 'Success' | Select Name, Data
"----------------------------------------
"


"--- Hosts File & Attributes ---"
gc "C:\Windows\System32\Drivers\etc\hosts"
gci "C:\Windows\System32\Drivers\etc\hosts" | fl *Time* 
"----------------------------------------
"

"====SHARED FOLDERS===="
net use
"----------------------------------------
"

"==== PROCESS INFORMATION ===="
"--- Process Connections ---"
$nets = netstat -bano|select-string 'TCP|UDP'; 
foreach ($n in $nets)    
{
$p = $n -replace ' +',' ';
$nar = $p.Split(' ');
$pname = $(Get-Process -id $nar[-1]).Path;
$n -replace "$($nar[-1])","$($ppath) $($pname)";
}
"----------------------------------------
"
"--- Running processes ---"
tasklist /v /fo table /fi "STATUS ne Unknown"
"----------------------------------------
"
"--- Process AppData ---"
get-process | ?{$_.Path -like '*appdata*'}
"----------------------------------------
"
"--- Process AppData Detailed ---"
get-process | select name, path, starttime, ID | ?{$_.Path -like '*appdata*'} | fl
"----------------------------------------
"
"--- Process List ---"
Get-Process -IncludeUserName | Format-Table -Property Name, Id, Path, UserName, Company, Handles, StartTime, HasExited -Wrap
"----------------------------------------
"
"--- Top 7 CPU Usage   ---"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 7 | Format-Table Name, CPU, WorkingSet -AutoSize
"----------------------------------------
"
"--- Top 7 MEMORY Usage   ---"
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 7 | Format-Table Name, WorkingSet -AutoSize
"----------------------------------------
"
"--- Process Commandline ---"
Get-WmiObject Win32_Process | Select-Object Name,  ProcessId, CommandLine | Sort Name | Format-Table -Wrap
"----------------------------------------
"


"==== PERSISTENCE ===="
"--- Commands on Startup ---"
Get-CimInstance -Class Win32_StartupCommand | Format-Table -Property Name, Command, User, Location -Wrap
"----------------------------------------
"
"--- Scheduled Tasks ---"
(Get-ScheduledTask).Where({$_.State -ne "Disabled"}) | Sort TaskPath | Format-Table -Wrap
"----------------------------------------
"
"--- Scheduled Tasks (WIFI) ---"
Get-ScheduledTask -Taskname "wifi*" | fl *
"----------------------------------------
"


"======== SERVICE QUERIES ======="
"--- Basic Services Information ---"
Get-Service | Select-Object Name, DisplayName, Status, StartType
"----------------------------------------
"
"--- Detailed Service Information ---"
Get-WmiObject win32_service | Select-Object Name, PathName, StartName, StartMode, State, ProcessId | Sort PathName| Format-Table -Wrap
#Get-CimInstance -Class Win32_Service -Filter "Caption LIKE '%'" | Select-Object Name, PathName, ProcessId, StartMode, State | Format-Table
"----------------------------------------
"
"--- Automatic Service Information ---"
Get-Service | Select-Object Name,DisplayName, Status,StartType | where StartType -eq "Automatic"
"----------------------------------------
"
"--- Running Service Information ---"
Get-Service | Select-Object Name,DisplayName, Status,StartType | where Status -eq "Running"
"----------------------------------------
"
"--- EventLog Service ---"
get-service -name "eventlog" | fl *
"----------------------------------------
"


"======== INSTLLATION Of SOFTWARE ======="
Get-CimInstance -ClassName win32_product | Select-Object Name,Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage |  Format-Table -Wrap
"----------------------------------------
"


"==== USER ACTIVITY ===="
"--- Recently used USB devices ---"
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Select FriendlyName
"----------------------------------------
"
"--- Recently modified files ---"
$RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File
$RecentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 50 FullName, LastWriteTime
"----------------------------------------
"

"--- PowerShell history ---"
Get-History
"----------------------------------------
"
"--- Kerberos sessions ---"
klist sessions
"----------------------------------------
"


"==== SMB QUERIES ===="
"--- Smb sessions ---"
Get-SmbSession
"----------------------------------------
"
"--- SMB share ---"
Get-SmbShare; Get-SmbShare | Select-Object Dialect, ServerName, ShareName | Sort-Object Dialect
"----------------------------------------
"
"--- SMB connection ---"
Get-SmbConnection
"----------------------------------------
"


"==== REMOTING QUERIES ===="
"--- RDP sessions ---"
qwinsta /counter
"----------------------------------------
"
"--- RDP status Enabled-Disabled ---"
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0){write-host "RDP Enabled" } else { echo "RDP Disabled" }
"----------------------------------------
"
"--- PowerShell sessions ---"
Get-PSSession
"----------------------------------------
"
"--- PowerShell sessions Configurations ---"
Get-PSSessionConfiguration | fl Name, PSVersion, Permission
"----------------------------------------
"


"==== REGISTRY ANALYSIS ===="
"--- List IWindows registry keys ---"
(Gci -Path Registry::).name
"----------------------------------------
"
"--- List HKCU registry keys ---"
Get-ChildItem -Path HKCU:\ | Select-Object -ExpandProperty Name
"----------------------------------------
"
"--- HKCU Properties of items in the Run registry key ---"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
"----------------------------------------
"
"--- HKLM Properties of items in the Run registry key ---"
Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\" | Get-ItemProperty


"==== LOG QUERIES ===="
"--- Event Log List ---"
Get-Eventlog -List 
"----------------------------------------
"
"--- Last 20 Application Log ---"
Get-Eventlog Application -Newest 20
"----------------------------------------
"
"--- Last 20 System Log ---"
Get-Eventlog system -Newest 20
"----------------------------------------
"
"--- Last 20 Security Log ---"
Get-Eventlog security -Newest 20
"----------------------------------------
"



if ($a -eq $true)
{
"==== ADVANCED INVESTIGATION ===="
"--- Total Process Instances ---"
Get-Process | Group-Object ProcessName | Select Count, Name | Sort Count -Descending
"----------------------------------------
"

"--- Prefetch files ---"
gci C:\Windows\Prefetch\ | Sort Name | Format-Table Name,CreationTime,LastWriteTime,LastAccessTime
"----------------------------------------
"

"--- DLL List ---"
gps | Format-List ProcessName, @{l="Modules";e={$_.Modules|Out-String}}
"----------------------------------------
"

"--- WMI ---"
Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription | FT Consumer,Filter,__SERVER -wrap
"----------------------------------------
"

"--- WMI Filters ---"
Get-WmiObject -Class __EventFilter -Namespace root\subscription | FT Name, Query, PSComputerName -wrap
"----------------------------------------
"

"--- WMI Consumers ---"
Get-WmiObject -Class __EventConsumer -Namespace root\subscription | FT Name,ScriptingEngine,ScriptText -wrap
"-------------------------------------------------------------------
"

"--- Windows Defender Exclusions ---"
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
"--------------------------------------------------------------------
"
"--- List of .exe Files Modified In The Last 3 Days ---"
$limit = (Get-Date).AddDays(-3); Get-ChildItem -Path C:\ -Recurse -Include *.exe | Where-Object { $_.LastWriteTime -ge $limit } | ForEach-Object { Write-Host "$($_.Extension) $($_.Name) $($_.LastWriteTime)" }
"--------------------------------------------------------------------
"


"--- Named Pipes List ---"
Get-ChildItem -Path '\\.\pipe\' |  Sort Length | Format-Table FullName, Length, IsReadOnly, Exists, CreationTime, LastAccessTime
"-------------------------------------------------------------------
"

}

}

& $data | Out-File -FilePath $pwd\REPORT_$blue.txt
Write-Host "Data saved in $pwd\REPORT_$blue.txt" -ForegroundColor Green