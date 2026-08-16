<#
.SYNOPSIS
    Douglas-042 v2 - Incident Response & Threat Hunting Collector

.DESCRIPTION
    Tek script, tek calistirma, otomatik toplama. Domain ortaminda
    Client / Member Server / Domain Controller uzerinde rol tespiti yapip
    ilgili modulleri calistirir.

    Cikti: klasor + artefakt basina CSV/JSON + FINDINGS.csv + REPORT.html

.PARAMETER Days
    Event log ve dosya sistemi icin geriye donuk gun sayisi. Varsayilan 14.

.PARAMETER OutputPath
    Cikti kok dizini. Varsayilan: script dizini altinda .\Output

.PARAMETER Quick
    Hizli triage modu. Faz 3 (dosya tarama/hash) atlanir. ~1-2 dakika.

.PARAMETER CollectRaw
    Ham adli artefakt kopyalama (MFT, registry hive, evtx, SRUM, Amcache).
    VSS snapshot uzerinden calisir. Birkac GB olabilir.

.PARAMETER NoResolve
    Reverse DNS ve dis ag sorgularini kapatir. (OPSEC / izole ortam)

.PARAMETER MaxEventsPerChannel
    Kanal basina maksimum event sayisi. Varsayilan 100000.

.PARAMETER IocFile
    Satir basina bir IOC iceren dosya (hash / IP / domain / dosya adi).
    Toplanan tum veriyle eslestirilir.

.EXAMPLE
    .\Douglas-042.ps1
    .\Douglas-042.ps1 -Days 30 -CollectRaw
    .\Douglas-042.ps1 -Quick

.NOTES
    Requires: Administrator.


#>

[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$Days = 14,

    [string]$OutputPath,

    [switch]$Quick,

    [switch]$CollectRaw,

    [switch]$NoResolve,

    [ValidateRange(1000, 2000000)]
    [int]$MaxEventsPerChannel = 100000,

    [string]$IocFile,

    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]$Credential,

    [ValidateRange(1, 100)]
    [int]$ThrottleLimit = 16,

    [switch]$ExportRuleCatalog,

    [string]$SigmaPath,

    # --- FAZ 3: HUNTING ---
    [string]$Baseline,

    [ValidateSet('LOLBin','Beacon','Persistence','CredentialAccess','DefenseEvasion','All')]
    [string[]]$Hunt,

    # --- FAZ 2: ARAYUZ ---
    [ValidateSet('Auto','TR','EN')]
    [string]$Language = 'EN',

    [switch]$NoMenu,

    [switch]$Help
)

# ============================================================================
#  FAZ 2: DIL ALTYAPISI + MENU
# ============================================================================

$Script:Lang = 'EN'

$Script:L = @{
    EN = @{
        'ui.phase'        = 'PHASE {0} - {1}'
        'ui.admin_req'    = 'Douglas-042 must be run with administrator rights.'
        'ui.admin_hint'   = 'Example: Start-Process powershell -Verb RunAs'
        'ui.ps_req'       = 'PowerShell 4.0+ required. Current: '
        'ui.ps4_fallback' = 'PowerShell 4.0 detected - fallback mode active.'
        'ui.collect_start'= 'Collection started: {0} ({1}) | Role: {2} | Operator: {3}'
        'ui.window'       = 'Window: last {0} days (>= {1} UTC)'
        'ui.output'       = 'Output: {0}'
        'ui.quick_mode'   = 'QUICK MODE - Phase 3 skipped'
        'ui.raw_mode'     = 'RAW COLLECTION active - may be several GB'
        'ui.done'         = 'COMPLETED'
        'ui.risk'         = 'RISK'
        'ui.report_at'    = 'Report'
        'menu.title'      = 'USAGE MENU'
        'menu.hint'       = 'Pass any parameter and this menu is skipped entirely.'
        'menu.modes'      = '-- COLLECTION MODES --'
        'menu.tools'      = '-- TOOLS --'
        'menu.1'          = '[1] Standard collection   Phase 0-3, last 14 days'
        'menu.1d'         = 'The right choice for most incidents. Process/net/services/tasks/autoruns + event logs + file scan.'
        'menu.2'          = '[2] Quick triage          Phase 3 skipped'
        'menu.2d'         = 'First response. No file scan or hashing; volatile data + event logs.'
        'menu.3'          = '[3] Wide scope + raw       30 days + VSS artifacts'
        'menu.3d'         = 'Deep dive. Copies MFT/hives/evtx/SRUM/Amcache.'
        'menu.4'          = '[4] Sigma-assisted        + external rule set'
        'menu.4d'         = 'Standard collection plus sigma-pack.json matching. Reported separately, excluded from risk score.'
        'menu.5'          = '[5] Remote sweep          WinRM fan-out'
        'menu.5d'         = 'Multi-host collection + stack counting + host risk ranking.'
        'menu.6'          = '[6] Advanced / custom     choose parameters individually'
        'menu.7'          = '[7] Usage guide           parameter reference and examples'
        'menu.8'          = '[8] Rule catalog          {0} triage rules, export to CSV'
        'menu.9'          = '[9] Update center        download Sigma / YARA / MITRE rules'
        'menu.9d'         = 'Fetches current rule sets from the internet. Not needed offline.'
        'menu.0'          = '[0] Exit'
        'menu.ask'        = '  Choice: '
        'menu.bad'        = '  Invalid choice.'
        'menu.equiv'      = '  Equivalent command:'
        'menu.confirm'    = '  Start? [Y/n]: '
        'menu.cancel'     = '  Cancelled.'
        'menu.warnraw'    = '  WARNING: Raw artifact collection uses several GB and may take 15-40 minutes.'
        'menu.asksigma'   = '  Sigma rule set [blank = .\sigma-pack.json]: '
        'menu.asktargets' = '  Targets (comma separated) or @file.txt: '
        'menu.askdays'    = '  Lookback days [1-365, default 14]: '
        'menu.askout'     = '  Output directory [blank = .\Output]: '
        'menu.askquick'   = '  Quick mode (skip Phase 3)? [y/N]: '
        'menu.askraw'     = '  Collect raw forensic artifacts? [y/N]: '
        'menu.asknores'   = '  Disable reverse DNS (OPSEC)? [y/N]: '
        'menu.askcred'    = '  Use alternate credentials? [y/N]: '
        'menu.nofile'     = '  File not found: {0}'
        'menu.notargets'  = '  No targets entered.'
        'menu.anykey'     = '  Press ENTER to continue...'
        'menu.exported'   = '  Catalog written: {0}'
        'lang.timeout'    = '  No response - {0} selected.'
        'rep.subtitle'    = 'Incident Response & Threat Hunting'
        'rep.title'       = 'Collection Report'
        'rep.risk'        = 'Risk Level'
        'rep.score'       = 'score'
        'rep.threshold'   = 'threshold'
        'rep.all'         = 'ALL'
        'rep.correlation' = 'Attack Entities (Correlation)'
        'rep.corr_note'   = 'Findings originating from the same file, IP or hash are grouped into one entity. An entity sharing many findings represents different stages of a single attack chain.'
        'rep.findings'    = 'Findings'
        'rep.uniq_raw'    = '{0} unique / {1} raw evidence - full list in FINDINGS.csv'
        'rep.timeline'    = 'Timeline'
        'rep.tl_note'     = 'Hourly event density. Tall bars mark the activity window; attacker activity usually clusters into a narrow range.'
        'rep.attack'      = 'ATT&CK Coverage'
        'rep.artifacts'   = 'Artifacts'
        'rep.modperf'     = 'Module Performance'
        'rep.errors'      = 'Errors & Skipped Modules'
        'rep.err_note'    = '"No data" and "module did not run" are different. This table shows which data could not be collected.'
        'rep.scope'       = 'Out of Scope'
        'rep.col_sev'     = 'Severity'; 'rep.col_rule' = 'Rule'; 'rep.col_title' = 'Title'
        'rep.col_ev'      = 'Evidence'; 'rep.col_mitre' = 'ATT&CK'; 'rep.col_time' = 'Time (UTC)'
        'rep.col_art'     = 'Artifact'; 'rep.col_source' = 'Source'; 'rep.col_desc' = 'Description'
        'rep.search_ph'   = 'Search findings (path, user, IP, MITRE ID...)'
        'rep.no_finding'  = 'No findings.'
        'rep.nfindings'   = '{0} findings ? {1} techniques'
    }
}

function T {
    param([Parameter(Mandatory)][string]$Key, [object[]]$Args)
    $s = $Script:L[$Script:Lang][$Key]
    if (-not $s) { $s = $Script:L['EN'][$Key] }
    if (-not $s) { return "[$Key]" }
    if ($Args -and $Args.Count -gt 0) { return ($s -f $Args) }
    return $s
}

function Test-DInteractive {
    if ($ComputerName -and $ComputerName.Count -gt 0) { return $false }
    if (-not [Environment]::UserInteractive)          { return $false }
    if ($Host.Name -eq 'ServerRemoteHost')            { return $false }
    if ($env:DOUGLAS_NONINTERACTIVE)                  { return $false }
    try { if ([Console]::IsInputRedirected)           { return $false } } catch { }
    return $true
}

function Read-DHostTimeout {
    param([int]$Seconds = 15, [string]$Default = '')
    try { $null = [Console]::KeyAvailable } catch {
        $r = Read-Host
        if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
        return $r.Trim()
    }
    $sb = New-Object System.Text.StringBuilder
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Enter') { Write-Host ''; break }
            if ($k.Key -eq 'Backspace') {
                if ($sb.Length -gt 0) { $null = $sb.Remove($sb.Length - 1, 1); Write-Host "`b `b" -NoNewline }
                continue
            }
            if ($k.KeyChar) { $null = $sb.Append($k.KeyChar); Write-Host $k.KeyChar -NoNewline }
        }
        Start-Sleep -Milliseconds 60
    }
    $v = $sb.ToString().Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v
}

function Select-DLanguage {
    <# Cikti dili tek: Ingilizce. Parametre geriye uyum icin korunuyor. #>
    param([string]$Requested = 'EN', [int]$TimeoutSec = 0)
    $Script:Lang = 'EN'
}
function Read-DYesNo {
    param([string]$Prompt, [bool]$Default = $false)
    Write-Host $Prompt -ForegroundColor White -NoNewline
    $a = Read-Host
    if ([string]::IsNullOrWhiteSpace($a)) { return $Default }
    return ($a.Trim().ToLowerInvariant() -in @('e', 'y', 'evet', 'yes'))
}

function Show-DUsage {
    $tr = $false
    Write-Host ''
    Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
    Write-Host $(if ($tr) { '  DOUGLAS-042 KULLANIM KILAVUZU' } else { '  DOUGLAS-042 USAGE GUIDE' }) -ForegroundColor Cyan
    Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
    $rows = if ($tr) {
        @(
            @('CALISMA MODLARI','',''),
            @('-Quick','switch','Faz 3 atlanir (dosya/hash/webshell). ~1-2 dk.'),
            @('-CollectRaw','switch','VSS uzerinden ham artefakt (MFT/hive/evtx). GB.'),
            @('-IocFile <yol>','dosya','Satir basina bir IOC. Tum veriyle eslenir.'),
            @('-SigmaPath <yol>','dosya','Derlenmis Sigma kural seti (JSON). Ayri raporlanir.'),
            @('-ComputerName <liste>','string[]','Uzaktan toplu tarama. Lokal toplama yapilmaz.'),
            @('','',''),
            @('AYARLAR','',''),
            @('-Days <1-365>','int (14)','Event log ve dosya taramasi geriye donuk gun.'),
            @('-OutputPath <yol>','string','Cikti kok dizini. Varsayilan .\Output'),
            @('-NoResolve','switch','Reverse DNS kapali (OPSEC).'),
            @('-MaxEventsPerChannel','int','Kanal basina event limiti (100000).'),
            @('-ThrottleLimit <1-100>','int (16)','Es zamanli hedef sayisi.'),
            @('','',''),
            @('ARAYUZ','',''),
            @('-Language TR|EN|Auto','string','Cikti dili. Auto: interaktifse sorar.'),
            @('-NoMenu','switch','Parametresiz calistirmada menuyu acma.'),
            @('-ExportRuleCatalog','switch','Kural katalogunu CSV''ye yaz ve cik.'),
            @('-Help','switch','Bu kilavuzu goster ve cik.')
        )
    } else {
        @(
            @('COLLECTION MODES','',''),
            @('-Quick','switch','Skips Phase 3 (file/hash/webshell). ~1-2 min.'),
            @('-CollectRaw','switch','Raw artifacts via VSS (MFT/hives/evtx). GB.'),
            @('-IocFile <path>','file','One IOC per line. Matched against all data.'),
            @('-SigmaPath <path>','file','Compiled Sigma rule set (JSON). Reported separately.'),
            @('-ComputerName <list>','string[]','Remote sweep. No local collection.'),
            @('','',''),
            @('SETTINGS','',''),
            @('-Days <1-365>','int (14)','Lookback days for event logs and file scan.'),
            @('-OutputPath <path>','string','Output root. Defaults to .\Output'),
            @('-NoResolve','switch','Disables reverse DNS (OPSEC).'),
            @('-MaxEventsPerChannel','int','Max events per channel (100000).'),
            @('-ThrottleLimit <1-100>','int (16)','Concurrent target count.'),
            @('','',''),
            @('INTERFACE','',''),
            @('-Language TR|EN|Auto','string','Output language. Auto: prompts if interactive.'),
            @('-NoMenu','switch','Never show the menu with no parameters.'),
            @('-ExportRuleCatalog','switch','Write rule catalog to CSV and exit.'),
            @('-Help','switch','Show this guide and exit.')
        )
    }
    foreach ($r in $rows) {
        if (-not $r[0]) { Write-Host ''; continue }
        if (-not $r[1]) { Write-Host ("  {0}" -f $r[0]) -ForegroundColor Yellow; continue }
        Write-Host ("   {0,-24}" -f $r[0]) -ForegroundColor White -NoNewline
        Write-Host ("{0,-11}" -f $r[1]) -ForegroundColor DarkGray -NoNewline
        Write-Host $r[2] -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host $(if ($tr) { '  ORNEKLER' } else { '  EXAMPLES' }) -ForegroundColor Yellow
    foreach ($e in @(
        '.\Douglas-042.ps1',
        '.\Douglas-042.ps1 -Quick -Language EN',
        '.\Douglas-042.ps1 -Days 30 -CollectRaw',
        '$t=(Get-ADComputer -Filter *).Name; .\Douglas-042.ps1 -ComputerName $t'
    )) { Write-Host "   $e" -ForegroundColor Cyan }
    Write-Host ''
}

function Show-DEquivalent {
    param([hashtable]$Sel)
    $p = @()
    if ($Sel.Days -and $Sel.Days -ne 14) { $p += "-Days $($Sel.Days)" }
    if ($Sel.Quick)         { $p += '-Quick' }
    if ($Sel.CollectRaw)    { $p += '-CollectRaw' }
    if ($Sel.NoResolve)     { $p += '-NoResolve' }
    if ($Sel.SigmaPath)     { $p += "-SigmaPath '$($Sel.SigmaPath)'" }
    if ($Sel.OutputPath)    { $p += "-OutputPath '$($Sel.OutputPath)'" }
    if ($Sel.ComputerName)  { $p += "-ComputerName $(($Sel.ComputerName|Select -First 3) -join ',')" }
    if ($Sel.Credential)    { $p += '-Credential $cred' }
    if ($Sel.Baseline)      { $p += "-Baseline '$($Sel.Baseline)'" }
    if ($Sel.Hunt)          { $p += "-Hunt $($Sel.Hunt -join ',')" }
    Write-Host ''
    Write-Host (T 'menu.equiv') -ForegroundColor DarkGray
    Write-Host ("    .\Douglas-042.ps1 " + ($p -join ' ')) -ForegroundColor Cyan
    Write-Host ''
}

function Show-DMenu {
    while ($true) {
        $sel = @{ Days = 14; ThrottleLimit = 16 }
        # data klasorundeki hazir varliklari otomatik bul (kullanici yol yazmasin)
        $dd = Get-DDataDir
        $autoSigma = Get-DAssetPath 'sigma-pack.json'
        $hasSigma  = [bool]$autoSigma
        $hasYara   = [bool](Get-DAssetPath 'yara64.exe') -and [bool](Get-DAssetPath 'yara-rules.yar')
        $hasMitre  = [bool](Get-DAssetPath 'mitre-v19.json')

        Clear-Host
        Show-Banner          # Clear-Host banner'i siliyordu; her cizimde geri koy
        Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
        Write-Host ('  ' + (T 'menu.title')) -ForegroundColor Cyan
        Write-Host ('  ' + (T 'menu.hint')) -ForegroundColor DarkGray
        Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
        # kural seti durumu - kullanici neyin hazir oldugunu bir bakista gorsun
        $sigTxt = if ($hasSigma) { 'Sigma: ready' } else { 'Sigma: none' }
        $yarTxt = if ($hasYara)  { 'YARA: ready' }  else { 'YARA: none' }
        $mitTxt = if ($hasMitre) { 'MITRE: ready' } else { 'MITRE: none' }
        Write-Host ('   ' + $sigTxt) -ForegroundColor $(if ($hasSigma) { 'Green' } else { 'DarkGray' }) -NoNewline
        Write-Host ('   ' + $yarTxt) -ForegroundColor $(if ($hasYara) { 'Green' } else { 'DarkGray' }) -NoNewline
        Write-Host ('   ' + $mitTxt) -ForegroundColor $(if ($hasMitre) { 'Green' } else { 'DarkGray' })
        Write-Host ''
        Write-Host ('  ' + (T 'menu.modes')) -ForegroundColor Yellow
        foreach ($i in 1..5) {
            Write-Host ('   ' + (T "menu.$i")) -ForegroundColor White
            Write-Host ('       ' + (T "menu.${i}d")) -ForegroundColor DarkGray
        }
        Write-Host ''
        Write-Host ('  ' + (T 'menu.tools')) -ForegroundColor Yellow
        Write-Host ('   ' + (T 'menu.6')) -ForegroundColor White
        Write-Host ('   ' + (T 'menu.7')) -ForegroundColor White
        Write-Host ('   ' + (T 'menu.8' @([string]$Script:RuleCatalog.Count))) -ForegroundColor White
        Write-Host ('   ' + (T 'menu.9')) -ForegroundColor Cyan
        Write-Host ('       ' + (T 'menu.9d')) -ForegroundColor DarkGray
        Write-Host ''
        Write-Host ('   ' + (T 'menu.0')) -ForegroundColor DarkGray
        Write-Host ''
        Write-Host (T 'menu.ask') -ForegroundColor White -NoNewline
        $c = (Read-Host).Trim()

        # Sigma paketi hazirsa TUM toplama modlarinda otomatik kullanilir;
        # kullanicinin yol yazmasina gerek yok.
        if ($c -in '1','2','3','5','6' -and $hasSigma) { $sel.SigmaPath = $autoSigma }

        switch ($c) {
            '1' { }
            '2' { $sel.Quick = $true }
            '3' { $sel.Days = 30; $sel.CollectRaw = $true; Write-Host (T 'menu.warnraw') -ForegroundColor Yellow }
            '4' {
                # Sigma odakli mod: paket yoksa dogrudan guncelleme merkezine yonlendir
                if (-not $hasSigma) {
                    Write-Host ''
                    Write-Host '  Sigma pack not found.' -ForegroundColor Yellow
                    Write-Host '  Open the Update Center? [Y/n]: ' -ForegroundColor White -NoNewline
                    $a = (Read-Host).Trim().ToLowerInvariant()
                    if ($a -eq '' -or $a -in 'e','y','evet','yes') { Show-DUpdateMenu }
                    continue
                }
                $sel.SigmaPath = $autoSigma
            }
            '5' {
                Write-Host (T 'menu.asktargets') -ForegroundColor White -NoNewline
                $t = (Read-Host).Trim(); $targets = @()
                if ($t.StartsWith('@')) {
                    $tf = $t.Substring(1).Trim('"',' ',"'")
                    if (-not (Test-Path -LiteralPath $tf)) { Write-Host (T 'menu.nofile' @($tf)) -ForegroundColor Red; Start-Sleep 2; continue }
                    $targets = @(Get-Content -LiteralPath $tf | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
                } else {
                    $targets = @($t -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
                if ($targets.Count -eq 0) { Write-Host (T 'menu.notargets') -ForegroundColor Red; Start-Sleep 2; continue }
                $sel.ComputerName = $targets
                Write-Host (T 'menu.askout') -ForegroundColor White -NoNewline
                $o = (Read-Host).Trim('"',' ',"'"); if ($o) { $sel.OutputPath = $o }
                if (Read-DYesNo (T 'menu.askcred')) { $sel.Credential = Get-Credential }
            }
            '6' {
                Write-Host (T 'menu.askdays') -ForegroundColor White -NoNewline
                $dv = (Read-Host).Trim(); if ($dv -match '^\d+$' -and [int]$dv -ge 1 -and [int]$dv -le 365) { $sel.Days = [int]$dv }
                Write-Host (T 'menu.askout') -ForegroundColor White -NoNewline
                $o = (Read-Host).Trim('"',' ',"'"); if ($o) { $sel.OutputPath = $o }
                $sel.Quick = Read-DYesNo (T 'menu.askquick')
                if (-not $sel.Quick) { $sel.CollectRaw = Read-DYesNo (T 'menu.askraw') }
                $sel.NoResolve = Read-DYesNo (T 'menu.asknores')
                $bl = '  Baseline dir/zip (blank = none): '
                Write-Host $bl -ForegroundColor White -NoNewline
                $b = (Read-Host).Trim('"',' ',"'")
                if ($b -and (Test-Path -LiteralPath $b)) { $sel.Baseline = (Resolve-Path -LiteralPath $b).Path }
            }
            '7' { Show-DUsage; Write-Host (T 'menu.anykey') -NoNewline; $null = Read-Host; continue }
            '8' {
                $p = Join-Path (Get-Location).Path 'DGL-rule-catalog.csv'
                [void](Export-DRuleCatalog -Path $p)
                Write-Host (T 'menu.exported' @($p)) -ForegroundColor Green
                Write-Host (T 'menu.anykey') -NoNewline; $null = Read-Host; continue
            }
            '9' { Show-DUpdateMenu; continue }
            '0' { return $null }
            default { Write-Host (T 'menu.bad') -ForegroundColor Red; Start-Sleep 1; continue }
        }
        Show-DEquivalent -Sel $sel
        if (Read-DYesNo (T 'menu.confirm') -Default $true) { return $sel }
        Write-Host (T 'menu.cancel') -ForegroundColor DarkGray
    }
}


# ============================================================================
#  GLOBAL DURUM
# ============================================================================

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'   # Write-Progress cok yavaslatiyor
$WarningPreference     = 'SilentlyContinue'

# --- KULTUR SABITLEME ---
# TR locale'de ondalik ayraci virguldur: 12.5 -> "12,5". Export-Csv degerleri
# gecerli kulturle string'e cevirir, bu da virgul-ayracli CSV'yi ve sayisal
# analizi bozar. Ayrica tarih formati da degisir. Invariant'a sabitliyoruz.
$Script:OriginalCulture = [Threading.Thread]::CurrentThread.CurrentCulture
try {
    [Threading.Thread]::CurrentThread.CurrentCulture   = [Globalization.CultureInfo]::InvariantCulture
    [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::InvariantCulture
} catch { }

$Script:Version   = '2.1.0'
$Script:StartTime = Get-Date
$Script:Ctx       = @{}            # host / calisma baglami
$Script:Caps      = @{}            # yetenek matrisi
$Script:Findings  = New-Object System.Collections.ArrayList
$Script:Errors    = New-Object System.Collections.ArrayList
$Script:Manifest  = New-Object System.Collections.ArrayList
$Script:Timeline  = New-Object System.Collections.ArrayList
$Script:HashCache = @{}
$Script:SigCache  = @{}
$Script:Iocs      = @{}
$Script:SelfPids  = @{}            # F1.5-1: kendi process agacimiz (self-detection)
$Script:SelfExcluded = 0
$Script:IocExact  = @{}
$Script:IocSuffix = New-Object System.Collections.ArrayList
$Script:IocSub    = New-Object System.Collections.ArrayList

# ----------------------------------------------------------------------------
#  ATT&CK SURUM NORMALIZASYONU
#  v19 (28 Nisan 2026) Defense Evasion tactic'ini ikiye bolup T1562 agacini
#  yeniden yapilandirdi. Kural govdelerindeki teknik ID'leri tek tek degistirmek
#  yerine burada merkezi olarak esliyoruz: gelecek surumde sadece bu tablo
#  guncellenir.
#
#  Kaynak: MITRE "Defense Evasion split" crosswalk (JSON/CSV), 2026-04-28
# ----------------------------------------------------------------------------
$Script:MitreVersion = 'v19'

$Script:MitreRemap = @{
    # T1562, T1562.001 ve T1562.006 tek bir yeni teknige birlestirildi
    'T1562'     = 'T1685'        # Impair Defenses      -> Disable or Modify Tools
    'T1562.001' = 'T1685'        # Disable/Modify Tools -> Disable or Modify Tools
    'T1562.006' = 'T1685'        # Indicator Blocking   -> Disable or Modify Tools
    # Firewall kapatma yeni parent'a tasindi; Windows'a ozgu alt teknik T1686.003
    'T1562.004' = 'T1686.003'    # Disable/Modify System Firewall: Windows Host Firewall
}

# Crosswalk'ta yeni ID'si teyit edilmemis, v19'da revoke edilmis teknikler.
# Bunlar rapora "dogrulanmasi gerekiyor" olarak isaretlenir - sessizce yanlis
# ID basmaktansa gorunur birakiyoruz.
$Script:MitrePending = @('T1562.002', 'T1562.003', 'T1562.007', 'T1562.008',
                         'T1562.009', 'T1562.010', 'T1562.011')

$Script:MitreSeen = @{}

# FAZ 2: teknik detaylari (ad/taktik/aciklama) - script yanindaki opsiyonel dosya.
# Yoksa ATT&CK izgarasi sadece ID gosterir; varsa hover'da ad+taktik cikar.
$Script:MitreDetails = @{}
try {
    # NOT: bu blok script'in BASINDA calisir; Get-DAssetPath henuz TANIMLI DEGIL.
    # Bu yuzden arama burada elle yapilir (onceki surumde fonksiyona bagliydi ve
    # sessizce basarisiz oluyordu - teknik adlari hic yuklenmiyordu).
    $mdBase = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    foreach ($cand in @(
        (Join-Path (Join-Path $mdBase 'data') 'mitre-v19.json'),
        (Join-Path $mdBase 'mitre-v19.json'),
        (Join-Path (Get-Location).Path 'data\mitre-v19.json'),
        (Join-Path (Get-Location).Path 'mitre-v19.json'))) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) {
            $arr = Get-Content -LiteralPath $cand -Raw | ConvertFrom-Json
            foreach ($t in $arr) { $Script:MitreDetails[$t.id] = $t }
            break
        }
    }
} catch { }

function ConvertTo-DMitreV19 {
    <# Virgulle ayrilmis teknik listesini v19'a normalize eder. #>
    param([string]$Mitre)
    if ([string]::IsNullOrWhiteSpace($Mitre)) { return $Mitre }

    $out = New-Object System.Collections.ArrayList
    foreach ($raw in ($Mitre -split ',')) {
        $t = $raw.Trim()
        if (-not $t) { continue }
        if ($Script:MitreRemap.ContainsKey($t)) {
            $Script:MitreSeen[$t] = 'REMAPPED'
            $t = $Script:MitreRemap[$t]
        } elseif ($Script:MitrePending -contains $t) {
            $Script:MitreSeen[$t] = 'PENDING'
        }
        if ($out -notcontains $t) { $null = $out.Add($t) }
    }
    return ($out -join ', ')
}


# Suspicious path regex - malware'in %95'i bu dizinlerden calisir
$Script:SuspiciousPathRegex = '(?i)\\(Temp|Tmp|AppData|ProgramData|Users\\Public|' +
                              'Public|PerfLogs|\$Recycle\.Bin|Windows\\Tasks|' +
                              'Windows\\Debug|Windows\\Fonts|Windows\\addins|' +
                              'Windows\\Media|Recycler|Intel|AMD|Downloads)\\'

# Hedefli dosya tarama dizinleri - C:\ recurse ASLA
$Script:ScanPaths = @(
    "$env:SystemRoot\Temp"
    "$env:SystemRoot\Tasks"
    "$env:SystemRoot\Debug"
    "$env:SystemRoot\System32\Tasks"
    "$env:ProgramData"
    'C:\Users'
    'C:\PerfLogs'
    'C:\inetpub'
    'C:\Temp'
    'C:\Tmp'
)

$Script:InterestingExt = @('.exe', '.dll', '.ps1', '.psm1', '.bat', '.cmd',
                           '.vbs', '.js', '.jse', '.vbe', '.wsf', '.hta',
                           '.scr', '.jar', '.aspx', '.ashx', '.asmx', '.php',
                           '.jsp', '.sys', '.msi', '.lnk',
                           # F1.5-10: staged payload'lar masum uzantilara saklanir
                           '.dat', '.tmp', '.log', '.txt', '.bin', '.cfg', '.dll1',
                           '.gif', '.jpg', '.png', '.tmp1', '.old', '.bak')

# F1.5-10: bu uzantilar normalde zararsizdir; sadece supheli dizinde veya
# icerik imzasi eslesirse bulgu uretilir (yoksa her .txt gurultu olur).
$Script:LowTrustExt = @('.dat', '.tmp', '.log', '.txt', '.bin', '.cfg',
                        '.gif', '.jpg', '.png', '.old', '.bak')

# F1.5-10: dropped payload icerik imzalari (dosya ilk 4KB'inda aranir)
$Script:PayloadContentSig = @(
    @{ P = '(?i)(sekurlsa|logonpasswords|mimikatz|Invoke-Mimikatz)'; N = 'mimikatz output';        S = 'CRITICAL'; M = 'T1003.001' }
    @{ P = '(?is)Authentication Id\s*:.*?NTLM\s*:';                  N = 'credential dump format';  S = 'HIGH';     M = 'T1003' }
    @{ P = '(?i)(STAGE2|stage2_config|c2\s*=|beacon|implant)';        N = 'staged C2 config';         S = 'HIGH';     M = 'T1105' }
    @{ P = '(?i)BEGIN (RSA |OPENSSH )?PRIVATE KEY';                    N = 'private key';             S = 'HIGH';     M = 'T1552.004' }
    @{ P = '(?i)(TVqQAAMAAAAEAAAA|TVpQAAIAAAAEAA)';                    N = 'base64-embedded PE (MZ)';    S = 'CRITICAL'; M = 'T1027' }
)

# ============================================================================
#  BANNER
# ============================================================================

function Show-Banner {
    $art = @'
    ____                    __                 ____  __ __ ___
   / __ \____  __  ______ _/ /___ ______      / __ \/ // /|__ \
  / / / / __ \/ / / / __ `/ / __ `/ ___/_____/ / / / // /___/ /
 / /_/ / /_/ / /_/ / /_/ / / /_/ (__  )_____/ /_/ /__  __/ __/
/_____/\____/\__,_/\__, /_/\__,_/____/      \____/  /_/ /____/
                  /____/
'@
    Write-Host ''
    Write-Host $art -ForegroundColor Cyan
    Write-Host '        PowerShell Incident Response & Threat Hunting' -ForegroundColor White
    Write-Host ('        Live-system triage  |  {0} detections  |  single file, offline' -f `
                $Script:RuleCatalog.Count) -ForegroundColor DarkGray
    Write-Host ''
}

function Write-DLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'CRIT', 'STEP', 'DEBUG')]
        [string]$Level = 'INFO',
        [switch]$NoConsole
    )

    $ts  = (Get-Date).ToString('HH:mm:ss')
    $utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    if (-not $NoConsole) {
        $color = switch ($Level) {
            'OK'    { 'Green' }
            'WARN'  { 'Yellow' }
            'ERROR' { 'Red' }
            'CRIT'  { 'Magenta' }
            'STEP'  { 'Cyan' }
            'DEBUG' { 'DarkGray' }
            default { 'Gray' }
        }
        $tag = switch ($Level) {
            'OK'    { '[+]' }
            'WARN'  { '[!]' }
            'ERROR' { '[x]' }
            'CRIT'  { '[!!]' }
            'STEP'  { '[>]' }
            'DEBUG' { '[.]' }
            default { '[*]' }
        }
        Write-Host ("{0} {1} {2}" -f $ts, $tag, $Message) -ForegroundColor $color
    }

    if ($Script:Ctx.LogFile) {
        try {
            "$utc [$Level] $Message" |
                Out-File -FilePath $Script:Ctx.LogFile -Append -Encoding UTF8
        } catch { }
    }
}


function Test-DInstallWindow {
    <# F1.5-2: verilen zaman taze-kurulum penceresinde mi? Bu pencerede olusan
       "yeni X" bulgulari INFO'ya dusurulur. #>
    param($Timestamp)
    if (-not $Script:Ctx.IsFreshInstall -or -not $Script:Ctx.InstallWindowEndUtc) { return $false }
    if (-not $Timestamp) { return $false }
    try {
        $t = if ($Timestamp -is [DateTime]) { $Timestamp.ToUniversalTime() }
             else { ([DateTime]$Timestamp).ToUniversalTime() }
        return ($t -le $Script:Ctx.InstallWindowEndUtc)
    } catch { return $false }
}

function Get-DEffectiveSeverity {
    <# F1.5-2: kurulum penceresindeki "yeni nesne" bulgularini INFO'ya cek.
       Sadece zamana bagli 'yenilik' kurallari icin kullanilir, icerik-imzali
       (webshell, mimikatz, base64) kurallar icin DEGIL. #>
    param([string]$Severity, $Timestamp, [switch]$TimeBased)
    if ($TimeBased -and (Test-DInstallWindow -Timestamp $Timestamp)) { return 'INFO' }
    return $Severity
}

# ============================================================================
#  ONKOSUL KONTROLLERI
# ============================================================================

function Test-DAdmin {
    try {
        $id        = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($id)
        # SID tabanli kontrol - locale bagimsiz (TR Windows'ta "Yoneticiler")
        $adminSid  = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')

        $isAdmin  = $principal.IsInRole($adminSid)
        $isSystem = ($id.User.Value -eq 'S-1-5-18')

        return [PSCustomObject]@{
            IsAdmin   = ($isAdmin -or $isSystem)
            IsSystem  = $isSystem
            User      = $id.Name
            UserSid   = $id.User.Value
        }
    } catch {
        return [PSCustomObject]@{
            IsAdmin = $false; IsSystem = $false; User = 'UNKNOWN'; UserSid = $null
        }
    }
}

function Get-DCapabilities {
    <#
        Yetenek matrisi. Moduller "if (Get-Command X)" serpistirmek yerine
        buna bakar. 2012 R2 / PS4 fallback kararlari burada verilir.
    #>
    $c = @{}

    $c.PSVersion      = $PSVersionTable.PSVersion
    $c.PSMajor        = $PSVersionTable.PSVersion.Major
    $c.IsPS5Plus      = ($PSVersionTable.PSVersion.Major -ge 5)
    $c.IsPS7Plus      = ($PSVersionTable.PSVersion.Major -ge 7)
    $c.IsCoreEdition  = ($PSVersionTable.PSEdition -eq 'Core')

    # Cmdlet varligi
    $cmds = @{
        LocalAccounts  = 'Get-LocalUser'
        ScheduledTasks = 'Get-ScheduledTask'
        Defender       = 'Get-MpComputerStatus'
        NetTCP         = 'Get-NetTCPConnection'
        NetAdapter     = 'Get-NetAdapter'
        SmbShare       = 'Get-SmbShare'
        Firewall       = 'Get-NetFirewallProfile'
        DnsCache       = 'Get-DnsClientCache'
        Cim            = 'Get-CimInstance'
        Wmi            = 'Get-WmiObject'
        WinEvent       = 'Get-WinEvent'
        BitsTransfer   = 'Get-BitsTransfer'
        FileHash       = 'Get-FileHash'
        ADModule       = 'Get-ADDomain'
        AppxPackage    = 'Get-AppxPackage'
    }
    foreach ($k in $cmds.Keys) {
        $c[$k] = [bool](Get-Command $cmds[$k] -ErrorAction SilentlyContinue)
    }

    # Paralel isleme yetenegi
    $c.ParallelForEach = $c.IsPS7Plus
    $c.Runspaces       = $true   # PS3+ her yerde var

    return $c
}

function Get-DHostContext {
    param([object]$AdminInfo)

    $ctx = @{}

    $ctx.ComputerName = $env:COMPUTERNAME
    $ctx.UserDomain   = $env:USERDOMAIN
    $ctx.Operator     = $AdminInfo.User
    $ctx.OperatorSid  = $AdminInfo.UserSid
    $ctx.RunAsSystem  = $AdminInfo.IsSystem

    # --- Bilgisayar sistemi / rol ---
    $cs = $null
    try {
        if ($Script:Caps.Cim) { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
        else                  { $cs = Get-WmiObject  Win32_ComputerSystem -ErrorAction Stop }
    } catch { }

    $roleId = if ($cs) { [int]$cs.DomainRole } else { -1 }

    # FALLBACK: Win32_ComputerSystem alinamazsa rol tespiti tamamen coker ve
    # Scope'lu moduller sessizce atlanir. OS ProductType'a duselim.
    #   ProductType 1 = Workstation, 2 = Domain Controller, 3 = Server
    $ctx.RoleSource = 'Win32_ComputerSystem.DomainRole'
    if ($roleId -lt 0) {
        $ctx.RoleSource = 'Win32_OperatingSystem.ProductType (fallback)'
        try {
            $osTmp = if ($Script:Caps.Cim) { Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
                     else                  { Get-WmiObject  Win32_OperatingSystem -ErrorAction Stop }
            switch ([int]$osTmp.ProductType) {
                1 { $roleId = if ($env:USERDNSDOMAIN) { 1 } else { 0 } }
                2 { $roleId = 5 }
                3 { $roleId = if ($env:USERDNSDOMAIN) { 3 } else { 2 } }
            }
        } catch { }
    }
    if ($roleId -lt 0) {
        $ctx.RoleSource = 'UNDETERMINED - assuming Member Server'
        $roleId = 3          # en genis modul setini calistiran guvenli varsayilan
    }
    $ctx.DomainRoleId = $roleId
    $ctx.DomainRole   = switch ($roleId) {
        0 { 'Standalone Workstation' }
        1 { 'Member Workstation' }
        2 { 'Standalone Server' }
        3 { 'Member Server' }
        4 { 'Backup Domain Controller' }
        5 { 'Primary Domain Controller' }
        default { 'Unknown' }
    }
    $ctx.IsDomainController = ($roleId -in 4, 5)
    $ctx.IsServer           = ($roleId -in 2, 3, 4, 5)
    $ctx.IsWorkstation      = ($roleId -in 0, 1)
    $ctx.IsDomainJoined     = ($cs -and $cs.PartOfDomain)
    $ctx.Domain             = if ($cs) { $cs.Domain } else { $null }
    $ctx.Manufacturer       = if ($cs) { $cs.Manufacturer } else { $null }
    $ctx.Model              = if ($cs) { $cs.Model } else { $null }
    $ctx.TotalRAMGB         = if ($cs -and $cs.TotalPhysicalMemory) {
                                  [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                              } else { $null }

    # --- Isletim sistemi ---
    $os = $null
    try {
        if ($Script:Caps.Cim) { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
        else                  { $os = Get-WmiObject  Win32_OperatingSystem -ErrorAction Stop }
    } catch { }

    if ($os) {
        $ctx.OSCaption      = $os.Caption
        $ctx.OSVersion      = $os.Version
        $ctx.OSBuild        = $os.BuildNumber
        $ctx.OSArchitecture = $os.OSArchitecture
        $ctx.InstallDate    = ConvertTo-DDateTime $os.InstallDate
        $ctx.LastBootUtc    = (ConvertTo-DDateTime $os.LastBootUpTime)
        if ($ctx.LastBootUtc) {
            $ctx.UptimeDays = [math]::Round(((Get-Date) - $ctx.LastBootUtc).TotalDays, 2)
        }
    }

    # --- Zaman dilimi (timeline korelasyonu icin sart) ---
    try {
        $tz = Get-CimInstance Win32_TimeZone -ErrorAction SilentlyContinue
        $ctx.TimeZone       = if ($tz) { $tz.Caption } else { [TimeZoneInfo]::Local.DisplayName }
        $ctx.UtcOffsetHours = [math]::Round(
            [TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalHours, 2)
    } catch { }

    # --- IP adresleri (locale bagimsiz - ipconfig parse ETME) ---
    $ips = @()
    try {
        if ($Script:Caps.NetAdapter) {
            $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
                   Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
                   Select-Object -ExpandProperty IPAddress
        } else {
            $ips = ([System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
                    Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                    ForEach-Object { $_.IPAddressToString }) |
                   Where-Object { $_ -notmatch '^(127\.|169\.254\.)' }
        }
    } catch { }
    $ctx.IPAddresses = @($ips)
    $ctx.PrimaryIP   = if ($ips) { $ips[0] } else { 'N/A' }

    # --- Zaman penceresi ---
    $ctx.WindowDays     = $Days
    $ctx.WindowStart    = (Get-Date).AddDays(-$Days)
    $ctx.WindowStartUtc = $ctx.WindowStart.ToUniversalTime()

    # --- F1.5-2: KURULUM PENCERESI ---
    # Sistem analiz penceresi icinde kurulmussa, kurulumdan gelen binlerce
    # "yeni servis / yeni gorev / yeni firewall kurali" bulgusu gercek degil.
    # Kurulum + ilk boot sonrasi kisa bir tampon "kurulum penceresi" sayilir;
    # bu pencerede olusan nesneler bastirilmaz ama INFO'ya dusurulur.
    $ctx.IsFreshInstall = $false
    $ctx.InstallWindowEndUtc = $null
    if ($ctx.InstallDate) {
        $instUtc = $ctx.InstallDate.ToUniversalTime()
        $ctx.InstallDateUtc = $instUtc
        # kurulum, analiz penceresinin baslangicindan SONRA ise taze kurulum
        if ($instUtc -ge $ctx.WindowStartUtc) {
            $ctx.IsFreshInstall = $true
            # kurulum + 6 saat: OOBE, ilk update dalgasi, provisioning gorevleri
            $ctx.InstallWindowEndUtc = $instUtc.AddHours(6)
        }
    }

    # --- F1.5-1: KENDI PROCESS AGACIMIZ ---
    # Douglas modul import ettikce PowerShell 4104'e yazar; sonraki modul bunu
    # okuyup "supheli script block" bulgusu uretir (koleksiyon oz-kirlenmesi).
    # Kendi PID'imizi ve ust zincirimizi isaretle, event motorunda disla.
    $ctx.SelfPid = $PID
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        $seen = @{}
        while ($p -and -not $seen.ContainsKey([int]$p.ProcessId)) {
            $seen[[int]$p.ProcessId] = $true
            $Script:SelfPids[[int]$p.ProcessId] = $p.Name
            $pp = [int]$p.ParentProcessId
            if ($pp -le 4) { break }
            $p = Get-CimInstance Win32_Process -Filter "ProcessId=$pp" -ErrorAction SilentlyContinue
        }
    } catch { $Script:SelfPids[[int]$PID] = 'powershell' }
    $ctx.SelfStartUtc = $Script:StartTime.ToUniversalTime()

    return $ctx
}

function ConvertTo-DDateTime {
    <# WMI/CIM tarih alanlarini guvenle DateTime'a cevirir #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime]) { return $Value }

    # CIM_DATETIME formati: yyyyMMddHHmmss.ffffff+UUU
    # NOT: Get-CimInstance zaten DateTime dondurur; bu yol sadece
    # Get-WmiObject fallback'inde devreye girer.
    # System.Management assembly'si PS7 Core'da yuklu olmayabilir.
    try {
        return [Management.ManagementDateTimeConverter]::ToDateTime($Value)
    } catch {
        try {
            if ($Value -match '^(\d{14})') {
                return [DateTime]::ParseExact($Matches[1], 'yyyyMMddHHmmss',
                       [Globalization.CultureInfo]::InvariantCulture)
            }
            return [DateTime]::Parse($Value, [Globalization.CultureInfo]::InvariantCulture)
        } catch { return $null }
    }
}

function ConvertTo-DUtcString {
    param($DateTime)
    if ($null -eq $DateTime) { return $null }
    try { return ([DateTime]$DateTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    catch { return $null }
}

# ============================================================================
#  CIKTI ALTYAPISI
# ============================================================================

function Initialize-DOutput {
    param([string]$Root)

    if (-not $Root) {
        $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $Root = Join-Path $base 'Output'
    }

    $stamp  = $Script:StartTime.ToString('yyyyMMdd_HHmmss')
    $folder = 'DOUGLAS_{0}_{1}' -f $env:COMPUTERNAME, $stamp
    $full   = Join-Path $Root $folder

    $null = New-Item -Path $full -ItemType Directory -Force -ErrorAction Stop
    foreach ($sub in 'artifacts', 'events', 'raw', 'logs') {
        $null = New-Item -Path (Join-Path $full $sub) -ItemType Directory -Force -ErrorAction SilentlyContinue
    }

    return $full
}

function Export-DArtifact {
    <#
        Tek cikis noktasi. CSV her zaman, JSON istege bagli.
        Manifest'e satir sayisi + SHA256 kaydeder.
        DIKKAT: Format-Table/Format-List ASLA kullanilmaz - obje kaybolur.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()]$Data,
        [ValidateSet('artifacts', 'events', 'raw', 'logs')]
        [string]$SubDir = 'artifacts',
        [switch]$AsJson,
        [switch]$JsonOnly,
        [int]$JsonDepth = 6
    )

    $rows = @($Data | Where-Object { $null -ne $_ })
    $dir  = Join-Path $Script:Ctx.OutputDir $SubDir

    $csvPath  = Join-Path $dir "$Name.csv"
    $jsonPath = Join-Path $dir "$Name.json"
    $written  = @()

    try {
        if (-not $JsonOnly) {
            if ($rows.Count -gt 0) {
                $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Force
            } else {
                # Bos artefakt da kayit birakmali: "toplanmadi" ile "bos" ayri seyler
                '# NO DATA' | Out-File -FilePath $csvPath -Encoding UTF8 -Force
            }
            $written += $csvPath
        }

        if ($AsJson -or $JsonOnly) {
            $json = if ($rows.Count -gt 0) {
                $rows | ConvertTo-Json -Depth $JsonDepth
            } else { '[]' }
            $json | Out-File -FilePath $jsonPath -Encoding UTF8 -Force
            $written += $jsonPath
        }
    } catch {
        Write-DLog "Export-DArtifact '$Name' basarisiz: $($_.Exception.Message)" -Level ERROR
        return
    }

    foreach ($f in $written) {
        $null = $Script:Manifest.Add([PSCustomObject]@{
            Artifact = $Name
            File     = (Split-Path $f -Leaf)
            SubDir   = $SubDir
            Rows     = $rows.Count
            SizeKB   = if (Test-Path $f) { [math]::Round((Get-Item $f).Length / 1KB, 2) } else { 0 }
            SHA256   = Get-DFileHashSafe -Path $f
        })
    }

    Write-DLog "  -> $Name ($($rows.Count) records)" -Level DEBUG
}

function Add-DTimelineEvent {
    <# Birlesik timeline besleyicisi. Her modul zaman damgali kaydini buraya atar. #>
    param(
        [Parameter(Mandatory)]$Timestamp,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Description,
        [string]$Detail,
        [ValidateSet('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity = 'INFO'
    )
    $utc = ConvertTo-DUtcString $Timestamp
    if (-not $utc) { return }

    $null = $Script:Timeline.Add([PSCustomObject]@{
        TimeUtc     = $utc
        Source      = $Source
        Severity    = $Severity
        Description = $Description
        Detail      = $Detail
    })
}

function Add-DFinding {
    <# Triage bulgusu. HTML raporun en ustune ve FINDINGS.csv'ye gider. #>
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)]
        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [string]$Mitre,
        [string]$Why,
        [string]$Artifact,
        $Timestamp
    )

    $Mitre = ConvertTo-DMitreV19 $Mitre

    # Kural metinlerini KAYIT ANINDA Ingilizceye cevir. Boylece konsol ciktisi,
    # FINDINGS.csv ve rapor tek dilde olur. Dinamik sonek (": <pattern>") korunur.
    $enRule = $Script:RuleEN[$RuleId]
    if ($enRule) {
        $sfx = ''
        if ($Title -match '^(.*?):\s*(.+)$') { $sfx = ': ' + $Matches[2] }
        $Title = $enRule.T + $sfx
        if ($enRule.W) { $Why = $enRule.W }
    }

    $null = $Script:Findings.Add([PSCustomObject]@{
        RuleId    = $RuleId
        Severity  = $Severity
        Title     = $Title
        Evidence  = $Evidence
        Mitre     = $Mitre
        Why       = $Why
        Artifact  = $Artifact
        TimeUtc   = ConvertTo-DUtcString $Timestamp
        Host      = $Script:Ctx.ComputerName
    })

    # Konsolda onem seviyesi RENKLE ayrilir - hangisi kritik, hangisi bilgi
    # bir bakista gorulsun. CRITICAL/HIGH/MEDIUM basilir; LOW/INFO gurultu yapar.
    if ($Severity -in 'CRITICAL', 'HIGH', 'MEDIUM') {
        # Onem seviyeleri net ayrilsin: etiket kisaltilmaz, her seviye ayri renk.
        $sevColor = switch ($Severity) {
            'CRITICAL' { 'Red' }
            'HIGH'     { 'Magenta' }
            'MEDIUM'   { 'Yellow' }
            default    { 'DarkGray' }
        }
        $sevTag = switch ($Severity) {
            'CRITICAL' { '[CRITICAL]' }
            'HIGH'     { '[HIGH]    ' }
            'MEDIUM'   { '[MEDIUM]  ' }
            default    { '[INFO]    ' }
        }
        $ev = if ($Evidence -and $Evidence.Length -gt 120) { $Evidence.Substring(0,120) + '...' } else { $Evidence }
        $ts = (Get-Date).ToString('HH:mm:ss')
        Write-Host "$ts " -ForegroundColor DarkGray -NoNewline
        Write-Host "$sevTag " -ForegroundColor $sevColor -NoNewline
        Write-Host "$Title" -ForegroundColor $sevColor -NoNewline
        Write-Host " :: $ev" -ForegroundColor DarkGray
        # dosya logu (renksiz)
        Write-DLog "  [$Severity] $Title :: $Evidence" -Level $(
            switch ($Severity) { 'CRITICAL' {'CRIT'} 'HIGH' {'WARN'} default {'INFO'} }) -NoConsole
    }
}

# ============================================================================
#  YARDIMCILAR - HASH / IMZA (cache'li)
# ============================================================================

function Get-DFileHashSafe {
    <#
        SHA256. Cache'li - ayni exe 40 process'te calisiyorsa 1 kez hesaplanir.
        200 MB ustu dosya atlanir.
    #>
    param([string]$Path, [int]$MaxSizeMB = 200)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $key = $Path.ToLowerInvariant()
    if ($Script:HashCache.ContainsKey($key)) { return $Script:HashCache[$key] }

    $result = $null
    try {
        $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($fi.PSIsContainer) { $result = $null }
        elseif ($fi.Length -gt ($MaxSizeMB * 1MB)) { $result = 'SKIPPED_LARGE' }
        else {
            if ($Script:Caps.FileHash) {
                $result = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
            } else {
                # PS4 fallback
                $sha = [Security.Cryptography.SHA256]::Create()
                $fs  = [IO.File]::OpenRead($Path)
                try {
                    $result = ([BitConverter]::ToString($sha.ComputeHash($fs))) -replace '-', ''
                } finally { $fs.Dispose(); $sha.Dispose() }
            }
        }
    } catch {
        $result = 'ERROR_LOCKED'
    }

    $Script:HashCache[$key] = $result
    return $result
}

function Get-DSignature {
    <#
        Authenticode imza durumu. Cache'li.
        Donen: Status, Signer, IsMicrosoft, IsValid
    #>
    param([string]$Path)

    $unknown = [PSCustomObject]@{
        Status = 'NoPath'; Signer = $null; IsMicrosoft = $false; IsValid = $false
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $unknown }

    $key = $Path.ToLowerInvariant()
    if ($Script:SigCache.ContainsKey($key)) { return $Script:SigCache[$key] }

    $res = $unknown
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue) {
            $sig    = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
            $cn     = $null
            if ($signer -and $signer -match 'CN=([^,]+)') { $cn = $Matches[1].Trim('" ') }

            $res = [PSCustomObject]@{
                Status      = [string]$sig.Status
                Signer      = $cn
                IsMicrosoft = ($cn -like '*Microsoft*')
                IsValid     = ($sig.Status -eq 'Valid')
            }
        } else {
            $res = [PSCustomObject]@{
                Status = 'FileNotFound'; Signer = $null; IsMicrosoft = $false; IsValid = $false
            }
        }
    } catch {
        $res = [PSCustomObject]@{
            Status = 'Error'; Signer = $null; IsMicrosoft = $false; IsValid = $false
        }
    }

    $Script:SigCache[$key] = $res
    return $res
}

function Test-DSuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return [bool]($Path -match $Script:SuspiciousPathRegex)
}

function Get-DCleanPath {
    <# Servis/task komut satirindan gercek binary yolunu ayiklar #>
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $cl = $CommandLine.Trim()
    if ($cl.StartsWith('"')) {
        $end = $cl.IndexOf('"', 1)
        if ($end -gt 0) { return $cl.Substring(1, $end - 1) }
    }
    # Tirnaksiz: ilk .exe/.dll/.sys uzantisina kadar al
    if ($cl -match '^(.*?\.(exe|dll|sys|com|bat|cmd|scr))(\s|$)') {
        return (Expand-DPath $Matches[1])
    }
    # F1.5-3: %windir% gibi degiskenleri coz - yoksa Test-Path/imza yanlis calisir
    return (Expand-DPath (($cl -split '\s+')[0]))
}

# ============================================================================
#  F1.5 MERKEZI YARDIMCI KATMAN
#  Bu fonksiyonlar modullerin ortak kullandigi tespit mantigini tek yerde
#  toplar. Amac: ayni mantigi 6 module kopyalamamak (drift kaynagi) ve
#  duzeltmelerin genel amacli olmasi - belirli bir ornek IOC'ye degil,
#  tehdit sinifina karsi calismasi.
# ============================================================================

# --- F1.5-3/7: ortam degiskeni genisletme + gercek binary ayiklama ---
function Expand-DPath {
    <# %windir%, %SystemRoot% gibi degiskenleri cozer. Cozulemezse orijinali
       dondurur. IsMicrosoft/BinaryExists kontrolleri bunsuz yanlis calisir. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        $e = [Environment]::ExpandEnvironmentVariables($Path)
        # \??\ NT-yol on eki (surucu ImagePath'lerinde gorulur)
        $e = $e -replace '^\\\?\?\\', ''
        return $e
    } catch { return $Path }
}

# --- F1.5-12: korumali sistem binary maskeleme tablosu ---
# Bilinen Windows binary adlari yalnizca dogru dizinlerinden calismalidir.
# Ayni ad baska yerden calisiyorsa masquerading'dir (T1036.005).
$Script:ProtectedBinaries = @{
    'svchost.exe'  = @('\windows\system32\', '\windows\syswow64\')
    'lsass.exe'    = @('\windows\system32\')
    'services.exe' = @('\windows\system32\')
    'csrss.exe'    = @('\windows\system32\')
    'winlogon.exe' = @('\windows\system32\')
    'wininit.exe'  = @('\windows\system32\')
    'smss.exe'     = @('\windows\system32\')
    'lsaiso.exe'   = @('\windows\system32\')
    'spoolsv.exe'  = @('\windows\system32\')
    'taskhostw.exe'= @('\windows\system32\')
    'explorer.exe' = @('\windows\')
    'dllhost.exe'  = @('\windows\system32\', '\windows\syswow64\')
    'rundll32.exe' = @('\windows\system32\', '\windows\syswow64\')
    'conhost.exe'  = @('\windows\system32\')
    'dwm.exe'      = @('\windows\system32\')
    'fontdrvhost.exe' = @('\windows\system32\')
    'searchindexer.exe' = @('\windows\system32\')
}

function Test-DMasqueradedName {
    <# F1.5-12: process/servis binary'si korumali bir sistem adini tasiyor ama
       yanlis dizinden mi calisiyor? Ayrica ADI sistem binarysine BENZIYOR ama
       tam degil (svch0st, scvhost, lsas) ise homoglyph/typo-squat isareti.
       Donen: $null | @{ Reason; Expected } #>
    param([string]$Name, [string]$FullPath)
    if (-not $Name) { return $null }
    $n = $Name.ToLowerInvariant()
    if (-not $n.EndsWith('.exe')) { $n += '.exe' }
    $path = if ($FullPath) { (Expand-DPath $FullPath).ToLowerInvariant() } else { '' }

    # 1) Bilinen ad, yanlis dizin
    if ($Script:ProtectedBinaries.ContainsKey($n)) {
        if ($path) {
            $ok = $false
            foreach ($d in $Script:ProtectedBinaries[$n]) { if ($path.Contains($d)) { $ok = $true; break } }
            if (-not $ok) {
                return @{ Reason = "System binary name in wrong directory: $n"; Expected = ($Script:ProtectedBinaries[$n] -join ' or ') }
            }
        }
        return $null   # dogru yerde
    }

    # 2) Sistem binary adina cok benzeyen (1 karakter fark) - typo/homoglyph
    $base = $n -replace '\.exe$',''
    foreach ($known in $Script:ProtectedBinaries.Keys) {
        $kb = $known -replace '\.exe$',''
        if ([math]::Abs($kb.Length - $base.Length) -le 1 -and $base -ne $kb) {
            $d = Get-DLevenshtein $base $kb
            if ($d -eq 1) {
                return @{ Reason = "Suspicious name resembling a system binary: $n (~ $known)"; Expected = $known }
            }
        }
    }
    return $null
}

function Get-DLevenshtein {
    <# Iki string arasi edit mesafesi (typo-squat tespiti icin, kisa adlar).
       NOT: 2 boyutlu dizi ($d[$i,$j]) Windows PowerShell 5.1 parser'inda
       calismaz. Iki yuvarlanan 1 boyutlu satir kullaniyoruz - hem 5.1 hem 7
       uyumlu, ustelik O(n) bellek. #>
    param([string]$a, [string]$b)
    if ($a -eq $b) { return 0 }
    if (-not $a) { return $b.Length }
    if (-not $b) { return $a.Length }
    $m = $a.Length; $n = $b.Length
    $prev = New-Object 'int[]' ($n + 1)
    $cur  = New-Object 'int[]' ($n + 1)
    for ($j = 0; $j -le $n; $j++) { $prev[$j] = $j }
    for ($i = 1; $i -le $m; $i++) {
        $cur[0] = $i
        for ($j = 1; $j -le $n; $j++) {
            $cost = 1
            if ($a[$i - 1] -eq $b[$j - 1]) { $cost = 0 }
            $del = $prev[$j] + 1
            $ins = $cur[$j - 1] + 1
            $sub = $prev[$j - 1] + $cost
            $min = $del
            if ($ins -lt $min) { $min = $ins }
            if ($sub -lt $min) { $min = $sub }
            $cur[$j] = $min
        }
        $tmp = $prev; $prev = $cur; $cur = $tmp
    }
    return $prev[$n]
}

# --- F1.5-7/13: komut satirinda gizleme cozme (encoded + concat) ---
function Expand-DCommandLine {
    <# F1.5-7: her komut satiri turunu (servis binPath, gorev action, autorun
       value, event CommandLine) TEK yerden cozer. -enc base64 payload'ini
       acar; string-concat obfuscation'ini ('Wr'+'ite') birlestirir.
       Donen: @{ Decoded=<cozulmus metin veya $null>; Method=<enc|concat|format> } #>
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # 1) -EncodedCommand / -enc / -e <base64>
    if ($Text -match '(?i)(?:^|\s)-e(?:nc|ncod|ncoded|ncodedcommand)?\s+([A-Za-z0-9+/=]{20,})') {
        $b64 = $Matches[1]
        try {
            $bytes = [Convert]::FromBase64String($b64.PadRight([math]::Ceiling($b64.Length/4)*4,'='))
            $dec   = [Text.Encoding]::Unicode.GetString($bytes)
            if ($dec -match '[^\x09\x0A\x0D\x20-\x7E]' -and $dec -notmatch '\w{4}') {
                $dec = [Text.Encoding]::UTF8.GetString($bytes)
            }
            return @{ Decoded = ($dec -replace '\s+', ' ').Trim(); Method = 'base64' }
        } catch { }
    }

    # 2) String concatenation obfuscation: 'Wr'+'ite'+'-Output'
    if ($Text -match "('[^']*'\s*\+\s*)+'[^']*'") {
        # ardisik 'x'+'y'+'z' bloklarini birlestir
        $joined = [regex]::Replace($Text, "'([^']*)'(\s*\+\s*'([^']*)')+", {
            param($m)
            $sb = $m.Groups[1].Value
            foreach ($cap in $m.Groups[3].Captures) { $sb += $cap.Value }
            "'" + $sb + "'"
        })
        if ($joined -ne $Text) { return @{ Decoded = $joined.Trim(); Method = 'concat' } }
    }

    # 3) -f format string / char[] birlestirme (kaba tespit)
    if ($Text -match '(?i)\[char\]\d{2,3}(\s*[,+]\s*\[char\]\d{2,3}){3,}') {
        try {
            $chars = [regex]::Matches($Text, '\[char\](\d{2,3})') | ForEach-Object { [char][int]$_.Groups[1].Value }
            $joined = -join $chars
            return @{ Decoded = $joined; Method = 'char-array' }
        } catch { }
    }

    return $null
}

function Test-DObfuscatedCommand {
    <# F1.5-13: komut satiri obfuscation ISARETI tasiyor mu? PowerShell'in kendi
       4104 uyarisina guvenmeden, statik gostergelerle. Donen: gerekce listesi. #>
    param([string]$Text)
    if (-not $Text) { return @() }
    $flags = @()
    # GUCLU gostergeler - tek basina obfuscation kaniti (Strong = $true)
    $strong = @()
    if ($Text -match '(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}') { $strong += 'base64 encoded command' }
    if ($Text -match "('[^']*'\s*\+\s*){2,}") { $strong += 'string concatenation' }
    if ($Text -match '(?i)\[char\]\d{2,3}\s*[,+]\s*\[char\]') { $strong += 'char-code array' }
    if ($Text -match '(?i)FromBase64String\s*\(|::(UTF8|Unicode)\.GetString') { $strong += 'inline base64 decode' }
    # ZAYIF gostergeler - tek basina degil, korelasyon icin
    $weak = @()
    if ($Text -match '(?i)-join\s*\(') { $weak += 'join obfuscation' }
    if ($Text -match '(?i)(iex|invoke-expression)\b') { $weak += 'Invoke-Expression' }
    if ($Text -match '\$\{.+\}|\$\w+\[\d') { $weak += 'variable indirection' }
    $bt = ([regex]::Matches($Text, '`')).Count
    if ($Text.Length -gt 30 -and ($bt / [double]$Text.Length) -gt 0.05) { $weak += 'yuksek backtick yogunlugu' }

    $flags = @($strong) + @($weak)
    # meta: cagiran karar verebilsin diye guclu sayisini basa ekle degil,
    # dondurulen listede guclu olanlar once. Guclu >=1 VEYA zayif >=2 anlamli.
    if ($strong.Count -ge 1) { return @($strong + $weak) }
    if ($weak.Count -ge 2)   { return @($weak) }
    return @()
}

# --- F1.5-10/11: dosya artefakti analizi (icerik, entropi, PE, ADS) ---
function Get-DShannonEntropy {
    <# Byte dagilimi entropisi (0-8). >7.2 sifreli/paketli/sikistirilmis. #>
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return 0 }
    $freq = New-Object 'int[]' 256
    foreach ($b in $Bytes) { $freq[$b]++ }
    $len = [double]$Bytes.Length; $ent = 0.0
    foreach ($f in $freq) {
        if ($f -gt 0) { $p = $f / $len; $ent -= $p * [math]::Log($p, 2) }
    }
    return [math]::Round($ent, 2)
}

function Test-DFileArtifact {
    <# F1.5-10: bir dosyayi UZANTIDAN BAGIMSIZ degerlendirir. Karar konum +
       icerik imzasi + entropi + PE header'dan gelir, uzanti allowlist'inden
       DEGIL. Boylece update.dat, config.log, uzantisiz payload da yakalanir.
       Donen: bulgu ureten gozlemler listesi @( @{Sev;Rule;Title;Why;Mitre;Detail} ) #>
    param([string]$Path, [datetime]$WindowStartUtc)
    $obs = @()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $obs }

    $fi = $null
    try { $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return $obs }

    $inSuspPath = Test-DSuspiciousPath -Path $Path
    $ext        = $fi.Extension.ToLowerInvariant()
    $lowTrust   = ($Script:LowTrustExt -contains $ext)
    # Microsoft-imzali dosyalar icerik/entropi/PE analizinden muaf - mesru sistem
    # dosyalari (mpengine, defender imza db vb.) yanlis pozitif uretiyordu.
    $fSig = Get-DSignature -Path $Path
    if ($fSig.IsMicrosoft -and $fSig.IsValid) { return $obs }

    # ilk 4KB oku (icerik imzasi + PE header + entropi)
    $head = $null; $ent = 0
    try {
        $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        try {
            $len = [int][math]::Min(4096, $fs.Length)
            $head = New-Object byte[] $len
            $null = $fs.Read($head, 0, $len)
        } finally { $fs.Close() }
        if ($head) { $ent = Get-DShannonEntropy -Bytes $head }
    } catch { }

    $text = if ($head) { [Text.Encoding]::ASCII.GetString($head) } else { '' }

    # 1) PE header (MZ) ama .exe/.dll DEGIL -> gizlenmis calistirilabilir
    if ($head -and $head.Length -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) {
        if ($ext -notin '.exe','.dll','.sys','.scr','.cpl','.ocx','.efi') {
            $obs += @{ Sev='CRITICAL'; Rule='DGL-233'; Mitre='T1036.008'
                      Title='PE binary hidden behind the wrong extension'
                      Why='MZ header tasiyan dosya calistirilabilir; uzantisi bunu gizliyor'
                      Detail="$Path (uzanti $ext, entropi $ent)" }
        }
    }

    # 2) Icerik imzasi (mimikatz/credential dump/staged config/private key)
    foreach ($sig in $Script:PayloadContentSig) {
        if ($text -match $sig.P) {
            $obs += @{ Sev=$sig.S; Rule='DGL-234'; Mitre=$sig.M
                      Title="File content signature: $($sig.N)"
                      Why='Dosya icerigi bilinen saldiri araci/artefakti imzasiyla eslesti'
                      Detail="$Path :: $($sig.N)" }
            break
        }
    }

    # 3) Dusuk-guven uzanti + supheli dizin + yuksek entropi -> gizli payload
    if ($lowTrust -and $inSuspPath -and $ent -ge 7.2 -and $fi.Length -gt 512) {
        $obs += @{ Sev='HIGH'; Rule='DGL-235'; Mitre='T1027'
                  Title='High-entropy file with an innocuous extension in a suspicious directory'
                  Why='Sifreli/paketli icerik masum uzantiya saklanmis olabilir'
                  Detail="$Path (entropi $ent, $([math]::Round($fi.Length/1KB,1)) KB)" }
    }

    # 4) Analiz penceresi icinde supheli dizine yazilmis calistirilabilir
    if ($inSuspPath -and $ext -in '.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.hta','.scr' -and
        $WindowStartUtc -and $fi.LastWriteTimeUtc -ge $WindowStartUtc) {
        if (-not (Test-DInstallWindow -Timestamp $fi.LastWriteTimeUtc)) {
            $obs += @{ Sev='HIGH'; Rule='DGL-230'; Mitre='T1105'
                      Title='New executable file in a suspicious directory'
                      Why='Analiz penceresi icinde Temp/AppData/Public altina yazilan calistirilabilir payload olabilir'
                      Detail="$Path @ $($fi.LastWriteTimeUtc.ToString('o'))" }
        }
    }

    return $obs
}

function Get-DAlternateStreams {
    <# F1.5-11: dosyanin varsayilan disi (alternatif) veri akislarini dondurur.
       Zone.Identifier gibi mesru akislar haric. Calistirilabilir/kod iceren
       ADS gizleme teknigidir (T1564.004). #>
    param([string]$Path)
    $out = @()
    try {
        $streams = Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop |
                   Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        foreach ($s in $streams) {
            $out += [PSCustomObject]@{ Path = $Path; Stream = $s.Stream; Size = $s.Length }
        }
    } catch { }
    return $out
}

# --- F1.5-7/13: TEK merkez - komut satirini coz, cozuleni tara, obfuscation isaretle ---
function Format-DEvidence {
    <# Kanit metnini makul bir sinira kadar gosterir; kesilirse SESSIZCE degil,
       acik "[+N karakter]" isaretiyle keser. Boylece analist tam komutun
       FINDINGS.csv'de oldugunu bilir. Varsayilan 1000 - onceki 200-300 cok kisaydi
       ve PowerShell komutlarini ortadan boluyordu. #>
    param([string]$Text, [int]$Max = 1000)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    if ($Text.Length -le $Max) { return $Text }
    $kesik = $Text.Length - $Max
    return $Text.Substring(0, $Max) + " ...[+$kesik karakter - tam metin FINDINGS.csv]"
}

function Get-DFilesNoReparse {
    <# Reparse-point (junction/symlink) GUVENLI ozyineli dosya listeleyici.
       Windows'ta C:\ProgramData\Application Data -> C:\ProgramData junction'i
       Get-ChildItem -Recurse'u sonsuz donguye sokar (yuzlerce hayali
       "Application Data\Application Data\..." yolu). Bu fonksiyon reparse
       point'leri IZLEMEZ ve derinligi sinirlar. #>
    param(
        [string]$Root,
        [int]$MaxDepth = 12,
        [int]$Limit = 20000
    )
    $out = New-Object System.Collections.ArrayList
    $stack = New-Object System.Collections.Stack
    $stack.Push([PSCustomObject]@{ Path = $Root; Depth = 0 })
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $count = 0
    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        if ($node.Depth -gt $MaxDepth) { continue }
        # dongu koruma: ayni gercek yola iki kez girme
        $real = $node.Path
        try { $ri = Get-Item -LiteralPath $node.Path -Force -ErrorAction Stop
              if ($ri.Target) { $real = [string]$ri.Target } } catch { }
        if (-not $seen.Add($real.ToLowerInvariant())) { continue }

        $children = $null
        try { $children = Get-ChildItem -LiteralPath $node.Path -Force -ErrorAction SilentlyContinue } catch { continue }
        foreach ($c in $children) {
            # REPARSE POINT (junction/symlink) = IZLEME. Bu tek satir
            # Application Data dongusunu ve tum symlink tuzaklarini keser.
            $isReparse = ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq [IO.FileAttributes]::ReparsePoint
            if ($c.PSIsContainer) {
                if (-not $isReparse) { $stack.Push([PSCustomObject]@{ Path = $c.FullName; Depth = $node.Depth + 1 }) }
            } else {
                if ($isReparse) { continue }
                $null = $out.Add($c)
                $count++
                if ($count -ge $Limit) { return $out }
            }
        }
    }
    return $out
}

function Invoke-DDeobfuscateAndScan {
    <# Her komut-satiri tasiyan artefakt (process/servis/gorev/autorun/event/WMI)
       bunu cagirir. Uc is yapar:
         1) F1.5-7  encoded/concat payload'i cozer, RAPORA yazar (DGL-144)
         2) cozulmus icerigi CmdLinePatterns'den gecirir (gizli komut ortaya cikar)
         3) F1.5-13 obfuscation ISARETLERINI statik gosterge ile bulur (DGL-151)
       Donen: cozulmus metin veya $null #>
    param(
        [string]$Text,
        [string]$Context,
        [string]$Artifact,
        $Timestamp,
        [string]$DecodeRule = 'DGL-144',
        [string]$ObfRule    = 'DGL-151'
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    # 1) coz
    $d = Expand-DCommandLine -Text $Text
    $decoded = $null
    if ($d -and $d.Decoded) {
        $decoded = $d.Decoded
        $show = Format-DEvidence -Text $decoded -Max 1500
        Add-DFinding -RuleId $DecodeRule -Severity HIGH `
            -Title "Obfuscated command decoded ($($d.Method))" `
            -Evidence "$Context :: $show" `
            -Mitre 'T1027' -Artifact $Artifact -Timestamp $Timestamp `
            -Why 'Kodlama/gizleme tek basina zararli degildir; cozulmus icerik incelenmelidir'

        # 2) cozulmus icerigi de pattern setinden gecir
        foreach ($pat in $Script:CmdLinePatterns) {
            if ($decoded -match $pat.P) {
                Add-DFinding -RuleId 'DGL-145' -Severity $pat.S `
                    -Title "Suspicious pattern in decoded command: $($pat.N)" `
                    -Evidence "$Context :: $(Format-DEvidence -Text $decoded -Max 1200)" `
                    -Mitre $pat.M -Artifact $Artifact -Timestamp $Timestamp `
                    -Why 'Gizlenmis payload icinde saldirgan davranis pattern eslesmesi'
                break
            }
        }
        # cozulmus icerikte IOC var mi
        $null = Test-DIoc -Value $decoded -Context "$Context (cozulmus)" -Artifact $Artifact -Timestamp $Timestamp
    }

    # 3) obfuscation isaretleri (cozulemese bile)
    $flags = Test-DObfuscatedCommand -Text $Text
    if ($flags.Count -ge 2) {
        Add-DFinding -RuleId $ObfRule -Severity MEDIUM `
            -Title 'Obfuscated command line' `
            -Evidence "$(Format-DEvidence -Text $Text -Max 1000)  [$($flags -join ', ')]" `
            -Mitre 'T1027.010' -Artifact $Artifact -Timestamp $Timestamp `
            -Why 'Coklu gizleme gostergesi mesru komutlarda nadiren bir arada bulunur'
    }

    return $decoded
}


# ============================================================================
#  IOC YUKLEME
# ============================================================================

function Import-DIocs {
    <#
        Satir basina bir IOC. Tip otomatik tespit edilir ve tipe gore AYRI
        koleksiyona yazilir - eslesme mantigi tipe gore degisiyor:
          HASH   -> tam esitlik (hizli hashtable lookup)
          IP     -> tam esitlik
          DOMAIN -> son ek eslesmesi (evil.com, sub.evil.com ve URL icini yakalar)
          STRING -> alt dize eslesmesi
        Eski surumde hepsi tam esitlikti; bu yuzden "evil.com" IOC'si
        "https://evil.com/x.exe" DownloadUrl degeriyle eslesmiyordu.
    #>
    param([string]$Path)
    if (-not $Path -or -not (Test-Path $Path)) { return }

    $Script:IocExact  = @{}                                  # hash + ip
    $Script:IocSuffix = New-Object System.Collections.ArrayList   # domain
    $Script:IocSub    = New-Object System.Collections.ArrayList   # string
    $count = 0

    try {
        Get-Content -Path $Path -ErrorAction Stop | ForEach-Object {
            $line = $_.Trim()
            if (-not $line -or $line.StartsWith('#')) { return }
            $k = $line.ToLowerInvariant()

            $type = switch -Regex ($line) {
                '^[a-fA-F0-9]{64}$'                 { 'SHA256'; break }
                '^[a-fA-F0-9]{40}$'                 { 'SHA1';   break }
                '^[a-fA-F0-9]{32}$'                 { 'MD5';    break }
                '^\d{1,3}(\.\d{1,3}){3}$'           { 'IP';     break }
                '^[\w\-\.]+\.[a-zA-Z]{2,}$'         { 'DOMAIN'; break }
                default                             { 'STRING' }
            }

            switch ($type) {
                'DOMAIN' { $null = $Script:IocSuffix.Add(@{ V = $k; T = $type }) }
                'STRING' {
                    # 4 karakterden kisa alt dize her yerde eslesir, gurultu olur
                    if ($k.Length -ge 4) { $null = $Script:IocSub.Add(@{ V = $k; T = $type }) }
                    else { Write-DLog "IOC skipped (too short): $line" -Level WARN; return }
                }
                default  { $Script:IocExact[$k] = $type }
            }
            $Script:Iocs[$k] = $type          # katalog / raporlama icin
            $count++
        }
        Write-DLog ("IOC list loaded: {0} entries ({1} exact, {2} domain, {3} substring)" -f `
                    $count, $Script:IocExact.Count, $Script:IocSuffix.Count,
                    $Script:IocSub.Count) -Level OK
    } catch {
        Write-DLog "IOC file could not be read: $($_.Exception.Message)" -Level WARN
    }
}

function Test-DIoc {
    <# Toplanan her deger bundan gecer. Hit varsa otomatik CRITICAL finding. #>
    param([string]$Value, [string]$Context, [string]$Artifact, $Timestamp)
    if (-not $Value -or $Script:Iocs.Count -eq 0) { return $false }

    $k = $Value.ToLowerInvariant()
    $hitVal = $null; $hitType = $null

    if ($Script:IocExact.ContainsKey($k)) {
        $hitVal = $k; $hitType = $Script:IocExact[$k]
    }
    if (-not $hitVal) {
        foreach ($d in $Script:IocSuffix) {
            # tam alan adi, alt alan adi, veya URL/yol icinde gecmesi
            if ($k -eq $d.V -or $k.EndsWith('.' + $d.V) -or $k.Contains('/' + $d.V) -or
                $k.Contains('//' + $d.V) -or $k.Contains('.' + $d.V + '/') -or
                $k.Contains($d.V + ':')) {
                $hitVal = $d.V; $hitType = $d.T; break
            }
        }
    }
    if (-not $hitVal) {
        foreach ($s in $Script:IocSub) {
            if ($k.Contains($s.V)) { $hitVal = $s.V; $hitType = $s.T; break }
        }
    }
    if (-not $hitVal) { return $false }

    Add-DFinding -RuleId 'DGL-IOC' -Severity CRITICAL `
                 -Title "IOC eslesmesi ($hitType)" `
                 -Evidence "$hitVal <- $Value  |  $Context" `
                 -Why 'Saglanan IOC listesiyle eslesme' `
                 -Mitre 'T1587' `
                 -Artifact $Artifact -Timestamp $Timestamp
    return $true
}

# ============================================================================
#  MODUL MOTORU
# ============================================================================

$Script:ModuleRegistry = New-Object System.Collections.ArrayList


# ----------------------------------------------------------------------------
#  KURAL KATALOGU
#  Kod ile belge ayrismasini onlemek icin katalog burada tutulur ve
#  -ExportRuleCatalog ile CSV'ye yazilir. Complete-DCollection sonunda
#  uretilen her RuleId bu tabloda var mi diye kontrol edilir (drift alarmi).
# ----------------------------------------------------------------------------
$Script:RuleCatalog = @(
    @{ Id='DGL-000'; Sev='MEDIUM'; Title='Isletim sistemi 7 gunden yeni kurulmus'; Mitre=''; Why='Beklenmedik yeniden kurulum, izlerin silinmis olabilecegini gosterir'; Artifact='01_system'; Module='System Information' }
    @{ Id='DGL-001'; Sev='CRITICAL'; Title='Servis binary supheli dizinde'; Mitre='T1543.003'; Why='Mesru servisler System32 veya Program Files altinda calisir'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-002'; Sev='MEDIUM'; Title='Sistem 90+ gundur yamalanmamis'; Mitre='T1190'; Why='Yamasiz sistem bilinen exploitlere acik - initial access vektoru'; Artifact='01_hotfixes'; Module='Hotfix / Patch Status' }
    @{ Id='DGL-014'; Sev='CRITICAL'; Title='Event log temizlenmis olabilir'; Mitre='T1070.001'; Why='Log kapasitesi buyuk ve dolmamis, ama gecmis kayit yok. Rollover degil, temizleme.'; Artifact='11_log_health'; Module='Event Log Health' }
    @{ Id='DGL-015'; Sev='HIGH'; Title='Kritik event log kanali devre disi'; Mitre='T1562.002'; Why='Saldirgan gorunurlugu kapatmis olabilir'; Artifact='11_log_health'; Module='Event Log Health' }
    @{ Id='DGL-016'; Sev='INFO'; Title='Istenen zaman penceresi log retention suresini asiyor'; Mitre=''; Why='Analiz penceresi fiilen kisitli - kapsam belirlerken dikkate al'; Artifact='11_log_health'; Module='Event Log Health' }
    @{ Id='DGL-017'; Sev='MEDIUM'; Title='Sysmon kurulu degil'; Mitre=''; Why='Process/ag/pipe gorunurlugu ciddi sekilde kisitli - hunting derinligi dusuk'; Artifact='11_log_health'; Module='Event Log Health' }
    @{ Id='DGL-018'; Sev='INFO'; Title='Event toplama limiti asildi - veri kisitli'; Mitre=''; Why='Analiz penceresini daraltin veya -MaxEventsPerChannel degerini artirin'; Artifact='11_event_stats'; Module='Drivers' }
    @{ Id='DGL-019'; Sev='INFO'; Title='Dosya tarama limiti asildi'; Mitre=''; Why='Analiz penceresini daraltin'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-020'; Sev='MEDIUM'; Title='Hesap parolasi analiz penceresi icinde degistirilmis'; Mitre='T1098'; Why='Hesap ele gecirildiyse saldirgan parolayi degistirmis olabilir'; Artifact='02_local_users'; Module='Users and Groups' }
    @{ Id='DGL-021'; Sev='HIGH'; Title='Aktif hesap parola gerektirmiyor'; Mitre='T1078.003'; Why='Parolasiz aktif hesap dogrudan erisim saglar'; Artifact='02_local_users'; Module='Users and Groups' }
    @{ Id='DGL-022'; Sev='(tablo)'; Title='Yerlesik hesap aktif'; Mitre='T1078.001'; Why='Guest ve yerlesik Administrator genelde devre disi olmalidir'; Artifact='02_local_users'; Module='Users and Groups' }
    @{ Id='DGL-023'; Sev='HIGH'; Title='Analiz penceresi icinde yeni kullanici profili olusmus'; Mitre='T1136.001'; Why='Yeni hesap olusturma yaygin bir persistence teknigidir'; Artifact='02_user_profiles'; Module='Users and Groups' }
    @{ Id='DGL-024'; Sev='MEDIUM'; Title='Lokal Administrators grubunda cok sayida uye'; Mitre='T1078'; Why='Genis admin uyeligi yatay hareket yuzeyini buyutur'; Artifact='02_group_members'; Module='Users and Groups' }
    @{ Id='DGL-030'; Sev='CRITICAL'; Title='Autorun supheli dizinden calisiyor'; Mitre='T1547'; Why='Mesru autorun girdileri System32 veya Program Files altindadir'; Artifact=''; Module='Event Log Health' }
    @{ Id='DGL-031'; Sev='HIGH'; Title='Autorun imzasiz binary'; Mitre='T1547'; Why='Imzasiz kalici baslatma girdisi'; Artifact=''; Module='Event Log Health' }
    @{ Id='DGL-032'; Sev='MEDIUM'; Title='Autorun hedefi mevcut degil'; Mitre=''; Why='Temizlenmis malware kalintisi veya path hijacking firsati'; Artifact=''; Module='Event Log Health' }
    @{ Id='DGL-033'; Sev='(tablo)'; Title='Autorun supheli komut: <N>'; Mitre='(tablo)'; Why='Kalici girdide saldirgan davranis pattern eslesmesi'; Artifact=''; Module='Event Log Health' }
    @{ Id='DGL-040'; Sev='HIGH'; Title='Process supheli dizinden calisiyor'; Mitre='T1036'; Why='Temp/AppData/ProgramData malware icin en yaygin calisma dizinleridir'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-041'; Sev='HIGH'; Title='Imzasiz process kullanici profilinden calisiyor'; Mitre='T1204'; Why='Mesru yazilim genelde Program Files altinda ve imzalidir'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-042'; Sev='CRITICAL'; Title='Sistem binary beklenmedik konumda (masquerading)'; Mitre='T1036.005'; Why='$($pr.Name) normalde System32 altindan calisir'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-043'; Sev='(tablo)'; Title='Supheli komut satiri: <N>'; Mitre='(tablo)'; Why='Saldirgan davranisiyla eslesen komut satiri'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-044'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre='(tablo)'; Why='Bu ust-alt process iliskisi normal isletim sirasinda olusmaz'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-045'; Sev='HIGH'; Title='Sikistirma/exfil/tunel araci calisiyor'; Mitre='T1560'; Why='Veri toplama ve disari cikarma asamasinin gostergesi'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-046'; Sev='MEDIUM'; Title='Process yolu okunamadi'; Mitre=''; Why='Korunan process olabilir; ya da imaj diskten silinmis'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-047'; Sev='HIGH'; Title='Coklu kesif komutu ayni anda calisiyor'; Mitre='T1082'; Why='Elle yurutulen kesif faaliyeti gostergesi'; Artifact='03_processes'; Module='Process Tree' }
    @{ Id='DGL-050'; Sev='CRITICAL'; Title='netsh portproxy kurali mevcut (tunelleme)'; Mitre='T1090.001'; Why='Port yonlendirme neredeyse her zaman pivot/tunel amaclidir'; Artifact='04_portproxy'; Module='Network Connections' }
    @{ Id='DGL-051'; Sev='HIGH'; Title='Kullanici proxy AutoConfigURL ayarlanmis'; Mitre='T1090'; Why='Zararli PAC dosyasi trafigi saldirgan altyapisina yonlendirebilir'; Artifact='04_proxy_config'; Module='Network Connections' }
    @{ Id='DGL-052'; Sev='HIGH'; Title='Hosts dosyasi analiz penceresi icinde degistirilmis'; Mitre='T1565.001'; Why='Guvenlik urunu alan adlarinin bloklanmasi veya trafik yonlendirmesi'; Artifact='04_hosts'; Module='Network Connections' }
    @{ Id='DGL-053'; Sev='CRITICAL'; Title='Supheli process dis IP ile iletisimde (C2 supheli)'; Mitre='T1071'; Why='Gecici dizinden calisan bir processin dis baglantisi C2 gostergesidir'; Artifact='04_tcp_connections'; Module='Network Connections' }
    @{ Id='DGL-054'; Sev='HIGH'; Title='Imzasiz process dis IP ile iletisimde'; Mitre='T1071'; Why='Imzasiz binary ile dis ag trafigi C2 kanalinin en yaygin gorunumudur'; Artifact='04_tcp_connections'; Module='Network Connections' }
    @{ Id='DGL-055'; Sev='CRITICAL'; Title='Supheli process tum arayuzlerde dinliyor (backdoor)'; Mitre='T1571'; Why='Imzasiz veya gecici dizinden calisan bir dinleyici backdoor gostergesidir'; Artifact='04_listening_ports'; Module='Network Connections' }
    @{ Id='DGL-056'; Sev='HIGH'; Title='Firewall profili devre disi'; Mitre='T1562.004'; Why='Saldirganlar C2 ve lateral movement icin firewalli kapatir'; Artifact='04_firewall_profiles'; Module='Network Connections' }
    @{ Id='DGL-057'; Sev='CRITICAL'; Title='Firewall kurali supheli binary icin gelen trafige izin veriyor'; Mitre='T1562.004'; Why='Saldirgan kalici erisim icin firewall kurali ekler; mesru yazilim Temp/AppData altindan dinlemez'; Artifact='04_firewall_inbound_allow'; Module='Network Connections' }
    @{ Id='DGL-060'; Sev='HIGH'; Title='Servis binary imzasiz'; Mitre='T1543.003'; Why='Windows servislerinin buyuk cogunlugu imzalidir; imzasiz olan incelenmelidir'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-061'; Sev='MEDIUM'; Title='Tirnaksiz servis yolu (binary hijack riski)'; Mitre='T1574.009'; Why='Bosluk iceren tirnaksiz yol, ust dizine binary birakilarak ele gecirilebilir'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-062'; Sev='HIGH'; Title='Servis binary analiz penceresi icinde degismis'; Mitre='T1543.003'; Why='Mevcut servisin binarysi degistirilerek kalicilik saglanabilir (service hijacking)'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-063'; Sev='HIGH'; Title='Rastgele gorunumlu servis adi'; Mitre='T1569.002'; Why='Cobalt Strike ve benzeri araclar rastgele servis adi uretir'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-064'; Sev='CRITICAL'; Title='Uzaktan calistirma servisi tespit edildi'; Mitre='T1569.002'; Why='PsExec ve turevleri lateral movement icin kullanilir'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-065'; Sev='(tablo)'; Title='Servis yolunda supheli komut: <N>'; Mitre='(tablo)'; Why='Servis komut satirinda saldirgan davranisiyla eslesen pattern'; Artifact='05_services'; Module='Services' }
    @{ Id='DGL-070'; Sev='CRITICAL'; Title='Zamanlanmis gorev supheli dizinden calisiyor'; Mitre='T1053.005'; Why='Mesru gorevler System32 veya Program Files altindan calisir'; Artifact='06_scheduled_tasks'; Module='Scheduled Tasks' }
    @{ Id='DGL-071'; Sev='MEDIUM'; Title='Gorev kok dizinde tanimli'; Mitre='T1053.005'; Why='Saldirgan tarafindan olusturulan gorevler genelde kok dizinde birakilir'; Artifact='06_scheduled_tasks'; Module='Scheduled Tasks' }
    @{ Id='DGL-072'; Sev='HIGH'; Title='Zamanlanmis gorev imzasiz binary calistiriyor'; Mitre='T1053.005'; Why='Imzasiz binary calistiran gorev yaygin bir kalicilik yontemidir'; Artifact='06_scheduled_tasks'; Module='Scheduled Tasks' }
    @{ Id='DGL-073'; Sev='HIGH'; Title='Microsoft disi gorev SYSTEM olarak calisiyor'; Mitre='T1053.005'; Why='SYSTEM yetkisiyle calisan ucuncu parti gorev yetki yukseltme ve kalicilik saglar'; Artifact='06_scheduled_tasks'; Module='Scheduled Tasks' }
    @{ Id='DGL-074'; Sev='(tablo)'; Title='Gorev komutunda supheli pattern: <N>'; Mitre='(tablo)'; Why='Gorev komut satirinda saldirgan davranisiyla eslesen pattern'; Artifact='06_scheduled_tasks'; Module='Scheduled Tasks' }
    @{ Id='DGL-075'; Sev='HIGH'; Title='Analiz penceresi icinde yeni gorev olusturulmus'; Mitre='T1053.005'; Why='Analiz penceresi icinde olusturulan gorev saldirgan kaliciligi olabilir'; Artifact='06_task_files'; Module='Scheduled Tasks' }
    @{ Id='DGL-080'; Sev='CRITICAL'; Title='Winlogon <NAME> degeri degistirilmis'; Mitre='T1547.004'; Why='Beklenen deger: $exp'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-081'; Sev='CRITICAL'; Title='AppInit_DLLs tanimli'; Mitre='T1546.010'; Why='AppInit_DLLs her user32.dll yukleyen process icine DLL enjekte eder'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-082'; Sev='(tablo)'; Title='IFEO Debugger tanimli'; Mitre='T1546.012'; Why='Hedef binary calistirildiginda onun yerine debugger calisir (accessibility backdoor)'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-083'; Sev='CRITICAL'; Title='SilentProcessExit MonitorProcess tanimli'; Mitre='T1546.012'; Why='Hedef process sonlandiginda belirtilen binary calisir'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-084'; Sev='CRITICAL'; Title='LSA paket listesinde bilinmeyen giris'; Mitre='T1547.002'; Why='LSA icine yuklenen ozel DLL kimlik bilgisi calabilir'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-085'; Sev='CRITICAL'; Title='AppCertDlls girdisi mevcut'; Mitre='T1546.009'; Why='Bu anahtar varsayilan olarak bostur; her CreateProcess cagrisinda DLL yuklenir'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-086'; Sev='HIGH'; Title='Standart disi Time Provider DLL'; Mitre='T1547.003'; Why='Time Provider kaydi w32time tarafindan SYSTEM olarak yuklenir; varsayilan disi DLL kaliciliktir'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-087'; Sev='CRITICAL'; Title='UserInitMprLogonScript tanimli'; Mitre='T1037.001'; Why='Bu deger varsayilan olarak yoktur; her oturum acilisinda calisir'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-088'; Sev='HIGH'; Title='BITS transfer isi mevcut'; Mitre='T1197'; Why='BITS hem indirme hem kalicilik icin kullanilir'; Artifact='07_bits_jobs'; Module='Autoruns / ASEP' }
    @{ Id='DGL-089'; Sev='HIGH'; Title='Winlogon <NAME> tanimli'; Mitre='T1547.004'; Why='Bu deger varsayilan olarak bulunmaz'; Artifact='07_autoruns'; Module='Autoruns / ASEP' }
    @{ Id='DGL-090'; Sev='CRITICAL'; Title='WMI kalici event aboneligi mevcut'; Mitre='T1546.003'; Why='Filter-Consumer baglamasi fileless kaliciligin en yaygin bicimidir'; Artifact='08_wmi_persistence'; Module='WMI Persistence' }
    @{ Id='DGL-091'; Sev='CRITICAL'; Title='WMI consumer supheli komut: <N>'; Mitre='(tablo)'; Why='WMI consumer komutu tetiklendiginde SYSTEM yetkisiyle calisir'; Artifact='08_wmi_persistence'; Module='WMI Persistence' }
    @{ Id='DGL-100'; Sev='HIGH'; Title='Bilinen C2 pipe pattern eslesmesi'; Mitre='T1071'; Why='Cobalt Strike ve benzeri C2 cerceveleri karakteristik pipe adlari kullanir'; Artifact='09_named_pipes'; Module='Named Pipes' }
    @{ Id='DGL-110'; Sev='CRITICAL'; Title='Defender koruma bileseni devre disi'; Mitre='T1562.001'; Why='Saldirganlarin ilk isi genelde AV korumasini kapatmaktir'; Artifact='12_defender_status'; Module='Security Posture' }
    @{ Id='DGL-111'; Sev='MEDIUM'; Title='Defender imzalari guncel degil'; Mitre='T1562.001'; Why='Eski imza veritabani yeni tehditleri kacirir; guncelleme engellenmis olabilir'; Artifact='12_defender_status'; Module='Security Posture' }
    @{ Id='DGL-112'; Sev='(tablo)'; Title='Defender exclusion tanimli'; Mitre='T1562.001'; Why='Saldirganlar payload dizinini exclusion listesine ekler'; Artifact='12_defender_exclusions'; Module='Security Posture' }
    @{ Id='DGL-113'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre=''; Why='Temizlenemeyen tespit aktif enfeksiyona isaret eder; temizlenen tespit bile giris vektorunu gosterir'; Artifact='12_defender_threats'; Module='Security Posture' }
    @{ Id='DGL-114'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre='(tablo)'; Why='(tablo)'; Artifact='12_security_config'; Module='Security Posture' }
    @{ Id='DGL-115'; Sev='HIGH'; Title='Kayitli AMSI provider bulunamadi'; Mitre='T1562.001'; Why='AMSI provider kaydi silinmis olabilir - script tarama devre disi'; Artifact='12_security_config'; Module='Security Posture' }
    @{ Id='DGL-116'; Sev='MEDIUM'; Title='Kritik denetim kategorisi kapali'; Mitre='T1562.002'; Why='Bu kategori kapaliyken ilgili eventler hic uretilmez'; Artifact='12_audit_policy'; Module='Security Posture' }
    @{ Id='DGL-117'; Sev='MEDIUM'; Title='Hicbir shadow copy bulunamadi'; Mitre='T1490'; Why='Sunucularda genelde shadow copy bulunur; silinmis olabilir'; Artifact='12_shadow_copies'; Module='Security Posture' }
    @{ Id='DGL-120'; Sev='HIGH'; Title='Paylasim Everyone hesabina tam yetki veriyor'; Mitre='T1135'; Why='Kimlik dogrulamasiz yazma yetkisi lateral movement ve veri sizdirmayi kolaylastirir'; Artifact='10_smb_shares'; Module='SMB / Shares' }
    @{ Id='DGL-121'; Sev='HIGH'; Title='Surucu koku paylasima acilmis'; Mitre='T1135'; Why='Varsayilan yonetimsel paylasimlar disinda surucu koku paylasimi nadiren mesrudur'; Artifact='10_smb_shares'; Module='SMB / Shares' }
    @{ Id='DGL-130'; Sev='CRITICAL'; Title='Surucu supheli dizinden yuklenmis'; Mitre='T1068'; Why='BYOVD saldirilarinda surucu gecici dizinden yuklenir'; Artifact='09_drivers'; Module='Drivers' }
    @{ Id='DGL-131'; Sev='HIGH'; Title='Imzasiz surucu calisiyor'; Mitre='T1068'; Why='Kernel modunda calisan imzasiz kod rootkit veya BYOVD gostergesidir'; Artifact='09_drivers'; Module='Drivers' }
    @{ Id='DGL-132'; Sev='HIGH'; Title='Surucu analiz penceresi icinde yazilmis'; Mitre='T1068'; Why='Analiz penceresi icinde diske yazilan surucu BYOVD saldirisi olabilir'; Artifact='09_drivers'; Module='Drivers' }
    @{ Id='DGL-140'; Sev='MEDIUM'; Title='Process olusturma denetimi (4688) kaydi yok'; Mitre='T1562.002'; Why='Bu denetim kapaliysa gecmis calistirma faaliyeti gorunmez'; Artifact='11_evt_4688'; Module='Event: Process Creation (4688)' }
    @{ Id='DGL-141'; Sev='MEDIUM'; Title='4688 eventleri komut satiri icermiyor'; Mitre='T1562.002'; Why='ProcessCreationIncludeCmdLine_Enabled kapali - hunting degeri buyuk olcude dusuk'; Artifact='11_evt_4688'; Module='Event: Process Creation (4688)' }
    @{ Id='DGL-142'; Sev='HIGH'; Title='Gecmiste supheli dizinden process calistirilmis'; Mitre='T1036'; Why='Process artik calismiyor olabilir; event kaydi tek kanittir'; Artifact='11_evt_4688'; Module='Event: Process Creation (4688)' }
    @{ Id='DGL-144'; Sev='HIGH'; Title='Encoded PowerShell komutu cozuldu'; Mitre='T1027'; Why='Base64 gizlenmis komutun acik hali'; Artifact='11_evt_4688'; Module='Event: Process Creation (4688)' }
    @{ Id='DGL-146'; Sev='(tablo)'; Title='<NAME> [gecmis]'; Mitre='(tablo)'; Why='Gecmis event kaydinda supheli ust-alt process iliskisi'; Artifact='11_evt_4688'; Module='Event: Process Creation (4688)' }
    @{ Id='DGL-150'; Sev='HIGH'; Title='PowerShell supheli script block olarak isaretledi'; Mitre='T1059.001'; Why='Script block logging kapali olsa bile Warning seviyeli bloklar kaydedilir'; Artifact='11_evt_ps_4104'; Module='Event: PowerShell (4104/4103/400)' }
    @{ Id='DGL-152'; Sev='MEDIUM'; Title='PowerShell Remoting oturumu tespit edildi'; Mitre='T1021.006'; Why='Uzaktan PowerShell erisimi lateral movement gostergesi olabilir'; Artifact='11_evt_ps_classic'; Module='Event: PowerShell (4104/4103/400)' }
    @{ Id='DGL-160'; Sev='HIGH'; Title='Logon Type 9 (NewCredentials/RunAs) tespit edildi'; Mitre='T1550.002'; Why='Type 9 pass-the-hash ve overpass-the-hash saldirilarinin tipik izidir'; Artifact='11_evt_4624_logon'; Module='Event: Logon Activity' }
    @{ Id='DGL-161'; Sev='MEDIUM'; Title='Logon Type 8 (NetworkCleartext)'; Mitre='T1078'; Why='Parola ag uzerinden duz metin gecmis olabilir'; Artifact='11_evt_4624_logon'; Module='Event: Logon Activity' }
    @{ Id='DGL-162'; Sev='HIGH'; Title='Ozel ag disindan RDP oturumu'; Mitre='T1021.001'; Why='Internete acik RDP yaygin bir initial access vektorudur'; Artifact='11_evt_4624_logon'; Module='Event: Logon Activity' }
    @{ Id='DGL-163'; Sev='HIGH'; Title='<DEGISKEN> supheli (4625 yogunlugu)'; Mitre='T1110'; Why='Tek kaynaktan yogun kimlik dogrulama hatasi'; Artifact='11_evt_4625_failed'; Module='Event: Logon Activity' }
    @{ Id='DGL-164'; Sev='CRITICAL'; Title='Basarisiz denemelerden sonra BASARILI logon'; Mitre='T1110'; Why='Brute force / spray sonrasi hesap ele gecirilmis olabilir'; Artifact='11_evt_4624_logon'; Module='Event: Logon Activity' }
    @{ Id='DGL-165'; Sev='MEDIUM'; Title='Explicit credential ile uzak sunucuya erisim'; Mitre='T1021'; Why='4648 lateral movementin en guvenilir gostergelerindendir'; Artifact='11_evt_4648_explicit'; Module='Event: Logon Activity' }
    @{ Id='DGL-166'; Sev='MEDIUM'; Title='Mesai disi interaktif oturum (00:00-05:00 UTC)'; Mitre=''; Why='Saldirgan aktivitesi genelde normal calisma saatleri disinda gorulur'; Artifact='11_evt_4624_logon'; Module='Event: Logon Activity' }
    @{ Id='DGL-170'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre='T1136.001'; Why='Hesap olusturma, silme ve parola sifirlama saldirgan kaliciliginin en yaygin izleridir'; Artifact='11_evt_account_mgmt'; Module='Event: Account / Policy Changes' }
    @{ Id='DGL-171'; Sev='(tablo)'; Title='Ayricalikli gruba uye eklendi'; Mitre='T1098'; Why='Grup uyeligi degisimi yetki yukseltme ve kalicilik gostergesidir'; Artifact='11_evt_group_mgmt'; Module='Event: Account / Policy Changes' }
    @{ Id='DGL-172'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre='T1070.001'; Why='Iz temizleme faaliyeti - saldirinin aktif oldugunun gostergesi'; Artifact='11_evt_antiforensics'; Module='Event: Account / Policy Changes' }
    @{ Id='DGL-173'; Sev='HIGH'; Title='Servis kurulumu kaydi (4697)'; Mitre='T1543.003'; Why='Servis kurulumu uzaktan calistirma ve kalicilik icin kullanilir'; Artifact='11_evt_4697_service'; Module='Event: Account / Policy Changes' }
    @{ Id='DGL-175'; Sev='HIGH'; Title='(tablo tanimli)'; Mitre='T1053.005'; Why='Gorev olusturma ve guncelleme kaydi kalicilik kurulumunu tarihlendirir'; Artifact='11_evt_task_mgmt'; Module='Event: Account / Policy Changes' }
    @{ Id='DGL-180'; Sev='(tablo)'; Title='Yeni servis kuruldu (7045)'; Mitre='T1543.003'; Why='PsExec, Impacket ve Cobalt Strike SMB beaconi servis olarak kurulur'; Artifact='11_evt_7045_newservice'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-181'; Sev='CRITICAL'; Title='Rastgele isimli servis kurulmus'; Mitre='T1569.002'; Why='Rastgele karakter dizisi C2 cerceve varsayilanlarinin tipik imzasidir'; Artifact='11_evt_7045_newservice'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-183'; Sev='CRITICAL'; Title='Guvenlik servisinin baslangic tipi degistirildi'; Mitre='T1562.001'; Why='Savunma mekanizmasi devre disi birakilmis olabilir'; Artifact='11_evt_7040_starttype'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-184'; Sev='CRITICAL'; Title='Guvenlik servisi beklenmedik sekilde sonlandi'; Mitre='T1562.001'; Why='Guvenlik servisinin durmasi ya saldiri ya da telemetri kaybidir; her iki durumda kapsam daralir'; Artifact='11_evt_system'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-185'; Sev='CRITICAL'; Title='Event log temizlendi (System 104)'; Mitre='T1070.001'; Why='Iz temizleme faaliyeti'; Artifact='11_evt_system'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-190'; Sev='HIGH'; Title='Ozel ag disindan RDP baglantisi (1149)'; Mitre='T1021.001'; Why='Internete acik RDP en yaygin ilk erisim vektorlerinden biridir'; Artifact='11_evt_rdp_inbound'; Module='Event: RDP / WinRM' }
    @{ Id='DGL-191'; Sev='HIGH'; Title='Bu hosttan DISARI RDP baglantisi'; Mitre='T1021.001'; Why='Giden RDP, bu hostun lateral movement kaynagi oldugunu gosterir'; Artifact='11_evt_rdp_outbound'; Module='Event: RDP / WinRM' }
    @{ Id='DGL-192'; Sev='MEDIUM'; Title='WinRM kimlik dogrulamasi'; Mitre='T1021.006'; Why='Uzaktan yonetim erisimi lateral movement icin kullanilabilir'; Artifact='11_evt_winrm'; Module='Event: RDP / WinRM' }
    @{ Id='DGL-200'; Sev='HIGH'; Title='(tablo tanimli)'; Mitre='T1053.005'; Why='Gorev kaydi ve calistirma olaylari kalicilik zaman cizelgesini kurar'; Artifact='11_evt_taskscheduler'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-201'; Sev='CRITICAL'; Title='WMI kalici event aboneligi kaydi (5861)'; Mitre='T1546.003'; Why='5861 dogrudan WMI kaliciliginin kanitidir'; Artifact='11_evt_wmi_activity'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-202'; Sev='(tablo)'; Title='(tablo tanimli)'; Mitre='T1562.001'; Why='Koruma bileseninin kapanmasi payload calistirmadan hemen once yapilir'; Artifact='11_evt_defender'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-203'; Sev='MEDIUM'; Title='BITS uzerinden dosya transferi'; Mitre='T1197'; Why='BITS AV/EDR gozunden kacan yaygin bir indirme kanalidir'; Artifact='11_evt_bits'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-204'; Sev='HIGH'; Title='Kod butunlugu ihlali (imzasiz surucu/imaj)'; Mitre='T1068'; Why='BYOVD saldiri denemesinin izi olabilir'; Artifact='11_evt_codeintegrity'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-205'; Sev='(tablo)'; Title='Firewall: <ACTION>'; Mitre='T1562.004'; Why='Firewall kurali degisiklikleri gelen C2 ve lateral movement icin yol acar'; Artifact='11_evt_firewall'; Module='Event: Persistence and Defense Channels' }
    @{ Id='DGL-210'; Sev='CRITICAL'; Title='LSASS bellegine erisim (credential dump)'; Mitre='T1003.001'; Why='Bu erisim maskesi LSASS bellegini okumak icin kullanilir'; Artifact='11_sysmon_10_lsass'; Module='Event: Sysmon' }
    @{ Id='DGL-211'; Sev='HIGH'; Title='CreateRemoteThread (process injection)'; Mitre='T1055'; Why='Process injection tespit kacirma ve mesru process icinde calisma icin kullanilir'; Artifact='11_sysmon_08_injection'; Module='Event: Sysmon' }
    @{ Id='DGL-212'; Sev='HIGH'; Title='C2 patterni ile eslesen named pipe olusturuldu'; Mitre='T1071'; Why='Cobalt Strike ve benzeri cerceveler varsayilan pipe adlariyla haberlesir'; Artifact='11_sysmon_17_pipes'; Module='Event: Sysmon' }
    @{ Id='DGL-213'; Sev='CRITICAL'; Title='Process tampering (hollowing/herpaderping)'; Mitre='T1055.012'; Why='Hollowing ve herpaderping diskteki dosya ile bellekteki kodu birbirinden ayirir'; Artifact='11_sysmon_25_tampering'; Module='Event: Sysmon' }
    @{ Id='DGL-214'; Sev='CRITICAL'; Title='Sysmon WMI event kaydi (kalicilik)'; Mitre='T1546.003'; Why='WMI abonelikleri diskte dosya birakmadan kalicilik saglar'; Artifact='11_sysmon_19_wmi'; Module='Event: Sysmon' }
    @{ Id='DGL-220'; Sev='CRITICAL'; Title='Kerberoasting supheli (RC4 service ticket yogunlugu)'; Mitre='T1558.003'; Why='Tek hesabin cok sayida servise RC4 bileti almasi Kerberoast saldirisinin imzasidir'; Artifact='11_evt_4769_kerberos'; Module='Event: Kerberos (DC)' }
    @{ Id='DGL-221'; Sev='HIGH'; Title='Kerberos pre-authentication olmadan TGT istegi (AS-REP roast)'; Mitre='T1558.004'; Why='Pre-auth devre disi hesaplar cevrimdisi parola kirmaya aciktir'; Artifact='11_evt_4768_tgt'; Module='Event: Kerberos (DC)' }
    @{ Id='DGL-222'; Sev='MEDIUM'; Title='RC4 sifreleme ile TGT (encryption downgrade)'; Mitre='T1558'; Why='Overpass-the-hash saldirilari RC4 kullanir'; Artifact='11_evt_4768_tgt'; Module='Event: Kerberos (DC)' }
    @{ Id='DGL-223'; Sev='HIGH'; Title='Kerberos parola deneme saldirisi (4771 yogunlugu)'; Mitre='T1110.003'; Why='Yogun 4771 password spraying veya brute force gostergesidir'; Artifact='11_evt_4771_preauth'; Module='Event: Kerberos (DC)' }
    @{ Id='DGL-224'; Sev='CRITICAL'; Title='DCSync girisimi (dizin replikasyon hakki kullanildi)'; Mitre='T1003.006'; Why='DC olmayan bir principal replikasyon hakki kullaniyor - tum parola hashlerini cekebilir'; Artifact='11_evt_4662_dcsync'; Module='Event: Kerberos (DC)' }
    @{ Id='DGL-230'; Sev='HIGH'; Title='New executable file in a suspicious directory'; Mitre='T1105'; Why='Analiz penceresi icinde Temp/AppData altina yazilan calistirilabilir dosya payload olabilir'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-231'; Sev='MEDIUM'; Title='Internetten indirilmis dosya (MOTW)'; Mitre='T1105'; Why='Zone.Identifier alternatif veri akisi indirme kaynagini tasir'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-232'; Sev='MEDIUM'; Title='Zaman damgasi manipulasyonu supheli'; Mitre='T1070.006'; Why='Olusturma zamani degistirme zamanindan sonra veya milisaniye alanlari sifir'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-240'; Sev='(tablo)'; Title='Possible WEBSHELL: <PATTERN>'; Mitre='T1505.003'; Why='Command execution pattern matched in the web root'; Artifact='13_webshell_hits'; Module='Webshell Hunt' }
    @{ Id='DGL-241'; Sev='HIGH'; Title='Web kokune analiz penceresi icinde yeni dosya yazilmis'; Mitre='T1505.003'; Why='Deployment disi web dosyasi degisimi webshell yerlestirmesini gosterebilir'; Artifact='13_web_files'; Module='Webshell Hunt' }
    @{ Id='DGL-250'; Sev='(tablo)'; Title='Analiz penceresi icinde olusturulmus arsiv'; Mitre='T1560'; Why='Veri toplama asamasinda saldirgan dosyalari arsivler'; Artifact='13_archives'; Module='Exfiltration Traces' }
    @{ Id='DGL-251'; Sev='CRITICAL'; Title='Saldirgan/uzaktan erisim araci diskte bulundu'; Mitre='T1219'; Why='Bu araclar kullanici dizinlerinde mesru olarak bulunmaz'; Artifact='13_attacker_tools'; Module='Exfiltration Traces' }
    @{ Id='DGL-261'; Sev='HIGH'; Title='Konsol gecmisinde encoded komut cozuldu'; Mitre='T1027'; Why='PSReadLine gecmisi silinmemis komutlari saklar; kodlama gizleme amaclidir'; Artifact='14_ps_history'; Module='User Activity' }
    @{ Id='DGL-262'; Sev='MEDIUM'; Title='Bu hosttan RDP baglanti gecmisi kaydi'; Mitre='T1021.001'; Why='Yayilim haritasi: bu makineden hangi sistemlere baglanilmis'; Artifact='14_rdp_history'; Module='User Activity' }
    @{ Id='DGL-263'; Sev='MEDIUM'; Title='Prefetch kayitlari yok'; Mitre='T1070'; Why='Prefetch kapatilmis olabilir - calistirma kaniti kaybi'; Artifact='14_prefetch'; Module='User Activity' }
    @{ Id='DGL-264'; Sev='HIGH'; Title='Supheli program analiz penceresi icinde calistirilmis (Prefetch)'; Mitre='T1204'; Why='Prefetch, process sonlansa bile calistirma kanitini korur'; Artifact='14_prefetch'; Module='User Activity' }
    @{ Id='DGL-270'; Sev='(tablo)'; Title='Guvenilir kok deposunda taninmayan sertifika'; Mitre='T1553.004'; Why='Sahte kok CA, TLS kesme ve kod imzalama sahteciligine imkan verir'; Artifact='15_certificates'; Module='Certificate Store' }
    @{ Id='DGL-DYNAMIC'; Sev='(tablo)'; Title='Event kaydinda supheli komut: <N>'; Mitre='(tablo)'; Why='Gecmis event kaydinda saldirgan davranis pattern eslesmesi'; Artifact=''; Module='Drivers' }
    @{ Id='DGL-IOC'; Sev='CRITICAL'; Title='IOC eslesmesi (<DEGISKEN>)'; Mitre='T1587'; Why='Saglanan IOC listesiyle eslesme'; Artifact=''; Module='' }
    @{ Id='DGL-265'; Sev='MEDIUM'; Title='Prefetch: program supheli dizinden dosya yuklemis'; Mitre='T1204'; Why='Prefetch yuklenen dosya listesi payloadin diskteki gercek konumunu gosterir'; Artifact='14_prefetch'; Module='User Activity' }
    @{ Id='DGL-266'; Sev='INFO'; Title='ShimCache okunamadi veya bos'; Mitre='T1070'; Why='ShimCache silinmis binary izlerini tutar; erisilemiyorsa gorunurluk kaybidir'; Artifact='15_shimcache'; Module='Execution Evidence (ShimCache/Amcache)' }
    @{ Id='DGL-267'; Sev='HIGH'; Title='ShimCache: supheli dizinde binary kaydi'; Mitre='T1070.004'; Why='ShimCache dosya silinse bile kaydi korur; silinmis payloadin en guclu kanitidir'; Artifact='15_shimcache'; Module='Execution Evidence (ShimCache/Amcache)' }
    @{ Id='DGL-268'; Sev='CRITICAL'; Title='ShimCache: saldiri araci kaydi'; Mitre='T1588.002'; Why='Bu araclar mesru is yuklerinde bulunmaz; kayit diskten silinse bile kalir'; Artifact='15_shimcache'; Module='Execution Evidence (ShimCache/Amcache)' }
    @{ Id='DGL-269'; Sev='HIGH'; Title='Amcache: supheli dizinde program kaydi'; Mitre='T1204'; Why='Amcache SHA1 hash ve ilk gorulme zamanini tutar; Prefetch silinse bile iz kalir'; Artifact='15_amcache'; Module='Execution Evidence (ShimCache/Amcache)' }
    @{ Id='DGL-271'; Sev='INFO'; Title='Amcache okunamadi'; Mitre='T1070'; Why='Amcache calistirma izlerinin ikinci kaynagidir; -CollectRaw ile VSS uzerinden alinabilir'; Artifact='15_amcache'; Module='Execution Evidence (ShimCache/Amcache)' }
    @{ Id='DGL-400'; Sev='INFO'; Title='Sigma kural eslesmeleri mevcut'; Mitre=''; Why='Topluluk Sigma kurallari degisken kalitededir; risk skoruna dahil edilmez, ipucu olarak incelenir'; Artifact='SIGMA'; Module='Sigma Matching' }
    @{ Id='DGL-401'; Sev='INFO'; Title='Sigma degerlendirmesi sure butcesi nedeniyle tamamlanmadi'; Mitre=''; Why='Daha kucuk/odakli bir sigma-pack kullanin veya butceyi artirin; kapsam eksikligi bilinmelidir'; Artifact='SIGMA'; Module='Sigma Matching' }
    @{ Id='DGL-410'; Sev='INFO'; Title='YARA taramasi yapilmadi (bilesen eksik)'; Mitre=''; Why='Menu > Guncelleme Merkezi uzerinden YARA motoru ve kurallari indirilebilir'; Artifact='16_yara'; Module='YARA Scan' }
    @{ Id='DGL-411'; Sev='HIGH'; Title='YARA eslesmesi'; Mitre='T1204'; Why='YARA-Forge kalite filtreli kural seti; eslesme dogrulanmalidir'; Artifact='16_yara'; Module='YARA Scan' }
    @{ Id='DGL-412'; Sev='INFO'; Title='YARA taramasi sure siniri nedeniyle tamamlanmadi'; Mitre=''; Why='Kapsam eksikligi bilinmelidir'; Artifact='16_yara'; Module='YARA Scan' }
    @{ Id='DGL-182'; Sev='HIGH'; Title='Suspicious command in new service (7045)'; Mitre='T1543.003'; Why='Attacker behaviour pattern matched in the ImagePath of a newly installed service'; Artifact='11_evt_7045_newservice'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-260'; Sev='HIGH'; Title='Suspicious command in console history'; Mitre='T1059.001'; Why='PSReadLine history retains commands that were not cleared; hands-on-keyboard evidence'; Artifact='14_ps_history'; Module='User Activity' }
    @{ Id='DGL-300'; Sev='HIGH'; Title='Baseline''da olmayan yeni nesne'; Mitre='T1543'; Why='Onceki koleksiyonda bu nesne yoktu; analiz penceresi disinda eklenmis olabilir'; Artifact='DELTA'; Module='Baseline Comparison' }
    @{ Id='DGL-301'; Sev='MEDIUM'; Title='Yuksek nadirlik skoru'; Mitre='T1543'; Why='Imzasiz + bilinmeyen yayinci + sira-disi konum kombinasyonu; tekil inceleme adayi'; Artifact='RARITY'; Module='Rarity Scoring' }
    @{ Id='DGL-058'; Sev='CRITICAL'; Title='Duzenli aralikli dis baglanti (beaconing supheli)'; Mitre='T1071'; Why='Sabit araliklarla tekrar eden dis baglanti otomatik C2 beacon imzasidir'; Artifact='11_sysmon_3_network'; Module='Event: Sysmon' }
    @{ Id='DGL-059'; Sev='INFO'; Title='Ag gorunurlugu kisitli - sadece anlik baglantilar'; Mitre='T1071'; Why='Beaconing analizi icin Sysmon Event 3 gerekir'; Artifact='04_tcp_connections'; Module='Network Connections' }
    @{ Id='DGL-145'; Sev='HIGH'; Title='Cozulmus komutta supheli pattern'; Mitre=''; Why='Gizlenmis payload icinde saldirgan davranis pattern eslesmesi'; Artifact=''; Module='Central (Invoke-DDeobfuscateAndScan)' }
    @{ Id='DGL-151'; Sev='MEDIUM'; Title='Obfuscated komut satiri'; Mitre='T1027.010'; Why='Coklu gizleme gostergesi mesru komutlarda nadiren bir arada bulunur'; Artifact=''; Module='Central (Invoke-DDeobfuscateAndScan)' }
    @{ Id='DGL-186'; Sev='CRITICAL'; Title='Yeni servis sistem binary maskeliyor'; Mitre='T1036.005'; Why='Servis binary adi korumali sistem binarysini taklit ediyor'; Artifact='11_evt_7045_newservice'; Module='Event: System (7045/7040/104)' }
    @{ Id='DGL-233'; Sev='CRITICAL'; Title='PE binary hidden behind the wrong extension'; Mitre='T1036.008'; Why='MZ header tasiyan dosya calistirilabilir; uzantisi bunu gizliyor'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-234'; Sev='HIGH'; Title='Dosya icerik imzasi eslesmesi'; Mitre='T1003'; Why='Dosya icerigi bilinen saldiri araci/artefakti imzasiyla eslesti'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-235'; Sev='HIGH'; Title='High-entropy file with an innocuous extension in a suspicious directory'; Mitre='T1027'; Why='Sifreli/paketli icerik masum uzantiya saklanmis olabilir'; Artifact='13_recent_files'; Module='File System Scan' }
    @{ Id='DGL-236'; Sev='HIGH'; Title='Alternatif veri akisi (ADS) tespit edildi'; Mitre='T1564.004'; Why='Varsayilan disi veri akislari kod/payload gizlemek icin kullanilir'; Artifact='13_recent_files'; Module='File System Scan' }
)

# ============================================================================
#  KURAL METINLERI - INGILIZCE (rapor -Language EN icin)
#  Sadece rapor render aninda uygulanir; toplama mantigi degismez.
#  Eksik ID icin Turkce metin korunur (fallback).
# ============================================================================

$Script:RuleEN = @{
'DGL-000' = @{ T='Operating system installed less than 7 days ago'; W='An unexpected reinstall may indicate evidence was wiped' }
'DGL-001' = @{ T='Service binary in a suspicious directory'; W='Legitimate services run from System32 or Program Files' }
'DGL-002' = @{ T='System unpatched for 90+ days'; W='An unpatched system is exposed to known exploits - a common initial access vector' }
'DGL-014' = @{ T='Event log may have been cleared'; W='Log capacity is large and not full, yet no historical records exist. This is deletion, not rollover.' }
'DGL-015' = @{ T='Critical event log channel disabled'; W='An attacker may have disabled visibility' }
'DGL-016' = @{ T='Requested time window exceeds log retention'; W='The effective analysis window is shorter than requested - account for this when scoping' }
'DGL-017' = @{ T='Sysmon is not installed'; W='Process/network/pipe visibility is severely limited - hunting depth is reduced' }
'DGL-018' = @{ T='Event collection limit reached - data truncated'; W='Narrow the analysis window or raise -MaxEventsPerChannel' }
'DGL-019' = @{ T='File scan limit reached'; W='Narrow the analysis window' }
'DGL-020' = @{ T='Account password changed within the analysis window'; W='If the account was compromised, the attacker may have changed the password' }
'DGL-021' = @{ T='Enabled account requires no password'; W='An enabled passwordless account grants direct access' }
'DGL-022' = @{ T='Built-in account is enabled'; W='Guest and the built-in Administrator should normally be disabled' }
'DGL-023' = @{ T='New user profile created within the analysis window'; W='Account creation is a common persistence technique' }
'DGL-024' = @{ T='Large membership in local Administrators group'; W='Broad admin membership expands the lateral movement surface' }
'DGL-030' = @{ T='Autorun executes from a suspicious directory'; W='Legitimate autorun entries live under System32 or Program Files' }
'DGL-031' = @{ T='Autorun points to an unsigned binary'; W='Unsigned persistent startup entry' }
'DGL-032' = @{ T='Autorun target does not exist'; W='Remnant of removed malware, or an opportunity for path hijacking' }
'DGL-033' = @{ T='Suspicious autorun command'; W='Attacker behaviour pattern matched in a persistent entry' }
'DGL-040' = @{ T='Process running from a suspicious directory'; W='Temp/AppData/ProgramData are the most common malware execution directories' }
'DGL-041' = @{ T='Unsigned process running from a user profile'; W='Legitimate software usually lives under Program Files and is signed' }
'DGL-042' = @{ T='System binary masquerading'; W='This binary name is expected only in its protected system directory' }
'DGL-043' = @{ T='Suspicious command line'; W='Command line matching known attacker behaviour' }
'DGL-044' = @{ T='Anomalous parent-child process relationship'; W='This parent-child relationship does not occur during normal operation' }
'DGL-045' = @{ T='Compression/exfiltration/tunnelling tool running'; W='Indicator of the collection and exfiltration stage' }
'DGL-046' = @{ T='Process image path could not be read'; W='May be a protected process, or the image was deleted from disk' }
'DGL-047' = @{ T='Multiple discovery commands running simultaneously'; W='Indicator of hands-on-keyboard reconnaissance' }
'DGL-050' = @{ T='netsh portproxy rule present (tunnelling)'; W='Port forwarding is almost always for pivoting or tunnelling' }
'DGL-051' = @{ T='User proxy AutoConfigURL is set'; W='A malicious PAC file can redirect traffic to attacker infrastructure' }
'DGL-052' = @{ T='Hosts file modified within the analysis window'; W='Blocking security vendor domains or redirecting traffic' }
'DGL-053' = @{ T='Suspicious process communicating with an external IP (possible C2)'; W='An external connection from a process running in a temp directory indicates C2' }
'DGL-054' = @{ T='Unsigned process communicating with an external IP'; W='External traffic from an unsigned binary is the most common C2 channel appearance' }
'DGL-055' = @{ T='Suspicious process listening on all interfaces (backdoor)'; W='A listener that is unsigned or runs from a temp directory indicates a backdoor' }
'DGL-056' = @{ T='Firewall profile disabled'; W='Attackers disable the firewall for C2 and lateral movement' }
'DGL-057' = @{ T='Firewall rule allows inbound traffic to a suspicious binary'; W='Attackers add firewall rules for persistent access; legitimate software does not listen from Temp/AppData' }
'DGL-058' = @{ T='Regularly spaced external connections (possible beaconing)'; W='External connections repeating at fixed intervals are the signature of an automated C2 beacon' }
'DGL-059' = @{ T='Limited network visibility - point-in-time connections only'; W='Sysmon Event 3 is required for beaconing analysis' }
'DGL-060' = @{ T='Service binary is unsigned'; W='The vast majority of Windows services are signed; unsigned ones warrant review' }
'DGL-061' = @{ T='Unquoted service path (binary hijack risk)'; W='An unquoted path containing spaces can be hijacked by planting a binary in a parent directory' }
'DGL-062' = @{ T='Service binary modified within the analysis window'; W='Replacing an existing service binary provides persistence (service hijacking)' }
'DGL-063' = @{ T='Randomised-looking service name'; W='Cobalt Strike and similar tools generate random service names' }
'DGL-064' = @{ T='Remote execution service detected'; W='PsExec and its derivatives are used for lateral movement' }
'DGL-065' = @{ T='Suspicious command in service path'; W='Attacker behaviour pattern matched in the service command line' }
'DGL-070' = @{ T='Scheduled task runs from a suspicious directory'; W='Legitimate tasks run from System32 or Program Files' }
'DGL-071' = @{ T='Task defined in the root folder'; W='Attacker-created tasks are usually left in the root folder' }
'DGL-072' = @{ T='Scheduled task executes an unsigned binary'; W='A task launching an unsigned binary is a common persistence method' }
'DGL-073' = @{ T='Non-Microsoft task running as SYSTEM'; W='A third-party task running as SYSTEM provides privilege escalation and persistence' }
'DGL-074' = @{ T='Suspicious pattern in task command'; W='Attacker behaviour pattern matched in the task command line' }
'DGL-075' = @{ T='New task created within the analysis window'; W='A non-Microsoft task created within the analysis window may be attacker persistence' }
'DGL-080' = @{ T='Winlogon value modified'; W='Value differs from the expected default' }
'DGL-081' = @{ T='AppInit_DLLs is set'; W='AppInit_DLLs injects a DLL into every process that loads user32.dll' }
'DGL-082' = @{ T='IFEO Debugger is set'; W='The debugger runs instead of the target binary when launched (accessibility backdoor)' }
'DGL-083' = @{ T='SilentProcessExit MonitorProcess is set'; W='The specified binary runs when the target process exits' }
'DGL-084' = @{ T='Unknown entry in the LSA package list'; W='A custom DLL loaded into LSA can steal credentials' }
'DGL-085' = @{ T='AppCertDlls entry present'; W='This key is empty by default; a DLL is loaded on every CreateProcess call' }
'DGL-086' = @{ T='Non-standard Time Provider DLL'; W='Time Provider registrations are loaded by w32time as SYSTEM; a non-default DLL is persistence' }
'DGL-087' = @{ T='UserInitMprLogonScript is set'; W='This value does not exist by default and runs at every logon' }
'DGL-088' = @{ T='BITS transfer job present'; W='BITS is used for both download and persistence' }
'DGL-089' = @{ T='Winlogon value defined'; W='This value is not present by default' }
'DGL-090' = @{ T='Persistent WMI event subscription present'; W='Filter-to-consumer binding is the most common form of fileless persistence' }
'DGL-091' = @{ T='Suspicious command in WMI consumer'; W='The WMI consumer command runs as SYSTEM when triggered' }
'DGL-100' = @{ T='Known C2 named pipe pattern matched'; W='Cobalt Strike and similar C2 frameworks use characteristic pipe names' }
'DGL-110' = @{ T='Defender protection component disabled'; W='Disabling AV protection is usually an attacker first step' }
'DGL-111' = @{ T='Defender signatures are out of date'; W='An outdated signature database misses new threats; updates may have been blocked' }
'DGL-112' = @{ T='Defender exclusion configured'; W='Attackers add their payload directory to the exclusion list' }
'DGL-113' = @{ T='Defender threat detection'; W='An unremediated detection indicates active infection; even a remediated one shows the entry vector' }
'DGL-114' = @{ T='Defender remediation action'; W='Records what was acted upon and when' }
'DGL-115' = @{ T='No registered AMSI provider found'; W='The AMSI provider registration may have been removed - script scanning is disabled' }
'DGL-116' = @{ T='Critical audit category disabled'; W='While this category is off, the related events are never generated' }
'DGL-117' = @{ T='No shadow copies found'; W='Servers usually retain shadow copies; they may have been deleted' }
'DGL-120' = @{ T='Share grants full control to Everyone'; W='Unauthenticated write access eases lateral movement and data exfiltration' }
'DGL-121' = @{ T='Drive root has been shared'; W='Beyond the default administrative shares, sharing a drive root is rarely legitimate' }
'DGL-130' = @{ T='Driver loaded from a suspicious directory'; W='In BYOVD attacks the driver is loaded from a temp directory' }
'DGL-131' = @{ T='Unsigned driver running'; W='Unsigned code running in kernel mode indicates a rootkit or BYOVD' }
'DGL-132' = @{ T='Driver written within the analysis window'; W='A driver written to disk within the analysis window may be a BYOVD attack' }
'DGL-140' = @{ T='No process creation audit (4688) records'; W='With this audit disabled, historical execution activity is invisible' }
'DGL-141' = @{ T='4688 events do not include command lines'; W='ProcessCreationIncludeCmdLine_Enabled is off - hunting value is greatly reduced' }
'DGL-142' = @{ T='Process previously executed from a suspicious directory'; W='The process may no longer be running; the event record is the only evidence' }
'DGL-144' = @{ T='Obfuscated command decoded'; W='Encoding is not malicious by itself; the decoded content must be reviewed' }
'DGL-145' = @{ T='Suspicious pattern in decoded command'; W='Attacker behaviour pattern matched inside an obfuscated payload' }
'DGL-146' = @{ T='Anomalous parent-child relationship [historical]'; W='Suspicious parent-child process relationship in a historical event record' }
'DGL-150' = @{ T='PowerShell flagged a suspicious script block'; W='Warning-level blocks are recorded even when script block logging is off' }
'DGL-151' = @{ T='Obfuscated command line'; W='Multiple obfuscation indicators rarely co-occur in legitimate commands' }
'DGL-152' = @{ T='PowerShell Remoting session detected'; W='Remote PowerShell access can indicate lateral movement' }
'DGL-160' = @{ T='Logon Type 9 (NewCredentials/RunAs) detected'; W='Type 9 is the typical trace of pass-the-hash and overpass-the-hash attacks' }
'DGL-161' = @{ T='Logon Type 8 (NetworkCleartext)'; W='The password may have traversed the network in cleartext' }
'DGL-162' = @{ T='RDP session from outside the private network'; W='Internet-exposed RDP is a common initial access vector' }
'DGL-163' = @{ T='Possible brute force (4625 volume)'; W='High volume of authentication failures from a single source' }
'DGL-164' = @{ T='SUCCESSFUL logon after failed attempts'; W='The account may have been compromised following brute force or spraying' }
'DGL-165' = @{ T='Remote server accessed with explicit credentials'; W='4648 is among the most reliable indicators of lateral movement' }
'DGL-166' = @{ T='Out-of-hours interactive session (00:00-05:00 UTC)'; W='Attacker activity is typically seen outside normal working hours' }
'DGL-170' = @{ T='Account management event'; W='Account creation, deletion and password reset are the most common traces of attacker persistence' }
'DGL-171' = @{ T='Member added to a privileged group'; W='Group membership changes indicate privilege escalation and persistence' }
'DGL-172' = @{ T='Audit log tampering'; W='Anti-forensic activity - an indicator that the attack is active' }
'DGL-173' = @{ T='Service installation record (4697)'; W='Service installation is used for remote execution and persistence' }
'DGL-175' = @{ T='Scheduled task registration/update'; W='Task creation and update records date the persistence setup' }
'DGL-180' = @{ T='New service installed (7045)'; W='PsExec, Impacket and the Cobalt Strike SMB beacon install as services' }
'DGL-181' = @{ T='Service with a randomised name installed'; W='Random character strings are the typical signature of C2 framework defaults' }
'DGL-183' = @{ T='Security service start type changed'; W='A defensive mechanism may have been disabled' }
'DGL-184' = @{ T='Security service terminated unexpectedly'; W='A stopped security service is either an attack or telemetry loss; either way coverage narrows' }
'DGL-185' = @{ T='Event log cleared (System 104)'; W='Anti-forensic activity' }
'DGL-186' = @{ T='New service masquerades as a system binary'; W='The service binary name imitates a protected system binary' }
'DGL-190' = @{ T='RDP connection from outside the private network (1149)'; W='Internet-exposed RDP is one of the most common initial access vectors' }
'DGL-191' = @{ T='OUTBOUND RDP connection from this host'; W='Outbound RDP indicates this host is a source of lateral movement' }
'DGL-192' = @{ T='WinRM authentication'; W='Remote management access can be used for lateral movement' }
'DGL-200' = @{ T='Scheduled task lifecycle event'; W='Task registration and execution events establish the persistence timeline' }
'DGL-201' = @{ T='Persistent WMI event subscription record (5861)'; W='5861 is direct evidence of WMI persistence' }
'DGL-202' = @{ T='Defender protection state change'; W='Protection components are disabled immediately before payload execution' }
'DGL-203' = @{ T='File transfer over BITS'; W='BITS is a common download channel that evades AV/EDR attention' }
'DGL-204' = @{ T='Code integrity violation (unsigned driver/image)'; W='May be the trace of a BYOVD attack attempt' }
'DGL-205' = @{ T='Firewall rule change'; W='Firewall rule changes open the way for inbound C2 and lateral movement' }
'DGL-210' = @{ T='Access to LSASS memory (credential dump)'; W='This access mask is used to read LSASS memory' }
'DGL-211' = @{ T='CreateRemoteThread (process injection)'; W='Process injection is used for detection evasion and execution inside a legitimate process' }
'DGL-212' = @{ T='Named pipe created matching a C2 pattern'; W='Cobalt Strike and similar frameworks communicate over default pipe names' }
'DGL-213' = @{ T='Process tampering (hollowing/herpaderping)'; W='Hollowing and herpaderping decouple the on-disk file from the in-memory code' }
'DGL-214' = @{ T='Sysmon WMI event record (persistence)'; W='WMI subscriptions provide persistence without leaving a file on disk' }
'DGL-220' = @{ T='Possible Kerberoasting (RC4 service ticket volume)'; W='A single account requesting RC4 tickets for many services is the signature of a Kerberoast attack' }
'DGL-221' = @{ T='TGT request without Kerberos pre-authentication (AS-REP roast)'; W='Accounts with pre-auth disabled are exposed to offline password cracking' }
'DGL-222' = @{ T='TGT with RC4 encryption (encryption downgrade)'; W='Overpass-the-hash attacks use RC4' }
'DGL-223' = @{ T='Kerberos password guessing attack (4771 volume)'; W='High 4771 volume indicates password spraying or brute force' }
'DGL-224' = @{ T='DCSync attempt (directory replication right used)'; W='A non-DC principal is using replication rights - it can pull every password hash' }
'DGL-230' = @{ T='New executable file in a suspicious directory'; W='An executable written under Temp/AppData within the analysis window may be a payload' }
'DGL-231' = @{ T='File downloaded from the internet (MOTW)'; W='The Zone.Identifier alternate data stream carries the download source' }
'DGL-232' = @{ T='Possible timestamp manipulation'; W='Creation time is later than the modification time (>5 min) - timestamps may have been backdated' }
'DGL-233' = @{ T='PE binary hidden behind the wrong extension'; W='A file carrying an MZ header is executable; its extension conceals that' }
'DGL-234' = @{ T='File content signature match'; W='File content matched the signature of a known attack tool or artifact' }
'DGL-235' = @{ T='High-entropy file with an innocuous extension in a suspicious directory'; W='Encrypted or packed content may be hidden behind an innocuous extension' }
'DGL-236' = @{ T='Alternate data stream (ADS) detected'; W='Non-default data streams are used to hide code or payloads' }
'DGL-240' = @{ T='Possible WEBSHELL'; W='Command execution pattern matched in the web root' }
'DGL-241' = @{ T='New file written to the web root within the analysis window'; W='Web file changes outside deployment may indicate webshell placement' }
'DGL-250' = @{ T='Archive created within the analysis window'; W='Attackers archive files during the collection stage' }
'DGL-251' = @{ T='Attack or remote access tool found on disk'; W='These tools are not legitimately present in user directories' }
'DGL-261' = @{ T='Encoded command decoded from console history'; W='PSReadLine history retains uncleaned commands; encoding is used for obfuscation' }
'DGL-262' = @{ T='RDP connection history from this host'; W='Spread map: which systems were reached from this machine' }
'DGL-263' = @{ T='No prefetch records'; W='Prefetch may be disabled - loss of execution evidence' }
'DGL-264' = @{ T='Suspicious program executed within the analysis window (Prefetch)'; W='Prefetch preserves execution evidence even after the process exits' }
'DGL-270' = @{ T='Unrecognised certificate in the trusted root store'; W='A rogue root CA enables TLS interception and code signing forgery' }
'DGL-265' = @{ T='Prefetch: program loaded a file from a suspicious directory'; W='The prefetch loaded-file list reveals the payload actual location on disk' }
'DGL-266' = @{ T='ShimCache unreadable or empty'; W='ShimCache retains traces of deleted binaries; losing access to it is a visibility gap' }
'DGL-267' = @{ T='ShimCache: binary record in a suspicious directory'; W='ShimCache keeps the record even after the file is deleted - the strongest evidence of a removed payload' }
'DGL-268' = @{ T='ShimCache: attack tool record'; W='These tools are absent from legitimate workloads; the record survives deletion from disk' }
'DGL-269' = @{ T='Amcache: program record in a suspicious directory'; W='Amcache retains the SHA1 hash and first-seen time; traces remain even if Prefetch is cleared' }
'DGL-271' = @{ T='Amcache unreadable'; W='Amcache is the secondary source of execution evidence; it can be captured via VSS with -CollectRaw' }
'DGL-400' = @{ T='Sigma rule matches present (review separately)'; W='Community Sigma rules vary in quality; excluded from the risk score and reviewed as leads' }
'DGL-401' = @{ T='Sigma evaluation did not complete within the time budget'; W='Use a smaller focused sigma-pack or raise the budget; the coverage gap must be known' }
'DGL-410' = @{ T='YARA scan not performed (component missing)'; W='The YARA engine and rules can be downloaded from Menu > Update Center' }
'DGL-411' = @{ T='YARA match'; W='YARA-Forge quality-filtered rule set; matches must be verified (packer rules also match legitimate software)' }
'DGL-412' = @{ T='YARA scan did not complete within the time limit'; W='The coverage gap must be known' }
'DGL-182' = @{ T='Suspicious command in new service (7045)'; W='Attacker behaviour pattern matched in the ImagePath of a newly installed service' }
'DGL-260' = @{ T='Suspicious command in console history'; W='PSReadLine history retains commands that were not cleared; hands-on-keyboard evidence' }
'DGL-300' = @{ T='New object not present in baseline'; W='This object did not exist in the previous collection; it may have been added outside the analysis window' }
'DGL-301' = @{ T='High rarity score'; W='Unsigned + unknown publisher + unusual location combination; a candidate for individual review' }
'DGL-DYNAMIC' = @{ T='Suspicious command in event record'; W='Attacker behaviour pattern matched in a historical event record' }
'DGL-IOC' = @{ T='IOC match'; W='Matched against the supplied IOC list' }
}

function ConvertTo-DRuleEN {
    <# Rapor -Language EN iken bulgu Title/Why alanlarini Ingilizceye cevirir.
       Kural ID'si tabloda yoksa Turkce metin korunur (kayip yok).
       Dinamik basliklarda (": <pattern>") sonek korunur. #>
    param([object]$Finding)
    if ($Script:Lang -ne 'EN' -or -not $Finding) { return $Finding }
    $e = $Script:RuleEN[$Finding.RuleId]
    if (-not $e) { return $Finding }
    $o = $Finding.PSObject.Copy()
    # "Baslik: dinamik kisim" -> Ingilizce baslik + ayni dinamik kisim
    $suffix = ''
    if ($Finding.Title -match '^(.*?):\s*(.+)$') { $suffix = ': ' + $Matches[2] }
    $o.Title = $e.T + $suffix
    if ($e.W) { $o.Why = $e.W }
    return $o
}

function Export-DRuleCatalog {
    <# Katalogu CSV'ye yazar. Menude [8], komut satirinda -ExportRuleCatalog. #>
    param([string]$Path = (Join-Path (Get-Location).Path 'DGL-rule-catalog.csv'))
    $rows = foreach ($r in $Script:RuleCatalog) {
        # Katalog da Ingilizce yazilir (RuleEN tablosu tek dogruluk kaynagi)
        $en = $Script:RuleEN[$r.Id]
        [PSCustomObject]@{
            RuleId   = $r.Id
            Severity = $r.Sev
            Title    = $(if ($en) { $en.T } else { $r.Title })
            Mitre    = (ConvertTo-DMitreV19 $r.Mitre)
            Why      = $(if ($en -and $en.W) { $en.W } else { $r.Why })
            Artifact = $r.Artifact
            Module   = $r.Module
        }
    }
    $rows | Sort-Object RuleId |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
    return $Path
}

function Test-DCatalogDrift {
    <# Uretilen kural ID'leri katalogla ortusuyor mu? Ortusmuyorsa gorunur uyari. #>
    $known   = @($Script:RuleCatalog | ForEach-Object { $_.Id })
    $emitted = @($Script:Findings | ForEach-Object { $_.RuleId } | Sort-Object -Unique)
    $orphan  = @($emitted | Where-Object { $_ -notin $known -and $_ -ne 'DGL-IOC' })
    if ($orphan.Count -gt 0) {
        Write-DLog ("CATALOG DRIFT: {0} rules missing from catalog -> {1}" -f `
                    $orphan.Count, ($orphan -join ', ')) -Level WARN
        $null = $Script:Errors.Add([PSCustomObject]@{
            Module  = 'RuleCatalog'
            Type    = 'CatalogDrift'
            Message = "Katalogda tanimsiz kural uretildi: $($orphan -join ', ')"
            TimeUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
    }
    return $orphan
}

function Get-DEntityCorrelation {
    <# F1.5-9: bulgulari ortak "varlik"a gore gruplar - ayni dosya yolu, servis
       adi, gorev adi, IP veya SHA256'dan dogan bulgular tek saldiri zinciri
       olarak sunulur. Kanittan varlik anahtari cikarir. #>
    param([object[]]$Findings)

    $entities = @{}
    $rxPath = '(?i)([a-z]:\\[^\s"''|:]+\.(?:ps1|exe|dll|bat|cmd|vbs|js|hta|scr|dat|log|txt))'
    $rxIp   = '\b(\d{1,3}(?:\.\d{1,3}){3})\b'
    $rxSvc  = '(?i)(?:servis|service)\s+([A-Za-z0-9_\-]{3,})'
    $rxHash = '\b([a-fA-F0-9]{64})\b'

    foreach ($f in $Findings) {
        $blob = "$($f.Evidence) $($f.Title)"
        $keys = New-Object System.Collections.Generic.HashSet[string]

        foreach ($m in [regex]::Matches($blob, $rxPath)) {
            $null = $keys.Add('file:' + $m.Groups[1].Value.ToLowerInvariant())
        }
        foreach ($m in [regex]::Matches($blob, $rxIp)) {
            $ip = $m.Groups[1].Value
            if ($ip -notmatch '^(10\.|127\.|169\.254\.|192\.168\.|0\.0\.0\.0|255\.)') {
                $null = $keys.Add('ip:' + $ip)
            }
        }
        foreach ($m in [regex]::Matches($blob, $rxHash)) {
            $null = $keys.Add('hash:' + $m.Groups[1].Value.ToLowerInvariant())
        }

        foreach ($k in $keys) {
            if (-not $entities.ContainsKey($k)) {
                $entities[$k] = [PSCustomObject]@{
                    Key      = $k
                    Type     = ($k -split ':')[0]
                    Value    = ($k -split ':',2)[1]
                    Findings = New-Object System.Collections.ArrayList
                    MaxSev   = 'INFO'
                    Tactics  = New-Object System.Collections.Generic.HashSet[string]
                }
            }
            $null = $entities[$k].Findings.Add($f)
            $sevRank = @{ CRITICAL=4; HIGH=3; MEDIUM=2; LOW=1; INFO=0 }
            if ($sevRank[$f.Severity] -gt $sevRank[$entities[$k].MaxSev]) {
                $entities[$k].MaxSev = $f.Severity
            }
            if ($f.Mitre) { foreach ($t in ($f.Mitre -split ',')) { $null = $entities[$k].Tactics.Add($t.Trim()) } }
        }
    }

    # sadece 2+ bulgu iceren varliklar ilginctir (korelasyon degeri)
    $result = @($entities.Values | Where-Object { $_.Findings.Count -ge 2 } |
                Sort-Object @{E={ @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;INFO=4}[$_.MaxSev] }},
                            @{E={ -$_.Findings.Count }})
    return $result
}


function Register-DModule {
    <#
        Modul kaydi. Calisma sirasi Phase + kayit sirasi.
        Scope: All / Client / Server / DC  (rol filtresi)
        RequiresCap: yetenek matrisinde true olmasi gereken anahtarlar
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateRange(0, 4)][int]$Phase,
        [Parameter(Mandatory)][scriptblock]$Body,
        [ValidateSet('All', 'Client', 'Server', 'DC')]
        [string[]]$Scope = @('All'),
        [string[]]$RequiresCap = @(),
        [string]$Description,
        [switch]$SkipOnQuick,
        [string[]]$HuntTags = @()
    )

    $null = $Script:ModuleRegistry.Add([PSCustomObject]@{
        Name        = $Name
        Phase       = $Phase
        Scope       = $Scope
        RequiresCap = $RequiresCap
        Description = $Description
        SkipOnQuick = [bool]$SkipOnQuick
        HuntTags    = $HuntTags
        Body        = $Body
    })
}

function Test-DModuleScope {
    param([string[]]$Scope)
    if ($Scope -contains 'All') { return $true }
    if ($Scope -contains 'DC'     -and $Script:Ctx.IsDomainController) { return $true }
    if ($Scope -contains 'Server' -and $Script:Ctx.IsServer)           { return $true }
    if ($Scope -contains 'Client' -and $Script:Ctx.IsWorkstation)      { return $true }
    return $false
}

function Invoke-DModule {
    <#
        Modul izolasyonu. Bir modul patlarsa script DEVAM EDER.
        Hata errors.json'a duser, sure manifest'e yazilir.
    #>
    param([Parameter(Mandatory)][object]$Module)

    # Kapsam filtresi
    if (-not (Test-DModuleScope -Scope $Module.Scope)) {
        Write-DLog "$($Module.Name) - out of scope (role: $($Script:Ctx.DomainRole))" -Level DEBUG
        # "Veri yok" ile "modul calismadi" farkli seylerdir: kapsam disi kalan
        # modul de rapordaki Atlanan Moduller tablosunda gorunmeli.
        $null = $Script:Errors.Add([PSCustomObject]@{
            Module  = $Module.Name
            Type    = 'SkippedScope'
            Message = "Rol kapsami disi. Gerekli: $($Module.Scope -join '/') | Tespit edilen: $($Script:Ctx.DomainRole)"
            TimeUtc = (Get-Date).ToUniversalTime().ToString('o')
        })
        return
    }

    # F3: Hunt paketi filtresi - -Hunt verildiyse sadece ilgili moduller
    if ($Hunt -and $Hunt.Count -gt 0 -and $Module.Phase -ge 1) {
        if (-not (Test-DHuntScope -ModuleTags $Module.HuntTags)) {
            Write-DLog "$($Module.Name) - outside hunt scope (-Hunt $($Hunt -join ','))" -Level DEBUG
            return
        }
    }

    # Quick mod filtresi
    if ($Quick -and $Module.SkipOnQuick) {
        Write-DLog "$($Module.Name) - skipped in Quick mode" -Level DEBUG
        return
    }

    # Yetenek filtresi
    foreach ($cap in $Module.RequiresCap) {
        if (-not $Script:Caps[$cap]) {
            Write-DLog "$($Module.Name) - capability missing ($cap), skipped" -Level WARN
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module    = $Module.Name
                Type      = 'SkippedCapability'
                Message   = "Gerekli yetenek mevcut degil: $cap"
                TimeUtc   = (Get-Date).ToUniversalTime().ToString('o')
            })
            return
        }
    }

    Write-DLog "$($Module.Name)" -Level STEP
    $sw           = [Diagnostics.Stopwatch]::StartNew()
    $errCountPre  = $Global:Error.Count
    $status       = 'OK'

    try {
        & $Module.Body
    } catch {
        $status = 'FAILED'
        Write-DLog "$($Module.Name) ERROR: $($_.Exception.Message)" -Level ERROR
        $null = $Script:Errors.Add([PSCustomObject]@{
            Module     = $Module.Name
            Type       = 'Terminating'
            Message    = $_.Exception.Message
            Category   = $_.CategoryInfo.Category
            ScriptLine = $_.InvocationInfo.ScriptLineNumber
            TimeUtc    = (Get-Date).ToUniversalTime().ToString('o')
        })
    } finally {
        $sw.Stop()
    }

    # Non-terminating hatalari da yakala (SilentlyContinue ile yutulanlar)
    $newErrors = $Global:Error.Count - $errCountPre
    if ($newErrors -gt 0) {
        $take = [Math]::Min($newErrors, 5)
        for ($i = 0; $i -lt $take; $i++) {
            $e = $Global:Error[$i]
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module     = $Module.Name
                Type       = 'NonTerminating'
                Message    = "$e"
                Category   = $e.CategoryInfo.Category
                ScriptLine = $e.InvocationInfo.ScriptLineNumber
                TimeUtc    = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
        if ($newErrors -gt 5) {
            $null = $Script:Errors.Add([PSCustomObject]@{
                Module  = $Module.Name
                Type    = 'NonTerminating'
                Message = "... ve $($newErrors - 5) hata daha (kirpildi)"
                TimeUtc = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
    }

    $null = $Script:ModuleStats.Add([PSCustomObject]@{
        Module     = $Module.Name
        Phase      = $Module.Phase
        Status     = $status
        DurationMs = [int]$sw.ElapsedMilliseconds
        ErrorCount = $newErrors
    })

    $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($secs -gt 10) {
        Write-DLog "  completed ($secs s)" -Level WARN
    } else {
        Write-DLog "  completed ($secs s)" -Level DEBUG
    }
}

$Script:ModuleStats = New-Object System.Collections.ArrayList

function Invoke-DPhase {
    param([Parameter(Mandatory)][int]$Phase, [string]$Title)

    $mods = @($Script:ModuleRegistry | Where-Object { $_.Phase -eq $Phase })
    if ($mods.Count -eq 0) { return }

    Write-Host ''
    Write-Host ("  === FAZ {0}: {1} ===" -f $Phase, $Title) -ForegroundColor White `
               -BackgroundColor DarkBlue
    Write-DLog "FAZ $Phase basladi: $Title" -Level INFO -NoConsole

    foreach ($m in $mods) { Invoke-DModule -Module $m }

    # Her faz sonunda ara kayit - script 8. dakikada patlarsa veri kaybolmasin
    Save-DInterimState
}

function Save-DInterimState {
    try {
        if ($Script:Findings.Count -gt 0) {
            $Script:Findings |
                Sort-Object @{E = {
                    switch ($_.Severity) {
                        'CRITICAL' { 0 } 'HIGH' { 1 } 'MEDIUM' { 2 } 'LOW' { 3 } default { 4 }
                    }}} |
                Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'FINDINGS.csv') `
                           -NoTypeInformation -Encoding UTF8 -Force
        }
        if ($Script:Errors.Count -gt 0) {
            $Script:Errors | ConvertTo-Json -Depth 4 |
                Out-File -FilePath (Join-Path $Script:Ctx.OutputDir 'logs\errors.json') `
                         -Encoding UTF8 -Force
        }
    } catch { }
}

# ============================================================================
#  FINALIZE
# ============================================================================


# ============================================================================
#  FAZ 3: HUNTING - BASELINE/DELTA + RARITY + HUNT PAKETLERI
# ============================================================================

function Compare-DBaseline {
    <# F3: onceki bir Douglas ciktisiyla su anki durumu karsilastirir.
       Servis/autorun/gorev/surucu tablolarinda YENI ve DEGISEN satirlari bulur.
       "Gecen hafta bu servis yoktu" IR'de en hizli sonuc veren cumledir. #>
    param([string]$BaselineDir)
    if (-not (Test-Path $BaselineDir)) {
        Write-DLog "Baseline directory not found: $BaselineDir" -Level WARN
        return
    }
    # baseline bir zip veya klasor olabilir
    $bDir = $BaselineDir
    if ($BaselineDir -match '\.zip$') {
        $tmp = Join-Path $env:TEMP ("dgl_base_" + [guid]::NewGuid().ToString('N').Substring(0,8))
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [IO.Compression.ZipFile]::ExtractToDirectory($BaselineDir, $tmp)
            $bDir = $tmp
            # zip icinde tek klasor olabilir
            $inner = @(Get-ChildItem $tmp -Directory)
            if ($inner.Count -eq 1) { $bDir = $inner[0].FullName }
        } catch { Write-DLog "Baseline zip could not be opened: $($_.Exception.Message)" -Level WARN; return }
    }

    $compareMap = @{
        '05_services.csv'        = @{ Key = { param($r) "$($r.Name)|$($r.BinaryPath)" }; Label = 'Servis' }
        '07_autoruns.csv'        = @{ Key = { param($r) "$($r.Category)|$($r.Name)|$($r.Value)" }; Label = 'Autorun' }
        '06_scheduled_tasks.csv' = @{ Key = { param($r) "$($r.TaskPath)$($r.TaskName)|$($r.Actions)" }; Label = 'Gorev' }
        '09_drivers.csv'         = @{ Key = { param($r) "$($r.Name)|$($r.PathName)" }; Label = 'Surucu' }
        '02_local_users.csv'     = @{ Key = { param($r) "$($r.Name)|$($r.SID)" }; Label = 'Hesap' }
    }

    $deltaRows = New-Object System.Collections.ArrayList
    foreach ($file in $compareMap.Keys) {
        $curPath  = Join-Path $Script:Ctx.OutputDir "artifacts\$file"
        $basePath = Join-Path $bDir "artifacts\$file"
        if (-not (Test-Path $curPath)) { continue }
        $cur  = @(try { Import-Csv $curPath -EA Stop } catch { @() })
        $base = @(if (Test-Path $basePath) { try { Import-Csv $basePath -EA Stop } catch { @() } } else { @() })
        $keyFn = $compareMap[$file].Key
        $label = $compareMap[$file].Label

        $baseKeys = @{}
        foreach ($b in $base) { $baseKeys[(& $keyFn $b)] = $true }

        foreach ($c in $cur) {
            $k = & $keyFn $c
            if (-not $baseKeys.ContainsKey($k)) {
                $null = $deltaRows.Add([PSCustomObject]@{
                    Type = $label; Change = 'NEW'; Key = $k
                })
                # yeni servis/gorev/autorun = yuksek dikkat
                $sev = if ($label -in 'Servis','Gorev','Autorun','Surucu') { 'HIGH' } else { 'MEDIUM' }
                Add-DFinding -RuleId 'DGL-300' -Severity $sev `
                    -Title "New $label not present in baseline" `
                    -Evidence $k -Mitre 'T1543' -Artifact 'DELTA' `
                    -Why "This $label did not exist in the previous collection; it may have been added outside the analysis window"
            }
        }
    }
    if ($deltaRows.Count -gt 0) {
        $deltaRows | Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'DELTA.csv') `
                     -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "Baseline comparison: $($deltaRows.Count) new/changed objects (DELTA.csv)" -Level OK
    } else {
        Write-DLog "Baseline comparison: no differences" -Level OK
    }
    if ($bDir -ne $BaselineDir -and $bDir -match 'dgl_base_') {
        Remove-Item (Split-Path $bDir -Parent) -Recurse -Force -EA SilentlyContinue
    }
}

function Invoke-DRarityScoring {
    <# F3: tek-host modunda "nadirlik" skoru. Servis/autorun/gorev binary'lerini
       bilinen-iyi (Microsoft imzali + System32/Program Files) ile karsilastirir;
       imzasiz + supheli dizin + bilinmeyen yayinci = yuksek nadirlik. Fan-out
       stack counting'in tek-makine karsiligi. #>

    $items = New-Object System.Collections.ArrayList
    $sources = @(
        @{ File = 'artifacts\05_services.csv';        Name = { param($r) $r.Name };  Path = { param($r) $r.BinaryPath }; T = 'Servis' }
        @{ File = 'artifacts\07_autoruns.csv';        Name = { param($r) $r.Name };  Path = { param($r) $r.BinaryPath }; T = 'Autorun' }
        @{ File = 'artifacts\06_scheduled_tasks.csv'; Name = { param($r) $r.TaskName }; Path = { param($r) $r.BinaryPath }; T = 'Gorev' }
    )
    foreach ($src in $sources) {
        $p = Join-Path $Script:Ctx.OutputDir $src.File
        if (-not (Test-Path $p)) { continue }
        $rows = @(try { Import-Csv $p -EA Stop } catch { @() })
        foreach ($r in $rows) {
            $path = & $src.Path $r
            if (-not $path) { continue }
            $signed = ($r.PSObject.Properties.Name -contains 'Signed' -and $r.Signed -eq 'True')
            $isMs   = ($r.PSObject.Properties.Name -contains 'IsMicrosoft' -and $r.IsMicrosoft -eq 'True')
            $susp   = ($r.PSObject.Properties.Name -contains 'SuspiciousPath' -and $r.SuspiciousPath -eq 'True')

            # nadirlik puani (0-100)
            $score = 0
            if (-not $isMs)   { $score += 30 }
            if (-not $signed) { $score += 30 }
            if ($susp)        { $score += 30 }
            if ($path -match '(?i)\\(temp|appdata|programdata|public)\\') { $score += 10 }
            if ($score -eq 0) { continue }   # bilinen-iyi, atla

            $null = $items.Add([PSCustomObject]@{
                Type = $src.T; Name = (& $src.Name $r); Path = $path
                Rarity = $score
                Signed = $signed; IsMicrosoft = $isMs; SuspiciousPath = $susp
            })
        }
    }
    $items = @($items | Sort-Object Rarity -Descending)
    if ($items.Count -gt 0) {
        $items | Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'RARITY.csv') `
                 -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "Rarity scoring: $($items.Count) unusual objects (RARITY.csv)" -Level OK
        # en nadir olanlar bulgu olarak
        foreach ($it in @($items | Where-Object Rarity -ge 70 | Select-Object -First 20)) {
            Add-DFinding -RuleId 'DGL-301' -Severity 'MEDIUM' `
                -Title "High rarity: $($it.Type)" `
                -Evidence "$($it.Name) -> $($it.Path) (rarity $($it.Rarity)/100)" `
                -Mitre 'T1543' -Artifact 'RARITY' `
                -Why 'Imzasiz + bilinmeyen yayinci + sira-disi konum kombinasyonu; tekil inceleme adayi'
        }
    }
}

function Test-DHuntScope {
    <# F3: -Hunt verildiyse sadece secili paketle ilgili moduller calisir.
       Her modulun HuntTags'i ile kesisim var mi? #>
    param([string[]]$ModuleTags)
    if (-not $Hunt -or $Hunt.Count -eq 0) { return $true }         # hunt modu kapali
    if ($Hunt -contains 'All') { return $true }
    if (-not $ModuleTags -or $ModuleTags.Count -eq 0) { return $false }
    foreach ($h in $Hunt) { if ($ModuleTags -contains $h) { return $true } }
    return $false
}


# ============================================================================
#  FAZ 4: GERCEK ADLI ARTEFAKT PARSER'LARI
#  Prefetch (.pf, MAM sikistirma dahil), ShimCache (AppCompatCache),
#  Amcache (hive). Bunlar ham binary/registry yapilardir - dosya adina
#  degil, icerige bakarlar.
# ============================================================================

function Expand-DMamCompressed {
    <# Windows 8+ Prefetch dosyalari MAM (Xpress Huffman) ile sikistirilmistir.
       Basligi: 'MAM\x04' + 4 byte decompressed size. Cozmek icin ntdll'deki
       RtlDecompressBufferEx kullanilir (harici bagimlilik yok).
       Donen: cozulmus byte[] veya $null #>
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -lt 8) { return $null }
    if (-not ($Bytes[0] -eq 0x4D -and $Bytes[1] -eq 0x41 -and $Bytes[2] -eq 0x4D)) { return $null }

    $decSize = [BitConverter]::ToUInt32($Bytes, 4)
    if ($decSize -le 0 -or $decSize -gt 64MB) { return $null }

    if (-not ('DGLNtDll' -as [type])) {
        try {
            Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DGLNtDll {
    [DllImport("ntdll.dll")]
    public static extern uint RtlGetCompressionWorkSpaceSize(
        ushort CompressionFormat, ref uint BufferWorkSpaceSize, ref uint FragmentWorkSpaceSize);
    [DllImport("ntdll.dll")]
    public static extern uint RtlDecompressBufferEx(
        ushort CompressionFormat, byte[] UncompressedBuffer, uint UncompressedBufferSize,
        byte[] CompressedBuffer, uint CompressedBufferSize, ref uint FinalUncompressedSize,
        byte[] WorkSpace);
}
'@
        } catch { return $null }
    }

    # COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004 | ENGINE_MAXIMUM 0x0100 = 0x0104
    $fmt = [uint16]0x0104
    $wsBuf = [uint32]0; $wsFrag = [uint32]0
    try {
        $st = [DGLNtDll]::RtlGetCompressionWorkSpaceSize($fmt, [ref]$wsBuf, [ref]$wsFrag)
        if ($st -ne 0) { return $null }
        $ws  = New-Object byte[] $wsBuf
        $out = New-Object byte[] $decSize
        $comp = New-Object byte[] ($Bytes.Length - 8)
        [Array]::Copy($Bytes, 8, $comp, 0, $comp.Length)
        $final = [uint32]0
        $st = [DGLNtDll]::RtlDecompressBufferEx($fmt, $out, $decSize, $comp, $comp.Length, [ref]$final, $ws)
        if ($st -ne 0) { return $null }
        return $out
    } catch { return $null }
}

function Read-DPrefetchFile {
    <# Tek bir .pf dosyasini PARSE eder (dosya adi degil, ICERIK).
       Cikarilan: calisma sayisi, son 8 calisma zamani, yuklenen dosya/volume
       listesi. Surumler: 17=WinXP, 23=Vista/7, 26=Win8.1, 30/31=Win10+.
       Win10+ dosyalari MAM sikistirmalidir - once acilir. #>
    param([string]$Path)
    try {
        $raw = [IO.File]::ReadAllBytes($Path)
    } catch { return $null }
    if ($raw.Length -lt 84) { return $null }

    # MAM sikistirma varsa ac
    if ($raw[0] -eq 0x4D -and $raw[1] -eq 0x41 -and $raw[2] -eq 0x4D) {
        $raw = Expand-DMamCompressed -Bytes $raw
        if (-not $raw -or $raw.Length -lt 84) { return $null }
    }

    # imza 'SCCA' offset 4
    if (-not ($raw[4] -eq 0x53 -and $raw[5] -eq 0x43 -and $raw[6] -eq 0x43 -and $raw[7] -eq 0x41)) { return $null }

    $ver = [BitConverter]::ToUInt32($raw, 0)
    # calistirilabilir adi: offset 0x10, 60 UTF-16 karakter
    $name = ''
    try {
        $name = [Text.Encoding]::Unicode.GetString($raw, 0x10, 60).TrimEnd([char]0)
        if ($name.Contains([char]0)) { $name = $name.Substring(0, $name.IndexOf([char]0)) }
    } catch { }

    # surume gore offsetler
    switch ($ver) {
        23 { $runCountOff = 0x98; $lastRunOff = 0x80; $lastRunCount = 1; $infoOff = 0x54 }
        26 { $runCountOff = 0xD0; $lastRunOff = 0x80; $lastRunCount = 8; $infoOff = 0x54 }
        30 { $runCountOff = 0xD0; $lastRunOff = 0x80; $lastRunCount = 8; $infoOff = 0x54 }
        31 { $runCountOff = 0xD0; $lastRunOff = 0x80; $lastRunCount = 8; $infoOff = 0x54 }
        17 { $runCountOff = 0x90; $lastRunOff = 0x78; $lastRunCount = 1; $infoOff = 0x54 }
        default { $runCountOff = 0xD0; $lastRunOff = 0x80; $lastRunCount = 8; $infoOff = 0x54 }
    }

    $runCount = 0
    try { if ($raw.Length -gt $runCountOff + 4) { $runCount = [BitConverter]::ToUInt32($raw, $runCountOff) } } catch { }
    if ($runCount -gt 100000) { $runCount = 0 }   # yanlis offset korumasi

    # son calisma zamanlari (FILETIME, 8 byte her biri)
    $runTimes = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $lastRunCount; $i++) {
        $off = $lastRunOff + ($i * 8)
        if ($raw.Length -lt $off + 8) { break }
        try {
            $ft = [BitConverter]::ToInt64($raw, $off)
            if ($ft -gt 0 -and $ft -lt 2650467744000000000) {
                $dt = [DateTime]::FromFileTimeUtc($ft)
                if ($dt.Year -ge 2000 -and $dt.Year -le 2100) {
                    $null = $runTimes.Add($dt.ToString('o'))
                }
            }
        } catch { }
    }

    # yuklenen dosya listesi (filename strings blogu)
    $loadedFiles = New-Object System.Collections.ArrayList
    try {
        $fnOff = [BitConverter]::ToUInt32($raw, $infoOff + 16)
        $fnLen = [BitConverter]::ToUInt32($raw, $infoOff + 20)
        if ($fnOff -gt 0 -and $fnLen -gt 0 -and ($fnOff + $fnLen) -le $raw.Length -and $fnLen -lt 4MB) {
            $blob = [Text.Encoding]::Unicode.GetString($raw, $fnOff, $fnLen)
            foreach ($f in ($blob -split [char]0)) {
                if ($f -and $f.Length -gt 3 -and $f -match '\\') { $null = $loadedFiles.Add($f) }
            }
        }
    } catch { }

    return [PSCustomObject]@{
        PrefetchFile = Split-Path $Path -Leaf
        Executable   = $name
        Version      = $ver
        RunCount     = $runCount
        LastRunUtc   = if ($runTimes.Count -gt 0) { $runTimes[0] } else { $null }
        AllRunTimes  = ($runTimes -join '; ')
        LoadedCount  = $loadedFiles.Count
        LoadedFiles  = (($loadedFiles | Select-Object -First 40) -join '; ')
        AllLoaded    = $loadedFiles
    }
}

function Read-DShimCache {
    <# ShimCache (AppCompatCache) PARSE. Registry'deki ham binary degerdir;
       calistirilmasa bile "goruldu" kaydi tutar - execution degil EXISTENCE
       kanitidir (yaygin yanlis yorum). Win10/11 formati: baslik 0x30,
       ardindan '10ts' imzali girdiler. Win7: '00ts' / baslik 0x80. #>
    $entries = New-Object System.Collections.ArrayList
    $data = $null
    foreach ($p in @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility')) {
        try {
            $v = Get-ItemProperty -Path $p -Name 'AppCompatCache' -ErrorAction Stop
            if ($v.AppCompatCache) { $data = [byte[]]$v.AppCompatCache; break }
        } catch { }
    }
    if (-not $data -or $data.Length -lt 0x30) { return $entries }

    $sig = [BitConverter]::ToUInt32($data, 0)
    # Win10/11: baslik uzunlugu 0x30 veya 0x34; girdiler '10ts'
    $off = 0
    if ($sig -eq 0x30 -or $sig -eq 0x34) { $off = $sig }
    elseif ($sig -eq 0x80) { $off = 0x80 }         # Win7
    elseif ($sig -eq 0xBADC0FEE -or $sig -eq 0xDEADBEEF) { $off = 0x08 }
    else { $off = 0x30 }

    $guard = 0
    while ($off -lt ($data.Length - 12) -and $guard -lt 2000) {
        $guard++
        try {
            $tag = [Text.Encoding]::ASCII.GetString($data, $off, 4)
            if ($tag -ne '10ts' -and $tag -ne '00ts' -and $tag -ne '01ts') {
                # imza bulunamadi - ilerlemeyi dene
                $off++
                continue
            }
            $p = $off + 8
            $entryLen = [BitConverter]::ToUInt32($data, $p); $p += 4
            if ($entryLen -le 0 -or ($off + 12 + $entryLen) -gt $data.Length) { break }
            $pathLen = [BitConverter]::ToUInt16($data, $p); $p += 2
            if ($pathLen -le 0 -or ($p + $pathLen) -gt $data.Length) { break }
            $path = [Text.Encoding]::Unicode.GetString($data, $p, $pathLen); $p += $pathLen
            $ft = [BitConverter]::ToInt64($data, $p); $p += 8
            $ts = $null
            try {
                if ($ft -gt 0 -and $ft -lt 2650467744000000000) {
                    $d = [DateTime]::FromFileTimeUtc($ft)
                    if ($d.Year -ge 2000 -and $d.Year -le 2100) { $ts = $d.ToString('o') }
                }
            } catch { }
            $null = $entries.Add([PSCustomObject]@{
                Position     = $entries.Count
                Path         = $path
                LastModified = $ts
            })
            $off = $off + 12 + $entryLen
        } catch { break }
    }
    return $entries
}

function Read-DAmcache {
    <# Amcache.hve PARSE. Calistirilmis/kurulmus programlarin SHA1 hash'ini
       ve ilk gorulme zamanini tutar - Prefetch silinse bile burada iz kalir.
       Canli sistemde hive kilitlidir; 'reg save' ile kopyasi alinip
       'reg load' ile gecici bir anahtara baglanir, okunur, sonra kaldirilir. #>
    $rows = New-Object System.Collections.ArrayList
    $src  = "$env:SystemRoot\appcompat\Programs\Amcache.hve"
    if (-not (Test-Path $src)) { return $rows }

    $tmp  = Join-Path $env:TEMP ("dgl_amc_" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.hve')
    $mount = 'DGLAMC'
    $loaded = $false
    try {
        # kilitli hive'i kopyala (reg save canli hive'da calisir)
        $null = & reg.exe save "HKLM\SYSTEM" "$tmp.probe" /y 2>&1   # yetki testi
        Remove-Item "$tmp.probe" -Force -ErrorAction SilentlyContinue
        Copy-Item -LiteralPath $src -Destination $tmp -Force -ErrorAction Stop
    } catch {
        # kilitliyse VSS olmadan kopyalanamaz - sessizce cik
        try { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } catch { }
        return $rows
    }
    try {
        $out = & reg.exe load "HKLM\$mount" $tmp 2>&1
        if ($LASTEXITCODE -ne 0) { throw "reg load basarisiz: $out" }
        $loaded = $true

        # Win10+: Root\InventoryApplicationFile  | Win8: Root\File\<volume>\<id>
        $invPath = "HKLM:\$mount\Root\InventoryApplicationFile"
        if (Test-Path $invPath) {
            foreach ($k in (Get-ChildItem $invPath -ErrorAction SilentlyContinue)) {
                try {
                    $pv = Get-ItemProperty $k.PSPath -ErrorAction Stop
                    $null = $rows.Add([PSCustomObject]@{
                        Source      = 'InventoryApplicationFile'
                        Name        = $pv.LowerCaseLongPath
                        FileName    = $pv.FileId
                        SHA1        = if ($pv.FileId -and $pv.FileId.Length -ge 40) { $pv.FileId.Substring($pv.FileId.Length-40) } else { $pv.FileId }
                        Publisher   = $pv.Publisher
                        ProductName = $pv.ProductName
                        Size        = $pv.Size
                        LinkDate    = $pv.LinkDate
                        FirstSeenUtc= $pv.FileInsertDate
                    })
                } catch { }
            }
        }
        # eski format
        $filePath = "HKLM:\$mount\Root\File"
        if ($rows.Count -eq 0 -and (Test-Path $filePath)) {
            foreach ($vol in (Get-ChildItem $filePath -ErrorAction SilentlyContinue)) {
                foreach ($k in (Get-ChildItem $vol.PSPath -ErrorAction SilentlyContinue)) {
                    try {
                        $pv = Get-ItemProperty $k.PSPath -ErrorAction Stop
                        $null = $rows.Add([PSCustomObject]@{
                            Source      = 'File'
                            Name        = $pv.'15'
                            FileName    = $pv.'6'
                            SHA1        = $pv.'101'
                            Publisher   = $pv.''
                            ProductName = $pv.'0'
                            Size        = $pv.'6'
                            LinkDate    = $pv.'f'
                            FirstSeenUtc= $pv.'11'
                        })
                    } catch { }
                }
            }
        }
    } catch {
        Write-DLog "  Amcache could not be read: $($_.Exception.Message)" -Level DEBUG
    } finally {
        if ($loaded) {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $null = & reg.exe unload "HKLM\$mount" 2>&1
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
    return $rows
}


# ============================================================================
#  MODUL: EXECUTION EVIDENCE (ShimCache + Amcache) - FAZ 4
# ============================================================================

Register-DModule -Name 'Execution Evidence (ShimCache/Amcache)' -Phase 3 -SkipOnQuick `
    -Description 'AppCompatCache ve Amcache.hve ham parse - silinmis binary izleri' `
    -HuntTags @('Persistence','DefenseEvasion') -Body {

    # --- ShimCache (AppCompatCache) ---
    # ONEMLI YORUM NOTU: ShimCache girdisi CALISTIRMA kaniti DEGILDIR; dosyanin
    # sistem tarafindan GORULDUGUNU gosterir. Yaygin bir yanlis yorumdur.
    $shim = @(Read-DShimCache)
    Export-DArtifact -Name '15_shimcache' -Data $shim

    if ($shim.Count -eq 0) {
        Add-DFinding -RuleId 'DGL-266' -Severity INFO `
            -Title 'ShimCache okunamadi veya bos' `
            -Evidence 'AppCompatCache registry degeri yok/parse edilemedi' `
            -Mitre 'T1070' -Artifact '15_shimcache' `
            -Why 'ShimCache silinmis binary izlerini tutar; erisilemiyorsa bu gorunurluk kaybidir'
    } else {
        Write-DLog "  ShimCache: $($shim.Count) entries parsed" -Level DEBUG
        foreach ($e in $shim) {
            if (-not $e.Path) { continue }
            $pp = Expand-DPath $e.Path
            # supheli dizinden gorulmus binary
            if (Test-DSuspiciousPath -Path $pp) {
                $exists = Test-Path -LiteralPath $pp -PathType Leaf -ErrorAction SilentlyContinue
                $sev = if ($exists) { 'HIGH' } else { 'CRITICAL' }
                $note = if ($exists) { 'file still on disk' } else { 'FILE NO LONGER PRESENT - deleted' }
                Add-DFinding -RuleId 'DGL-267' -Severity $sev `
                    -Title 'ShimCache: supheli dizinde binary kaydi' `
                    -Evidence "$($e.Path) [$note] son degisiklik: $($e.LastModified)" `
                    -Mitre 'T1070.004' -Artifact '15_shimcache' -Timestamp $e.LastModified `
                    -Why 'ShimCache dosya silinse bile kaydi korur; silinmis payload''in en guclu kanitidir'
                if ($e.LastModified) {
                    Add-DTimelineEvent -Timestamp $e.LastModified -Source 'ShimCache' `
                        -Description "ShimCache record: $(Split-Path $e.Path -Leaf)" `
                        -Detail $e.Path -Severity $sev
                }
            }
            # saldiri araci adlari
            $leaf = try { (Split-Path $pp -Leaf).ToLowerInvariant() } catch { '' }
            if ($leaf -and ($Script:ExfilBins -contains $leaf -or
                $leaf -match '(?i)^(psexec|mimikatz|procdump|lazagne|rubeus|seatbelt|sharphound|winpeas|nmap|rclone)')) {
                Add-DFinding -RuleId 'DGL-268' -Severity CRITICAL `
                    -Title 'ShimCache: saldiri araci kaydi' `
                    -Evidence "$($e.Path) @ $($e.LastModified)" `
                    -Mitre 'T1588.002' -Artifact '15_shimcache' -Timestamp $e.LastModified `
                    -Why 'Bu araclar mesru is yuklerinde bulunmaz; ShimCache kaydi diskten silinse bile kalir'
            }
            if ($e.Path) { $null = Test-DIoc -Value $e.Path -Context 'ShimCache' -Artifact '15_shimcache' }
        }
    }

    # --- Amcache ---
    $amc = @(Read-DAmcache)
    Export-DArtifact -Name '15_amcache' -Data $amc
    if ($amc.Count -gt 0) {
        Write-DLog "  Amcache: $($amc.Count) records" -Level DEBUG
        foreach ($a in $amc) {
            if (-not $a.Name) { continue }
            $np = Expand-DPath ([string]$a.Name)
            if (Test-DSuspiciousPath -Path $np) {
                Add-DFinding -RuleId 'DGL-269' -Severity HIGH `
                    -Title 'Amcache: supheli dizinde program kaydi' `
                    -Evidence "$($a.Name) SHA1:$($a.SHA1) yayinci:$($a.Publisher) ilk gorulme:$($a.FirstSeenUtc)" `
                    -Mitre 'T1204' -Artifact '15_amcache' -Timestamp $a.FirstSeenUtc `
                    -Why 'Amcache SHA1 hash ve ilk gorulme zamanini tutar; Prefetch silinse bile iz kalir' 
            }
            if ($a.SHA1) { $null = Test-DIoc -Value ([string]$a.SHA1) -Context "Amcache $($a.Name)" -Artifact '15_amcache' }
        }
    } else {
        Add-DFinding -RuleId 'DGL-271' -Severity INFO `
            -Title 'Amcache okunamadi' `
            -Evidence 'Amcache.hve kilitli veya erisilemedi (yonetici + kilitsiz kopya gerekir)' `
            -Mitre 'T1070' -Artifact '15_amcache' `
            -Why 'Amcache calistirma/kurulum izlerinin ikinci kaynagidir; -CollectRaw ile VSS uzerinden alinabilir'
    }
}


# ============================================================================
#  FAZ 5: SIGMA DESTEGI
#  Derlenmis sigma-pack.json yuklenir ve toplanan artefaktlara uygulanir.
#  TASARIM KARARI: Sigma bulgulari AYRI raporlanir ve risk skoruna GIRMEZ.
#  Topluluk kurallari degisken kalitededir; birincil skoru kirletmemeleri icin
#  ayri tutulur. Analist bunlari ipucu olarak degerlendirir.
# ============================================================================

function Import-DSigmaPack {
    <# Derlenmis sigma-pack.json yukler. Beklenen sema:
       { "meta": {...}, "rules": [ { id, title, level, logsource:{category,service},
         detection: { <selName>: [ {field, op, values[]} ... ], ... },
         condition: "sel and not filt", tags:[], description } ] }
       Build-SigmaPack.ps1 bu formati uretir. #>
    param([string]$Path)
    $pack = $null
    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-DLog "Sigma pack not found: $Path" -Level WARN
        return $null
    }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $pack = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-DLog "Sigma pack could not be read: $($_.Exception.Message)" -Level ERROR
        return $null
    }
    if (-not $pack.rules) {
        Write-DLog 'Sigma pack has no rules array' -Level WARN
        return $null
    }
    Write-DLog "Sigma pack loaded: $(@($pack.rules).Count) rules" -Level OK
    return $pack
}

function ConvertTo-DSigmaRecordMap {
    <# PERFORMANS: kaydin alanlarini bir kez kucuk-harfli hashtable'a cevirir.
       Onceki surumde her alan kontrolu icin PSObject.Properties taraniyordu;
       7177 kural x yuzlerce kayit x birkac alan = milyonlarca tarama (~1.8 saat).
       Bu donusum ile lookup O(1) olur. #>
    param($Record)
    $m = @{}
    foreach ($p in $Record.PSObject.Properties) {
        $m[$p.Name.ToLowerInvariant()] = [string]$p.Value
    }
    # Sigma alan adlarini Douglas alan adlarina esle.
    # DIKKAT: takma adlar DAR tutulur. Onceki genis eslemede ornegin
    # 'commandline' -> 'pathname'/'value' idi; bu, dosya/registry kayitlarinda
    # komut satiri kurallarinin yanlis atesle mesine yol aciyordu
    # (mesru MpCmdRun.log dosyasi "credential dump tool" olarak isaretlendi).
    # Anlamsal olarak AYNI seyi ifade eden alanlar disinda esleme yapilmaz.
    # KURAL: yalnizca ANLAMSAL OLARAK AYNI seyi ifade eden alanlar eslenir.
    # Sigma 'Image' = calistirilabilirin tam yolu = bizde 'Path' (dogru esleme).
    # Ama 'CommandLine' -> 'PathName'/'Value' YANLISTI: dosya ve registry
    # kayitlarinda komut satiri kurallarini yanlis atesliyordu.
    $alias = @{
        'image'            = @('path','processpath','imagepath','newprocessname','binarypath')
        'commandline'      = @('cmdline','processcommandline')
        'parentimage'      = @('parentpath','parentname','parentprocessname')
        'parentcommandline'= @('parentcmdline')
        'targetfilename'   = @('fullname')
        'imageloaded'      = @('pathname','path')
        'destinationip'    = @('remoteaddress','dstip')
        'destinationport'  = @('remoteport','dstport')
        'sourceip'         = @('localaddress','srcip')
        'destinationhostname' = @('dsthost','remotehost','remotednsname')
        'query'            = @('queryname')
        'queryname'        = @('query')
        'pipename'         = @('name')
        'servicename'      = @('name','servicename')
        'servicefilename'  = @('binarypath','imagepath','pathname')
        'targetobject'     = @('key','keypath')
        'user'             = @('username','owner')
        'scriptblocktext'  = @('scriptblock')
        'originalfilename' = @('originalfilename')
    }
    foreach ($k in $alias.Keys) {
        if (-not $m.ContainsKey($k) -or [string]::IsNullOrEmpty($m[$k])) {
            foreach ($cand in $alias[$k]) {
                if ($m.ContainsKey($cand) -and -not [string]::IsNullOrEmpty($m[$cand])) {
                    $m[$k] = $m[$cand]; break
                }
            }
        }
    }
    # keywords (serbest metin) + on-eleme blob'u. Blob SADECE on-eleme icin
    # kullanilir; gercek eslesme kararini vermez.
    $m['__keywords__'] = (($Record.PSObject.Properties | ForEach-Object { [string]$_.Value }) -join ' ')
    return $m
}

function Test-DSigmaFieldMatch {
    <# Tek alan kosulu. $Map onceden kurulmus kucuk-harfli alan sozlugu.
       op: equals | contains | startswith | endswith | re | gt | lt | exists #>
    param([hashtable]$Map, [string]$Field, [string]$Op, [object[]]$Values)
    if (-not $Map) { return $false }
    $key = $Field.ToLowerInvariant()
    $sv = $null
    if ($Map.ContainsKey($key)) { $sv = $Map[$key] }
    elseif ($key -match '\.') {
        $last = ($key -split '\.')[-1]
        if ($Map.ContainsKey($last)) { $sv = $Map[$last] }
    }
    if ($Op -eq 'exists') { return (-not [string]::IsNullOrEmpty($sv)) }
    if ([string]::IsNullOrEmpty($sv)) { return $false }

    foreach ($v in $Values) {
        $vs = [string]$v
        if ($vs -eq '') { continue }
        $hit = switch ($Op) {
            'equals'     { $sv.Equals($vs, [StringComparison]::OrdinalIgnoreCase) }
            'contains'   { $sv.IndexOf($vs, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
            'startswith' { $sv.StartsWith($vs, [StringComparison]::OrdinalIgnoreCase) }
            'endswith'   { $sv.EndsWith($vs, [StringComparison]::OrdinalIgnoreCase) }
            're'         { try { [regex]::IsMatch($sv, $vs, 'IgnoreCase') } catch { $false } }
            'gt'         { try { [double]$sv -gt [double]$vs } catch { $false } }
            'lt'         { try { [double]$sv -lt [double]$vs } catch { $false } }
            default      { $sv.IndexOf($vs, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
        }
        if ($hit) { return $true }
    }
    return $false
}

function Test-DSigmaSelection {
    <# Selection blogu.
       Sema: kosul = 'field' alani olan nesne.
             dizi-of-kosul  -> AND
             dizi-of-dizi   -> OR (alternatifler)
       NOT: ayrim SADECE 'field' alaninin varligina gore yapilir. Onceki
       surumde hatali ayrim sonsuz ozyinelemeye (call depth overflow) yol
       aciyordu - kosul nesnesi kendisini "alternatif" sanip tekrar cagiriyordu. #>
    param([hashtable]$Map, $Selection)
    if ($null -eq $Selection) { return $false }

    # Tek kosul nesnesi mi?
    if (Test-DSigmaIsCondition $Selection) {
        return (Test-DSigmaFieldMatch -Map $Map -Field $Selection.field -Op $Selection.op -Values @($Selection.values))
    }

    $items = @($Selection)
    if ($items.Count -eq 0) { return $false }

    # Tum elemanlar kosul ise -> AND
    $allCond = $true
    foreach ($it in $items) { if (-not (Test-DSigmaIsCondition $it)) { $allCond = $false; break } }
    if ($allCond) {
        foreach ($c in $items) {
            if (-not (Test-DSigmaFieldMatch -Map $Map -Field $c.field -Op $c.op -Values @($c.values))) {
                return $false
            }
        }
        return $true
    }

    # Aksi halde alternatif gruplar -> OR
    foreach ($alt in $items) {
        if (Test-DSigmaIsCondition $alt) {
            if (Test-DSigmaFieldMatch -Map $Map -Field $alt.field -Op $alt.op -Values @($alt.values)) { return $true }
            continue
        }
        # alt grup: kendi icinde AND
        $ok = $true
        foreach ($c in @($alt)) {
            if (-not (Test-DSigmaIsCondition $c)) { $ok = $false; break }
            if (-not (Test-DSigmaFieldMatch -Map $Map -Field $c.field -Op $c.op -Values @($c.values))) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

function Test-DSigmaIsCondition {
    <# Nesne tek bir alan kosulu mu? ('field' ozelligi tasiyor mu) #>
    param($o)
    if ($null -eq $o) { return $false }
    if ($o -is [string]) { return $false }
    if ($o -is [System.Array]) { return $false }
    if ($o -is [hashtable] -or $o -is [System.Collections.IDictionary]) { return $o.Contains('field') }
    try { return (@($o.PSObject.Properties.Name) -contains 'field') } catch { return $false }
}

function Test-DSigmaCondition {
    <# Mini condition degerlendirici: and/or/not/parantez, "all of them",
       "N of sel*". Aggregation (|) desteklenmez -> $null doner.
       NOT: [regex]::Replace MatchEvaluator scriptblock'u icinde disaridaki
       degiskenler (SelResults) guvenilir sekilde gorunmuyor; bu yuzden
       "N of X" ifadeleri dongu ile, scriptblock kullanmadan cozuluyor. #>
    param([string]$Condition, [hashtable]$SelResults)
    if ([string]::IsNullOrWhiteSpace($Condition)) { return $false }
    $c = $Condition.Trim().ToLowerInvariant()
    if ($c -match '\|') { return $null }
    if (-not $SelResults) { $SelResults = @{} }

    # --- "all/any/N of <pattern>" ifadelerini scriptblock'suz coz ---
    $guard = 0
    while ($guard -lt 20) {
        $guard++
        $m = [regex]::Match($c, '(all|any|\d+)\s+of\s+([a-z0-9_\*]+)')
        if (-not $m.Success) { break }
        $qty = $m.Groups[1].Value
        $pat = $m.Groups[2].Value
        if ($pat -eq 'them') { $keys = @($SelResults.Keys) }
        else { $keys = @($SelResults.Keys | Where-Object { $_.ToLowerInvariant() -like $pat }) }
        $rep = 'false'
        if ($keys.Count -gt 0) {
            $tc = 0
            foreach ($k in $keys) { if ($SelResults[$k]) { $tc++ } }
            $ok = switch ($qty) {
                'all'   { $tc -eq $keys.Count }
                'any'   { $tc -ge 1 }
                default { $tc -ge ([int]$qty) }
            }
            if ($ok) { $rep = 'true' }
        }
        $c = $c.Substring(0, $m.Index) + $rep + $c.Substring($m.Index + $m.Length)
    }

    # --- selection adlarini sonuclariyla degistir (uzun adlar once) ---
    foreach ($k in ($SelResults.Keys | Sort-Object { $_.Length } -Descending)) {
        $rep = 'false'
        if ($SelResults[$k]) { $rep = 'true' }
        $pattern = "(?<![a-z0-9_])" + [regex]::Escape($k.ToLowerInvariant()) + "(?![a-z0-9_])"
        $c = [regex]::Replace($c, $pattern, $rep)
    }

    # --- kalan bilinmeyen tanimlayicilar -> false ---
    $c = [regex]::Replace($c, '(?<![a-z0-9_$])(?!true\b|false\b|and\b|or\b|not\b)[a-z][a-z0-9_]*', 'false')

    # --- guvenlik: sadece true/false/and/or/not/parantez/bosluk kalmali ---
    $probe = [regex]::Replace($c, '\b(true|false|and|or|not)\b', '')
    $probe = [regex]::Replace($probe, '[\s\(\)]', '')
    if ($probe -ne '') { return $null }

    try {
        # Sigma "and/or/not" kelime operatorlerini PowerShell "-and/-or/-not"
        # bicimine cevir. Bu olmadan "$true and $true" gecersiz sozdizimidir.
        $expr = [regex]::Replace($c, '\btrue\b',  '$true')
        $expr = [regex]::Replace($expr, '\bfalse\b', '$false')
        $expr = [regex]::Replace($expr, '\band\b', '-and')
        $expr = [regex]::Replace($expr, '\bor\b',  '-or')
        $expr = [regex]::Replace($expr, '\bnot\b', '-not')
        if ([string]::IsNullOrWhiteSpace($expr)) { return $null }
        return [bool](& ([scriptblock]::Create($expr)))
    } catch { return $null }
}

function Invoke-DSigmaMatching {
    <# Sigma paketini toplanan artefaktlara uygular.
       PERFORMANS TASARIMI:
         1) Her kayit icin alan sozlugu BIR KEZ kurulur (kural basina degil)
         2) Kural, kategorisinde veri yoksa hic degerlendirilmez
         3) Kaba on-eleme: kuralin tum literal degerleri kaydin birlesik
            metninde hic gecmiyorsa kural atlanir (ucuz string tarama)
       Sonuclar SIGMA.csv'ye yazilir; risk skoruna DAHIL EDILMEZ. #>
    param($Pack, [int]$TimeBudgetSec = 300, [int]$PerRuleCap = 5)
    if (-not $Pack) { return }

    $catMap = @{
        'process_creation'    = @('artifacts\03_processes.csv', 'artifacts\events\11_evt_4688_procs.csv')
        'network_connection'  = @('artifacts\04_tcp_connections.csv', 'artifacts\events\11_sysmon_3_network.csv')
        'registry_set'        = @('artifacts\07_autoruns.csv')
        'registry_add'        = @('artifacts\07_autoruns.csv')
        'registry_event'      = @('artifacts\07_autoruns.csv')
        'file_event'          = @('artifacts\13_recent_files.csv')
        'ps_script'           = @('artifacts\events\11_evt_ps_4104.csv')
        'ps_module'           = @('artifacts\events\11_evt_ps_4104.csv')
        'ps_classic_start'    = @('artifacts\events\11_evt_ps_classic.csv')
        'image_load'          = @('artifacts\09_drivers.csv')
        'driver_load'         = @('artifacts\09_drivers.csv')
        'pipe_created'        = @('artifacts\events\11_sysmon_17_pipes.csv')
        'wmi_event'           = @('artifacts\08_wmi_subscriptions.csv')
        'dns_query'           = @('artifacts\events\11_sysmon_22_dns.csv')
        'create_remote_thread'= @('artifacts\events\11_sysmon_8_createremotethread.csv')
        'service_creation'    = @('artifacts\05_services.csv', 'artifacts\events\11_evt_7045_newservice.csv')
        'scheduled_task'      = @('artifacts\06_scheduled_tasks.csv')
    }

    # --- veri setlerini bir kez yukle ve alan sozluklerini onceden kur ---
    $prepared  = @{}   # kategori -> @( @{Map;Rec;Blob} )
    $catSchema = @{}   # kategori -> alan adlari kumesi
    foreach ($cat in $catMap.Keys) {
        $recs = New-Object System.Collections.ArrayList
        foreach ($rel in $catMap[$cat]) {
            $p = Join-Path $Script:Ctx.OutputDir $rel
            if (-not (Test-Path -LiteralPath $p)) { continue }
            try {
                foreach ($r in (Import-Csv -LiteralPath $p -ErrorAction Stop)) {
                    $map = ConvertTo-DSigmaRecordMap -Record $r
                    $null = $recs.Add(@{
                        Map  = $map
                        Rec  = $r
                        Blob = $map['__keywords__'].ToLowerInvariant()
                    })
                }
            } catch { }
        }
        if ($recs.Count -gt 0) {
            $prepared[$cat] = @($recs)
            # kategori alan semasi (on-eleme + alan kapsami kontrolu icin)
            $schema = New-Object System.Collections.Generic.HashSet[string]
            foreach ($k2 in $recs[0].Map.Keys) { $null = $schema.Add($k2) }
            $catSchema[$cat] = $schema
        }
    }
    $totalRecs = ($prepared.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-DLog "  Sigma: $totalRecs records prepared ($($prepared.Keys.Count) categories)" -Level DEBUG

    $hits      = New-Object System.Collections.ArrayList
    $evaluated = 0; $skipped = 0; $noData = 0; $prefiltered = 0; $budgetHit = $false; $capped = 0; $uncovered = 0

    # PERFORMANS GERCEGI: PowerShell fonksiyon cagri maliyeti ~0.35ms. 7000+
    # kural x binlerce kayit dakikalar surer. Bu yuzden bir SURE BUTCESI var:
    # butce dolunca kalan kurallar atlanir ve rapora acikca yazilir. Boylece
    # koleksiyon asla saatlerce asili kalmaz.
    $swBudget = [Diagnostics.Stopwatch]::StartNew()
    $ruleList = @($Pack.rules)
    $ruleTotal = $ruleList.Count
    $lastReport = 0

    foreach ($rule in $ruleList) {
        if ($swBudget.Elapsed.TotalSeconds -gt $TimeBudgetSec) { $budgetHit = $true; break }
        # her 500 kuralda bir ilerleme (uzun calismada kullanici bilgilensin)
        if ($evaluated - $lastReport -ge 500) {
            $lastReport = $evaluated
            Write-DLog ("  Sigma progress: {0}/{1} rules, {2} matches, {3}s" -f `
                        $evaluated, $ruleTotal, $hits.Count, [int]$swBudget.Elapsed.TotalSeconds) -Level DEBUG
        }
        $cat = $null
        try { $cat = [string]$rule.logsource.category } catch { }
        if (-not $cat -or -not $catMap.ContainsKey($cat)) { $skipped++; continue }
        if (-not $prepared.ContainsKey($cat)) { $noData++; continue }

        $selNames = @($rule.detection.PSObject.Properties.Name)
        if ($selNames.Count -eq 0) { $skipped++; continue }

        # --- ALAN KAPSAMI KONTROLU ---
        # Topluluk Sigma kurallari Sysmon/EDR alan semasi varsayar
        # (OriginalFileName, IntegrityLevel, Hashes...). Douglas bu alanlarin
        # bir kismini toplamaz. Kural bilmedigimiz alanlara dayaniyorsa,
        # ozellikle "X and not filter" kaliplarinda filter HER ZAMAN false olur
        # ve kural yanlis atesler. Bu yuzden alanlarinin cogunu
        # karsilayamadigimiz kurallari DEGERLENDIRMIYORUZ - sessizce yanlis
        # sonuc uretmektense kapsam disi saymak dogrudur.
        $refFields = New-Object System.Collections.Generic.HashSet[string]
        foreach ($sn in $selNames) {
            foreach ($cond in @($rule.detection.$sn)) {
                foreach ($c2 in @($cond)) {
                    if ($null -eq $c2) { continue }
                    $fn = [string]$c2.field
                    if ($fn) { $null = $refFields.Add($fn.ToLowerInvariant()) }
                }
            }
        }
        if ($refFields.Count -gt 0 -and $catSchema.ContainsKey($cat)) {
            $known = 0
            foreach ($fn in $refFields) {
                if ($fn -eq '__keywords__') { $known++; continue }
                if ($catSchema[$cat].Contains($fn)) { $known++ }
            }
            if (($known / [double]$refFields.Count) -lt 0.6) { $uncovered++; continue }
        }

        # --- kaba on-eleme: kuralin ZORUNLU (AND) literalleri ---
        # Sadece TEK selection'lu ve hepsi AND olan kurallarda guvenli bir
        # kisayol: en ayirt edici literal kayitta hic gecmiyorsa kural elenir.
        # Coklu selection'da OR olabilecegi icin daha temkinli davraniyoruz:
        # TUM literalleri tek regex'te birlestirip "hicbiri yok" durumunda eliyoruz.
        if (-not $rule.PSObject.Properties.Name.Contains('__prefilter')) {
            $lits = New-Object System.Collections.Generic.HashSet[string]
            foreach ($sn in $selNames) {
                foreach ($cond in @($rule.detection.$sn)) {
                    foreach ($c2 in @($cond)) {
                        if ($null -eq $c2 -or $c2.op -in 're','gt','lt','exists') { continue }
                        foreach ($v in @($c2.values)) {
                            $vs = [string]$v
                            if ($vs.Length -ge 5) { $null = $lits.Add($vs.ToLowerInvariant()) }
                        }
                    }
                }
            }
            $rx = $null
            if ($lits.Count -gt 0 -and $lits.Count -le 400) {
                try {
                    $pat = ($lits | ForEach-Object { [regex]::Escape($_) }) -join '|'
                    $rx = [regex]::new($pat, [Text.RegularExpressions.RegexOptions]::Compiled -bor
                                              [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                } catch { $rx = $null }
            }
            Add-Member -InputObject $rule -NotePropertyName '__prefilter' -NotePropertyValue $rx -Force
        }
        $preRx = $rule.__prefilter

        $evaluated++
        $ruleHitCount = 0
        foreach ($item in $prepared[$cat]) {
            # on-eleme: kuralin hicbir literali kayitta gecmiyorsa atla
            if ($preRx -and -not $preRx.IsMatch($item.Blob)) { $prefiltered++; continue }

            $selRes = @{}
            foreach ($sn in $selNames) {
                $selRes[$sn] = [bool](Test-DSigmaSelection -Map $item.Map -Selection $rule.detection.$sn)
            }
            $res = Test-DSigmaCondition -Condition ([string]$rule.condition) -SelResults $selRes
            if ($res -ne $true) { continue }

            $rec = $item.Rec
            $ev = ''
            foreach ($f in @('CommandLine','Path','FullName','Name','ImagePath','Value','ScriptBlock','QueryName','PathName','Actions')) {
                $pp = $rec.PSObject.Properties | Where-Object { $_.Name -ieq $f } | Select-Object -First 1
                if ($pp -and $pp.Value) { $ev = "$f=$($pp.Value)"; break }
            }
            if (-not $ev) { $ev = ($rec.PSObject.Properties | Select-Object -First 3 |
                                   ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' ' }

            # Kural basina TAVAN: tek bir Sigma kurali yuzlerce kayitla
            # eslesebilir (ozellikle genis "dropped files" kurallari). Analist
            # icin ilk N ornek yeterlidir; sayac toplami korur.
            $ruleHitCount++
            if ($ruleHitCount -le $PerRuleCap) {
                $null = $hits.Add([PSCustomObject]@{
                    SigmaId     = [string]$rule.id
                    Title       = [string]$rule.title
                    Level       = [string]$rule.level
                    Category    = $cat
                    Tags        = (@($rule.tags) -join ',')
                    Evidence    = (Format-DEvidence -Text $ev -Max 700)
                    Description = (Format-DEvidence -Text ([string]$rule.description) -Max 300)
                    MatchCount  = 1
                })
            }
        }
        if ($ruleHitCount -gt $PerRuleCap) {
            # tavan asildi: son eklenen kaydin sayacini gercek toplama cek
            $lastIdx = $hits.Count - 1
            if ($lastIdx -ge 0) { $hits[$lastIdx].MatchCount = $ruleHitCount }
            $capped++
        }
    }

    $Script:SigmaHits = @($hits)
    Write-DLog ("Sigma: {0}/{1} rules evaluated, {2} outside field coverage, {3} no data -> {4} matches ({5} capped, {6}s)" -f `
                $evaluated, $ruleTotal, $uncovered, $noData, $hits.Count, $capped, [int]$swBudget.Elapsed.TotalSeconds) -Level OK
    if ($budgetHit) {
        Write-DLog ("  Sigma time budget ({0}s) exhausted - {1} rules not evaluated" -f `
                    $TimeBudgetSec, ($ruleTotal - $evaluated)) -Level WARN
        Add-DFinding -RuleId 'DGL-401' -Severity INFO `
            -Title 'Sigma degerlendirmesi sure butcesi nedeniyle tamamlanmadi' `
            -Evidence "$evaluated/$ruleTotal kural islendi ($TimeBudgetSec sn butce)" `
            -Artifact 'SIGMA' `
            -Why 'Daha kucuk/odakli bir sigma-pack kullanin veya butceyi artirin; kapsam eksikligi bilinmelidir'
    }

    if ($hits.Count -gt 0) {
        $hits | Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'SIGMA.csv') `
                -NoTypeInformation -Encoding UTF8 -Force
        $byLevel = $hits | Group-Object Level | ForEach-Object { "$($_.Name):$($_.Count)" }
        Add-DFinding -RuleId 'DGL-400' -Severity INFO `
            -Title 'Sigma kural eslesmeleri mevcut (ayri degerlendirin)' `
            -Evidence "$($hits.Count) eslesme [$($byLevel -join ' ')] - detay: SIGMA.csv" `
            -Artifact 'SIGMA' `
            -Why 'Topluluk Sigma kurallari degisken kalitededir; risk skoruna dahil edilmez, ipucu olarak incelenir'
    }
}


# ============================================================================
#  UPDATE CENTER - kural setleri ve yardimci veriler
#  Tum indirmeler script'in yanindaki "data" klasorune yapilir.
#  Cevrimdisi ortamda calisilabilmesi icin hicbir indirme ZORUNLU degildir.
# ============================================================================

function Get-DAssetPath {
    <# Bir kural seti dosyasini ARAR: once data\ klasoru, sonra script'in
       yanindaki kok dizin, sonra calisma dizini. Kullanicilar dosyalari
       genelde script'in yanina duz kopyalar; sadece data\ icine bakmak
       "elinde oldugu halde yok" demeye yol aciyordu. #>
    param([string]$FileName)
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $cands = @(
        (Join-Path (Join-Path $base 'data') $FileName)
        (Join-Path $base $FileName)
        (Join-Path (Get-Location).Path $FileName)
    )
    foreach ($c in $cands) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { return (Resolve-Path -LiteralPath $c).Path }
    }
    return $null
}

function Get-DDataDir {
    <# Kural setleri ve indirilen veriler icin kalici klasor. Script'in yaninda
       tutulur ki USB/paylasim ile tasindiginda beraber gitsin. #>
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $d = Join-Path $base 'data'
    if (-not (Test-Path $d)) { $null = New-Item -ItemType Directory -Path $d -Force -EA SilentlyContinue }
    return $d
}

$Script:UpdateSources = [ordered]@{
    'sigma' = @{
        Name = 'Sigma rules (SigmaHQ official repo)'
        Url  = 'https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master'
        File = 'sigma-master.zip'
        Kind = 'zip'
        Note = 'Raw YAML rules; compiled into sigma-pack.json after download'
    }
    'mitre' = @{
        Name = 'MITRE ATT&CK Enterprise (STIX)'
        Url  = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
        File = 'enterprise-attack.json'
        Kind = 'json'
        Note = 'Technique names/tactics; distilled into mitre-v19.json (~50 MB download)'
    }
    'yara' = @{
        Name = 'YARA rules (YARA-Forge core package)'
        Url  = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip'
        File = 'yara-forge-core.zip'
        Kind = 'zip'
        Note = 'Quality-filtered, deduplicated build (~5000 rules)'
    }
    'yarafull' = @{
        Name = 'YARA rules (YARA-Forge full package)'
        Url  = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip'
        File = 'yara-forge-full.zip'
        Kind = 'zip'
        Note = 'Wider coverage, higher false-positive risk'
    }
    'yaraengine' = @{
        Name = 'YARA engine (VirusTotal official yara64.exe)'
        Url  = 'https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip'
        File = 'yara-win64.zip'
        Kind = 'zip'
        Note = 'Executable required for YARA scanning (PowerShell has no YARA engine)'
    }
}

function Get-DUpdateStatus {
    <# data klasorundeki varliklarin durumunu dondurur (menude gosterilir). #>
    $d = Get-DDataDir
    $items = New-Object System.Collections.ArrayList

    $checks = @(
        @{ Key='sigma-pack'; Label='Sigma pack (compiled)'   ; File='sigma-pack.json' }
        @{ Key='sigma-raw';  Label='Sigma raw rules';      File='sigma-master.zip' }
        @{ Key='mitre';      Label='MITRE ATT&CK data';      File='mitre-v19.json' }
        @{ Key='yara';       Label='YARA rule package';        File='yara-rules.yar' }
        @{ Key='yaraengine'; Label='YARA engine (yara64.exe)'; File='yara64.exe' }
    )
    foreach ($c in $checks) {
        $found = Get-DAssetPath $c.File
        $c.Path = if ($found) { $found } else { Join-Path $d $c.File }
        $exists = [bool]$found
        $size = 0; $age = $null
        if ($exists) {
            try {
                $fi = Get-Item -LiteralPath $c.Path
                $size = $fi.Length
                $age = [int]((Get-Date) - $fi.LastWriteTime).TotalDays
            } catch { }
        }
        $null = $items.Add([PSCustomObject]@{
            Key = $c.Key; Label = $c.Label; Path = $c.Path
            Exists = $exists
            SizeMB = if ($size) { [math]::Round($size/1MB, 1) } else { 0 }
            AgeDays = $age
        })
    }
    return $items
}

function Invoke-DDownload {
    <# TLS 1.2 zorlayarak dosya indirir, ilerleme gosterir.
       PowerShell 5.1 varsayilan olarak TLS 1.0 deneyebilir - GitHub reddeder. #>
    param([string]$Url, [string]$Destination, [string]$Label)
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
    } catch { }
    Write-Host "  downloading: $Label" -ForegroundColor Gray
    $tmp = "$Destination.part"
    try {
        $pp = $ProgressPreference
        $ProgressPreference = 'Continue'
        Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
        $ProgressPreference = $pp
        if (Test-Path $Destination) { Remove-Item $Destination -Force -EA SilentlyContinue }
        Move-Item $tmp $Destination -Force
        $mb = [math]::Round((Get-Item $Destination).Length/1MB, 1)
        Write-Host "  done: $Label ($mb MB)" -ForegroundColor Green
        return $true
    } catch {
        Remove-Item $tmp -Force -EA SilentlyContinue
        Write-Host "  FAILED: $Label - $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Update-DSigmaRules {
    <# SigmaHQ ham kurallarini indirir ve sigma-pack.json olarak derler.
       Derleme icin Build-SigmaPack.ps1 script'in yaninda olmalidir. #>
    $d = Get-DDataDir
    $zip = Join-Path $d 'sigma-master.zip'
    if (-not (Invoke-DDownload -Url $Script:UpdateSources['sigma'].Url -Destination $zip -Label 'SigmaHQ rules')) { return }

    $ext = Join-Path $d 'sigma-src'
    Write-Host '  extracting archive...' -ForegroundColor Gray
    try {
        if (Test-Path $ext) { Remove-Item $ext -Recurse -Force -EA SilentlyContinue }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $ext)
    } catch {
        Write-Host "  archive could not be opened: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $rulesDir = Get-ChildItem $ext -Directory -Recurse -EA SilentlyContinue |
                Where-Object { $_.Name -eq 'rules' } | Select-Object -First 1
    if (-not $rulesDir) {
        Write-Host '  rules folder not found' -ForegroundColor Red
        return
    }
    $ymlCount = @(Get-ChildItem $rulesDir.FullName -Recurse -Include '*.yml' -File -EA SilentlyContinue).Count
    Write-Host "  $ymlCount YAML rules found" -ForegroundColor Gray

    $builder = $null
    $builder = Get-DAssetPath 'Build-SigmaPack.ps1'
    if (-not $builder) {
        Write-Host '  Build-SigmaPack.ps1 not found - raw rules downloaded but not compiled' -ForegroundColor Yellow
        Write-Host "  Ham kurallar: $($rulesDir.FullName)" -ForegroundColor Gray
        return
    }
    Write-Host '  compiling rules (may take a few minutes)...' -ForegroundColor Gray
    $out = Join-Path $d 'sigma-pack.json'
    try {
        & $builder -SigmaRoot $rulesDir.FullName -Out $out
        if (Test-Path $out) {
            Write-Host "  Sigma pack ready: $out" -ForegroundColor Green
        }
    } catch {
        Write-Host "  compilation error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-DMitreData {
    <# MITRE ATT&CK STIX verisini indirir ve Douglas'in kullandigi sade
       formata damitir (id -> ad, taktikler, aciklama). #>
    $d = Get-DDataDir
    $raw = Join-Path $d 'enterprise-attack.json'
    if (-not (Invoke-DDownload -Url $Script:UpdateSources['mitre'].Url -Destination $raw -Label 'MITRE ATT&CK (large file, be patient)')) { return }

    Write-Host '  distilling...' -ForegroundColor Gray
    try {
        $stix = Get-Content $raw -Raw | ConvertFrom-Json
        $out = New-Object System.Collections.ArrayList
        foreach ($o in $stix.objects) {
            if ($o.type -ne 'attack-pattern') { continue }
            if ($o.x_mitre_deprecated -eq $true -or $o.revoked -eq $true) { continue }
            $tid = $null
            foreach ($r in @($o.external_references)) {
                if ($r.source_name -eq 'mitre-attack') { $tid = $r.external_id; break }
            }
            if (-not $tid) { continue }
            $tactics = @()
            foreach ($ph in @($o.kill_chain_phases)) {
                if ($ph.kill_chain_name -eq 'mitre-attack') {
                    $tactics += (Get-Culture).TextInfo.ToTitleCase(($ph.phase_name -replace '-', ' '))
                }
            }
            $null = $out.Add([PSCustomObject]@{
                id = $tid; name = $o.name; tactics = $tactics
                description = if ($o.description) { $o.description.Substring(0, [Math]::Min(300, $o.description.Length)) } else { '' }
            })
        }
        $dest = Join-Path $d 'mitre-v19.json'
        $out | ConvertTo-Json -Depth 6 -Compress | Set-Content $dest -Encoding UTF8
        Write-Host "  $($out.Count) techniques distilled: $dest" -ForegroundColor Green
        # ham dosyayi sil (50+ MB)
        Remove-Item $raw -Force -EA SilentlyContinue
    } catch {
        Write-Host "  distillation error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-DYaraRules {
    param([switch]$Full)
    $d = Get-DDataDir
    $key = if ($Full) { 'yarafull' } else { 'yara' }
    $src = $Script:UpdateSources[$key]
    $zip = Join-Path $d $src.File
    if (-not (Invoke-DDownload -Url $src.Url -Destination $zip -Label $src.Name)) { return }
    try {
        $ext = Join-Path $d 'yara-src'
        if (Test-Path $ext) { Remove-Item $ext -Recurse -Force -EA SilentlyContinue }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $ext)
        $yar = Get-ChildItem $ext -Recurse -Include '*.yar','*.yara' -File -EA SilentlyContinue |
               Sort-Object Length -Descending | Select-Object -First 1
        if ($yar) {
            $dest = Join-Path $d 'yara-rules.yar'
            Copy-Item $yar.FullName $dest -Force
            $ruleCount = 0
            try { $ruleCount = @([regex]::Matches((Get-Content $dest -Raw), '(?m)^\s*rule\s+\w+')).Count } catch { }
            Write-Host "  YARA rules ready: $dest ($ruleCount rules)" -ForegroundColor Green
        } else {
            Write-Host '  no .yar file found in archive' -ForegroundColor Red
        }
    } catch {
        Write-Host "  archive error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Update-DYaraEngine {
    <# YARA motoru: PowerShell'de YARA yorumlayicisi YOKTUR. Tarama icin
       VirusTotal'in resmi yara64.exe ikilisi kullanilir. Bu, Douglas'in
       "sifir bagimlilik" kuralinin bilincli ve opsiyonel bir istisnasidir:
       indirilmezse YARA modulu sessizce atlanir, diger her sey calisir. #>
    $d = Get-DDataDir
    $zip = Join-Path $d 'yara-win64.zip'
    if (-not (Invoke-DDownload -Url $Script:UpdateSources['yaraengine'].Url -Destination $zip -Label 'YARA engine')) { return }
    try {
        $ext = Join-Path $d 'yara-bin'
        if (Test-Path $ext) { Remove-Item $ext -Recurse -Force -EA SilentlyContinue }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($zip, $ext)
        $exe = Get-ChildItem $ext -Recurse -Filter 'yara*.exe' -File -EA SilentlyContinue |
               Where-Object { $_.Name -notmatch 'yarac' } | Select-Object -First 1
        if ($exe) {
            $dest = Join-Path $d 'yara64.exe'
            Copy-Item $exe.FullName $dest -Force
            Write-Host "  YARA engine ready: $dest" -ForegroundColor Green
            try {
                $v = & $dest --version 2>&1 | Select-Object -First 1
                Write-Host "  version: $v" -ForegroundColor Gray
            } catch { }
        } else {
            Write-Host '  yara.exe not found in archive' -ForegroundColor Red
        }
    } catch {
        Write-Host "  archive error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-DUpdateMenu {
    while ($true) {
        $st = Get-DUpdateStatus
        Clear-Host
        Show-Banner
        Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
        Write-Host '  UPDATE CENTER' -ForegroundColor Cyan
        Write-Host ('  ' + ('=' * 74)) -ForegroundColor DarkCyan
        Write-Host "  Folder: $(Get-DDataDir)" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  CURRENT STATUS' -ForegroundColor Yellow
        foreach ($s in $st) {
            if ($s.Exists) {
                $ageTxt = if ($null -ne $s.AgeDays) { "$($s.AgeDays) days ago" } else { '' }
                $col = if ($null -ne $s.AgeDays -and $s.AgeDays -gt 30) { 'Yellow' } else { 'Green' }
                Write-Host ("   [+] {0,-32} {1,6} MB  {2}" -f $s.Label, $s.SizeMB, $ageTxt) -ForegroundColor $col
            } else {
                Write-Host ("   [ ] {0,-32} none" -f $s.Label) -ForegroundColor DarkGray
            }
        }
        Write-Host ''
        Write-Host '  DOWNLOAD / UPDATE' -ForegroundColor Yellow
        Write-Host '   [1] Sigma rules          SigmaHQ official repo + auto-compile' -ForegroundColor White
        Write-Host '   [2] MITRE ATT&CK         current technique names and tactics' -ForegroundColor White
        Write-Host '   [3] YARA rules           YARA-Forge core (quality-filtered, recommended)' -ForegroundColor White
        Write-Host '   [4] YARA rules FULL      wider coverage, more false positives' -ForegroundColor White
        Write-Host '   [5] YARA engine          yara64.exe (required for YARA scanning)' -ForegroundColor White
        Write-Host '   [6] UPDATE EVERYTHING    1 + 2 + 3 + 5' -ForegroundColor Cyan
        Write-Host ''
        Write-Host '   [7] Show source URLs' -ForegroundColor Gray
        Write-Host '   [0] Back' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  Choice: ' -ForegroundColor White -NoNewline
        $c = (Read-Host).Trim()
        Write-Host ''
        switch ($c) {
            '1' { Update-DSigmaRules }
            '2' { Update-DMitreData }
            '3' { Update-DYaraRules }
            '4' { Update-DYaraRules -Full }
            '5' { Update-DYaraEngine }
            '6' {
                Write-Host '  Updating all sources - may take 5-20 min depending on connection.' -ForegroundColor Yellow
                Update-DSigmaRules; Update-DMitreData; Update-DYaraRules; Update-DYaraEngine
            }
            '7' {
                Write-Host '  SOURCES' -ForegroundColor Yellow
                foreach ($k in $Script:UpdateSources.Keys) {
                    $s2 = $Script:UpdateSources[$k]
                    Write-Host "   $($s2.Name)" -ForegroundColor White
                    Write-Host "     $($s2.Url)" -ForegroundColor Cyan
                    Write-Host "     $($s2.Note)" -ForegroundColor DarkGray
                }
            }
            '0' { return }
            default { Write-Host '  Invalid choice.' -ForegroundColor Red }
        }
        Write-Host ''
        Write-Host '  Press ENTER to continue...' -ForegroundColor DarkGray -NoNewline
        $null = Read-Host
    }
}


# ============================================================================
#  MODUL: YARA TARAMASI (opsiyonel - motor ve kurallar indirilmisse calisir)
# ============================================================================

Register-DModule -Name 'YARA Scan' -Phase 3 -SkipOnQuick `
    -Description 'YARA-Forge kurallariyla hedefli dizin taramasi' `
    -HuntTags @('Persistence','DefenseEvasion') -Body {

    $engine = Get-DAssetPath 'yara64.exe'
    $rules  = Get-DAssetPath 'yara-rules.yar'

    if (-not $engine -or -not $rules) {
        # Sessizce atlamak YANLIS olurdu: analist YARA taramasinin yapildigini
        # sanabilir. Eksik bilesen rapora acikca yazilir.
        Add-DFinding -RuleId 'DGL-410' -Severity INFO `
            -Title 'YARA taramasi yapilmadi (bilesen eksik)' `
            -Evidence "motor: $(if($engine){'var'}else{'YOK'}) | kurallar: $(if($rules){'var'}else{'YOK'})" `
            -Artifact '16_yara' `
            -Why 'Menu > Guncelleme Merkezi uzerinden YARA motoru ve kurallari indirilebilir'
        Write-DLog '  YARA engine/rules missing, skipped (downloadable from the Update Center)' -Level DEBUG
        return
    }

    # Hedefli tarama: C:\ genelinde YARA saatler surer. Supheli dizinlerle sinirli.
    $targets = @($Script:ScanPaths | Where-Object { Test-Path $_ })
    if ($targets.Count -eq 0) { return }

    $hits = New-Object System.Collections.ArrayList
    $timeoutSec = 600
    $sw = [Diagnostics.Stopwatch]::StartNew()

    foreach ($t in $targets) {
        if ($sw.Elapsed.TotalSeconds -gt $timeoutSec) {
            Write-DLog "  YARA time limit ($timeoutSec s) exceeded, remaining directories skipped" -Level WARN
            Add-DFinding -RuleId 'DGL-412' -Severity INFO `
                -Title 'YARA taramasi sure siniri nedeniyle tamamlanmadi' `
                -Evidence "islenen dizinler sure siniri ($timeoutSec sn) icinde kesildi" `
                -Artifact '16_yara' `
                -Why 'Kapsam eksikligi bilinmelidir; -Days daraltarak veya dizin sayisini azaltarak tekrar deneyin'
            break
        }
        try {
            # -r ozyineli, -f hizli mod, -N tanimsiz modul hatalarini yut,
            # -w uyarilari bastir, -p paralel is parcacigi
            $raw = & $engine -r -f -w -N -p 4 --timeout=120 $rules $t 2>&1
            foreach ($line in @($raw)) {
                $ln = [string]$line
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                if ($ln -match '^(error|warning)' ) { continue }
                # cikti bicimi: "<RuleName> <DosyaYolu>"
                if ($ln -match '^(\S+)\s+(.+)$') {
                    $rule = $Matches[1]; $file = $Matches[2].Trim()
                    if (-not (Test-Path -LiteralPath $file)) { continue }
                    $null = $hits.Add([PSCustomObject]@{
                        Rule = $rule; File = $file
                        SHA256 = Get-DFileHashSafe -Path $file
                        SizeKB = try { [math]::Round((Get-Item -LiteralPath $file).Length/1KB,1) } catch { $null }
                    })
                }
            }
        } catch {
            Write-DLog "  YARA error ($t): $($_.Exception.Message)" -Level DEBUG
        }
    }

    Export-DArtifact -Name '16_yara' -Data @($hits)

    # Kural basina tavan - tek kural yuzlerce dosyayla eslesebilir
    $byRule = $hits | Group-Object Rule
    foreach ($g in $byRule) {
        $sample = @($g.Group | Select-Object -First 3 | ForEach-Object { $_.File })
        $ev = "$($g.Count) dosya :: " + ($sample -join '  |  ')
        Add-DFinding -RuleId 'DGL-411' -Severity HIGH `
            -Title "YARA eslesmesi: $($g.Name)" `
            -Evidence (Format-DEvidence -Text $ev -Max 800) `
            -Mitre 'T1204' -Artifact '16_yara' `
            -Why 'YARA-Forge kalite filtreli kural seti; eslesme dogrulanmali (paketleyici kurallari mesru yazilimda da eslesebilir)'
        foreach ($h in @($g.Group | Select-Object -First 5)) {
            if ($h.SHA256) { $null = Test-DIoc -Value $h.SHA256 -Context "YARA $($g.Name)" -Artifact '16_yara' }
        }
    }
    Write-DLog "  YARA: $($hits.Count) matches across $($byRule.Count) distinct rules" -Level DEBUG
}

function Complete-DCollection {
    Write-Host ''
    Write-Host '  === FINALIZE ===' -ForegroundColor White -BackgroundColor DarkBlue

    # Timeline
    if ($Script:Timeline.Count -gt 0) {
        $Script:Timeline | Sort-Object TimeUtc |
            Export-Csv -Path (Join-Path $Script:Ctx.OutputDir 'TIMELINE.csv') `
                       -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "Timeline: $($Script:Timeline.Count) records" -Level OK
    }

    # --- F1.5-4: DEDUP + KURAL BASINA TAVAN ---
    # Ayni kural + ayni baslik yuzlerce satir uretebiliyordu (DGL-150 = 432).
    # Tekil kanit satirlari FINDINGS.csv'de kalir; ozet gorunumu tek satira toplar.
    $Script:FindingsRaw = @($Script:Findings)     # tam liste (CSV icin)
    $CAP = 25                                      # kural basina gosterilecek maks
    $grouped = $Script:FindingsRaw | Group-Object RuleId, Title
    $deduped = New-Object System.Collections.ArrayList
    $cappedRules = New-Object System.Collections.ArrayList
    foreach ($g in $grouped) {
        $items = @($g.Group)
        $first = $items[0]
        if ($items.Count -eq 1) { $null = $deduped.Add($first); continue }
        # coklu: temsili kanitlari birlestir, sayiyi tasi
        $sample = @($items | Select-Object -First 3 | ForEach-Object { $_.Evidence })
        $times  = @($items | ForEach-Object { $_.TimeUtc } | Where-Object { $_ } | Sort-Object)
        $merged = $first.PSObject.Copy()
        $merged.Evidence = "[$($items.Count) kayit] " + ($sample -join '  ||  ')
        if ($items.Count -gt 3) { $merged.Evidence += "  || (+$($items.Count - 3) daha, tam liste: FINDINGS.csv)" }
        if ($times.Count -ge 2) {
            $merged | Add-Member -NotePropertyName Count -NotePropertyValue $items.Count -Force
            $merged | Add-Member -NotePropertyName FirstUtc -NotePropertyValue $times[0] -Force
            $merged | Add-Member -NotePropertyName LastUtc  -NotePropertyValue $times[-1] -Force
        } else {
            $merged | Add-Member -NotePropertyName Count -NotePropertyValue $items.Count -Force
        }
        $null = $deduped.Add($merged)
        if ($items.Count -gt $CAP) { $null = $cappedRules.Add("$($g.Name) : $($items.Count)") }
    }
    # ozet listeyi ana listeye al; tam liste FINDINGS.csv'ye Save-DInterimState'te gider
    $Script:FindingsDedup = @($deduped)
    if ($cappedRules.Count -gt 0) {
        Write-DLog ("Dedup: $($cappedRules.Count) high-volume rules summarised") -Level INFO
    }
    Write-DLog ("Dedup: $($Script:FindingsRaw.Count) raw findings -> $($deduped.Count) unique") -Level OK
    if ($Script:SelfExcluded -gt 0) {
        Write-DLog ("Self-noise: $($Script:SelfExcluded) records excluded") -Level OK
    }

    # F3: baseline delta + nadirlik skorlama (fan-out disinda, tek host)
    if ($Baseline) { Compare-DBaseline -BaselineDir $Baseline }
    if (-not $ComputerName) { Invoke-DRarityScoring }

    # F5: Sigma eslestirme (opsiyonel, -SigmaPath ile)
    if ($SigmaPath) {
        $pack = Import-DSigmaPack -Path $SigmaPath
        if ($pack) { Invoke-DSigmaMatching -Pack $pack }
    }

    # Findings (tam liste CSV'ye)
    Save-DInterimState

    # Katalog drift kontrolu
    $null = Test-DCatalogDrift

    # --- F1.5-9: VARLIK KORELASYONU ---
    # Ayni dosya/servis/gorev/IP'den dogan bulgulari tek "saldiri varligi"nda topla.
    # Boylece msedge_svc.ps1 6 kopuk satir yerine 1 zincir olarak gorunur.
    $Script:Entities = Get-DEntityCorrelation -Findings $Script:FindingsRaw

    # --- F1.5-5: NORMALIZE RISK SKORU (0-100) ---
    # Eski skor sinirsizdi (temiz makinede 4028). Artik BENZERSIZ bulgu uzerinden,
    # dogrusal olmayan (doyumlu) agirlikla, tavan 100.
    $uCrit = @($deduped | Where-Object Severity -eq 'CRITICAL').Count
    $uHigh = @($deduped | Where-Object Severity -eq 'HIGH').Count
    $uMed  = @($deduped | Where-Object Severity -eq 'MEDIUM').Count
    $uLow  = @($deduped | Where-Object Severity -eq 'LOW').Count
    # ham agirlikli puan
    $raw = ($uCrit * 25) + ($uHigh * 10) + ($uMed * 3) + ($uLow * 1)
    # doyum: ilk bulgular cok, sonrakiler az katkida bulunur (log egrisi)
    $score = [math]::Round(100 * (1 - [math]::Exp(-$raw / 60.0)))
    if ($uCrit -ge 1 -and $score -lt 50) { $score = 50 }   # tek CRITICAL en az HIGH bandi
    $score = [math]::Min(100, [math]::Max(0, $score))
    $risk  = if ($score -ge 75) { 'CRITICAL' }
             elseif ($score -ge 50) { 'HIGH' }
             elseif ($score -ge 25) { 'MEDIUM' }
             elseif ($score -gt 0)  { 'LOW' }
             else { 'CLEAN' }

    # geriye uyum icin sayaclar (rapor bunlari kullaniyor) - BENZERSIZ uzerinden
    $crit = $uCrit; $high = $uHigh; $med = $uMed; $low = $uLow

    $Script:Ctx.RiskScore = $score
    $Script:Ctx.RiskLevel = $risk
    $Script:Ctx.RawFindingCount = $Script:FindingsRaw.Count
    $Script:Ctx.UniqueFindingCount = $deduped.Count

    # Modul istatistikleri
    $Script:ModuleStats | Export-Csv `
        -Path (Join-Path $Script:Ctx.OutputDir 'logs\module_stats.csv') `
        -NoTypeInformation -Encoding UTF8 -Force

    # Manifest
    $elapsed = (Get-Date) - $Script:StartTime
    $manifest = [ordered]@{
        Tool = [ordered]@{
            Name        = 'Douglas-042'
            Version     = $Script:Version
            ScriptPath  = $PSCommandPath
            ScriptSHA256 = if ($PSCommandPath) { Get-DFileHashSafe -Path $PSCommandPath } else { $null }
        }
        Collection = [ordered]@{
            StartUtc        = $Script:StartTime.ToUniversalTime().ToString('o')
            EndUtc          = (Get-Date).ToUniversalTime().ToString('o')
            StartLocal      = $Script:StartTime.ToString('o')
            DurationSeconds = [math]::Round($elapsed.TotalSeconds, 1)
            Operator        = $Script:Ctx.Operator
            OperatorSid     = $Script:Ctx.OperatorSid
            RunAsSystem     = $Script:Ctx.RunAsSystem
            Parameters      = [ordered]@{
                Days               = $Days
                Quick              = [bool]$Quick
                CollectRaw         = [bool]$CollectRaw
                NoResolve          = [bool]$NoResolve
                MaxEventsPerChannel = $MaxEventsPerChannel
                IocFile            = $IocFile
            }
        }
        Host = [ordered]@{
            ComputerName   = $Script:Ctx.ComputerName
            IPAddresses    = $Script:Ctx.IPAddresses
            Domain         = $Script:Ctx.Domain
            DomainRole     = $Script:Ctx.DomainRole
            IsDC           = $Script:Ctx.IsDomainController
            OS             = $Script:Ctx.OSCaption
            OSVersion      = $Script:Ctx.OSVersion
            OSBuild        = $Script:Ctx.OSBuild
            Architecture   = $Script:Ctx.OSArchitecture
            TimeZone       = $Script:Ctx.TimeZone
            UtcOffsetHours = $Script:Ctx.UtcOffsetHours
            LastBootUtc    = ConvertTo-DUtcString $Script:Ctx.LastBootUtc
            UptimeDays     = $Script:Ctx.UptimeDays
        }
        Capabilities = $Script:Caps
        Result = [ordered]@{
            RiskScore     = $score
            RiskLevel     = $risk
            FindingCount  = [ordered]@{
                CRITICAL = $crit; HIGH = $high; MEDIUM = $med; LOW = $low
                TOTAL    = $Script:Findings.Count
            }
            TimelineRows  = $Script:Timeline.Count
            ArtifactCount = $Script:Manifest.Count
            ErrorCount    = $Script:Errors.Count
        }
        Artifacts = @($Script:Manifest)
        Scope     = [ordered]@{
            NotCollected = @(
                'RAM imaji (WinPmem / DumpIt / Magnet RAM Capture)'
                'Disk imaji (FTK Imager / dd)'
                'Tarayici gecmisi tam parse (Hindsight / BrowsingHistoryView)'
                'Tam ShellBag / Jumplist rekonstruksiyonu (Eric Zimmerman araclari)'
                'Ag trafigi yakalama (PCAP)'
            )
            Note = 'Bu koleksiyon canli sistem uzerinde calisti; dosya erisim zamanlari ve Prefetch etkilenmis olabilir.'
        }
    }

    $manifest | ConvertTo-Json -Depth 8 |
        Out-File -FilePath (Join-Path $Script:Ctx.OutputDir 'MANIFEST.json') -Encoding UTF8 -Force

    # --- HTML rapor ---
    $htmlPath = $null
    try { $htmlPath = New-DHtmlReport } catch {
        Write-DLog "HTML report error: $($_.Exception.Message)" -Level ERROR
    }

    # --- Paketleme ---
    # Start-Transcript transcript.log dosyasini ACIK tutar; zip alirken
    # "another process" hatasi veriyordu. Arsivden ONCE transcript kapatilir.
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    $zipPath = $null
    try {
        $zipPath = "$($Script:Ctx.OutputDir).zip"
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive -Path "$($Script:Ctx.OutputDir)\*" -DestinationPath $zipPath `
                             -CompressionLevel Optimal -Force -ErrorAction Stop
            $zipMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
            Write-DLog "Archive created ($zipMB MB)" -Level OK
        }
    } catch {
        Write-DLog "Archiving failed: $($_.Exception.Message)" -Level WARN
        $zipPath = $null
    }

    # --- Konsol ozeti ---
    Write-Host ''
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray
    Write-Host ('   HOST      : {0}  ({1})' -f $Script:Ctx.ComputerName, $Script:Ctx.PrimaryIP)
    Write-Host ('   ROLE      : {0}' -f $Script:Ctx.DomainRole)
    Write-Host ('   DURATION  : {0} s   |   WINDOW: last {1} days' -f `
                [math]::Round($elapsed.TotalSeconds, 1), $Days)
    Write-Host ('   ARTIFACTS : {0} files   |   TIMELINE: {1} records   |   ERRORS: {2}' -f `
                $Script:Manifest.Count, $Script:Timeline.Count, $Script:Errors.Count)
    Write-Host ('  ' + ('-' * 68)) -ForegroundColor DarkGray

    $riskColor = switch ($risk) {
        'CRITICAL' { 'Red' } 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' }
        'LOW' { 'Cyan' } default { 'Green' }
    }
    Write-Host ('   RISK      : {0}   (score {1}/100)' -f $risk, $score) -ForegroundColor $riskColor
    Write-Host ('   FINDINGS  : CRITICAL {0}  |  HIGH {1}  |  MEDIUM {2}  |  LOW {3}' -f `
                $crit, $high, $med, $low) -ForegroundColor $riskColor
    Write-Host ('  ' + ('=' * 68)) -ForegroundColor DarkGray
    Write-Host ''

    if ($crit -gt 0) {
        Write-Host '   PRIORITY FINDINGS:' -ForegroundColor Red
        $Script:Findings | Where-Object Severity -eq 'CRITICAL' |
            Select-Object -First 10 | ForEach-Object {
                Write-Host ('     [{0}] {1}' -f $_.RuleId, $_.Title) -ForegroundColor Red
                $ev = if ($_.Evidence.Length -gt 110) {
                          $_.Evidence.Substring(0, 110) + '...' } else { $_.Evidence }
                Write-Host ('            {0}' -f $ev) -ForegroundColor DarkGray
            }
        if ($crit -gt 10) { Write-Host "     ... and $($crit - 10) more critical findings" -ForegroundColor DarkGray }
        Write-Host ''
    }

    Write-Host ('   KLASOR : {0}' -f $Script:Ctx.OutputDir) -ForegroundColor Green
    if ($htmlPath) { Write-Host ('   RAPOR  : {0}' -f $htmlPath) -ForegroundColor Green }
    if ($zipPath)  { Write-Host ('   ARSIV  : {0}' -f $zipPath) -ForegroundColor Green }
    Write-Host ''

    # Etkilesimli oturumda raporu ac
    if ($htmlPath -and -not $Script:Ctx.RunAsSystem) {
        try { Start-Process $htmlPath -ErrorAction SilentlyContinue } catch { }
    }
}

# ============================================================================
#  ORNEK MODULLER  (dikey kesit dogrulamasi - Adim 2'de genisleyecek)
# ============================================================================

Register-DModule -Name 'System Information' -Phase 0 -Description 'OS, donanim, zaman' -Body {
    $sys = [PSCustomObject]@{
        ComputerName   = $Script:Ctx.ComputerName
        Domain         = $Script:Ctx.Domain
        DomainRole     = $Script:Ctx.DomainRole
        OS             = $Script:Ctx.OSCaption
        Version        = $Script:Ctx.OSVersion
        Build          = $Script:Ctx.OSBuild
        Architecture   = $Script:Ctx.OSArchitecture
        InstallDateUtc = ConvertTo-DUtcString $Script:Ctx.InstallDate
        LastBootUtc    = ConvertTo-DUtcString $Script:Ctx.LastBootUtc
        UptimeDays     = $Script:Ctx.UptimeDays
        TimeZone       = $Script:Ctx.TimeZone
        UtcOffsetHours = $Script:Ctx.UtcOffsetHours
        IPAddresses    = ($Script:Ctx.IPAddresses -join '; ')
        Manufacturer   = $Script:Ctx.Manufacturer
        Model          = $Script:Ctx.Model
        TotalRAMGB     = $Script:Ctx.TotalRAMGB
        PSVersion      = $Script:Caps.PSVersion.ToString()
    }
    Export-DArtifact -Name '01_system' -Data $sys -AsJson

    # Yeni kurulmus sistem = muhtemelen yeniden kurulmus / sahte
    if ($Script:Ctx.InstallDate -and
        ((Get-Date) - $Script:Ctx.InstallDate).TotalDays -lt 7) {
        Add-DFinding -RuleId 'DGL-000' -Severity MEDIUM `
                     -Title 'Isletim sistemi 7 gunden yeni kurulmus' `
                     -Evidence "InstallDate: $($Script:Ctx.InstallDate)" `
                     -Why 'Beklenmedik yeniden kurulum, izlerin silinmis olabilecegini gosterir' `
                     -Artifact '01_system'
    }

    Add-DTimelineEvent -Timestamp $Script:Ctx.LastBootUtc -Source 'System' `
                       -Description 'Sistem baslatildi' -Severity INFO
}

Register-DModule -Name 'Hotfix / Patch Status' -Phase 0 -Body {
    $hf = @()
    try {
        $hf = Get-HotFix -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                HotFixID    = $_.HotFixID
                Description = $_.Description
                InstalledBy = $_.InstalledBy
                InstalledOn = ConvertTo-DUtcString $_.InstalledOn
            }
        }
    } catch { }

    Export-DArtifact -Name '01_hotfixes' -Data $hf

    $last = $hf | Where-Object InstalledOn | Sort-Object InstalledOn -Descending |
            Select-Object -First 1
    if ($last) {
        $age = ((Get-Date) - [DateTime]$last.InstalledOn).TotalDays
        if ($age -gt 90) {
            Add-DFinding -RuleId 'DGL-002' -Severity MEDIUM `
                         -Title 'Sistem 90+ gundur yamalanmamis' `
                         -Evidence "Son yama: $($last.HotFixID) @ $($last.InstalledOn)" `
                         -Mitre 'T1190' `
                         -Why 'Yamasiz sistem bilinen exploitlere acik - initial access vektoru' `
                         -Artifact '01_hotfixes'
        }
    }
}

Register-DModule -Name 'Event Log Health' -Phase 1 -RequiresCap 'WinEvent' `
    -Description 'Anti-forensics tespiti: log temizlenmis mi?' -Body {

    # Her kanala -Oldest sorgusu atmak pahali (Win11/2022'de 1100+ kanal var).
    # Sadece hunting acisindan onemli kanallari probe ediyoruz.
    $probe = @(
        'Security', 'System', 'Application', 'Setup'
        'Windows PowerShell'
        'Microsoft-Windows-PowerShell/Operational'
        'Microsoft-Windows-Sysmon/Operational'
        'Microsoft-Windows-WinRM/Operational'
        'Microsoft-Windows-TaskScheduler/Operational'
        'Microsoft-Windows-Windows Defender/Operational'
        'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        'Microsoft-Windows-TerminalServices-RDPClient/Operational'
        'Microsoft-Windows-WMI-Activity/Operational'
        'Microsoft-Windows-Bits-Client/Operational'
        'Microsoft-Windows-CodeIntegrity/Operational'
        'Microsoft-Windows-SMBServer/Security'
        'Microsoft-Windows-SMBClient/Security'
        'Microsoft-Windows-NTLM/Operational'
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        'Directory Service'
        'DNS Server'
    )

    $logs = @()
    try {
        $logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordCount -gt 0 } |
                ForEach-Object {
                    $oldest    = $null
                    $oldestAge = $null
                    if ($probe -contains $_.LogName) {
                        try {
                            $first = Get-WinEvent -LogName $_.LogName -Oldest -MaxEvents 1 -ErrorAction Stop
                            if ($first) {
                                $oldest    = $first.TimeCreated
                                $oldestAge = [math]::Round(((Get-Date) - $first.TimeCreated).TotalDays, 2)
                            }
                        } catch { }
                    }

                    [PSCustomObject]@{
                        LogName         = $_.LogName
                        IsEnabled       = $_.IsEnabled
                        RecordCount     = $_.RecordCount
                        MaxSizeMB       = [math]::Round($_.MaximumSizeInBytes / 1MB, 1)
                        CurrentSizeMB   = [math]::Round($_.FileSize / 1MB, 1)
                        PctFull         = if ($_.MaximumSizeInBytes -gt 0) {
                                              [math]::Round(($_.FileSize / $_.MaximumSizeInBytes) * 100, 1)
                                          } else { 0 }
                        OldestRecordUtc = ConvertTo-DUtcString $oldest
                        OldestAgeDays   = $oldestAge
                        LogMode         = [string]$_.LogMode
                        LastWriteUtc    = ConvertTo-DUtcString $_.LastWriteTime
                    }
                }
    } catch {
        Write-DLog "Event log listesi alinamadi: $($_.Exception.Message)" -Level ERROR
    }

    Export-DArtifact -Name '11_log_health' -Data $logs

    # --- Triage: log temizlenmis mi? ---
    # Mantik: log kapasitesi buyuk + doluluk dusuk + gecmis kisa = temizlenmis
    foreach ($l in $logs) {
        if ($l.LogName -in 'Security', 'System', 'Application' -or
            $l.LogName -like '*PowerShell*' -or $l.LogName -like '*Sysmon*') {

            if ($null -ne $l.OldestAgeDays -and $l.OldestAgeDays -lt 3 -and
                $l.MaxSizeMB -gt 50 -and $l.PctFull -lt 70) {

                Add-DFinding -RuleId 'DGL-014' -Severity CRITICAL `
                    -Title 'Event log temizlenmis olabilir' `
                    -Evidence ("{0}: en eski kayit {1} gun once, kapasite {2} MB, doluluk %{3}" -f `
                               $l.LogName, $l.OldestAgeDays, $l.MaxSizeMB, $l.PctFull) `
                    -Mitre 'T1070.001' `
                    -Why 'Log kapasitesi buyuk ve dolmamis, ama gecmis kayit yok. Rollover degil, temizleme.' `
                    -Artifact '11_log_health'
            }

            if (-not $l.IsEnabled) {
                Add-DFinding -RuleId 'DGL-015' -Severity HIGH `
                    -Title 'Kritik event log kanali devre disi' `
                    -Evidence "$($l.LogName) kapali" `
                    -Mitre 'T1562.002' `
                    -Why 'Saldirgan gorunurlugu kapatmis olabilir' `
                    -Artifact '11_log_health'
            }
        }

        # Istenen pencere gercekten mevcut mu?
        if ($l.LogName -eq 'Security' -and $null -ne $l.OldestAgeDays -and
            $l.OldestAgeDays -lt $Days) {
            Add-DFinding -RuleId 'DGL-016' -Severity INFO `
                -Title 'Istenen zaman penceresi log retention suresini asiyor' `
                -Evidence ("-Days {0} istendi, Security logunda {1} gunluk veri var" -f `
                           $Days, $l.OldestAgeDays) `
                -Why 'Analiz penceresi fiilen kisitli - kapsam belirlerken dikkate al' `
                -Artifact '11_log_health'
        }
    }

    # Sysmon var mi?
    $sysmon = $logs | Where-Object LogName -like '*Sysmon*'
    if (-not $sysmon) {
        Add-DFinding -RuleId 'DGL-017' -Severity MEDIUM `
            -Title 'Sysmon kurulu degil' `
            -Evidence 'Microsoft-Windows-Sysmon/Operational kanali bulunamadi' `
            -Why 'Process/ag/pipe gorunurlugu ciddi sekilde kisitli - hunting derinligi dusuk' `
            -Artifact '11_log_health'
    }
    $Script:Caps.Sysmon = [bool]$sysmon
    $Script:Caps.AvailableLogs = @($logs.LogName)
}

# ============================================================================
#  TESPIT SOZLUKLERI
# ============================================================================

# LOLBAS - mesru ama saldirganin execution proxy olarak kullandigi binary'ler
$Script:LolBasExec = @(
    'certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
    'installutil.exe', 'cmstp.exe', 'odbcconf.exe', 'msbuild.exe', 'msiexec.exe',
    'regasm.exe', 'regsvcs.exe', 'ieexec.exe', 'presentationhost.exe', 'dfsvc.exe',
    'msdt.exe', 'pcalua.exe', 'xwizard.exe', 'mavinject.exe', 'wsreset.exe',
    'forfiles.exe', 'scriptrunner.exe', 'wmic.exe', 'hh.exe', 'extrac32.exe',
    'esentutl.exe', 'expand.exe', 'makecab.exe', 'print.exe', 'replace.exe',
    'ftp.exe', 'curl.exe', 'wget.exe', 'finger.exe', 'diskshadow.exe'
)

# Kesif komutlari - tek basina zararsiz, kumelenirse hands-on-keyboard gostergesi
$Script:DiscoveryBins = @(
    'whoami.exe', 'systeminfo.exe', 'nltest.exe', 'net.exe', 'net1.exe',
    'tasklist.exe', 'ipconfig.exe', 'arp.exe', 'route.exe', 'netstat.exe',
    'quser.exe', 'qwinsta.exe', 'klist.exe', 'dsquery.exe', 'nbtstat.exe'
)

# Sikistirma / exfil / tunel araclari
$Script:ExfilBins = @(
    'rar.exe', 'winrar.exe', '7z.exe', '7za.exe', 'rclone.exe', 'megacmd.exe',
    'megasync.exe', 'azcopy.exe', 'winscp.exe', 'psftp.exe', 'pscp.exe', 'ncat.exe',
    'nc.exe', 'plink.exe', 'chisel.exe', 'frpc.exe', 'ngrok.exe'
)

# Komut satiri tehlike pattern'leri
$Script:CmdLinePatterns = @(
    @{ P = '(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}'; N = 'Base64 encoded PowerShell'; S = 'CRITICAL'; M = 'T1027' }
    @{ P = '(?i)frombase64string';                           N = 'Base64 decode';            S = 'HIGH';     M = 'T1140' }
    @{ P = '(?i)(iex|invoke-expression)\s';                  N = 'Invoke-Expression';        S = 'HIGH';     M = 'T1059.001' }
    @{ P = '(?i)downloadstring|downloadfile|net\.webclient'; N = 'PowerShell downloader';      S = 'CRITICAL'; M = 'T1105' }
    @{ P = '(?i)invoke-webrequest|iwr\s|curl\s+http';        N = 'HTTP download';             S = 'MEDIUM';   M = 'T1105' }
    @{ P = '(?i)-w(indowstyle)?\s+hidden|-nop\b|-noni\b';    N = 'Hidden PowerShell';         S = 'HIGH';     M = 'T1564.003' }
    @{ P = '(?i)-ex(ecutionpolicy)?\s+bypass';               N = 'ExecutionPolicy bypass';   S = 'HIGH';     M = 'T1059.001' }
    @{ P = '(?i)vssadmin.*delete\s+shadows';                 N = 'Shadow copy deletion';        S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)wbadmin.*delete\s+(catalog|backup)';         N = 'Backup deletion';              S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)bcdedit.*(recoveryenabled\s+no|bootstatuspolicy)'; N = 'Recovery disabled'; S = 'CRITICAL'; M = 'T1490' }
    @{ P = '(?i)wevtutil\s+cl|clear-eventlog';               N = 'Event log clearing';      S = 'CRITICAL'; M = 'T1070.001' }
    @{ P = '(?i)comsvcs\.dll.*minidump';                     N = 'LSASS dump (comsvcs)';     S = 'CRITICAL'; M = 'T1003.001' }
    @{ P = '(?i)(procdump|rundll32).*lsass';                 N = 'LSASS dump attempt';      S = 'CRITICAL'; M = 'T1003.001' }
    @{ P = '(?i)ntdsutil|ntds\.dit';                         N = 'NTDS.dit access';         S = 'CRITICAL'; M = 'T1003.003' }
    @{ P = '(?i)reg\s+save.*(hklm\\sam|hklm\\system|hklm\\security)'; N = 'SAM/SYSTEM hive dump'; S = 'CRITICAL'; M = 'T1003.002' }
    @{ P = '(?i)certutil.*(-urlcache|-decode|-encode|-decodehex)'; N = 'Certutil abuse'; S = 'HIGH'; M = 'T1105' }
    @{ P = '(?i)add-mppreference.*exclusionpath|set-mppreference.*-disable'; N = 'Defender exclusion/disable'; S = 'CRITICAL'; M = 'T1562.001' }
    @{ P = '(?i)netsh.*(firewall|advfirewall).*(disable|off)'; N = 'Firewall disable';       S = 'HIGH';     M = 'T1562.004' }
    @{ P = '(?i)netsh\s+interface\s+portproxy';              N = 'Port proxy (tunnelling)';   S = 'CRITICAL'; M = 'T1090' }
    @{ P = '(?i)\\\\[\w\.\-]+\\(admin|c|ipc)\$';             N = 'Admin share access';      S = 'HIGH';     M = 'T1021.002' }
    @{ P = '(?i)(psexec|paexec|smbexec|wmiexec|atexec)';      N = 'Remote execution tool'; S = 'HIGH';     M = 'T1569.002' }
    @{ P = '(?i)mimikatz|sekurlsa|lsadump|kerberos::';        N = 'Mimikatz';                 S = 'CRITICAL'; M = 'T1003' }
    @{ P = '(?i)rubeus|sharphound|seatbelt|bloodhound|certify\.exe'; N = 'Offensive toolkit'; S = 'CRITICAL'; M = 'T1587' }
    @{ P = '(?i)(rar|7z)(\.exe)?\s+a\s+.*-hp';               N = 'Password-protected archiving (exfil)'; S = 'HIGH';   M = 'T1560.001' }
    @{ P = '(?i)schtasks.*/create.*/ru\s+system';            N = 'Task creation as SYSTEM'; S = 'HIGH'; M = 'T1053.005' }
    @{ P = '(?i)sc\s+(create|config).*binpath';              N = 'Service creation/modification'; S = 'HIGH';  M = 'T1543.003' }
    @{ P = '(?i)net\s+(user|localgroup).*\/add';             N = 'Account/group creation';        S = 'HIGH';     M = 'T1136' }
    @{ P = '(?i)nltest.*(/dclist|/domain_trusts)';           N = 'Domain discovery';             S = 'MEDIUM';   M = 'T1482' }
)

# Ust process -> alt process anomalileri
$Script:BadParentChild = @(
    @{ Parent = 'winword|excel|powerpnt|outlook|msaccess|onenote'
       Child  = 'cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil'
       Name   = 'Office uygulamasi shell baslatti'; S = 'CRITICAL'; M = 'T1566.001' }
    @{ Parent = 'w3wp|httpd|nginx|tomcat|java|php-cgi|node'
       Child  = 'cmd|powershell|pwsh|wscript|cscript|net|net1|whoami'
       Name   = 'Web sunucusu shell baslatti (WEBSHELL)'; S = 'CRITICAL'; M = 'T1505.003' }
    @{ Parent = 'sqlservr|mysqld|postgres'
       Child  = 'cmd|powershell|pwsh'
       Name   = 'Veritabani servisi shell baslatti'; S = 'CRITICAL'; M = 'T1190' }
    @{ Parent = 'wmiprvse'
       Child  = 'cmd|powershell|pwsh|mshta|rundll32'
       Name   = 'WMI uzerinden calistirma (lateral movement)'; S = 'HIGH'; M = 'T1047' }
    @{ Parent = 'mmc|taskeng|schtasks'
       Child  = 'cmd|powershell|pwsh'
       Name   = 'Zamanlanmis gorev/MMC shell baslatti'; S = 'MEDIUM'; M = 'T1053.005' }
    @{ Parent = 'services'
       Child  = 'cmd|powershell|pwsh|rundll32'
       Name   = 'services.exe dogrudan shell baslatti'; S = 'HIGH'; M = 'T1543.003' }
    @{ Parent = 'winlogon|lsass|csrss|smss'
       Child  = 'cmd|powershell|pwsh|net|whoami'
       Name   = 'Kritik sistem process kotuye kullanimi'; S = 'CRITICAL'; M = 'T1055' }
    @{ Parent = 'explorer'
       Child  = 'mshta|regsvr32|certutil|bitsadmin'
       Name   = 'Kullanici LOLBAS calistirdi'; S = 'MEDIUM'; M = 'T1218' }
)

# Bilinen C2 named pipe pattern'leri (Cobalt Strike varsayilanlari dahil)
$Script:BadPipePatterns = @(
    'msagent_', 'MSSE-', 'postex_', 'status_', 'srvsvc_', 'ntsvcs_', 'scerpc_',
    'wkssvc_', 'lsarpc_', 'atsvc_', 'spoolss_', 'netlogon_', 'f4c3',
    'demoagent', 'gruntsvc', 'psexesvc', 'paexec', 'remcom', 'csexec', '^\d{4}$'
)

# Windows'un mesru kisa servis adlari - rastgele-isim kuralinda haric tutulur
$Script:KnownServiceNames = @(
    'Spooler','Winmgmt','Dnscache','EventLog','Themes','Schedule','LanmanServer',
    'LanmanWorkstation','TermService','RpcSs','RpcEptMapper','DcomLaunch','BITS','wuauserv',
    'W32Time','WinRM','WinDefend','MpsSvc','SessionEnv','UmRdpService','ProfSvc','Netlogon',
    'NlaSvc','Dhcp','Audiosrv','AudioEndpointBuilder','CryptSvc','TrustedInstaller','MSDTC',
    'SamSs','KeyIso','Power','SysMain','Wcmsvc','WlanSvc','WSearch','WdiServiceHost',
    'WdiSystemHost','Wecsvc','WEPHOSTSVC','WPDBusEnum','wscsvc','WerSvc','TrkWks','swprv',
    'StorSvc','ShellHWDetection','seclogon','SENS','SharedAccess','RemoteRegistry','PolicyAgent',
    'PlugPlay','pla','p2pimsvc','netprofm','MSiSCSI','msiserver','LSM','KtmRm','iphlpsvc',
    'IKEEXT','gpsvc','FontCache','EFS','DsmSvc','DPS','DoSvc','DiagTrack','Dfs','DFSR',
    'defragsvc','CertPropSvc','CDPSvc','camsvc','BrokerInfrastructure','BFE','Browser',
    'AppMgmt','Appinfo','AJRouter','ALG','aspnet_state','NTDS','DNS','kdc','IsmServ',
    'ADWS','Eaphost','hidserv','hkmsvc','lltdsvc','MMCSS','napagent','NcaSvc','Netman',
    'NcbService','nsi','PcaSvc','PerfHost','PNRPsvc','QWAVE','RasAuto','RasMan','RmSvc',
    'RpcLocator','RSoPProv','sacsvr','SCardSvr','ScDeviceEnum','SCPolicySvc','SDRSVC',
    'SNMPTRAP','sppsvc','SSDPSRV','SstpSvc','svsvc','TabletInputService','TapiSrv',
    'TieringEngineService','TimeBrokerSvc','TokenBroker','UALSVC','UI0Detect','UevAgentService',
    'upnphost','UserManager','usosvc','VaultSvc','vds','VSS','W3SVC','WAS','WalletService',
    'WbioSrvc','wbengine','WcsPlugInService','webthreatdefsvc','wercplsupport','WFDSConMgrSvc',
    'WiaRpc','WinHttpAutoProxySvc','wisvc','wlidsvc','wmiApSrv','WMPNetworkSvc','workfolderssvc',
    'WpnService','WwanSvc','XblAuthManager','XboxNetApiSvc','WMSvc','AppHostSvc','SQLBrowser',
    'MSSQLSERVER','SQLSERVERAGENT','SQLTELEMETRY','SQLWriter','ClusSvc','Netlogon','IaStorDataMgrSvc'
)

function Test-DRandomName {
    <#
        Rastgele uretilmis servis/gorev adi tespiti (Cobalt Strike, Impacket, Metasploit
        varsayilan davranisi). Basit "buyuk+kucuk harf" kontrolu 'Spooler', 'Winmgmt'
        gibi mesru servislerde false positive uretir; entropi gostergeleri kullaniyoruz.
    #>
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -notmatch '^[a-zA-Z0-9]{6,14}$') { return $false }
    if ($Script:KnownServiceNames -contains $Name) { return $false }
    # Bilinen urun onekleri
    if ($Name -match '(?i)^(Microsoft|Windows|Intel|NVIDIA|AMD|Realtek|Adobe|Google|Mozilla|VMware|Citrix|Dell|HP|Lenovo|Sophos|Symantec|McAfee|Trend|Kaspersky|ESET|CrowdStrike|SentinelOne|Splunk|Nessus|Qualys|Rapid7|Tanium|Zabbix|Nagios|Veeam|Acronis|Sql|MSSql|Oracle|IBM|SAP)') { return $false }
    # Urun adlandirma sonekleri - rastgele ureticiler bunlari kullanmaz
    if ($Name -match '(?i)(Svc|Service|Srv|Server|Host|Agent|Mgr|Manager|Sys|Daemon|Broker|Helper|Monitor|Update|Client|Sync|Launcher|Worker|Handler|Provider|Listener)$') { return $false }

    $signals = 0

    # 1. Harf ve rakam ic ice (a9d3f1c2, xY9kLm2p) - urun adlarinda rakam genelde sonda olur
    if ($Name -match '[a-zA-Z]' -and $Name -match '\d' -and $Name -notmatch '^\D+\d+$') { $signals++ }

    # 2. Cok dusuk sesli harf orani - rastgele diziler telaffuz edilemez
    $vowels = ([regex]::Matches($Name, '(?i)[aeiou]')).Count
    if (($vowels / $Name.Length) -lt 0.20) { $signals++ }

    # 3. Coklu buyuk/kucuk gecisi (aBcDeF) - CamelCase'de 1-2 gecis olur, 3+ anormal
    $trans = 0
    for ($i = 1; $i -lt $Name.Length; $i++) {
        $p = $Name[$i - 1]; $c = $Name[$i]
        if ([char]::IsLetter($p) -and [char]::IsLetter($c)) {
            if ([char]::IsUpper($p) -ne [char]::IsUpper($c)) { $trans++ }
        }
    }
    if ($trans -ge 3) { $signals++ }

    # 4. Ustuste 6+ sessiz harf (kisaltmalar 5'e kadar cikabilir: SQLBr, NPSMS)
    if ($Name -match '(?i)[bcdfghjklmnpqrstvwxyz]{6,}') { $signals++ }

    return ($signals -ge 2)
}
$Script:SystemBinNames = @(
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe',
    'smss.exe', 'wininit.exe', 'taskhostw.exe', 'spoolsv.exe', 'dllhost.exe',
    'conhost.exe', 'RuntimeBroker.exe', 'SearchIndexer.exe', 'lsm.exe', 'ctfmon.exe'
)

# ============================================================================
#  REGISTRY YARDIMCILARI
# ============================================================================

function Get-DRegValues {
    <# Bir registry anahtarindaki degerleri PS meta-property'leri haric dondurur #>
    param([string]$Path)

    $out = @()
    try { $item = Get-ItemProperty -Path $Path -ErrorAction Stop } catch { return $out }
    if (-not $item) { return $out }

    foreach ($p in $item.PSObject.Properties) {
        if ($p.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
        $val = $p.Value
        if ($val -is [array]) { $val = ($val -join ' | ') }
        $out += [PSCustomObject]@{ Name = $p.Name; Value = [string]$val }
    }
    return $out
}

function Get-DUserHives {
    <#
        Yuklu kullanici hive'lari (HKU). Eski script sadece HKCU'ya bakiyordu,
        yani IR operatorunun kendi profiline - kurbanin degil.
    #>
    $hives = @()
    try {
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object { $_.PSChildName -match '^S-1-5-21-' -and
                           $_.PSChildName -notmatch '_Classes$' } |
            ForEach-Object {
                $sid  = $_.PSChildName
                $name = $sid
                try {
                    $sidObj = New-Object Security.Principal.SecurityIdentifier($sid)
                    $name   = $sidObj.Translate([Security.Principal.NTAccount]).Value
                } catch { }
                $hives += [PSCustomObject]@{
                    Sid = $sid; User = $name; RegRoot = "Registry::HKEY_USERS\$sid"
                }
            }
    } catch { }
    return $hives
}

function New-DAutorunEntry {
    <# Tum ASEP'ler icin normalize kayit uretici - hash/imza/suspicious otomatik #>
    param(
        [string]$Category, [string]$Location, [string]$Name,
        [string]$Value, [string]$User = 'MACHINE'
    )

    $bin  = Get-DCleanPath -CommandLine $Value
    $sig  = Get-DSignature -Path $bin
    $exists = $false
    $hash = $null
    $ft   = $null

    if ($bin) {
        try {
            if (Test-Path -LiteralPath $bin -PathType Leaf -ErrorAction SilentlyContinue) {
                $exists = $true
                $hash   = Get-DFileHashSafe -Path $bin
                $ft     = (Get-Item -LiteralPath $bin -Force -ErrorAction Stop).LastWriteTime
            }
        } catch { }
    }

    return [PSCustomObject]@{
        Category       = $Category
        Location       = $Location
        User           = $User
        Name           = $Name
        Value          = $Value
        BinaryPath     = $bin
        BinaryExists   = $exists
        BinaryWriteUtc = ConvertTo-DUtcString $ft
        Signed         = $sig.IsValid
        Signer         = $sig.Signer
        SigStatus      = $sig.Status
        IsMicrosoft    = $sig.IsMicrosoft
        SHA256         = $hash
        SuspiciousPath = Test-DSuspiciousPath -Path $bin
    }
}

function Invoke-DAutorunTriage {
    <# Autoruns tablosundaki her satir icin ortak kural seti #>
    param([object]$Entry, [string]$Artifact)

    $ev = "[$($Entry.Category)] $($Entry.Name) = $($Entry.Value)"

    if ($Entry.SuspiciousPath) {
        Add-DFinding -RuleId 'DGL-030' -Severity CRITICAL `
            -Title 'Autorun supheli dizinden calisiyor' -Evidence $ev `
            -Mitre 'T1547' -Artifact $Artifact `
            -Why 'Mesru autorun girdileri System32 veya Program Files altindadir'
    }
    elseif ($Entry.BinaryExists -and -not $Entry.Signed -and -not $Entry.IsMicrosoft) {
        Add-DFinding -RuleId 'DGL-031' -Severity HIGH `
            -Title 'Autorun imzasiz binary' -Evidence "$ev  (imza: $($Entry.SigStatus))" `
            -Mitre 'T1547' -Artifact $Artifact -Why 'Imzasiz kalici baslatma girdisi'
    }

    if ($Entry.BinaryPath -and -not $Entry.BinaryExists -and
        $Entry.Category -notmatch 'Winlogon|LSA|Netsh') {
        Add-DFinding -RuleId 'DGL-032' -Severity MEDIUM `
            -Title 'Autorun hedefi mevcut degil' -Evidence $ev -Artifact $Artifact `
            -Why 'Temizlenmis malware kalintisi veya path hijacking firsati'
    }

    foreach ($pat in $Script:CmdLinePatterns) {
        if ($Entry.Value -match $pat.P) {
            Add-DFinding -RuleId 'DGL-033' -Severity $pat.S `
                -Title "Autorun supheli komut: $($pat.N)" -Evidence $ev `
                -Mitre $pat.M -Artifact $Artifact `
                -Why 'Kalici girdide saldirgan davranis pattern eslesmesi'
            break
        }
    }
    # F1.5-7: autorun degerindeki gizli komutu coz ve tara (Run key -enc payload)
    $null = Invoke-DDeobfuscateAndScan -Text $Entry.Value -Context "Autorun [$($Entry.Category)] $($Entry.Name)" `
        -Artifact $Artifact -Timestamp $null

    if ($Entry.SHA256) { $null = Test-DIoc -Value $Entry.SHA256 -Context $ev -Artifact $Artifact }
}

# ============================================================================
#  MODUL: HESAPLAR VE GRUPLAR
# ============================================================================

Register-DModule -Name 'Users and Groups' -Phase 1 `
    -Description 'Lokal hesaplar, grup uyelikleri, profiller, oturumlar' -Body {

    # --- Lokal kullanicilar ---
    $users = @()
    if ($Script:Caps.LocalAccounts) {
        try {
            $users = Get-LocalUser -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Name                  = $_.Name
                    SID                   = $_.SID.Value
                    Enabled               = $_.Enabled
                    Description           = $_.Description
                    LastLogonUtc          = ConvertTo-DUtcString $_.LastLogon
                    PasswordLastSetUtc    = ConvertTo-DUtcString $_.PasswordLastSet
                    PasswordRequired      = $_.PasswordRequired
                    UserMayChangePassword = $_.UserMayChangePassword
                    PrincipalSource       = [string]$_.PrincipalSource
                }
            }
        } catch { }
    } else {
        # PS4 / 2012 R2 fallback - ADSI
        try {
            $adsi  = [ADSI]"WinNT://$env:COMPUTERNAME"
            $users = $adsi.Children | Where-Object { $_.SchemaClassName -eq 'user' } |
                ForEach-Object {
                    $u = $_
                    [PSCustomObject]@{
                        Name        = [string]$u.Name
                        SID         = (New-Object Security.Principal.SecurityIdentifier(
                                        $u.objectSid.Value, 0)).Value
                        Enabled     = -not (($u.UserFlags.Value -band 2) -eq 2)
                        Description = [string]$u.Description
                        LastLogonUtc = ConvertTo-DUtcString $u.LastLogin.Value
                        PasswordLastSetUtc = $null
                        PasswordRequired = -not (($u.UserFlags.Value -band 32) -eq 32)
                        UserMayChangePassword = $null
                        PrincipalSource = 'Local(ADSI)'
                    }
                }
        } catch { }
    }
    Export-DArtifact -Name '02_local_users' -Data $users

    # --- Kritik grup uyelikleri ---
    # ESKI SCRIPT BUGU: Get-LocalGroup Administrators grubun KENDISINI donuyordu,
    # uyelerini degil. Get-LocalGroupMember olmasi gerekiyordu.
    $members = @()
    $criticalGroups = @('Administrators', 'Remote Desktop Users', 'Backup Operators',
                        'Power Users', 'Remote Management Users', 'Distributed COM Users',
                        'Print Operators', 'Server Operators', 'Account Operators')

    foreach ($g in $criticalGroups) {
        try {
            foreach ($m in (Get-LocalGroupMember -Group $g -ErrorAction Stop)) {
                $members += [PSCustomObject]@{
                    Group           = $g
                    Member          = $m.Name
                    SID             = $m.SID.Value
                    ObjectClass     = $m.ObjectClass
                    PrincipalSource = [string]$m.PrincipalSource
                }
            }
        } catch { continue }
    }

    # SID tabanli yedek (lokalize Windows: "Yoneticiler" vb.)
    if ($members.Count -eq 0) {
        $sidMap = @{ 'S-1-5-32-544' = 'Administrators'
                     'S-1-5-32-555' = 'Remote Desktop Users'
                     'S-1-5-32-551' = 'Backup Operators' }
        foreach ($sid in $sidMap.Keys) {
            try {
                $grp = Get-CimInstance Win32_Group -Filter "SID='$sid'" -ErrorAction Stop
                if (-not $grp) { continue }
                $adsiGrp = [ADSI]"WinNT://$env:COMPUTERNAME/$($grp.Name),group"
                foreach ($mem in @($adsiGrp.Invoke('Members'))) {
                    $mname = $mem.GetType().InvokeMember('Name', 'GetProperty', $null, $mem, $null)
                    $members += [PSCustomObject]@{
                        Group = $sidMap[$sid]; Member = $mname
                        SID = $null; ObjectClass = 'Unknown'; PrincipalSource = 'ADSI'
                    }
                }
            } catch { }
        }
    }
    Export-DArtifact -Name '02_group_members' -Data $members

    # --- Kullanici profilleri (yeni hesap = persistence gostergesi) ---
    $profiles = @()
    try {
        $profiles = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
            Where-Object { $_.SID -match '^S-1-5-21-' } |
            ForEach-Object {
                $created = $null
                try {
                    if ($_.LocalPath -and (Test-Path $_.LocalPath)) {
                        $created = (Get-Item $_.LocalPath -Force -ErrorAction Stop).CreationTime
                    }
                } catch { }
                $uname = $_.SID
                try {
                    $sidObj = New-Object Security.Principal.SecurityIdentifier($_.SID)
                    $uname  = $sidObj.Translate([Security.Principal.NTAccount]).Value
                } catch { }
                [PSCustomObject]@{
                    User           = $uname
                    SID            = $_.SID
                    LocalPath      = $_.LocalPath
                    ProfileCreated = ConvertTo-DUtcString $created
                    LastUseUtc     = ConvertTo-DUtcString $_.LastUseTime
                    Loaded         = $_.Loaded
                    Special        = $_.Special
                }
            }
    } catch { }
    Export-DArtifact -Name '02_user_profiles' -Data $profiles

    # --- Aktif oturumlar ---
    $sessions = @()
    try {
        $logonSessions = Get-CimInstance Win32_LogonSession -ErrorAction Stop
        $loggedOn      = Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop
        $userBySession = @{}
        foreach ($lo in $loggedOn) {
            if ($lo.Dependent.LogonId) {
                $userBySession[[string]$lo.Dependent.LogonId] =
                    "$($lo.Antecedent.Domain)\$($lo.Antecedent.Name)"
            }
        }
        $sessions = $logonSessions | ForEach-Object {
            $lt = [int]$_.LogonType
            [PSCustomObject]@{
                LogonId       = $_.LogonId
                User          = $userBySession[[string]$_.LogonId]
                LogonType     = $lt
                LogonTypeName = switch ($lt) {
                    2 { 'Interactive' } 3 { 'Network' } 4 { 'Batch' } 5 { 'Service' }
                    7 { 'Unlock' } 8 { 'NetworkCleartext' } 9 { 'NewCredentials(RunAs)' }
                    10 { 'RemoteInteractive(RDP)' } 11 { 'CachedInteractive' }
                    default { "Type$lt" }
                }
                AuthPackage = $_.AuthenticationPackage
                StartUtc    = ConvertTo-DUtcString $_.StartTime
            }
        }
    } catch { }
    Export-DArtifact -Name '02_logon_sessions' -Data $sessions

    # --- TRIAGE ---
    $now = Get-Date

    foreach ($u in $users) {
        if ($u.PasswordLastSetUtc) {
            try {
                $age = ($now - [DateTime]$u.PasswordLastSetUtc).TotalDays
                if ($age -lt $Days -and $u.Enabled) {
                    Add-DFinding -RuleId 'DGL-020' -Severity MEDIUM `
                        -Title 'Hesap parolasi analiz penceresi icinde degistirilmis' `
                        -Evidence "$($u.Name) - $($u.PasswordLastSetUtc)" `
                        -Mitre 'T1098' -Artifact '02_local_users' `
                        -Timestamp $u.PasswordLastSetUtc `
                        -Why 'Hesap ele gecirildiyse saldirgan parolayi degistirmis olabilir'
                }
            } catch { }
        }
        if ($u.Enabled -and $false -eq $u.PasswordRequired) {
            Add-DFinding -RuleId 'DGL-021' -Severity HIGH `
                -Title 'Aktif hesap parola gerektirmiyor' -Evidence $u.Name `
                -Mitre 'T1078.003' -Artifact '02_local_users' `
                -Why 'Parolasiz aktif hesap dogrudan erisim saglar'
        }
        if ($u.Enabled -and $u.SID -match '-(500|501)$') {
            $sev = if ($u.SID -match '-501$') { 'HIGH' } else { 'MEDIUM' }
            Add-DFinding -RuleId 'DGL-022' -Severity $sev `
                -Title 'Yerlesik hesap aktif' `
                -Evidence "$($u.Name) (RID: $($u.SID.Split('-')[-1]))" `
                -Mitre 'T1078.001' -Artifact '02_local_users' `
                -Why 'Guest ve yerlesik Administrator genelde devre disi olmalidir'
        }
    }

    foreach ($p in $profiles) {
        if (-not $p.ProfileCreated) { continue }
        try {
            $age = ($now - [DateTime]$p.ProfileCreated).TotalDays
            if ($age -lt $Days) {
                Add-DFinding -RuleId 'DGL-023' -Severity HIGH `
                    -Title 'Analiz penceresi icinde yeni kullanici profili olusmus' `
                    -Evidence "$($p.User) - $($p.LocalPath) @ $($p.ProfileCreated)" `
                    -Mitre 'T1136.001' -Artifact '02_user_profiles' `
                    -Timestamp $p.ProfileCreated `
                    -Why 'Yeni hesap olusturma yaygin bir persistence teknigidir'
                Add-DTimelineEvent -Timestamp $p.ProfileCreated -Source 'Accounts' `
                    -Description "New profile: $($p.User)" -Detail $p.LocalPath -Severity HIGH
            }
        } catch { }
    }

    $adminCount = @($members | Where-Object Group -eq 'Administrators').Count
    if ($adminCount -gt 5) {
        Add-DFinding -RuleId 'DGL-024' -Severity MEDIUM `
            -Title 'Lokal Administrators grubunda cok sayida uye' `
            -Evidence "$adminCount uye" -Mitre 'T1078' -Artifact '02_group_members' `
            -Why 'Genis admin uyeligi yatay hareket yuzeyini buyutur'
    }

    Write-DLog "  $($users.Count) users, $($members.Count) group memberships, $($sessions.Count) sessions" -Level DEBUG
}

# ============================================================================
#  MODUL: PROCESS AGACI
# ============================================================================

Register-DModule -Name 'Process Tree' -Phase 1 `
    -Description 'Tum processler + cmdline + imza + hash + parent-child analizi' `
    -HuntTags @('LOLBin','Persistence','DefenseEvasion') -Body {

    # NOT: Get-Process DEGIL Win32_Process - CommandLine alani sadece CIM/WMI'de var
    $raw = @()
    try { $raw = Get-CimInstance Win32_Process -ErrorAction Stop }
    catch { try { $raw = Get-WmiObject Win32_Process -ErrorAction Stop } catch { } }

    if (@($raw).Count -eq 0) {
        Write-DLog '  Could not retrieve process list!' -Level ERROR
        return
    }

    # Kullanici eslemesi - process basina GetOwner cagirmak yavas
    $ownerMap = @{}
    try {
        Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object {
            if ($_.UserName) { $ownerMap[[int]$_.Id] = $_.UserName }
        }
    } catch {
        foreach ($p in $raw) {
            try {
                $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($o.ReturnValue -eq 0) {
                    $ownerMap[[int]$p.ProcessId] = "$($o.Domain)\$($o.User)"
                }
            } catch { }
        }
    }

    # PID -> isim haritasi (parent cozumlemesi icin)
    $nameMap = @{}
    foreach ($p in $raw) { $nameMap[[int]$p.ProcessId] = $p.Name }

    # CPU / bellek icin tek cagri
    $perfMap = @{}
    try {
        Get-Process -ErrorAction Stop | ForEach-Object {
            $perfMap[[int]$_.Id] = [PSCustomObject]@{
                CPU = $_.CPU; WS = $_.WorkingSet64
                Threads = $_.Threads.Count; Handles = $_.HandleCount
            }
        }
    } catch { }

    $procs = foreach ($p in $raw) {
        $procId   = [int]$p.ProcessId
        $parentId = [int]$p.ParentProcessId
        $path     = $p.ExecutablePath
        $sig      = Get-DSignature -Path $path
        $perf     = $perfMap[$procId]
        $baseName = if ($p.Name) { $p.Name.ToLowerInvariant() } else { '' }

        [PSCustomObject]@{
            PID            = $procId
            PPID           = $parentId
            ParentName     = $nameMap[$parentId]
            Name           = $p.Name
            Path           = $path
            CommandLine    = $p.CommandLine
            User           = $ownerMap[$procId]
            StartTimeUtc   = ConvertTo-DUtcString (ConvertTo-DDateTime $p.CreationDate)
            SessionId      = $p.SessionId
            Signed         = $sig.IsValid
            Signer         = $sig.Signer
            SigStatus      = $sig.Status
            IsMicrosoft    = $sig.IsMicrosoft
            SHA256         = if ($path) { Get-DFileHashSafe -Path $path } else { $null }
            SuspiciousPath = Test-DSuspiciousPath -Path $path
            IsLolBas       = ($Script:LolBasExec -contains $baseName)
            IsDiscovery    = ($Script:DiscoveryBins -contains $baseName)
            IsExfilTool    = ($Script:ExfilBins -contains $baseName)
            CPU            = if ($perf) { [math]::Round($perf.CPU, 2) } else { $null }
            WorkingSetMB   = if ($perf) { [math]::Round($perf.WS / 1MB, 2) } else { $null }
            Threads        = if ($perf) { $perf.Threads } else { $null }
            Handles        = if ($perf) { $perf.Handles } else { $null }
        }
    }

    $procs = @($procs)
    Export-DArtifact -Name '03_processes' -Data $procs -AsJson

    # Process index - ag modulu bunu kullanacak, tekrar sorgu yok (O(1) lookup)
    $Script:ProcIndex = @{}
    foreach ($pr in $procs) { $Script:ProcIndex[$pr.PID] = $pr }

    # --- TRIAGE ---
    foreach ($pr in $procs) {
        $ev = "PID $($pr.PID) $($pr.Name) -> $($pr.Path)"

        if ($pr.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-040' -Severity HIGH `
                -Title 'Process supheli dizinden calisiyor' `
                -Evidence "$ev  [kullanici: $($pr.User)]" `
                -Mitre 'T1036' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Temp/AppData/ProgramData malware icin en yaygin calisma dizinleridir'
        }

        if ($pr.Path -and $false -eq $pr.Signed -and -not $pr.IsMicrosoft -and
            $pr.Path -match '(?i)\\Users\\') {
            Add-DFinding -RuleId 'DGL-041' -Severity HIGH `
                -Title 'Imzasiz process kullanici profilinden calisiyor' `
                -Evidence "$ev  (imza: $($pr.SigStatus))" `
                -Mitre 'T1204' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Mesru yazilim genelde Program Files altinda ve imzalidir'
        }

        # F1.5-12: masquerading - dogru isim yanlis dizin VE typo/homoglyph
        # (svch0st, scvhost, lsas...) merkezi helper ile
        $masq = Test-DMasqueradedName -Name $pr.Name -FullPath $pr.Path
        if ($masq) {
            Add-DFinding -RuleId 'DGL-042' -Severity CRITICAL `
                -Title 'Sistem binary maskeleme (masquerading)' `
                -Evidence "$ev :: $($masq.Reason)" `
                -Mitre 'T1036.005' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why "Beklenen: $($masq.Expected)"
        }

        if ($pr.CommandLine) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($pr.CommandLine -match $pat.P) {
                    $cl  = Format-DEvidence -Text $pr.CommandLine -Max 1200
                    Add-DFinding -RuleId 'DGL-043' -Severity $pat.S `
                        -Title "Supheli komut satiri: $($pat.N)" `
                        -Evidence "PID $($pr.PID) [$($pr.User)] $cl" `
                        -Mitre $pat.M -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                        -Why 'Saldirgan davranisiyla eslesen komut satiri'
                }
            }
            # F1.5-7: encoded/obfuscated payload'i coz ve cozulmus icerigi de tara
            $Script:DeobfCmd = Invoke-DDeobfuscateAndScan -Text $pr.CommandLine `
                -Context "PID $($pr.PID) [$($pr.User)]" -Artifact '03_processes' -Timestamp $pr.StartTimeUtc
        }

        if ($pr.ParentName) {
            $pn = $pr.ParentName -replace '\.exe$', ''
            $cn = $pr.Name -replace '\.exe$', ''
            foreach ($rule in $Script:BadParentChild) {
                if ($pn -match "^($($rule.Parent))$" -and $cn -match "^($($rule.Child))$") {
                    Add-DFinding -RuleId 'DGL-044' -Severity $rule.S -Title $rule.Name `
                        -Evidence "$($pr.ParentName) (PID $($pr.PPID)) -> $($pr.Name) (PID $($pr.PID))" `
                        -Mitre $rule.M -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                        -Why 'Bu ust-alt process iliskisi normal isletim sirasinda olusmaz'
                    break
                }
            }
        }

        if ($pr.IsExfilTool) {
            Add-DFinding -RuleId 'DGL-045' -Severity HIGH `
                -Title 'Sikistirma/exfil/tunel araci calisiyor' -Evidence $ev `
                -Mitre 'T1560' -Artifact '03_processes' -Timestamp $pr.StartTimeUtc `
                -Why 'Veri toplama ve disari cikarma asamasinin gostergesi'
        }

        if (-not $pr.Path -and $pr.PID -gt 4 -and
            $pr.Name -notmatch '^(System|Registry|Secure System|Memory Compression)$') {
            Add-DFinding -RuleId 'DGL-046' -Severity MEDIUM `
                -Title 'Process yolu okunamadi' -Evidence "PID $($pr.PID) $($pr.Name)" `
                -Artifact '03_processes' `
                -Why 'Korunan process olabilir; ya da imaj diskten silinmis'
        }

        if ($pr.SHA256) { $null = Test-DIoc -Value $pr.SHA256 -Context $ev -Artifact '03_processes' }

        if ($pr.StartTimeUtc) {
            $sev = if ($pr.SuspiciousPath -or $pr.IsLolBas) { 'MEDIUM' } else { 'INFO' }
            Add-DTimelineEvent -Timestamp $pr.StartTimeUtc -Source 'Process' `
                -Description "$($pr.Name) started (PID $($pr.PID))" `
                -Detail $pr.CommandLine -Severity $sev
        }
    }

    # Kesif komutu kumelenmesi = hands-on-keyboard
    $disc = @($procs | Where-Object IsDiscovery)
    if ($disc.Count -ge 4) {
        $names = ($disc | Select-Object -First 8 |
                  ForEach-Object { "$($_.Name)(PID $($_.PID))" }) -join ', '
        Add-DFinding -RuleId 'DGL-047' -Severity HIGH `
            -Title 'Coklu kesif komutu ayni anda calisiyor' -Evidence $names `
            -Mitre 'T1082' -Artifact '03_processes' `
            -Why 'Elle yurutulen kesif faaliyeti gostergesi'
    }

    $unsigned = @($procs | Where-Object { $_.Path -and $false -eq $_.Signed }).Count
    Write-DLog "  $($procs.Count) processes (unsigned: $unsigned)" -Level DEBUG
}

# ============================================================================
#  MODUL: AG BAGLANTILARI
# ============================================================================

Register-DModule -Name 'Network Connections' -Phase 1 -RequiresCap 'NetTCP' `
    -Description 'TCP/UDP + process join + portproxy + proxy + DNS' `
    -HuntTags @('Beacon') -Body {

    if (-not $Script:ProcIndex) { $Script:ProcIndex = @{} }

    $privateRegex = '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.0\.0\.0$|::1$|::$|fe80:)'

    # --- TCP (process'e JOIN edilmis - eski scriptte sadece IP listesi vardi) ---
    $tcp = @()
    try {
        $tcp = Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $op = [int]$_.OwningProcess
            $pi = $Script:ProcIndex[$op]
            $rdns = $null
            if (-not $NoResolve -and $_.RemoteAddress -notmatch $privateRegex) {
                try { $rdns = [Net.Dns]::GetHostEntry($_.RemoteAddress).HostName } catch { }
            }
            [PSCustomObject]@{
                Protocol        = 'TCP'
                LocalAddress    = $_.LocalAddress
                LocalPort       = $_.LocalPort
                RemoteAddress   = $_.RemoteAddress
                RemotePort      = $_.RemotePort
                State           = [string]$_.State
                PID             = $op
                ProcessName     = if ($pi) { $pi.Name } else { $null }
                ProcessPath     = if ($pi) { $pi.Path } else { $null }
                ProcessUser     = if ($pi) { $pi.User } else { $null }
                Signed          = if ($pi) { $pi.Signed } else { $null }
                SHA256          = if ($pi) { $pi.SHA256 } else { $null }
                SuspiciousPath  = if ($pi) { $pi.SuspiciousPath } else { $false }
                CreationTimeUtc = ConvertTo-DUtcString $_.CreationTime
                RemoteIsPrivate = [bool]($_.RemoteAddress -match $privateRegex)
                RemoteRDNS      = $rdns
            }
        }
    } catch {
        Write-DLog "  TCP baglantilari alinamadi: $($_.Exception.Message)" -Level WARN
    }
    Export-DArtifact -Name '04_tcp_connections' -Data $tcp
    # F1.5: anlik snapshot'in beaconing korlugu - Sysmon 3 yoksa gorunurluk uyarisi
    if (-not $Script:Caps.Sysmon) {
        Add-DFinding -RuleId 'DGL-059' -Severity INFO `
            -Title 'Ag gorunurlugu kisitli - sadece anlik baglantilar' `
            -Evidence 'Sysmon kurulu degil; periyodik C2 beacon iki check-in arasinda gorunmez' `
            -Mitre 'T1071' -Artifact '04_tcp_connections' `
            -Why 'Gecmis ag baglantilari ve beaconing analizi icin Sysmon Event 3 gerekir'
    }

    # --- UDP ---
    $udp = @()
    try {
        $udp = Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
            $op = [int]$_.OwningProcess
            $pi = $Script:ProcIndex[$op]
            [PSCustomObject]@{
                Protocol = 'UDP'; LocalAddress = $_.LocalAddress; LocalPort = $_.LocalPort
                PID = $op
                ProcessName = if ($pi) { $pi.Name } else { $null }
                ProcessPath = if ($pi) { $pi.Path } else { $null }
                Signed = if ($pi) { $pi.Signed } else { $null }
                SuspiciousPath = if ($pi) { $pi.SuspiciousPath } else { $false }
                CreationTimeUtc = ConvertTo-DUtcString $_.CreationTime
            }
        }
    } catch { }
    Export-DArtifact -Name '04_udp_endpoints' -Data $udp

    # --- Dinleyen portlar (backdoor dinleyicisi burada cikar) ---
    $listen = @($tcp | Where-Object { $_.State -eq 'Listen' })
    Export-DArtifact -Name '04_listening_ports' -Data $listen

    # --- Port proxy (tunelleme - eski scriptte hic yoktu, cok kritik) ---
    $portproxy = @()
    try {
        $pp = netsh interface portproxy show all 2>$null
        if ($pp) {
            $portproxy = @($pp | Where-Object { $_ -match '^\s*[\d\*]' } | ForEach-Object {
                $f = (($_ -replace '\s+', ' ').Trim() -split ' ')
                if ($f.Count -ge 4) {
                    [PSCustomObject]@{
                        ListenAddress = $f[0]; ListenPort = $f[1]
                        ConnectAddress = $f[2]; ConnectPort = $f[3]
                    }
                }
            })
        }
    } catch { }
    Export-DArtifact -Name '04_portproxy' -Data $portproxy

    foreach ($p in $portproxy) {
        Add-DFinding -RuleId 'DGL-050' -Severity CRITICAL `
            -Title 'netsh portproxy kurali mevcut (tunelleme)' `
            -Evidence "$($p.ListenAddress):$($p.ListenPort) -> $($p.ConnectAddress):$($p.ConnectPort)" `
            -Mitre 'T1090.001' -Artifact '04_portproxy' `
            -Why 'Port yonlendirme neredeyse her zaman pivot/tunel amaclidir'
    }

    # --- Proxy yapilandirmasi ---
    $proxyCfg = New-Object System.Collections.ArrayList
    try {
        $wh = netsh winhttp show proxy 2>$null
        $null = $proxyCfg.Add([PSCustomObject]@{
            Scope = 'WinHTTP'; Setting = (($wh -join ' ') -replace '\s+', ' ').Trim()
        })
    } catch { }

    foreach ($h in (Get-DUserHives)) {
        $isKey = "$($h.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        foreach ($x in (Get-DRegValues -Path $isKey |
                        Where-Object Name -in 'ProxyEnable', 'ProxyServer', 'AutoConfigURL')) {
            $null = $proxyCfg.Add([PSCustomObject]@{
                Scope = "WinINET:$($h.User)"; Setting = "$($x.Name)=$($x.Value)"
            })
            if ($x.Name -eq 'AutoConfigURL' -and $x.Value) {
                Add-DFinding -RuleId 'DGL-051' -Severity HIGH `
                    -Title 'Kullanici proxy AutoConfigURL ayarlanmis' `
                    -Evidence "$($h.User): $($x.Value)" `
                    -Mitre 'T1090' -Artifact '04_proxy_config' `
                    -Why 'Zararli PAC dosyasi trafigi saldirgan altyapisina yonlendirebilir'
            }
        }
    }
    Export-DArtifact -Name '04_proxy_config' -Data @($proxyCfg)

    # --- ARP + route (lateral movement haritasi) ---
    $arp = @()
    try {
        $arp = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
               Where-Object { $_.State -notin 'Unreachable', 'Permanent' } |
               Select-Object IPAddress, LinkLayerAddress,
                             @{N = 'State'; E = { [string]$_.State } }, InterfaceAlias
    } catch { }
    Export-DArtifact -Name '04_arp_cache' -Data $arp

    $routes = @()
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
                  Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias,
                                @{N = 'Store'; E = { [string]$_.Store } }
    } catch { }
    Export-DArtifact -Name '04_routes' -Data $routes

    # --- DNS cache ---
    $dns = @()
    if ($Script:Caps.DnsCache) {
        try {
            $dns = Get-DnsClientCache -ErrorAction Stop |
                   Select-Object Entry, Name,
                                 @{N = 'Type'; E = { [string]$_.Type } },
                                 @{N = 'Status'; E = { [string]$_.Status } },
                                 Data, TimeToLive
        } catch { }
    }
    Export-DArtifact -Name '04_dns_cache' -Data $dns

    foreach ($d in $dns) {
        if ($d.Name) { $null = Test-DIoc -Value $d.Name -Context 'DNS cache' -Artifact '04_dns_cache' }
        if ($d.Data) { $null = Test-DIoc -Value $d.Data -Context "DNS: $($d.Name)" -Artifact '04_dns_cache' }
    }

    # --- Hosts dosyasi ---
    $hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsData = @()
    try {
        $hi = Get-Item $hostsFile -Force -ErrorAction Stop
        $hostsData = @(Get-Content $hostsFile -ErrorAction Stop |
            Where-Object { $_ -match '^\s*[^#\s]' } |
            ForEach-Object { [PSCustomObject]@{ Entry = $_.Trim() } })

        if (((Get-Date) - $hi.LastWriteTime).TotalDays -lt $Days -and $hostsData.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-052' -Severity HIGH `
                -Title 'Hosts dosyasi analiz penceresi icinde degistirilmis' `
                -Evidence "Son yazma: $($hi.LastWriteTime) - $($hostsData.Count) aktif kayit" `
                -Mitre 'T1565.001' -Artifact '04_hosts' -Timestamp $hi.LastWriteTime `
                -Why 'Guvenlik urunu alan adlarinin bloklanmasi veya trafik yonlendirmesi'
            Add-DTimelineEvent -Timestamp $hi.LastWriteTime -Source 'Network' `
                -Description 'Hosts dosyasi degistirildi' -Severity HIGH
        }
    } catch { }
    Export-DArtifact -Name '04_hosts' -Data $hostsData

    # --- Firewall ---
    $fwProfiles = @()
    if ($Script:Caps.Firewall) {
        try {
            $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop |
                Select-Object Name, Enabled,
                              @{N = 'DefaultInbound'; E = { [string]$_.DefaultInboundAction } },
                              @{N = 'DefaultOutbound'; E = { [string]$_.DefaultOutboundAction } },
                              @{N = 'LogBlocked'; E = { [string]$_.LogBlocked } }
        } catch { }
    }
    Export-DArtifact -Name '04_firewall_profiles' -Data $fwProfiles

    foreach ($f in $fwProfiles) {
        if ($false -eq $f.Enabled) {
            Add-DFinding -RuleId 'DGL-056' -Severity HIGH `
                -Title 'Firewall profili devre disi' -Evidence "$($f.Name) profili kapali" `
                -Mitre 'T1562.004' -Artifact '04_firewall_profiles' `
                -Why 'Saldirganlar C2 ve lateral movement icin firewalli kapatir'
        }
    }

    # Izin veren gelen kurallar (backdoor icin acilan portlar)
    $fwRules = @()
    if ($Script:Caps.Firewall) {
        try {
            $fwRules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -EA Stop |
                ForEach-Object {
                    $pf = $null; $ap = $null
                    try { $pf = ($_ | Get-NetFirewallPortFilter -EA Stop) } catch { }
                    try { $ap = ($_ | Get-NetFirewallApplicationFilter -EA Stop) } catch { }
                    [PSCustomObject]@{
                        Name        = $_.DisplayName
                        Group       = $_.DisplayGroup
                        Profile     = [string]$_.Profile
                        Protocol    = if ($pf) { $pf.Protocol } else { $null }
                        LocalPort   = if ($pf) { ($pf.LocalPort -join ',') } else { $null }
                        Program     = if ($ap) { $ap.Program } else { $null }
                    }
                }
        } catch { }
    }
    Export-DArtifact -Name '04_firewall_inbound_allow' -Data $fwRules

    foreach ($r in $fwRules) {
        if ($r.Program -and (Test-DSuspiciousPath -Path $r.Program)) {
            Add-DFinding -RuleId 'DGL-057' -Severity CRITICAL `
                -Title 'Firewall kurali supheli binary icin gelen trafige izin veriyor' `
                -Evidence "$($r.Name) -> $($r.Program) : $($r.LocalPort)" `
                -Mitre 'T1562.004' -Artifact '04_firewall_inbound_allow' `
                -Why 'Saldirgan kalici erisim icin firewall kurali ekler; mesru yazilim Temp/AppData altindan dinlemez'
        }
    }

    # --- TRIAGE: baglanti bazli ---
    foreach ($c in $tcp) {
        if ($c.State -ne 'Established') { continue }

        if (-not $c.RemoteIsPrivate -and $c.SuspiciousPath) {
            # NOT: Get-NetTCPConnection ANLIK durumdur. Periyodik beacon iki
            # check-in arasinda uyurken bu snapshot'ta gorunmez. Gecmis
            # baglantilar icin Sysmon Event 3 (DGL-058 beaconing) kullanilir.
            Add-DFinding -RuleId 'DGL-053' -Severity CRITICAL `
                -Title 'Supheli process dis IP ile iletisimde (C2 supheli)' `
                -Evidence "$($c.ProcessName) (PID $($c.PID)) -> $($c.RemoteAddress):$($c.RemotePort)  [$($c.ProcessPath)]" `
                -Mitre 'T1071' -Artifact '04_tcp_connections' -Timestamp $c.CreationTimeUtc `
                -Why 'Gecici dizinden calisan bir processin dis baglantisi C2 gostergesidir'
        }
        elseif (-not $c.RemoteIsPrivate -and $false -eq $c.Signed -and $c.ProcessPath) {
            Add-DFinding -RuleId 'DGL-054' -Severity HIGH `
                -Title 'Imzasiz process dis IP ile iletisimde' `
                -Evidence "$($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" `
                -Mitre 'T1071' -Artifact '04_tcp_connections' -Timestamp $c.CreationTimeUtc `
                -Why 'Imzasiz binary ile dis ag trafigi C2 kanalinin en yaygin gorunumudur'
        }

        if ($c.RemoteAddress) {
            $null = Test-DIoc -Value $c.RemoteAddress `
                -Context "$($c.ProcessName) -> $($c.RemoteAddress):$($c.RemotePort)" `
                -Artifact '04_tcp_connections'
        }
    }

    foreach ($l in $listen) {
        if ($l.LocalAddress -in '0.0.0.0', '::' -and $l.ProcessPath -and
            ($l.SuspiciousPath -or $false -eq $l.Signed)) {
            Add-DFinding -RuleId 'DGL-055' -Severity CRITICAL `
                -Title 'Supheli process tum arayuzlerde dinliyor (backdoor)' `
                -Evidence "$($l.ProcessName) :$($l.LocalPort) - $($l.ProcessPath)" `
                -Mitre 'T1571' -Artifact '04_listening_ports' `
                -Why 'Imzasiz veya gecici dizinden calisan bir dinleyici backdoor gostergesidir'
        }
    }

    Write-DLog "  $($tcp.Count) TCP, $($udp.Count) UDP, $($listen.Count) dinleyen, $(@($portproxy).Count) portproxy" -Level DEBUG
}

# ============================================================================
#  MODUL: SERVISLER
# ============================================================================

Register-DModule -Name 'Services' -Phase 1 `
    -Description 'Servis binaryleri + imza + tirnaksiz path + ServiceDll' `
    -HuntTags @('Persistence') -Body {

    $svcRaw = @()
    try { $svcRaw = Get-CimInstance Win32_Service -ErrorAction Stop }
    catch { try { $svcRaw = Get-WmiObject Win32_Service -ErrorAction Stop } catch { } }

    $svcs = foreach ($s in $svcRaw) {
        $bin = Get-DCleanPath -CommandLine $s.PathName
        $sig = Get-DSignature -Path $bin

        $binWrite = $null
        try {
            if ($bin -and (Test-Path -LiteralPath $bin -PathType Leaf -EA SilentlyContinue)) {
                $binWrite = (Get-Item -LiteralPath $bin -Force -EA Stop).LastWriteTime
            }
        } catch { }

        # svchost servisleri icin gercek DLL
        $svcDll = $null
        try {
            $sp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" `
                                  -Name ServiceDll -ErrorAction Stop
            $svcDll = [Environment]::ExpandEnvironmentVariables($sp.ServiceDll)
        } catch { }

        # Tirnaksiz path + bosluk = binary hijack firsati
        $unquoted = $false
        if ($s.PathName -and -not $s.PathName.Trim().StartsWith('"') -and
            $s.PathName -match '^[A-Za-z]:\\[^"]*\s+[^"]*\.(exe|bat|cmd)') {
            $unquoted = $true
        }

        [PSCustomObject]@{
            Name           = $s.Name
            DisplayName    = $s.DisplayName
            State          = $s.State
            StartMode      = $s.StartMode
            StartName      = $s.StartName
            PathName       = $s.PathName
            BinaryPath     = $bin
            ServiceDll     = $svcDll
            ProcessId      = $s.ProcessId
            Signed         = $sig.IsValid
            Signer         = $sig.Signer
            SigStatus      = $sig.Status
            IsMicrosoft    = $sig.IsMicrosoft
            SHA256         = if ($bin) { Get-DFileHashSafe -Path $bin } else { $null }
            BinaryWriteUtc = ConvertTo-DUtcString $binWrite
            SuspiciousPath = Test-DSuspiciousPath -Path $bin
            UnquotedPath   = $unquoted
            Description    = $s.Description
        }
    }

    $svcs = @($svcs)
    Export-DArtifact -Name '05_services' -Data $svcs -AsJson

    # --- TRIAGE ---
    foreach ($s in $svcs) {
        $ev = "$($s.Name) -> $($s.PathName)"

        if ($s.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-001' -Severity CRITICAL `
                -Title 'Servis binary supheli dizinde' -Evidence $ev `
                -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc `
                -Why 'Mesru servisler System32 veya Program Files altinda calisir'
        }

        if ($s.BinaryPath -and $false -eq $s.Signed -and -not $s.IsMicrosoft -and
            $s.SigStatus -notin 'FileNotFound', 'NoPath') {
            Add-DFinding -RuleId 'DGL-060' -Severity HIGH `
                -Title 'Servis binary imzasiz' -Evidence "$ev  (imza: $($s.SigStatus))" `
                -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc `
                -Why 'Windows servislerinin buyuk cogunlugu imzalidir; imzasiz olan incelenmelidir'
        }

        if ($s.UnquotedPath) {
            Add-DFinding -RuleId 'DGL-061' -Severity MEDIUM `
                -Title 'Tirnaksiz servis yolu (binary hijack riski)' -Evidence $ev `
                -Mitre 'T1574.009' -Artifact '05_services' `
                -Why 'Bosluk iceren tirnaksiz yol, ust dizine binary birakilarak ele gecirilebilir'
        }

        if ($s.BinaryWriteUtc) {
            try {
                $age = ((Get-Date) - [DateTime]$s.BinaryWriteUtc).TotalDays
                if ($age -lt $Days -and -not $s.IsMicrosoft) {
                    Add-DFinding -RuleId 'DGL-062' -Severity HIGH `
                        -Title 'Servis binary analiz penceresi icinde degismis' `
                        -Evidence "$ev @ $($s.BinaryWriteUtc)" `
                        -Mitre 'T1543.003' -Artifact '05_services' -Timestamp $s.BinaryWriteUtc `
                        -Why 'Mevcut servisin binarysi degistirilerek kalicilik saglanabilir (service hijacking)'
                    Add-DTimelineEvent -Timestamp $s.BinaryWriteUtc -Source 'Service' `
                        -Description "Service binary written: $($s.Name)" `
                        -Detail $s.BinaryPath -Severity HIGH
                }
            } catch { }
        }

        # Rastgele isimli servis (PsExec / CS beacon imzasi)
        if ((Test-DRandomName -Name $s.Name) -and -not $s.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-063' -Severity HIGH `
                -Title 'Rastgele gorunumlu servis adi' -Evidence $ev `
                -Mitre 'T1569.002' -Artifact '05_services' `
                -Why 'Cobalt Strike ve benzeri araclar rastgele servis adi uretir'
        }

        if ($s.Name -match '(?i)(psexesvc|paexec|remcom|csexec|winexesvc)') {
            Add-DFinding -RuleId 'DGL-064' -Severity CRITICAL `
                -Title 'Uzaktan calistirma servisi tespit edildi' -Evidence $ev `
                -Mitre 'T1569.002' -Artifact '05_services' `
                -Why 'PsExec ve turevleri lateral movement icin kullanilir'
        }

        if ($s.PathName) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($s.PathName -match $pat.P) {
                    Add-DFinding -RuleId 'DGL-065' -Severity $pat.S `
                        -Title "Servis yolunda supheli komut: $($pat.N)" -Evidence $ev `
                        -Mitre $pat.M -Artifact '05_services' `
                        -Why 'Servis komut satirinda saldirgan davranisiyla eslesen pattern'
                    break
                }
            }
            # F1.5-7: servis ImagePath'indeki gizli komutu coz ve tara
            $null = Invoke-DDeobfuscateAndScan -Text $s.PathName -Context "Servis $($s.Name)" `
                -Artifact '05_services' -Timestamp $null
        }

        if ($s.SHA256) { $null = Test-DIoc -Value $s.SHA256 -Context $ev -Artifact '05_services' }
    }

    $running = @($svcs | Where-Object State -eq 'Running').Count
    Write-DLog "  $($svcs.Count) services (running: $running)" -Level DEBUG
}

# ============================================================================
#  MODUL: ZAMANLANMIS GOREVLER
# ============================================================================

Register-DModule -Name 'Scheduled Tasks' -Phase 1 -RequiresCap 'ScheduledTasks' `
    -Description 'Task Execute + Arguments alanlari - eski script bunlari almiyordu' `
    -HuntTags @('Persistence') -Body {

    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
            $t = $_
            $info = $null
            try {
                $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -EA Stop
            } catch { }

            $actions = @()
            foreach ($a in $t.Actions) {
                if ($a.Execute)      { $actions += (($a.Execute + ' ' + $a.Arguments).Trim()) }
                elseif ($a.ClassId)  { $actions += "COM:$($a.ClassId)" }
            }
            $actionStr = ($actions -join ' ;; ')
            $bin = Get-DCleanPath -CommandLine $actionStr
            $sig = Get-DSignature -Path $bin

            $triggers = @()
            foreach ($tr in $t.Triggers) {
                try { $triggers += ($tr.CimClass.CimClassName -replace '^MSFT_Task', '') } catch { }
            }

            [PSCustomObject]@{
                TaskName       = $t.TaskName
                TaskPath       = $t.TaskPath
                State          = [string]$t.State
                Author         = $t.Author
                Description    = $t.Description
                RunAsUser      = $t.Principal.UserId
                RunLevel       = [string]$t.Principal.RunLevel
                Actions        = $actionStr
                BinaryPath     = $bin
                Triggers       = ($triggers -join ',')
                Signed         = $sig.IsValid
                Signer         = $sig.Signer
                SigStatus      = $sig.Status
                IsMicrosoft    = $sig.IsMicrosoft
                SHA256         = if ($bin) { Get-DFileHashSafe -Path $bin } else { $null }
                LastRunUtc     = if ($info) { ConvertTo-DUtcString $info.LastRunTime } else { $null }
                NextRunUtc     = if ($info) { ConvertTo-DUtcString $info.NextRunTime } else { $null }
                SuspiciousPath = Test-DSuspiciousPath -Path $bin
            }
        }
    } catch {
        Write-DLog "  Scheduled task listesi alinamadi: $($_.Exception.Message)" -Level WARN
    }
    Export-DArtifact -Name '06_scheduled_tasks' -Data $tasks -AsJson

    # Task XML dosya zaman damgalari (gorev NE ZAMAN kaydedildi)
    $taskFiles = @()
    try {
        $tRoot = "$env:SystemRoot\System32\Tasks"
        $taskFiles = @(Get-DFilesNoReparse -Root $tRoot -Limit 8000 | ForEach-Object {
            $rel = $_.FullName.Replace($tRoot, '')
            [PSCustomObject]@{
                TaskFile    = $rel
                TaskName    = $rel
                CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                SizeBytes   = $_.Length
            }
        })
    } catch { }
    Export-DArtifact -Name '06_task_files' -Data $taskFiles

    # --- TRIAGE ---
    foreach ($t in $tasks) {
        if ($t.State -eq 'Disabled') { continue }
        $ev = "$($t.TaskPath)$($t.TaskName) -> $($t.Actions)"

        if ($t.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-070' -Severity CRITICAL `
                -Title 'Zamanlanmis gorev supheli dizinden calisiyor' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks' `
                -Why 'Mesru gorevler System32 veya Program Files altindan calisir'
        }

        if ($t.TaskPath -eq '\' -and -not $t.IsMicrosoft -and $t.BinaryPath) {
            Add-DFinding -RuleId 'DGL-071' -Severity MEDIUM `
                -Title 'Gorev kok dizinde tanimli' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks' `
                -Why 'Saldirgan tarafindan olusturulan gorevler genelde kok dizinde birakilir'
        }

        if ($t.BinaryPath -and $false -eq $t.Signed -and -not $t.IsMicrosoft -and
            $t.SigStatus -notin 'FileNotFound', 'NoPath') {
            Add-DFinding -RuleId 'DGL-072' -Severity HIGH `
                -Title 'Zamanlanmis gorev imzasiz binary calistiriyor' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks' `
                -Why 'Imzasiz binary calistiran gorev yaygin bir kalicilik yontemidir'
        }

        # F1.5-3: COM-handler gorevlerde binary yok -> IsMicrosoft yaniltici.
        # Sadece GERCEK bir dosya yolu olan gorevleri SYSTEM kuralindan gecir.
        $hasRealBinary = ($t.BinaryPath -and $t.BinaryPath -notmatch '^COM:' -and
                          (Test-Path -LiteralPath (Expand-DPath $t.BinaryPath) -PathType Leaf -EA SilentlyContinue))
        if ($t.RunAsUser -match '(?i)(SYSTEM|S-1-5-18)' -and -not $t.IsMicrosoft -and $hasRealBinary) {
            Add-DFinding -RuleId 'DGL-073' -Severity HIGH `
                -Title 'Microsoft disi gorev SYSTEM olarak calisiyor' -Evidence $ev `
                -Mitre 'T1053.005' -Artifact '06_scheduled_tasks' `
                -Why 'SYSTEM yetkisiyle calisan ucuncu parti gorev yetki yukseltme ve kalicilik saglar'
        }

        if ($t.Actions) {
            foreach ($pat in $Script:CmdLinePatterns) {
                if ($t.Actions -match $pat.P) {
                    Add-DFinding -RuleId 'DGL-074' -Severity $pat.S `
                        -Title "Gorev komutunda supheli pattern: $($pat.N)" -Evidence $ev `
                        -Mitre $pat.M -Artifact '06_scheduled_tasks' `
                        -Why 'Gorev komut satirinda saldirgan davranisiyla eslesen pattern'
                    break
                }
            }
            # F1.5-7: gorev aksiyonundaki gizli komutu coz ve tara
            $null = Invoke-DDeobfuscateAndScan -Text $t.Actions -Context "Gorev $($t.TaskName)" `
                -Artifact '06_scheduled_tasks' -Timestamp $null
        }
    }

    # Mesru gorevleri elemek icin: tasks listesinden MS-imzali gorev adlarini topla.
    # .NET NGEN, EdgeUpdate gibi gorevler Windows Update ile yeniden yazilir -
    # yeni CreationTime alirlar ama saldirgan kaliciligi degildirler.
    $msTaskNames = @{}
    foreach ($tk in $tasks) {
        if ($tk.IsMicrosoft -or ($tk.Signed -eq $true) -or
            ($tk.RunAsUser -match '(?i)SYSTEM|LocalService|NetworkService' -and $tk.BinaryPath -match '(?i)\\Windows\\(System32|Microsoft)')) {
            $key = "$($tk.TaskPath)$($tk.TaskName)".TrimStart('\').ToLowerInvariant()
            $msTaskNames[$key] = $true
        }
    }
    foreach ($tf in $taskFiles) {
        if (-not $tf.CreatedUtc) { continue }
        try {
            $age = ((Get-Date) - [DateTime]$tf.CreatedUtc).TotalDays
            if ($age -lt $Days) {
                $tfKey = $tf.TaskName.TrimStart('\').ToLowerInvariant()
                $isKnownMs = $msTaskNames.ContainsKey($tfKey)
                if (-not $isKnownMs -and $tf.TaskName -match '(?i)\\(Microsoft\\Windows|Microsoft\\Office|Mozilla|Google)\\') { $isKnownMs = $true }
                if ($isKnownMs) { continue }

                $sev075 = Get-DEffectiveSeverity 'HIGH' -Timestamp $tf.CreatedUtc -TimeBased
                Add-DFinding -RuleId 'DGL-075' -Severity $sev075 `
                    -Title 'Analiz penceresi icinde yeni gorev olusturulmus' `
                    -Evidence "$($tf.TaskFile) @ $($tf.CreatedUtc)" `
                    -Mitre 'T1053.005' -Artifact '06_task_files' -Timestamp $tf.CreatedUtc `
                    -Why 'Analiz penceresi icinde olusturulan Microsoft-disi gorev saldirgan kaliciligi olabilir'
                Add-DTimelineEvent -Timestamp $tf.CreatedUtc -Source 'ScheduledTask' `
                    -Description "Task created: $($tf.TaskFile)" -Severity $sev075
            }
        } catch { }
    }

    Write-DLog "  $(@($tasks).Count) tasks, $(@($taskFiles).Count) task files" -Level DEBUG
}

# ============================================================================
#  MODUL: AUTORUNS (NORMALIZE ASEP TABLOSU)
# ============================================================================

Register-DModule -Name 'Autoruns / ASEP' -Phase 1 `
    -Description 'Tum kalicilik noktalari tek normalize tabloda' `
    -HuntTags @('Persistence') -Body {

    $entries = New-Object System.Collections.ArrayList
    $hives   = Get-DUserHives

    # --- 1. Run / RunOnce (makine) ---
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($k in $runKeys) {
        foreach ($v in (Get-DRegValues -Path $k)) {
            $null = $entries.Add((New-DAutorunEntry -Category 'Run' -Location $k `
                                  -Name $v.Name -Value $v.Value))
        }
    }

    # --- 2. Run / RunOnce (TUM kullanicilar - eski script sadece HKCU'ya bakiyordu) ---
    foreach ($h in $hives) {
        foreach ($sub in 'Run', 'RunOnce', 'RunServices', 'Policies\Explorer\Run') {
            $k = "$($h.RegRoot)\Software\Microsoft\Windows\CurrentVersion\$sub"
            foreach ($v in (Get-DRegValues -Path $k)) {
                $null = $entries.Add((New-DAutorunEntry -Category 'Run(User)' -Location $k `
                                      -Name $v.Name -Value $v.Value -User $h.User))
            }
        }
    }

    # --- 3. Startup klasorleri (tum kullanicilar) ---
    $startupDirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    try {
        Get-ChildItem 'C:\Users' -Directory -EA SilentlyContinue | ForEach-Object {
            $startupDirs += "$($_.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        }
    } catch { }

    foreach ($d in $startupDirs) {
        if (-not (Test-Path $d)) { continue }
        $whose = 'ALLUSERS'
        if ($d -match '\\Users\\([^\\]+)\\') { $whose = $Matches[1] }
        try {
            Get-ChildItem $d -File -Force -EA Stop |
                Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
                    $null = $entries.Add((New-DAutorunEntry -Category 'StartupFolder' `
                            -Location $d -Name $_.Name -Value $_.FullName -User $whose))
                }
        } catch { }
    }

    # --- 4. Winlogon (Shell / Userinit / Taskman / GinaDLL) ---
    $wlKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlExpected = @{ 'Shell' = 'explorer.exe'; 'Userinit' = 'userinit.exe' }
    foreach ($v in (Get-DRegValues -Path $wlKey)) {
        if ($v.Name -notin 'Shell', 'Userinit', 'Taskman', 'AppSetup', 'VmApplet', 'GinaDLL') { continue }
        $null = $entries.Add((New-DAutorunEntry -Category 'Winlogon' -Location $wlKey `
                              -Name $v.Name -Value $v.Value))

        if ($wlExpected.ContainsKey($v.Name)) {
            $exp = $wlExpected[$v.Name]
            if ($v.Value -notmatch "^(?i)(C:\\Windows\\system32\\)?$([regex]::Escape($exp)),?\s*$") {
                Add-DFinding -RuleId 'DGL-080' -Severity CRITICAL `
                    -Title "Winlogon $($v.Name) degeri degistirilmis" `
                    -Evidence "$($v.Name) = $($v.Value)" `
                    -Mitre 'T1547.004' -Artifact '07_autoruns' `
                    -Why "Beklenen deger: $exp"
            }
        }
        if ($v.Name -in 'Taskman', 'GinaDLL', 'AppSetup', 'VmApplet') {
            Add-DFinding -RuleId 'DGL-089' -Severity HIGH `
                -Title "Winlogon $($v.Name) tanimli" -Evidence "$($v.Name) = $($v.Value)" `
                -Mitre 'T1547.004' -Artifact '07_autoruns' `
                -Why 'Bu deger varsayilan olarak bulunmaz'
        }
    }

    # --- 5. AppInit_DLLs ---
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $v = Get-DRegValues -Path $k | Where-Object Name -eq 'AppInit_DLLs'
        if ($v -and $v.Value -and $v.Value.Trim()) {
            $null = $entries.Add((New-DAutorunEntry -Category 'AppInit_DLLs' -Location $k `
                                  -Name 'AppInit_DLLs' -Value $v.Value))
            Add-DFinding -RuleId 'DGL-081' -Severity CRITICAL `
                -Title 'AppInit_DLLs tanimli' -Evidence $v.Value `
                -Mitre 'T1546.010' -Artifact '07_autoruns' `
                -Why 'AppInit_DLLs her user32.dll yukleyen process icine DLL enjekte eder'
        }
    }

    # --- 6. IFEO Debugger (accessibility backdoor dahil) ---
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        try {
            Get-ChildItem $base -EA Stop | ForEach-Object {
                $dbg = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'Debugger'
                if ($dbg -and $dbg.Value) {
                    $target = $_.PSChildName
                    $null = $entries.Add((New-DAutorunEntry -Category 'IFEO-Debugger' `
                            -Location $_.PSPath -Name $target -Value $dbg.Value))
                    $sev = if ($target -match '(?i)^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$') {
                               'CRITICAL' } else { 'HIGH' }
                    Add-DFinding -RuleId 'DGL-082' -Severity $sev -Title 'IFEO Debugger tanimli' `
                        -Evidence "$target -> $($dbg.Value)" `
                        -Mitre 'T1546.012' -Artifact '07_autoruns' `
                        -Why 'Hedef binary calistirildiginda onun yerine debugger calisir (accessibility backdoor)'
                }
            }
        } catch { }
    }

    # --- 6b. SilentProcessExit ---
    try {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -EA Stop |
            ForEach-Object {
                $mon = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'MonitorProcess'
                if ($mon -and $mon.Value) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'SilentProcessExit' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $mon.Value))
                    Add-DFinding -RuleId 'DGL-083' -Severity CRITICAL `
                        -Title 'SilentProcessExit MonitorProcess tanimli' `
                        -Evidence "$($_.PSChildName) -> $($mon.Value)" `
                        -Mitre 'T1546.012' -Artifact '07_autoruns' `
                        -Why 'Hedef process sonlandiginda belirtilen binary calisir'
                }
            }
    } catch { }

    # --- 7. LSA paketleri (SSP backdoor / mimilib) ---
    $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $knownLsa = 'kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|rassfm|scecli'
    foreach ($v in (Get-DRegValues -Path $lsaKey)) {
        if ($v.Name -notin 'Security Packages', 'Authentication Packages', 'Notification Packages') { continue }
        $null = $entries.Add((New-DAutorunEntry -Category 'LSA-Package' -Location $lsaKey `
                              -Name $v.Name -Value $v.Value))
        $unknown = @($v.Value -split '\s*\|\s*' |
                     Where-Object { $_ -and $_ -ne '""' -and $_ -notmatch "(?i)^($knownLsa)$" })
        if ($unknown.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-084' -Severity CRITICAL `
                -Title 'LSA paket listesinde bilinmeyen giris' `
                -Evidence "$($v.Name): $($unknown -join ', ')" `
                -Mitre 'T1547.002' -Artifact '07_autoruns' `
                -Why 'LSA icine yuklenen ozel DLL kimlik bilgisi calabilir'
        }
    }

    # --- 8. Netsh helper DLL ---
    foreach ($v in (Get-DRegValues -Path 'HKLM:\SOFTWARE\Microsoft\Netsh')) {
        $null = $entries.Add((New-DAutorunEntry -Category 'NetshHelper' `
                -Location 'HKLM:\SOFTWARE\Microsoft\Netsh' -Name $v.Name -Value $v.Value))
    }

    # --- 9. AppCertDlls (varsayilan olarak BOS olmali) ---
    $acKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    foreach ($v in (Get-DRegValues -Path $acKey)) {
        $null = $entries.Add((New-DAutorunEntry -Category 'AppCertDlls' -Location $acKey `
                              -Name $v.Name -Value $v.Value))
        Add-DFinding -RuleId 'DGL-085' -Severity CRITICAL `
            -Title 'AppCertDlls girdisi mevcut' -Evidence "$($v.Name) = $($v.Value)" `
            -Mitre 'T1546.009' -Artifact '07_autoruns' `
            -Why 'Bu anahtar varsayilan olarak bostur; her CreateProcess cagrisinda DLL yuklenir'
    }

    # --- 10. Print Monitors / Providers ---
    foreach ($k in @('HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors',
                     'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers')) {
        try {
            Get-ChildItem $k -EA Stop | ForEach-Object {
                foreach ($d in (Get-DRegValues -Path $_.PSPath |
                                Where-Object { $_.Name -match '^(Driver|Name)$' -and $_.Value })) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'PrintMonitor' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $d.Value))
                }
            }
        } catch { }
    }

    # --- 11. Time Providers ---
    try {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -EA Stop |
            ForEach-Object {
                $dll = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'DllName'
                if ($dll -and $dll.Value -notmatch '(?i)w32time\.dll') {
                    $null = $entries.Add((New-DAutorunEntry -Category 'TimeProvider' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $dll.Value))
                    Add-DFinding -RuleId 'DGL-086' -Severity HIGH `
                        -Title 'Standart disi Time Provider DLL' `
                        -Evidence "$($_.PSChildName) -> $($dll.Value)" `
                        -Mitre 'T1547.003' -Artifact '07_autoruns' `
                        -Why 'Time Provider kaydi w32time tarafindan SYSTEM olarak yuklenir; varsayilan disi DLL kaliciliktir'
                }
            }
    } catch { }

    # --- 12. Active Setup ---
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components')) {
        try {
            Get-ChildItem $base -EA Stop | ForEach-Object {
                $sc = Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'StubPath'
                if ($sc -and $sc.Value) {
                    $null = $entries.Add((New-DAutorunEntry -Category 'ActiveSetup' `
                            -Location $_.PSPath -Name $_.PSChildName -Value $sc.Value))
                }
            }
        } catch { }
    }

    # --- 13. UserInitMprLogonScript (logon script persistence) ---
    foreach ($h in $hives) {
        $v = Get-DRegValues -Path "$($h.RegRoot)\Environment" |
             Where-Object Name -eq 'UserInitMprLogonScript'
        if ($v -and $v.Value) {
            $null = $entries.Add((New-DAutorunEntry -Category 'LogonScript' `
                    -Location "$($h.RegRoot)\Environment" `
                    -Name 'UserInitMprLogonScript' -Value $v.Value -User $h.User))
            Add-DFinding -RuleId 'DGL-087' -Severity CRITICAL `
                -Title 'UserInitMprLogonScript tanimli' -Evidence "$($h.User): $($v.Value)" `
                -Mitre 'T1037.001' -Artifact '07_autoruns' `
                -Why 'Bu deger varsayilan olarak yoktur; her oturum acilisinda calisir'
        }
    }

    # --- 14. Screensaver ---
    foreach ($h in $hives) {
        $v = Get-DRegValues -Path "$($h.RegRoot)\Control Panel\Desktop" |
             Where-Object Name -eq 'SCRNSAVE.EXE'
        if ($v -and $v.Value -and $v.Value -notmatch '(?i)\\System32\\[\w\.]+\.scr$') {
            $null = $entries.Add((New-DAutorunEntry -Category 'Screensaver' `
                    -Location "$($h.RegRoot)\Control Panel\Desktop" `
                    -Name 'SCRNSAVE.EXE' -Value $v.Value -User $h.User))
        }
    }

    # --- 15. BITS transfer jobs (indirme + kalicilik) ---
    $bits = @()
    if ($Script:Caps.BitsTransfer) {
        try {
            $bits = @(Get-BitsTransfer -AllUsers -EA Stop | ForEach-Object {
                [PSCustomObject]@{
                    JobId       = $_.JobId
                    DisplayName = $_.DisplayName
                    Owner       = $_.OwnerAccount
                    State       = [string]$_.JobState
                    CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                    RemoteUrls  = (($_.FileList | ForEach-Object { $_.RemoteName }) -join ' ; ')
                    LocalFiles  = (($_.FileList | ForEach-Object { $_.LocalName }) -join ' ; ')
                }
            })
        } catch { }
    }
    Export-DArtifact -Name '07_bits_jobs' -Data $bits
    foreach ($b in $bits) {
        Add-DFinding -RuleId 'DGL-088' -Severity HIGH `
            -Title 'BITS transfer isi mevcut' `
            -Evidence "$($b.DisplayName) [$($b.Owner)] -> $($b.RemoteUrls)" `
            -Mitre 'T1197' -Artifact '07_bits_jobs' -Timestamp $b.CreatedUtc `
            -Why 'BITS hem indirme hem kalicilik icin kullanilir'
    }

    # --- Kaydet ve toplu triage ---
    $arr = @($entries)
    Export-DArtifact -Name '07_autoruns' -Data $arr -AsJson
    foreach ($e in $arr) { Invoke-DAutorunTriage -Entry $e -Artifact '07_autoruns' }

    Write-DLog "  $($arr.Count) autorun entries, $(@($bits).Count) BITS jobs" -Level DEBUG
}

# ============================================================================
#  MODUL: WMI KALICILIGI
# ============================================================================

Register-DModule -Name 'WMI Persistence' -Phase 1 `
    -Description 'Event filter/consumer/binding - fileless persistence' `
    -HuntTags @('Persistence') -Body {

    $wmi = New-Object System.Collections.ArrayList

    foreach ($ns in 'root\subscription', 'root\default') {
        try {
            Get-CimInstance -Namespace $ns -ClassName __EventFilter -EA Stop | ForEach-Object {
                $null = $wmi.Add([PSCustomObject]@{
                    Namespace = $ns; Type = 'EventFilter'; Name = $_.Name
                    Detail = $_.Query; Extra = $_.QueryLanguage
                })
            }
        } catch { }

        foreach ($cls in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer',
                         'LogFileEventConsumer', 'SMTPEventConsumer', 'NTEventLogEventConsumer') {
            try {
                Get-CimInstance -Namespace $ns -ClassName $cls -EA Stop | ForEach-Object {
                    $detail = if ($_.CommandLineTemplate) { $_.CommandLineTemplate }
                              elseif ($_.ScriptText)      { $_.ScriptText }
                              elseif ($_.ScriptFileName)  { $_.ScriptFileName }
                              elseif ($_.Filename)        { $_.Filename }
                              else { '(detay yok)' }
                    $null = $wmi.Add([PSCustomObject]@{
                        Namespace = $ns; Type = "Consumer:$cls"; Name = $_.Name
                        Detail = $detail; Extra = $_.ExecutablePath
                    })
                }
            } catch { }
        }

        try {
            Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -EA Stop |
                ForEach-Object {
                    $null = $wmi.Add([PSCustomObject]@{
                        Namespace = $ns; Type = 'Binding'
                        Name = "$($_.Filter) => $($_.Consumer)"
                        Detail = [string]$_.Consumer; Extra = [string]$_.Filter
                    })
                }
        } catch { }
    }

    $arr = @($wmi)
    Export-DArtifact -Name '08_wmi_persistence' -Data $arr -AsJson

    # Binding varsa bu neredeyse her zaman kalicilik demektir
    $bindings = @($arr | Where-Object Type -eq 'Binding')
    foreach ($b in $bindings) {
        if ($b.Name -match '(?i)(SCM Event Log|BVTFilter|TSlogonEvents|RmAssistEventFilter)') { continue }
        Add-DFinding -RuleId 'DGL-090' -Severity CRITICAL `
            -Title 'WMI kalici event aboneligi mevcut' -Evidence $b.Name `
            -Mitre 'T1546.003' -Artifact '08_wmi_persistence' `
            -Why 'Filter-Consumer baglamasi fileless kaliciligin en yaygin bicimidir'
    }

    foreach ($c in @($arr | Where-Object { $_.Type -match 'Consumer:(CommandLine|ActiveScript)' })) {
        if (-not $c.Detail) { continue }
        foreach ($pat in $Script:CmdLinePatterns) {
            if ($c.Detail -match $pat.P) {
                Add-DFinding -RuleId 'DGL-091' -Severity CRITICAL `
                    -Title "WMI consumer supheli komut: $($pat.N)" `
                    -Evidence "$($c.Name): $(Format-DEvidence -Text $c.Detail -Max 800)" `
                    -Mitre $pat.M -Artifact '08_wmi_persistence' `
                    -Why 'WMI consumer komutu tetiklendiginde SYSTEM yetkisiyle calisir'
                break
            }
        }
    }

    Write-DLog "  $($arr.Count) WMI nesnesi ($($bindings.Count) binding)" -Level DEBUG
}

# ============================================================================
#  MODUL: NAMED PIPES
# ============================================================================

Register-DModule -Name 'Named Pipes' -Phase 1 -Description 'C2 beacon pipe tespiti' -Body {

    $pipes = @()
    try {
        $pipes = @([IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object {
            $n = $_ -replace '^\\\\\.\\pipe\\', ''
            [PSCustomObject]@{ Name = $n; FullPath = $_; Length = $n.Length }
        })
    } catch {
        try {
            $pipes = @(Get-ChildItem '\\.\pipe\' -EA Stop | ForEach-Object {
                [PSCustomObject]@{ Name = $_.Name; FullPath = $_.FullName; Length = $_.Name.Length }
            })
        } catch { }
    }
    Export-DArtifact -Name '09_named_pipes' -Data $pipes

    foreach ($p in $pipes) {
        foreach ($pat in $Script:BadPipePatterns) {
            if ($p.Name -match $pat) {
                Add-DFinding -RuleId 'DGL-100' -Severity HIGH `
                    -Title 'Bilinen C2 pipe pattern eslesmesi' -Evidence $p.Name `
                    -Mitre 'T1071' -Artifact '09_named_pipes' `
                    -Why 'Cobalt Strike ve benzeri C2 cerceveleri karakteristik pipe adlari kullanir'
                break
            }
        }
    }

    Write-DLog "  $($pipes.Count) named pipe" -Level DEBUG
}

# ============================================================================
#  MODUL: GUVENLIK DURUMU / TAMPER TESPITI
# ============================================================================

Register-DModule -Name 'Security Posture' -Phase 1 `
    -Description 'Defender, exclusion, AMSI, LSA, PowerShell logging, audit policy, VSS' `
    -HuntTags @('DefenseEvasion') -Body {

    # --- Defender durumu ---
    $mpStatus = $null
    if ($Script:Caps.Defender) {
        try {
            $s = Get-MpComputerStatus -EA Stop
            $mpStatus = [PSCustomObject]@{
                AMServiceEnabled          = $s.AMServiceEnabled
                AntivirusEnabled          = $s.AntivirusEnabled
                AntispywareEnabled        = $s.AntispywareEnabled
                RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
                BehaviorMonitorEnabled    = $s.BehaviorMonitorEnabled
                IoavProtectionEnabled     = $s.IoavProtectionEnabled
                OnAccessProtectionEnabled = $s.OnAccessProtectionEnabled
                IsTamperProtected         = $s.IsTamperProtected
                AntivirusSignatureAge     = $s.AntivirusSignatureAge
                SignatureLastUpdatedUtc   = ConvertTo-DUtcString $s.AntivirusSignatureLastUpdated
                QuickScanAge              = $s.QuickScanAge
                FullScanAge               = $s.FullScanAge
            }
        } catch { }
    }
    Export-DArtifact -Name '12_defender_status' -Data $mpStatus -AsJson

    if ($mpStatus) {
        foreach ($prop in 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled',
                          'AntivirusEnabled', 'OnAccessProtectionEnabled') {
            if ($false -eq $mpStatus.$prop) {
                Add-DFinding -RuleId 'DGL-110' -Severity CRITICAL `
                    -Title 'Defender koruma bileseni devre disi' -Evidence "$prop = False" `
                    -Mitre 'T1562.001' -Artifact '12_defender_status' `
                    -Why 'Saldirganlarin ilk isi genelde AV korumasini kapatmaktir'
            }
        }
        if ($mpStatus.AntivirusSignatureAge -gt 14) {
            Add-DFinding -RuleId 'DGL-111' -Severity MEDIUM `
                -Title 'Defender imzalari guncel degil' `
                -Evidence "$($mpStatus.AntivirusSignatureAge) gun" `
                -Mitre 'T1562.001' -Artifact '12_defender_status' `
                -Why 'Eski imza veritabani yeni tehditleri kacirir; guncelleme engellenmis olabilir'
        }
    }

    # --- Exclusion'lar: cmdlet + registry + GPO (biri yoksa digeri calissin) ---
    $excl = New-Object System.Collections.ArrayList
    if ($Script:Caps.Defender) {
        try {
            $pref = Get-MpPreference -EA Stop
            foreach ($t in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
                foreach ($x in @($pref.$t)) {
                    if ($x) { $null = $excl.Add([PSCustomObject]@{ Type = $t; Value = $x; Source = 'Cmdlet' }) }
                }
            }
            Export-DArtifact -Name '12_defender_prefs' -AsJson -Data ([PSCustomObject]@{
                DisableRealtimeMonitoring    = $pref.DisableRealtimeMonitoring
                DisableBehaviorMonitoring    = $pref.DisableBehaviorMonitoring
                DisableScriptScanning        = $pref.DisableScriptScanning
                DisableIOAVProtection        = $pref.DisableIOAVProtection
                DisableArchiveScanning       = $pref.DisableArchiveScanning
                MAPSReporting                = [string]$pref.MAPSReporting
                SubmitSamplesConsent         = [string]$pref.SubmitSamplesConsent
                EnableControlledFolderAccess = [string]$pref.EnableControlledFolderAccess
            })
        } catch { }
    }
    foreach ($t in 'Paths', 'Processes', 'Extensions', 'IpAddresses') {
        foreach ($v in (Get-DRegValues -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\$t")) {
            $null = $excl.Add([PSCustomObject]@{ Type = "Exclusion$t"; Value = $v.Name; Source = 'Registry' })
        }
        foreach ($v in (Get-DRegValues -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$t")) {
            $null = $excl.Add([PSCustomObject]@{ Type = "Policy$t"; Value = $v.Name; Source = 'GPO' })
        }
    }
    $exclArr = @($excl)
    Export-DArtifact -Name '12_defender_exclusions' -Data $exclArr

    foreach ($e in $exclArr) {
        $sev = if ($e.Value -match '(?i)^[a-z]:\\?$|\\(Users|Temp|ProgramData|Windows)\\?$') {
                   'CRITICAL' } else { 'HIGH' }
        Add-DFinding -RuleId 'DGL-112' -Severity $sev -Title 'Defender exclusion tanimli' `
            -Evidence "$($e.Type) [$($e.Source)]: $($e.Value)" `
            -Mitre 'T1562.001' -Artifact '12_defender_exclusions' `
            -Why 'Saldirganlar payload dizinini exclusion listesine ekler'
    }

    # --- Tespit gecmisi ---
    $threats = @()
    if ($Script:Caps.Defender) {
        try {
            $threats = @(Get-MpThreatDetection -EA Stop | ForEach-Object {
                [PSCustomObject]@{
                    ThreatID         = $_.ThreatID
                    DetectionTimeUtc = ConvertTo-DUtcString $_.InitialDetectionTime
                    Resources        = ($_.Resources -join ' ; ')
                    ProcessName      = $_.ProcessName
                    DomainUser       = $_.DomainUser
                    ActionSuccess    = $_.ActionSuccess
                    CleaningAction   = [string]$_.CleaningActionID
                    ThreatStatus     = [string]$_.ThreatStatusID
                }
            })
        } catch { }
    }
    Export-DArtifact -Name '12_defender_threats' -Data $threats

    foreach ($t in $threats) {
        $failed = ($false -eq $t.ActionSuccess)
        $sev    = if ($failed) { 'CRITICAL' } else { 'HIGH' }
        $title  = if ($failed) { 'Defender tespiti TEMIZLENEMEDI' } else { 'Defender tehdit tespiti' }
        Add-DFinding -RuleId 'DGL-113' -Severity $sev -Title $title `
            -Evidence "$($t.Resources)  [$($t.DetectionTimeUtc)]" `
            -Artifact '12_defender_threats' -Timestamp $t.DetectionTimeUtc `
            -Why 'Temizlenemeyen tespit aktif enfeksiyona isaret eder; temizlenen tespit bile giris vektorunu gosterir'
        Add-DTimelineEvent -Timestamp $t.DetectionTimeUtc -Source 'Defender' `
            -Description 'Zararli tespiti' -Detail $t.Resources -Severity HIGH
    }

    # --- Guvenlik yapilandirmasi (tamper gostergeleri) ---
    $cfg = New-Object System.Collections.ArrayList

    $checks = @(
        @{ N = 'WDigest cleartext password storage'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
           K = 'UseLogonCredential'; E = '0'; S = 'CRITICAL'; M = 'T1003.001'
           W = 'UseLogonCredential=1 parolalari bellekte duz metin tutar' }
        @{ N = 'LSA Protection (RunAsPPL)'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
           K = 'RunAsPPL'; E = '1'; S = 'MEDIUM'; M = 'T1003.001'
           W = 'Kapali ise LSASS bellegi kolayca dump edilir' }
        @{ N = 'PowerShell Script Block Logging'
           P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
           K = 'EnableScriptBlockLogging'; E = '1'; S = 'MEDIUM'; M = 'T1562.002'
           W = 'Kapali ise PowerShell tabanli saldirilar gorunmez kalir (4104 uretilmez)' }
        @{ N = 'PowerShell Module Logging'
           P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
           K = 'EnableModuleLogging'; E = '1'; S = 'LOW'; M = 'T1562.002'; W = '' }
        @{ N = 'Command line auditing (4688)'
           P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
           K = 'ProcessCreationIncludeCmdLine_Enabled'; E = '1'; S = 'MEDIUM'; M = 'T1562.002'
           W = 'Kapali ise 4688 eventleri komut satiri icermez - hunting degeri buyuk olcude duser' }
        @{ N = 'SMBv1 protocol'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
           K = 'SMB1'; E = '0'; S = 'MEDIUM'; M = 'T1210'
           W = 'SMBv1 EternalBlue ve benzeri exploitlere aciktir' }
        @{ N = 'RestrictedAdmin RDP mode'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
           K = 'DisableRestrictedAdmin'; E = $null; S = 'INFO'; M = ''; W = '' }
        @{ N = 'RDP state (fDenyTSConnections)'
           P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
           K = 'fDenyTSConnections'; E = $null; S = 'INFO'; M = ''; W = '' }
    )

    foreach ($c in $checks) {
        $v   = (Get-DRegValues -Path $c.P | Where-Object Name -eq $c.K)
        $val = if ($v) { $v.Value } else { '(tanimsiz)' }
        $null = $cfg.Add([PSCustomObject]@{
            Setting = $c.N; Path = $c.P; Key = $c.K; Value = $val
        })
        if ($v -and $c.E -and $v.Value -ne $c.E) {
            Add-DFinding -RuleId 'DGL-114' -Severity $c.S -Title $c.N `
                -Evidence "$($c.K) = $($v.Value) (beklenen: $($c.E))" `
                -Mitre $c.M -Artifact '12_security_config' -Why $c.W
        }
    }

    # AMSI provider'lari silinmis mi?
    $amsiCount = 0
    try {
        $amsiCount = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -EA Stop).Count
    } catch { }
    $null = $cfg.Add([PSCustomObject]@{
        Setting = 'AMSI Providers'; Path = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
        Key = 'Count'; Value = $amsiCount
    })
    if ($amsiCount -eq 0) {
        Add-DFinding -RuleId 'DGL-115' -Severity HIGH -Title 'Kayitli AMSI provider bulunamadi' `
            -Evidence 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers bos' `
            -Mitre 'T1562.001' -Artifact '12_security_config' `
            -Why 'AMSI provider kaydi silinmis olabilir - script tarama devre disi'
    }
    Export-DArtifact -Name '12_security_config' -Data @($cfg)

    # --- Audit policy ---
    $audit = @()
    try {
        $ap = auditpol /get /category:* /r 2>$null
        if ($ap) {
            $audit = @($ap | ConvertFrom-Csv | ForEach-Object {
                [PSCustomObject]@{
                    Category = $_.'Subcategory'
                    GUID     = $_.'Subcategory GUID'
                    Setting  = $_.'Inclusion Setting'
                }
            })
        }
    } catch { }
    Export-DArtifact -Name '12_audit_policy' -Data $audit

    foreach ($ca in @('Process Creation', 'Logon', 'Special Logon', 'Security Group Management',
                      'User Account Management', 'Audit Policy Change', 'Security System Extension')) {
        $a = $audit | Where-Object Category -eq $ca
        if ($a -and $a.Setting -match '(?i)No Auditing') {
            Add-DFinding -RuleId 'DGL-116' -Severity MEDIUM `
                -Title 'Kritik denetim kategorisi kapali' -Evidence "$ca : $($a.Setting)" `
                -Mitre 'T1562.002' -Artifact '12_audit_policy' `
                -Why 'Bu kategori kapaliyken ilgili eventler hic uretilmez'
        }
    }

    # --- Shadow copy (ransomware / anti-forensics) ---
    $vss = @()
    try {
        $vss = @(Get-CimInstance Win32_ShadowCopy -EA Stop | ForEach-Object {
            [PSCustomObject]@{
                ID = $_.ID; VolumeName = $_.VolumeName
                InstallDateUtc = ConvertTo-DUtcString $_.InstallDate
            }
        })
    } catch { }
    Export-DArtifact -Name '12_shadow_copies' -Data $vss

    if ($vss.Count -eq 0 -and $Script:Ctx.IsServer) {
        Add-DFinding -RuleId 'DGL-117' -Severity MEDIUM `
            -Title 'Hicbir shadow copy bulunamadi' -Evidence 'Win32_ShadowCopy bos' `
            -Mitre 'T1490' -Artifact '12_shadow_copies' `
            -Why 'Sunucularda genelde shadow copy bulunur; silinmis olabilir'
    }

    Write-DLog "  $($exclArr.Count) exclusion, $(@($threats).Count) tehdit, $($vss.Count) shadow copy" -Level DEBUG
}

# ============================================================================
#  MODUL: SMB VE PAYLASIMLAR
# ============================================================================

Register-DModule -Name 'SMB / Shares' -Phase 1 -RequiresCap 'SmbShare' -Body {

    $shares = @()
    try {
        $shares = @(Get-SmbShare -EA Stop | ForEach-Object {
            $acl = $null
            try {
                $acl = ((Get-SmbShareAccess -Name $_.Name -EA Stop |
                         ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ' ; ')
            } catch { }
            [PSCustomObject]@{
                Name = $_.Name; Path = $_.Path; Description = $_.Description
                ShareType = [string]$_.ShareType; Special = $_.Special; Access = $acl
            }
        })
    } catch { }
    Export-DArtifact -Name '10_smb_shares' -Data $shares

    foreach ($s in $shares) {
        if ($s.Special) { continue }
        if ($s.Access -match '(?i)Everyone:Full') {
            Add-DFinding -RuleId 'DGL-120' -Severity HIGH `
                -Title 'Paylasim Everyone hesabina tam yetki veriyor' `
                -Evidence "$($s.Name) -> $($s.Path)" -Mitre 'T1135' -Artifact '10_smb_shares' `
                -Why 'Kimlik dogrulamasiz yazma yetkisi lateral movement ve veri sizdirmayi kolaylastirir'
        }
        if ($s.Path -match '(?i)^[A-Z]:\\?$') {
            Add-DFinding -RuleId 'DGL-121' -Severity HIGH `
                -Title 'Surucu koku paylasima acilmis' `
                -Evidence "$($s.Name) -> $($s.Path)" -Mitre 'T1135' -Artifact '10_smb_shares' `
                -Why 'Varsayilan yonetimsel paylasimlar disinda surucu koku paylasimi nadiren mesrudur'
        }
    }

    $sessions = @()
    try {
        $sessions = @(Get-SmbSession -EA Stop | Select-Object ClientComputerName,
                      ClientUserName, NumOpens, SessionId,
                      @{N = 'Dialect'; E = { [string]$_.Dialect } })
    } catch { }
    Export-DArtifact -Name '10_smb_sessions' -Data $sessions

    $conns = @()
    try {
        $conns = @(Get-SmbConnection -EA Stop | Select-Object ServerName, ShareName, UserName,
                   @{N = 'Dialect'; E = { [string]$_.Dialect } })
    } catch { }
    Export-DArtifact -Name '10_smb_connections' -Data $conns

    $mappings = @()
    try {
        $mappings = @(Get-SmbMapping -EA Stop | Select-Object LocalPath, RemotePath,
                      @{N = 'Status'; E = { [string]$_.Status } })
    } catch { }
    Export-DArtifact -Name '10_smb_mappings' -Data $mappings

    Write-DLog "  $($shares.Count) shares, $($sessions.Count) sessions, $($conns.Count) connections" -Level DEBUG
}

# ============================================================================
#  MODUL: SURUCULER (BYOVD)
# ============================================================================

Register-DModule -Name 'Drivers' -Phase 1 `
    -Description 'Imzasiz / supheli surucu tespiti (BYOVD)' -Body {

    $drivers = @()
    try {
        $drivers = @(Get-CimInstance Win32_SystemDriver -EA Stop | ForEach-Object {
            $p = $_.PathName
            if ($p) {
                $p = [Environment]::ExpandEnvironmentVariables(($p -replace '^\\\?\?\\', ''))
            }
            $sig = Get-DSignature -Path $p
            $wr = $null
            try {
                if ($p -and (Test-Path -LiteralPath $p -PathType Leaf -EA SilentlyContinue)) {
                    $wr = (Get-Item -LiteralPath $p -Force -EA Stop).LastWriteTime
                }
            } catch { }
            [PSCustomObject]@{
                Name = $_.Name; DisplayName = $_.DisplayName
                State = $_.State; StartMode = $_.StartMode; PathName = $p
                Signed = $sig.IsValid; Signer = $sig.Signer; SigStatus = $sig.Status
                IsMicrosoft = $sig.IsMicrosoft
                SHA256 = if ($p) { Get-DFileHashSafe -Path $p } else { $null }
                WriteUtc = ConvertTo-DUtcString $wr
                SuspiciousPath = Test-DSuspiciousPath -Path $p
            }
        })
    } catch { }
    Export-DArtifact -Name '09_drivers' -Data $drivers

    foreach ($d in $drivers) {
        if ($d.State -ne 'Running') { continue }

        if ($d.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-130' -Severity CRITICAL `
                -Title 'Surucu supheli dizinden yuklenmis' `
                -Evidence "$($d.Name) -> $($d.PathName)" `
                -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc `
                -Why 'BYOVD saldirilarinda surucu gecici dizinden yuklenir'
        }
        elseif ($d.PathName -and $false -eq $d.Signed -and -not $d.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-131' -Severity HIGH `
                -Title 'Imzasiz surucu calisiyor' `
                -Evidence "$($d.Name) -> $($d.PathName) ($($d.SigStatus))" `
                -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc `
                -Why 'Kernel modunda calisan imzasiz kod rootkit veya BYOVD gostergesidir'
        }

        if ($d.WriteUtc) {
            try {
                $age = ((Get-Date) - [DateTime]$d.WriteUtc).TotalDays
                if ($age -lt $Days -and -not $d.IsMicrosoft) {
                    Add-DFinding -RuleId 'DGL-132' -Severity HIGH `
                        -Title 'Surucu analiz penceresi icinde yazilmis' `
                        -Evidence "$($d.Name) @ $($d.WriteUtc)" `
                        -Mitre 'T1068' -Artifact '09_drivers' -Timestamp $d.WriteUtc `
                        -Why 'Analiz penceresi icinde diske yazilan surucu BYOVD saldirisi olabilir'
                }
            } catch { }
        }

        if ($d.SHA256) { $null = Test-DIoc -Value $d.SHA256 -Context $d.Name -Artifact '09_drivers' }
    }

    Write-DLog "  $($drivers.Count) surucu" -Level DEBUG
}

# ============================================================================
#  EVENT LOG MOTORU
# ============================================================================

$Script:EventStats = New-Object System.Collections.ArrayList

function Get-DWinEvents {
    <#
        Tek cikis noktasi. Kanal basina TEK cagri, ID'ler dizi olarak.
        Cap'e takilirsa rapora uyari duser - sessizce kesmez.
    #>
    param(
        [Parameter(Mandatory)][string]$LogName,
        [int[]]$Id,
        [int]$Max = 0
    )

    if ($Max -le 0) { $Max = $MaxEventsPerChannel }

    # Kanal yoksa bosuna sorgulama
    if ($Script:Caps.AvailableLogs -and ($Script:Caps.AvailableLogs -notcontains $LogName)) {
        $null = $Script:EventStats.Add([PSCustomObject]@{
            LogName = $LogName; RequestedIds = ($Id -join ','); Returned = 0
            Capped = $false; Status = 'CHANNEL_NOT_FOUND'
        })
        return @()
    }

    $filter = @{ LogName = $LogName; StartTime = $Script:Ctx.WindowStart }
    if ($Id) { $filter['ID'] = $Id }

    $events = @()
    $status = 'OK'
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $Max -ErrorAction Stop)
    } catch {
        if ($_.Exception.Message -match 'No events were found|Belirtilen secim') {
            $status = 'NO_EVENTS'
        } else {
            $status = 'ERROR'
            Write-DLog "  $LogName sorgusu basarisiz: $($_.Exception.Message)" -Level WARN
        }
    }

    $capped = ($events.Count -ge $Max)
    if ($capped) {
        $status = 'CAPPED'
        Write-DLog "  UYARI: $LogName cap'e takildi ($Max) - pencereyi daralt" -Level WARN
        Add-DFinding -RuleId 'DGL-018' -Severity INFO `
            -Title 'Event toplama limiti asildi - veri kisitli' `
            -Evidence "$LogName : $Max kayitta durduruldu (-Days $Days)" `
            -Artifact '11_event_stats' `
            -Why 'Analiz penceresini daraltin veya -MaxEventsPerChannel degerini artirin'
    }

    $null = $Script:EventStats.Add([PSCustomObject]@{
        LogName = $LogName; RequestedIds = ($Id -join ','); Returned = $events.Count
        Capped = $capped; Status = $status
    })

    return $events
}

function Get-DProp {
    <#
        Event property'sine indeksle guvenli erisim.
        NOT: .Message KULLANILMIYOR - her event icin mesaj formatlamasi yapar,
        50k eventte 4 dakikayi 40 dakikaya cikarir. Properties[] 10-20x hizli.
    #>
    param($Event, [int]$Index)
    try {
        if ($Event.Properties.Count -gt $Index) {
            return [string]$Event.Properties[$Index].Value
        }
    } catch { }
    return $null
}

function ConvertFrom-DEncodedCommand {
    <# -EncodedCommand payload'ini cozer. Raporda okunabilir hale getirir. #>
    param([string]$Text)
    if (-not $Text) { return $null }
    if ($Text -notmatch '(?i)\s-e(nc|ncod|ncoded|ncodedcommand)?\s+([A-Za-z0-9+/=]{24,})') {
        return $null
    }
    $b64 = $Matches[2]
    try {
        $bytes = [Convert]::FromBase64String($b64)
        $dec   = [Text.Encoding]::Unicode.GetString($bytes)
        # UTF-16LE degilse ASCII dene
        if ($dec -match '\x00') { $dec = [Text.Encoding]::UTF8.GetString($bytes) }
        return ($dec -replace '\s+', ' ').Trim()
    } catch { return $null }
}

function Get-DLogonTypeName {
    param($Type)
    switch ([string]$Type) {
        '2'  { 'Interactive' }
        '3'  { 'Network' }
        '4'  { 'Batch' }
        '5'  { 'Service' }
        '7'  { 'Unlock' }
        '8'  { 'NetworkCleartext' }
        '9'  { 'NewCredentials(RunAs)' }
        '10' { 'RemoteInteractive(RDP)' }
        '11' { 'CachedInteractive' }
        default { "Type$Type" }
    }
}

function Test-DEventCmdLine {
    <# Bir event komut satirini pattern setinden gecirir #>
    param([string]$CommandLine, [string]$Context, [string]$Artifact, $Timestamp, [string]$RuleId)

    if (-not $CommandLine) { return }
    foreach ($pat in $Script:CmdLinePatterns) {
        if ($CommandLine -match $pat.P) {
            Add-DFinding -RuleId $RuleId -Severity $pat.S `
                -Title "Event kaydinda supheli komut: $($pat.N)" `
                -Evidence "$Context :: $(Format-DEvidence -Text $CommandLine -Max 1000)" `
                -Mitre $pat.M -Artifact $Artifact -Timestamp $Timestamp `
                -Why 'Gecmis event kaydinda saldirgan davranis pattern eslesmesi'
            return
        }
    }
}

# ============================================================================
#  MODUL: EVENT - PROCESS OLUSTURMA (4688) + POWERSHELL (4104)
# ============================================================================

Register-DModule -Name 'Event: Process Creation (4688)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Gecmis process calistirmalari + komut satirlari' -Body {

    $evts = Get-DWinEvents -LogName 'Security' -Id 4688
    if ($evts.Count -eq 0) {
        Add-DFinding -RuleId 'DGL-140' -Severity MEDIUM `
            -Title 'Process olusturma denetimi (4688) kaydi yok' `
            -Evidence "Son $Days gunde hic 4688 event bulunamadi" `
            -Mitre 'T1562.002' -Artifact '11_evt_4688' `
            -Why 'Bu denetim kapaliysa gecmis calistirma faaliyeti gorunmez'
        return
    }

    $rows = foreach ($e in $evts) {
        $newProc = Get-DProp $e 5
        $cmdLine = Get-DProp $e 8
        $parent  = Get-DProp $e 13
        $baseName = if ($newProc) { (Split-Path $newProc -Leaf).ToLowerInvariant() } else { '' }

        [PSCustomObject]@{
            TimeUtc      = ConvertTo-DUtcString $e.TimeCreated
            SubjectUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            NewProcessId = Get-DProp $e 4
            NewProcess   = $newProc
            ParentProcess = $parent
            ParentPid    = Get-DProp $e 7
            CommandLine  = $cmdLine
            TokenElevation = Get-DProp $e 6
            TargetUser   = Get-DProp $e 10
            DecodedB64   = ConvertFrom-DEncodedCommand -Text $cmdLine
            IsLolBas     = ($Script:LolBasExec -contains $baseName)
            IsDiscovery  = ($Script:DiscoveryBins -contains $baseName)
            IsExfilTool  = ($Script:ExfilBins -contains $baseName)
            SuspiciousPath = Test-DSuspiciousPath -Path $newProc
        }
    }
    $rows = @($rows)
    Export-DArtifact -Name '11_evt_4688' -Data $rows -SubDir events

    # Komut satiri denetimi acik mi?
    $withCmd = @($rows | Where-Object { $_.CommandLine }).Count
    if ($withCmd -eq 0 -and $rows.Count -gt 0) {
        Add-DFinding -RuleId 'DGL-141' -Severity MEDIUM `
            -Title '4688 eventleri komut satiri icermiyor' `
            -Evidence "$($rows.Count) event var ama CommandLine alani bos" `
            -Mitre 'T1562.002' -Artifact '11_evt_4688' `
            -Why 'ProcessCreationIncludeCmdLine_Enabled kapali - hunting degeri buyuk olcude dusuk'
    }

    # --- TRIAGE ---
    $lolCount = @{}
    foreach ($r in $rows) {
        if ($r.SuspiciousPath) {
            Add-DFinding -RuleId 'DGL-142' -Severity HIGH `
                -Title 'Gecmiste supheli dizinden process calistirilmis' `
                -Evidence "$($r.TimeUtc) [$($r.SubjectUser)] $($r.NewProcess)" `
                -Mitre 'T1036' -Artifact '11_evt_4688' -Timestamp $r.TimeUtc `
                -Why 'Process artik calismiyor olabilir; event kaydi tek kanittir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Evt4688' `
                -Description "Suspicious execution: $($r.NewProcess)" `
                -Detail $r.CommandLine -Severity HIGH
        }

        Test-DEventCmdLine -CommandLine $r.CommandLine -RuleId 'DGL-143' `
            -Context "4688 $($r.TimeUtc) [$($r.SubjectUser)]" `
            -Artifact '11_evt_4688' -Timestamp $r.TimeUtc

        # Cozulmus base64 payload da taransin
        if ($r.DecodedB64) {
            Add-DFinding -RuleId 'DGL-144' -Severity HIGH `
                -Title 'Encoded PowerShell komutu cozuldu' `
                -Evidence "$($r.TimeUtc) :: $($r.DecodedB64.Substring(0, [Math]::Min(400, $r.DecodedB64.Length)))" `
                -Mitre 'T1027' -Artifact '11_evt_4688' -Timestamp $r.TimeUtc `
                -Why 'Base64 gizlenmis komutun acik hali'
            Test-DEventCmdLine -CommandLine $r.DecodedB64 -RuleId 'DGL-145' `
                -Context "4688-decoded $($r.TimeUtc)" `
                -Artifact '11_evt_4688' -Timestamp $r.TimeUtc
        }

        # Parent-child anomalisi (gecmis)
        if ($r.ParentProcess -and $r.NewProcess) {
            $pn = (Split-Path $r.ParentProcess -Leaf) -replace '\.exe$', ''
            $cn = (Split-Path $r.NewProcess -Leaf) -replace '\.exe$', ''
            foreach ($rule in $Script:BadParentChild) {
                if ($pn -match "^($($rule.Parent))$" -and $cn -match "^($($rule.Child))$") {
                    Add-DFinding -RuleId 'DGL-146' -Severity $rule.S `
                        -Title "$($rule.Name) [gecmis]" `
                        -Evidence "$($r.TimeUtc) $($r.ParentProcess) -> $($r.NewProcess) :: $($r.CommandLine)" `
                        -Mitre $rule.M -Artifact '11_evt_4688' -Timestamp $r.TimeUtc `
                        -Why 'Gecmis event kaydinda supheli ust-alt process iliskisi'
                    Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Evt4688' `
                        -Description $rule.Name -Detail "$($r.ParentProcess) -> $($r.NewProcess)" `
                        -Severity CRITICAL
                    break
                }
            }
        }

        if ($r.IsLolBas) {
            $key = (Split-Path $r.NewProcess -Leaf)
            if (-not $lolCount.ContainsKey($key)) { $lolCount[$key] = 0 }
            $lolCount[$key]++
        }
    }

    # LOLBAS ozeti
    $lolSummary = @($lolCount.GetEnumerator() | Sort-Object Value -Descending |
                    ForEach-Object { [PSCustomObject]@{ Binary = $_.Key; Count = $_.Value } })
    Export-DArtifact -Name '11_evt_4688_lolbas' -Data $lolSummary -SubDir events

    # Parent-child frekans tablosu (nadir kombinasyon = supheli)
    $pcPairs = @($rows | Where-Object { $_.ParentProcess -and $_.NewProcess } |
        Group-Object { "$(Split-Path $_.ParentProcess -Leaf) -> $(Split-Path $_.NewProcess -Leaf)" } |
        Sort-Object Count |
        ForEach-Object { [PSCustomObject]@{ Pair = $_.Name; Count = $_.Count } })
    Export-DArtifact -Name '11_evt_4688_parentchild' -Data $pcPairs -SubDir events

    Write-DLog "  $($rows.Count) x 4688 ($($lolSummary.Count) distinct LOLBAS)" -Level DEBUG
}

Register-DModule -Name 'Event: PowerShell (4104/4103/400)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Script block logging + remoting izleri' `
    -HuntTags @('LOLBin','DefenseEvasion') -Body {

    # --- 4104 Script Block Logging ---
    $sb = Get-DWinEvents -LogName 'Microsoft-Windows-PowerShell/Operational' -Id 4104
    $sbRows = foreach ($e in $sb) {
        $text = Get-DProp $e 2
        if ($text -and $text.Length -gt 4000) { $text = $text.Substring(0, 4000) + '...[KIRPILDI]' }
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            Level         = [string]$e.LevelDisplayName
            MessageNumber = Get-DProp $e 0
            MessageTotal  = Get-DProp $e 1
            ScriptBlockId = Get-DProp $e 3
            Path          = Get-DProp $e 4
            ScriptBlock   = $text
        }
    }
    # F1.5-1: KENDI GURULTUMUZU ELE. Douglas modul import ettikce (cmdletization,
    # #requires, Set-StrictMode...) 4104 uretir; bunlar bizim calisma zamanimizda
    # ve bilinen import imzalari. Koleksiyon baslangicindan SONRA olusan ve
    # modul-yukleme imzasi tasiyan bloklari isaretle.
    $selfStart = $Script:Ctx.SelfStartUtc
    $selfSig   = '(?i)cmdletization|__cmdletization_|ProcessRecord\(|Set-StrictMode\s+-Off|#requires\s+-version|MyInvocation\.MyCommand|New-Object\s+Management\.Automation'
    $selfN = 0
    $keep = New-Object System.Collections.ArrayList
    foreach ($r in $sbRows) {
        $isSelf = $false
        if ($selfStart -and $r.TimeUtc) {
            try {
                $t = ([DateTime]$r.TimeUtc).ToUniversalTime()
                if ($t -ge $selfStart.AddSeconds(-2) -and $r.ScriptBlock -match $selfSig) { $isSelf = $true }
            } catch { }
        }
        if ($isSelf) { $selfN++; $Script:SelfExcluded++ } else { $null = $keep.Add($r) }
    }
    $sbRows = @($keep)
    Export-DArtifact -Name '11_evt_ps_4104' -Data $sbRows -SubDir events
    if ($selfN -gt 0) {
        Write-DLog "  Self-noise: $selfN 4104 records belong to this collection, excluded" -Level DEBUG
    }

    foreach ($r in $sbRows) {
        # F1.5-13: PowerShell'in kendi Warning bayragina KOR guvenme. Warning +
        # gercek obfuscation gostergesi birlikte olmali; yoksa mesru modul
        # yuklemeleri de Warning uretip gurultu yapiyor.
        $obf = Test-DObfuscatedCommand -Text $r.ScriptBlock
        if ($r.Level -match '(?i)warning' -and $obf.Count -ge 1) {
            $sev = if ($obf.Count -ge 2) { 'HIGH' } else { 'MEDIUM' }
            Add-DFinding -RuleId 'DGL-150' -Severity $sev `
                -Title 'PowerShell supheli/gizlenmis script block' `
                -Evidence "$($r.TimeUtc) [$($obf -join ', ')] :: $(Format-DEvidence -Text $r.ScriptBlock -Max 1500)" `
                -Mitre 'T1059.001' -Artifact '11_evt_ps_4104' -Timestamp $r.TimeUtc `
                -Why 'PowerShell Warning bayragi + gizleme gostergesi birlikte'
        }
        Test-DEventCmdLine -CommandLine $r.ScriptBlock -RuleId 'DGL-151' `
            -Context "4104 $($r.TimeUtc)" -Artifact '11_evt_ps_4104' -Timestamp $r.TimeUtc
        # F1.5-7/13: encoded/concat coz + obfuscation isaretle (merkezi)
        $null = Invoke-DDeobfuscateAndScan -Text $r.ScriptBlock -Context "4104 $($r.TimeUtc)" `
            -Artifact '11_evt_ps_4104' -Timestamp $r.TimeUtc
    }

    # --- 400 klasik: PS Remoting girisi ---
    $classic = Get-DWinEvents -LogName 'Windows PowerShell' -Id 400, 403, 600
    $clRows = foreach ($e in $classic) {
        $detail = Get-DProp $e 2
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            EngineState = Get-DProp $e 0
            Detail  = if ($detail -and $detail.Length -gt 1000) {
                          $detail.Substring(0, 1000) } else { $detail }
            IsRemoting = [bool]($detail -match '(?i)ServerRemoteHost')
        }
    }
    $clRows = @($clRows)
    Export-DArtifact -Name '11_evt_ps_classic' -Data $clRows -SubDir events

    $remoting = @($clRows | Where-Object IsRemoting)
    foreach ($r in ($remoting | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-152' -Severity MEDIUM `
            -Title 'PowerShell Remoting oturumu tespit edildi' `
            -Evidence "$($r.TimeUtc) EventID $($r.EventId) HostName=ServerRemoteHost" `
            -Mitre 'T1021.006' -Artifact '11_evt_ps_classic' -Timestamp $r.TimeUtc `
            -Why 'Uzaktan PowerShell erisimi lateral movement gostergesi olabilir'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'PSRemoting' `
            -Description 'PowerShell Remoting oturumu' -Severity MEDIUM
    }

    Write-DLog "  $($sbRows.Count) x 4104, $($clRows.Count) classic PS ($($remoting.Count) remoting)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - OTURUM ACMA / KIMLIK DOGRULAMA
# ============================================================================

Register-DModule -Name 'Event: Logon Activity' -Phase 2 -RequiresCap 'WinEvent' `
    -Description '4624/4625/4648/4672/4776 - kim, nereden, nasil' `
    -HuntTags @('CredentialAccess') -Body {

    # --- 4624 basarili logon ---
    $ok = Get-DWinEvents -LogName 'Security' -Id 4624
    $okRows = foreach ($e in $ok) {
        $lt = Get-DProp $e 8
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            TargetUser    = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            TargetSid     = Get-DProp $e 4
            LogonType     = $lt
            LogonTypeName = Get-DLogonTypeName $lt
            LogonProcess  = Get-DProp $e 9
            AuthPackage   = Get-DProp $e 10
            Workstation   = Get-DProp $e 11
            ProcessName   = Get-DProp $e 17
            IpAddress     = Get-DProp $e 18
            IpPort        = Get-DProp $e 19
            LogonId       = Get-DProp $e 7
        }
    }
    # Makine hesaplarini ve ANONYMOUS'u ele - gurultu
    $okRows = @($okRows | Where-Object {
        $_.TargetUser -notmatch '\$$' -and $_.TargetUser -notmatch 'ANONYMOUS LOGON' -and
        $_.TargetSid -notin 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
    })
    Export-DArtifact -Name '11_evt_4624_logon' -Data $okRows -SubDir events

    # --- 4625 basarisiz logon ---
    $fail = Get-DWinEvents -LogName 'Security' -Id 4625
    $failRows = @(foreach ($e in $fail) {
        $lt = Get-DProp $e 10
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            TargetUser    = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            LogonType     = $lt
            LogonTypeName = Get-DLogonTypeName $lt
            Status        = Get-DProp $e 7
            SubStatus     = Get-DProp $e 9
            Workstation   = Get-DProp $e 13
            IpAddress     = Get-DProp $e 19
            ProcessName   = Get-DProp $e 18
        }
    })
    Export-DArtifact -Name '11_evt_4625_failed' -Data $failRows -SubDir events

    # --- 4648 explicit credential (lateral movement altin sinyali) ---
    $expl = Get-DWinEvents -LogName 'Security' -Id 4648
    $explRows = @(foreach ($e in $expl) {
        [PSCustomObject]@{
            TimeUtc      = ConvertTo-DUtcString $e.TimeCreated
            SubjectUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            TargetUser   = "$(Get-DProp $e 6)\$(Get-DProp $e 5)"
            TargetServer = Get-DProp $e 8
            ProcessName  = Get-DProp $e 11
            IpAddress    = Get-DProp $e 12
        }
    })
    Export-DArtifact -Name '11_evt_4648_explicit' -Data $explRows -SubDir events

    # --- 4672 ozel yetkiler ---
    $priv = Get-DWinEvents -LogName 'Security' -Id 4672
    $privAll = @(foreach ($e in $priv) {
        [PSCustomObject]@{
            TimeUtc    = ConvertTo-DUtcString $e.TimeCreated
            User       = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            Sid        = Get-DProp $e 0
            LogonId    = Get-DProp $e 3
        }
    })
    $privRows = @($privAll | Where-Object {
        $_.User -notmatch '\$$' -and $_.Sid -notin 'S-1-5-18', 'S-1-5-19', 'S-1-5-20'
    })
    Export-DArtifact -Name '11_evt_4672_privileged' -Data $privRows -SubDir events

    # --- TRIAGE ---

    # Type 9 = RunAs/NetOnly - pass-the-hash / overpass-the-hash klasigi
    foreach ($r in @($okRows | Where-Object LogonType -eq '9')) {
        Add-DFinding -RuleId 'DGL-160' -Severity HIGH `
            -Title 'Logon Type 9 (NewCredentials/RunAs) tespit edildi' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) via $($r.ProcessName)" `
            -Mitre 'T1550.002' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'Type 9 pass-the-hash ve overpass-the-hash saldirilarinin tipik izidir'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Logon' `
            -Description "Type9 RunAs logon: $($r.TargetUser)" -Severity HIGH
    }

    # Type 8 = NetworkCleartext - duz metin parola agdan gecti
    foreach ($r in @($okRows | Where-Object LogonType -eq '8' | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-161' -Severity MEDIUM `
            -Title 'Logon Type 8 (NetworkCleartext)' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) from $($r.IpAddress)" `
            -Mitre 'T1078' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'Parola ag uzerinden duz metin gecmis olabilir'
    }

    # RDP oturumlari (Type 10) - dis kaynakli olanlar
    foreach ($r in @($okRows | Where-Object { $_.LogonType -eq '10' -and $_.IpAddress -and
                     $_.IpAddress -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|-|::1)' })) {
        Add-DFinding -RuleId 'DGL-162' -Severity HIGH `
            -Title 'Ozel ag disindan RDP oturumu' `
            -Evidence "$($r.TimeUtc) $($r.TargetUser) <- $($r.IpAddress)" `
            -Mitre 'T1021.001' -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
            -Why 'Internete acik RDP yaygin bir initial access vektorudur'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'RDP' `
            -Description "External RDP: $($r.TargetUser) from $($r.IpAddress)" -Severity HIGH
    }

    # Brute force / password spray tespiti
    $byIp = $failRows | Where-Object { $_.IpAddress -and $_.IpAddress -notin '-', '::1', '127.0.0.1' } |
            Group-Object IpAddress | Sort-Object Count -Descending
    foreach ($g in ($byIp | Select-Object -First 10)) {
        if ($g.Count -ge 20) {
            $uniqUsers = @($g.Group | Select-Object -ExpandProperty TargetUser -Unique).Count
            $kind = if ($uniqUsers -ge 5) { 'Password spray' } else { 'Brute force' }
            Add-DFinding -RuleId 'DGL-163' -Severity HIGH `
                -Title "$kind supheli (4625 yogunlugu)" `
                -Evidence "$($g.Name) kaynagindan $($g.Count) basarisiz deneme, $uniqUsers farkli hesap" `
                -Mitre 'T1110' -Artifact '11_evt_4625_failed' `
                -Why 'Tek kaynaktan yogun kimlik dogrulama hatasi'
        }
    }

    # Basarisiz denemelerin ardindan BASARILI logon = ele gecirme
    foreach ($g in ($byIp | Select-Object -First 20)) {
        if ($g.Count -lt 10) { continue }
        $succ = @($okRows | Where-Object { $_.IpAddress -eq $g.Name })
        if ($succ.Count -gt 0) {
            Add-DFinding -RuleId 'DGL-164' -Severity CRITICAL `
                -Title 'Basarisiz denemelerden sonra BASARILI logon' `
                -Evidence "$($g.Name): $($g.Count) hata, ardindan $($succ.Count) basarili ($($succ[0].TargetUser))" `
                -Mitre 'T1110' -Artifact '11_evt_4624_logon' `
                -Why 'Brute force / spray sonrasi hesap ele gecirilmis olabilir'
        }
    }

    # 4648 - admin share hedefleri
    foreach ($r in @($explRows | Where-Object { $_.TargetServer -and
                     $_.TargetServer -notmatch '(?i)^(localhost|-)$' } | Select-Object -First 30)) {
        Add-DFinding -RuleId 'DGL-165' -Severity MEDIUM `
            -Title 'Explicit credential ile uzak sunucuya erisim' `
            -Evidence "$($r.TimeUtc) $($r.SubjectUser) -> $($r.TargetUser)@$($r.TargetServer) via $($r.ProcessName)" `
            -Mitre 'T1021' -Artifact '11_evt_4648_explicit' -Timestamp $r.TimeUtc `
            -Why '4648 lateral movementin en guvenilir gostergelerindendir'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Lateral' `
            -Description "Explicit cred: $($r.SubjectUser) -> $($r.TargetServer)" -Severity MEDIUM
    }

    # Mesai disi interaktif logon
    foreach ($r in @($okRows | Where-Object { $_.LogonType -in '2', '10' })) {
        try {
            $h = ([DateTime]$r.TimeUtc).Hour
            if ($h -ge 0 -and $h -le 5) {
                Add-DFinding -RuleId 'DGL-166' -Severity MEDIUM `
                    -Title 'Mesai disi interaktif oturum (00:00-05:00 UTC)' `
                    -Evidence "$($r.TimeUtc) $($r.TargetUser) [$($r.LogonTypeName)] from $($r.IpAddress)" `
                    -Artifact '11_evt_4624_logon' -Timestamp $r.TimeUtc `
                    -Why 'Saldirgan aktivitesi genelde normal calisma saatleri disinda gorulur'
            }
        } catch { }
    }

    Write-DLog "  4624:$($okRows.Count)  4625:$($failRows.Count)  4648:$($explRows.Count)  4672:$($privRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - HESAP YONETIMI VE POLITIKA
# ============================================================================

Register-DModule -Name 'Event: Account / Policy Changes' -Phase 2 -RequiresCap 'WinEvent' `
    -Description '4720-4756 hesap islemleri + 1102/4719 anti-forensics' -Body {

    # --- Hesap islemleri ---
    $acct = Get-DWinEvents -LogName 'Security' `
            -Id 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781
    $acctRows = @(foreach ($e in $acct) {
        [PSCustomObject]@{
            TimeUtc    = ConvertTo-DUtcString $e.TimeCreated
            EventId    = $e.Id
            Action     = switch ($e.Id) {
                4720 { 'Kullanici olusturuldu' }    4722 { 'Hesap etkinlestirildi' }
                4723 { 'Parola degistirildi' }      4724 { 'Parola sifirlandi' }
                4725 { 'Hesap devre disi' }         4726 { 'Kullanici silindi' }
                4738 { 'Hesap degistirildi' }       4740 { 'Hesap kilitlendi' }
                4767 { 'Hesap kilidi acildi' }      4781 { 'Hesap adi degistirildi' }
                default { "ID$($e.Id)" }
            }
            TargetUser = Get-DProp $e 0
            TargetSid  = Get-DProp $e 2
            ByUser     = "$(Get-DProp $e 5)\$(Get-DProp $e 4)"
        }
    })
    Export-DArtifact -Name '11_evt_account_mgmt' -Data $acctRows -SubDir events

    foreach ($r in $acctRows) {
        $sev = switch ($r.EventId) {
            4720 { 'HIGH' }  4726 { 'HIGH' }  4724 { 'HIGH' }
            4722 { 'MEDIUM' } 4781 { 'MEDIUM' } default { 'LOW' }
        }
        # F1.5-2: 4781 (yerlesik grup/hesap adi yerellestirme) kurulumda SYSTEM
        # tarafindan yigilir. Machine-account ($) veya SYSTEM tarafindan yapilan
        # rename'leri kurulum penceresinde INFO'ya cek.
        if ($r.EventId -eq 4781 -and ($r.ByUser -match '\$$|S-1-5-18')) {
            $sev = Get-DEffectiveSeverity $sev -Timestamp $r.TimeUtc -TimeBased
        }
        if ($sev -in 'HIGH', 'MEDIUM') {
            Add-DFinding -RuleId 'DGL-170' -Severity $sev -Title $r.Action `
                -Evidence "$($r.TimeUtc) hedef: $($r.TargetUser) | islemi yapan: $($r.ByUser)" `
                -Mitre 'T1136.001' -Artifact '11_evt_account_mgmt' -Timestamp $r.TimeUtc `
                -Why 'Hesap olusturma, silme ve parola sifirlama saldirgan kaliciliginin en yaygin izleridir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'AccountMgmt' `
                -Description "$($r.Action): $($r.TargetUser)" -Detail "by $($r.ByUser)" -Severity $sev
        }
    }

    # --- Grup uyelik degisimleri ---
    $grp = Get-DWinEvents -LogName 'Security' -Id 4728, 4732, 4756, 4729, 4733, 4757
    $grpRows = @(foreach ($e in $grp) {
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            EventId   = $e.Id
            Action    = if ($e.Id -in 4728, 4732, 4756) { 'Gruba EKLENDI' } else { 'Gruptan cikarildi' }
            Member    = Get-DProp $e 0
            MemberSid = Get-DProp $e 1
            Group     = Get-DProp $e 2
            ByUser    = "$(Get-DProp $e 7)\$(Get-DProp $e 6)"
        }
    })
    Export-DArtifact -Name '11_evt_group_mgmt' -Data $grpRows -SubDir events

    $privGroups = 'Domain Admins|Enterprise Admins|Schema Admins|Administrators|Yoneticiler|' +
                  'Account Operators|Backup Operators|Server Operators|Print Operators|' +
                  'DnsAdmins|Group Policy Creator Owners|Remote Desktop Users'
    foreach ($r in $grpRows) {
        if ($r.EventId -in 4728, 4732, 4756) {
            $sev = if ($r.Group -match "(?i)($privGroups)") { 'CRITICAL' } else { 'MEDIUM' }
            Add-DFinding -RuleId 'DGL-171' -Severity $sev `
                -Title 'Ayricalikli gruba uye eklendi' `
                -Evidence "$($r.TimeUtc) $($r.Member) -> $($r.Group) | ekleyen: $($r.ByUser)" `
                -Mitre 'T1098' -Artifact '11_evt_group_mgmt' -Timestamp $r.TimeUtc `
                -Why 'Grup uyeligi degisimi yetki yukseltme ve kalicilik gostergesidir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'GroupMgmt' `
                -Description "Added to group: $($r.Member) -> $($r.Group)" -Severity $sev
        }
    }

    # --- ANTI-FORENSICS: log temizleme ve denetim politikasi degisimi ---
    $af = Get-DWinEvents -LogName 'Security' -Id 1102, 4719, 4616
    $afRows = @(foreach ($e in $af) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                1102 { 'SECURITY LOG TEMIZLENDI' }
                4719 { 'Denetim politikasi degistirildi' }
                4616 { 'Sistem saati degistirildi' }
            }
            User    = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
        }
    })
    Export-DArtifact -Name '11_evt_antiforensics' -Data $afRows -SubDir events

    foreach ($r in $afRows) {
        $sev = if ($r.EventId -eq 1102) { 'CRITICAL' } else { 'HIGH' }
        Add-DFinding -RuleId 'DGL-172' -Severity $sev -Title $r.Action `
            -Evidence "$($r.TimeUtc) | $($r.User)" `
            -Mitre 'T1070.001' -Artifact '11_evt_antiforensics' -Timestamp $r.TimeUtc `
            -Why 'Iz temizleme faaliyeti - saldirinin aktif oldugunun gostergesi'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'AntiForensics' `
            -Description $r.Action -Detail $r.User -Severity CRITICAL
    }

    # --- Servis kurulumu (Security tarafi) + gorev islemleri ---
    $svcEvt = Get-DWinEvents -LogName 'Security' -Id 4697
    $svcRows = @(foreach ($e in $svcEvt) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            ServiceName = Get-DProp $e 4
            ServiceFile = Get-DProp $e 5
            StartType   = Get-DProp $e 7
            Account     = Get-DProp $e 8
            ByUser      = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
        }
    })
    Export-DArtifact -Name '11_evt_4697_service' -Data $svcRows -SubDir events

    foreach ($r in $svcRows) {
        Add-DFinding -RuleId 'DGL-173' -Severity HIGH `
            -Title 'Servis kurulumu kaydi (4697)' `
            -Evidence "$($r.TimeUtc) $($r.ServiceName) -> $($r.ServiceFile) [$($r.ByUser)]" `
            -Mitre 'T1543.003' -Artifact '11_evt_4697_service' -Timestamp $r.TimeUtc `
            -Why 'Servis kurulumu uzaktan calistirma ve kalicilik icin kullanilir'
        Test-DEventCmdLine -CommandLine $r.ServiceFile -RuleId 'DGL-174' `
            -Context "4697 $($r.ServiceName)" -Artifact '11_evt_4697_service' -Timestamp $r.TimeUtc
    }

    $taskEvt = Get-DWinEvents -LogName 'Security' -Id 4698, 4699, 4700, 4702
    $taskRows = @(foreach ($e in $taskEvt) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                4698 { 'Gorev olusturuldu' } 4699 { 'Gorev silindi' }
                4700 { 'Gorev etkinlestirildi' } 4702 { 'Gorev guncellendi' }
            }
            ByUser  = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
            TaskName = Get-DProp $e 4
        }
    })
    Export-DArtifact -Name '11_evt_task_mgmt' -Data $taskRows -SubDir events

    foreach ($r in $taskRows) {
        if ($r.EventId -in 4698, 4702) {
            Add-DFinding -RuleId 'DGL-175' -Severity HIGH -Title $r.Action `
                -Evidence "$($r.TimeUtc) $($r.TaskName) [$($r.ByUser)]" `
                -Mitre 'T1053.005' -Artifact '11_evt_task_mgmt' -Timestamp $r.TimeUtc `
                -Why 'Gorev olusturma ve guncelleme kaydi kalicilik kurulumunu tarihlendirir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'TaskMgmt' `
                -Description "$($r.Action): $($r.TaskName)" -Severity HIGH
        }
    }

    Write-DLog "  account:$($acctRows.Count) group:$($grpRows.Count) antiforensic:$($afRows.Count) service:$($svcRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - SYSTEM (SERVIS / SURUCU / LOG)
# ============================================================================

Register-DModule -Name 'Event: System (7045/7040/104)' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Servis kurulumu, baslangic tipi degisimi, log temizleme' -Body {

    $sys = Get-DWinEvents -LogName 'System' -Id 7045, 7034, 7040, 104, 6008, 1074, 20001

    $rows = @(foreach ($e in $sys) {
        $o = [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Provider = $e.ProviderName
            F0 = Get-DProp $e 0; F1 = Get-DProp $e 1
            F2 = Get-DProp $e 2; F3 = Get-DProp $e 3; F4 = Get-DProp $e 4
        }
        $o
    })

    # 7045: [0]ServiceName [1]ImagePath [2]ServiceType [3]StartType [4]AccountName
    $newSvc = @($rows | Where-Object EventId -eq 7045 | ForEach-Object {
        [PSCustomObject]@{
            TimeUtc     = $_.TimeUtc
            ServiceName = $_.F0
            ImagePath   = $_.F1
            ServiceType = $_.F2
            StartType   = $_.F3
            Account     = $_.F4
            SuspiciousPath = Test-DSuspiciousPath -Path (Get-DCleanPath -CommandLine $_.F1)
        }
    })
    Export-DArtifact -Name '11_evt_7045_newservice' -Data $newSvc -SubDir events

    foreach ($s in $newSvc) {
        $binClean = Get-DCleanPath -CommandLine $s.ImagePath
        $bSig     = Get-DSignature -Path $binClean
        # F1.5-8: severity artik korele. Sadece "yeni servis" HIGH degil MEDIUM;
        # supheli yol VEYA imzasiz binary varsa yukselir. Kurulum penceresinde INFO.
        $sev = 'MEDIUM'
        if ($s.SuspiciousPath) { $sev = 'CRITICAL' }
        elseif (-not $bSig.IsValid -and -not $bSig.IsMicrosoft -and
                $bSig.Status -notin 'FileNotFound','NoPath') { $sev = 'HIGH' }
        $sev = Get-DEffectiveSeverity $sev -Timestamp $s.TimeUtc -TimeBased
        Add-DFinding -RuleId 'DGL-180' -Severity $sev `
            -Title 'Yeni servis kuruldu (7045)' `
            -Evidence "$($s.TimeUtc) $($s.ServiceName) -> $($s.ImagePath) [$($s.Account)]" `
            -Mitre 'T1543.003' -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc `
            -Why 'PsExec, Impacket ve Cobalt Strike SMB beaconi servis olarak kurulur'
        Add-DTimelineEvent -Timestamp $s.TimeUtc -Source 'Service' `
            -Description "New service: $($s.ServiceName)" -Detail $s.ImagePath -Severity $sev

        # F1.5-8: rastgele ad TEK BASINA CRITICAL degil - VBoxWddm gibi mesru
        # surucu adlari yanlis atesliyordu. Korele et: imzasiz/supheli yol sart.
        if (Test-DRandomName -Name $s.ServiceName) {
            $corroborated = ($s.SuspiciousPath -or
                             (-not $bSig.IsValid -and -not $bSig.IsMicrosoft -and
                              $bSig.Status -notin 'FileNotFound','NoPath'))
            $rsev = if ($corroborated) { 'CRITICAL' } else { 'LOW' }
            $rwhy = if ($corroborated) {
                        'Rastgele ad + imzasiz/supheli yol = C2 cerceve imzasi'
                    } else {
                        'Rastgele gorunumlu ad; ancak binary imzali/mesru dizinde - dusuk oncelik'
                    }
            Add-DFinding -RuleId 'DGL-181' -Severity $rsev `
                -Title 'Rastgele isimli servis kurulmus' `
                -Evidence "$($s.TimeUtc) $($s.ServiceName) -> $($s.ImagePath) [imza: $($bSig.Status)]" `
                -Mitre 'T1569.002' -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc `
                -Why $rwhy
        }
        # F1.5-12: servis binary'si sistem adini maskeliyor mu
        $bName = if ($binClean) { Split-Path $binClean -Leaf } else { $null }
        $mq = Test-DMasqueradedName -Name $bName -FullPath $binClean
        if ($mq) {
            Add-DFinding -RuleId 'DGL-186' -Severity CRITICAL `
                -Title 'Yeni servis sistem binary maskeliyor' `
                -Evidence "$($s.ServiceName) -> $binClean :: $($mq.Reason)" `
                -Mitre 'T1036.005' -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc `
                -Why "Beklenen: $($mq.Expected)"
        }
        Test-DEventCmdLine -CommandLine $s.ImagePath -RuleId 'DGL-182' `
            -Context "7045 $($s.ServiceName)" `
            -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc
        # F1.5-7: servis ImagePath'inde gizli komut
        $null = Invoke-DDeobfuscateAndScan -Text $s.ImagePath -Context "7045 $($s.ServiceName)" `
            -Artifact '11_evt_7045_newservice' -Timestamp $s.TimeUtc
    }

    # 7040: baslangic tipi degisimi (savunma kapatma)
    $startChg = @($rows | Where-Object EventId -eq 7040)
    Export-DArtifact -Name '11_evt_7040_starttype' -Data $startChg -SubDir events
    foreach ($c in $startChg) {
        if ($c.F0 -match '(?i)(defender|windefend|wuauserv|eventlog|mpssvc|sense|wscsvc|sppsvc|bits)') {
            Add-DFinding -RuleId 'DGL-183' -Severity CRITICAL `
                -Title 'Guvenlik servisinin baslangic tipi degistirildi' `
                -Evidence "$($c.TimeUtc) $($c.F0) : $($c.F1) -> $($c.F2)" `
                -Mitre 'T1562.001' -Artifact '11_evt_7040_starttype' -Timestamp $c.TimeUtc `
                -Why 'Savunma mekanizmasi devre disi birakilmis olabilir'
        }
    }

    # 7034: beklenmedik sonlanma (EDR kill)
    $crashed = @($rows | Where-Object EventId -eq 7034)
    foreach ($c in $crashed) {
        if ($c.F0 -match '(?i)(defender|windefend|eventlog|mpssvc|sense|sysmon|wscsvc)') {
            Add-DFinding -RuleId 'DGL-184' -Severity CRITICAL `
                -Title 'Guvenlik servisi beklenmedik sekilde sonlandi' `
                -Evidence "$($c.TimeUtc) $($c.F0)" `
                -Mitre 'T1562.001' -Artifact '11_evt_system' -Timestamp $c.TimeUtc `
                -Why 'Guvenlik servisinin durmasi ya saldiri ya da telemetri kaybidir; her iki durumda kapsam daralir'
        }
    }

    # 104: log temizleme
    foreach ($c in @($rows | Where-Object EventId -eq 104)) {
        Add-DFinding -RuleId 'DGL-185' -Severity CRITICAL `
            -Title 'Event log temizlendi (System 104)' `
            -Evidence "$($c.TimeUtc) kanal: $($c.F2) | kullanici: $($c.F1)" `
            -Mitre 'T1070.001' -Artifact '11_evt_system' -Timestamp $c.TimeUtc `
            -Why 'Iz temizleme faaliyeti'
        Add-DTimelineEvent -Timestamp $c.TimeUtc -Source 'AntiForensics' `
            -Description "Log cleared: $($c.F2)" -Severity CRITICAL
    }

    Export-DArtifact -Name '11_evt_system' -Data $rows -SubDir events
    Write-DLog "  $($rows.Count) System events ($($newSvc.Count) new services)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - RDP VE WINRM
# ============================================================================

Register-DModule -Name 'Event: RDP / WinRM' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Gelen ve GIDEN RDP + uzaktan yonetim' -Body {

    # --- 1149: basarili RDP ag baglantisi (kullanici + kaynak IP) ---
    $rcm = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -Id 1149
    $rcmRows = @(foreach ($e in $rcm) {
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            User      = Get-DProp $e 0
            Domain    = Get-DProp $e 1
            SourceIP  = Get-DProp $e 2
        }
    })
    Export-DArtifact -Name '11_evt_rdp_inbound' -Data $rcmRows -SubDir events

    foreach ($r in $rcmRows) {
        if ($r.SourceIP -and $r.SourceIP -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1)') {
            Add-DFinding -RuleId 'DGL-190' -Severity HIGH `
                -Title 'Ozel ag disindan RDP baglantisi (1149)' `
                -Evidence "$($r.TimeUtc) $($r.Domain)\$($r.User) <- $($r.SourceIP)" `
                -Mitre 'T1021.001' -Artifact '11_evt_rdp_inbound' -Timestamp $r.TimeUtc `
                -Why 'Internete acik RDP en yaygin ilk erisim vektorlerinden biridir'
        }
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'RDP-In' `
            -Description "RDP logon: $($r.User)" -Detail $r.SourceIP -Severity MEDIUM
    }

    # --- 21/22/23/24/25: yerel oturum yonetimi ---
    $lsm = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' `
           -Id 21, 22, 23, 24, 25
    $lsmRows = @(foreach ($e in $lsm) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Action  = switch ($e.Id) {
                21 { 'Oturum acildi' }   22 { 'Shell baslatildi' }  23 { 'Oturum kapandi' }
                24 { 'Baglanti kesildi' } 25 { 'Yeniden baglandi' }
            }
            User      = Get-DProp $e 0
            SessionId = Get-DProp $e 1
            SourceIP  = Get-DProp $e 2
        }
    })
    Export-DArtifact -Name '11_evt_rdp_sessions' -Data $lsmRows -SubDir events

    # --- 1024/1102: BU HOSTTAN DISARI RDP - lateral movement kaynagi ---
    $rdpc = Get-DWinEvents -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -Id 1024, 1102
    $rdpcRows = @(foreach ($e in $rdpc) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Target  = Get-DProp $e 0
        }
    })
    Export-DArtifact -Name '11_evt_rdp_outbound' -Data $rdpcRows -SubDir events

    $targets = @($rdpcRows | Where-Object Target | Group-Object Target)
    foreach ($t in $targets) {
        Add-DFinding -RuleId 'DGL-191' -Severity HIGH `
            -Title 'Bu hosttan DISARI RDP baglantisi' `
            -Evidence "Hedef: $($t.Name) ($($t.Count) kez)" `
            -Mitre 'T1021.001' -Artifact '11_evt_rdp_outbound' `
            -Why 'Giden RDP, bu hostun lateral movement kaynagi oldugunu gosterir'
        Add-DTimelineEvent -Timestamp $t.Group[0].TimeUtc -Source 'RDP-Out' `
            -Description "Giden RDP: $($t.Name)" -Severity HIGH
    }

    # --- WinRM ---
    $wrm = Get-DWinEvents -LogName 'Microsoft-Windows-WinRM/Operational' -Id 6, 91, 168, 169
    $wrmRows = @(foreach ($e in $wrm) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = (Get-DProp $e 0)
            Extra   = (Get-DProp $e 1)
        }
    })
    Export-DArtifact -Name '11_evt_winrm' -Data $wrmRows -SubDir events

    $auth = @($wrmRows | Where-Object EventId -eq 169)
    foreach ($a in ($auth | Select-Object -First 20)) {
        Add-DFinding -RuleId 'DGL-192' -Severity MEDIUM `
            -Title 'WinRM kimlik dogrulamasi' `
            -Evidence "$($a.TimeUtc) $($a.Detail) $($a.Extra)" `
            -Mitre 'T1021.006' -Artifact '11_evt_winrm' -Timestamp $a.TimeUtc `
            -Why 'Uzaktan yonetim erisimi lateral movement icin kullanilabilir'
    }

    Write-DLog "  RDP-in:$($rcmRows.Count) sessions:$($lsmRows.Count) RDP-out:$($rdpcRows.Count) WinRM:$($wrmRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - GOREV / WMI / DEFENDER / BITS / CODEINTEGRITY / FIREWALL
# ============================================================================

Register-DModule -Name 'Event: Persistence and Defense Channels' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'TaskScheduler, WMI-Activity, Defender, BITS, CodeIntegrity, Firewall' `
    -HuntTags @('Persistence','DefenseEvasion') -Body {

    # --- Task Scheduler ---
    $ts = Get-DWinEvents -LogName 'Microsoft-Windows-TaskScheduler/Operational' -Id 106, 140, 141, 200
    $tsRows = @(foreach ($e in $ts) {
        [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Action   = switch ($e.Id) {
                106 { 'Gorev kaydedildi' } 140 { 'Gorev guncellendi' }
                141 { 'Gorev silindi' }    200 { 'Gorev eylemi basladi' }
            }
            TaskName = Get-DProp $e 0
            User     = Get-DProp $e 1
        }
    })
    Export-DArtifact -Name '11_evt_taskscheduler' -Data $tsRows -SubDir events

    foreach ($r in @($tsRows | Where-Object EventId -in 106, 140)) {
        Add-DFinding -RuleId 'DGL-200' -Severity HIGH -Title $r.Action `
            -Evidence "$($r.TimeUtc) $($r.TaskName) [$($r.User)]" `
            -Mitre 'T1053.005' -Artifact '11_evt_taskscheduler' -Timestamp $r.TimeUtc `
            -Why 'Gorev kaydi ve calistirma olaylari kalicilik zaman cizelgesini kurar'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'TaskScheduler' `
            -Description "$($r.Action): $($r.TaskName)" -Severity HIGH
    }

    # --- WMI Activity: 5861 = kalici event aboneligi ---
    $wmiEvt = Get-DWinEvents -LogName 'Microsoft-Windows-WMI-Activity/Operational' -Id 5857, 5858, 5860, 5861
    $wmiRows = @(foreach ($e in $wmiEvt) {
        $msg = $null
        # Dusuk hacimli kanal - burada Message kullanmak guvenli
        if ($e.Id -in 5860, 5861) {
            try { $msg = $e.Message } catch { }
            if ($msg -and $msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) }
        }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
        }
    })
    Export-DArtifact -Name '11_evt_wmi_activity' -Data $wmiRows -SubDir events

    foreach ($r in @($wmiRows | Where-Object EventId -eq 5861)) {
        Add-DFinding -RuleId 'DGL-201' -Severity CRITICAL `
            -Title 'WMI kalici event aboneligi kaydi (5861)' `
            -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
            -Mitre 'T1546.003' -Artifact '11_evt_wmi_activity' -Timestamp $r.TimeUtc `
            -Why '5861 dogrudan WMI kaliciliginin kanitidir'
        Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'WMI' `
            -Description 'WMI kalici abonelik olusturuldu' -Severity CRITICAL
    }

    # --- Defender ---
    $def = Get-DWinEvents -LogName 'Microsoft-Windows-Windows Defender/Operational' `
           -Id 1006, 1007, 1008, 1009, 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012
    $defRows = @(foreach ($e in $def) {
        $msg = $null
        try { $msg = $e.Message } catch { }
        if ($msg) { $msg = ($msg -replace '\s+', ' ').Trim() }
        if ($msg -and $msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
        }
    })
    Export-DArtifact -Name '11_evt_defender' -Data $defRows -SubDir events

    foreach ($r in $defRows) {
        $info = switch ($r.EventId) {
            1116 { @{ S = 'HIGH';     T = 'Defender zararli tespit etti' } }
            1117 { @{ S = 'HIGH';     T = 'Defender aksiyon aldi' } }
            1118 { @{ S = 'CRITICAL'; T = 'Defender temizleme BASARISIZ' } }
            1119 { @{ S = 'CRITICAL'; T = 'Defender kritik temizleme hatasi' } }
            5001 { @{ S = 'CRITICAL'; T = 'Real-time koruma DEVRE DISI birakildi' } }
            5007 { @{ S = 'HIGH';     T = 'Defender yapilandirmasi degistirildi (exclusion?)' } }
            5010 { @{ S = 'CRITICAL'; T = 'Zararli yazilim taramasi devre disi' } }
            5012 { @{ S = 'CRITICAL'; T = 'Virus taramasi devre disi' } }
            default { $null }
        }
        if ($info) {
            Add-DFinding -RuleId 'DGL-202' -Severity $info.S -Title $info.T `
                -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
                -Mitre 'T1562.001' -Artifact '11_evt_defender' -Timestamp $r.TimeUtc `
                -Why 'Koruma bileseninin kapanmasi payload calistirmadan hemen once yapilir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Defender' `
                -Description $info.T -Detail $r.Detail -Severity $info.S
        }
    }

    # --- BITS: URL iceren indirme kayitlari ---
    $bitsEvt = Get-DWinEvents -LogName 'Microsoft-Windows-Bits-Client/Operational' -Id 3, 59, 60, 61
    $bitsRows = @(foreach ($e in $bitsEvt) {
        $msg = $null
        try { $msg = ($e.Message -replace '\s+', ' ').Trim() } catch { }
        if ($msg -and $msg.Length -gt 1000) { $msg = $msg.Substring(0, 1000) }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = $msg
            Url     = if ($msg -match '(https?://[^\s,;]+)') { $Matches[1] } else { $null }
        }
    })
    Export-DArtifact -Name '11_evt_bits' -Data $bitsRows -SubDir events

    foreach ($r in @($bitsRows | Where-Object Url)) {
        $null = Test-DIoc -Value $r.Url -Context 'BITS transfer' -Artifact '11_evt_bits'
        Add-DFinding -RuleId 'DGL-203' -Severity MEDIUM `
            -Title 'BITS uzerinden dosya transferi' `
            -Evidence "$($r.TimeUtc) $($r.Url)" `
            -Mitre 'T1197' -Artifact '11_evt_bits' -Timestamp $r.TimeUtc `
            -Why 'BITS AV/EDR gozunden kacan yaygin bir indirme kanalidir'
    }

    # --- CodeIntegrity: imzasiz surucu bloklandi (BYOVD denemesi) ---
    $ci = Get-DWinEvents -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -Id 3033, 3077, 3001, 3002
    $ciRows = @(foreach ($e in $ci) {
        $msg = $null
        try { $msg = ($e.Message -replace '\s+', ' ').Trim() } catch { }
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = if ($msg -and $msg.Length -gt 800) { $msg.Substring(0, 800) } else { $msg }
        }
    })
    Export-DArtifact -Name '11_evt_codeintegrity' -Data $ciRows -SubDir events

    foreach ($r in $ciRows) {
        Add-DFinding -RuleId 'DGL-204' -Severity HIGH `
            -Title 'Kod butunlugu ihlali (imzasiz surucu/imaj)' `
            -Evidence "$($r.TimeUtc) ID$($r.EventId) :: $($r.Detail)" `
            -Mitre 'T1068' -Artifact '11_evt_codeintegrity' -Timestamp $r.TimeUtc `
            -Why 'BYOVD saldiri denemesinin izi olabilir'
    }

    # --- Firewall kural degisimleri ---
    $fw = Get-DWinEvents -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' `
          -Id 2004, 2005, 2006, 2033
    $fwRows = @(foreach ($e in $fw) {
        [PSCustomObject]@{
            TimeUtc  = ConvertTo-DUtcString $e.TimeCreated
            EventId  = $e.Id
            Action   = switch ($e.Id) {
                2004 { 'Kural eklendi' } 2005 { 'Kural degistirildi' }
                2006 { 'Kural silindi' } 2033 { 'TUM KURALLAR SILINDI' }
            }
            RuleName = Get-DProp $e 1
            AppPath  = Get-DProp $e 3
            Port     = Get-DProp $e 8
        }
    })
    Export-DArtifact -Name '11_evt_firewall' -Data $fwRows -SubDir events

    foreach ($r in $fwRows) {
        $sev = if ($r.EventId -eq 2033) { 'CRITICAL' }
               elseif ($r.EventId -eq 2004) { 'MEDIUM' } else { 'LOW' }
        # F1.5-2: "kural eklendi" kurulum penceresinde AppX'ten yigilir (106 gurultu).
        # Kural SILME (2033) her zaman kritik kalir - o zamana bagli degil.
        if ($r.EventId -ne 2033) {
            $sev = Get-DEffectiveSeverity $sev -Timestamp $r.TimeUtc -TimeBased
        }
        if ($sev -in 'CRITICAL', 'MEDIUM') {
            Add-DFinding -RuleId 'DGL-205' -Severity $sev -Title "Firewall: $($r.Action)" `
                -Evidence "$($r.TimeUtc) $($r.RuleName) | $($r.AppPath) | port $($r.Port)" `
                -Mitre 'T1562.004' -Artifact '11_evt_firewall' -Timestamp $r.TimeUtc `
                -Why 'Firewall kurali degisiklikleri gelen C2 ve lateral movement icin yol acar'
        }
    }

    Write-DLog "  task:$($tsRows.Count) wmi:$($wmiRows.Count) defender:$($defRows.Count) bits:$($bitsRows.Count) fw:$($fwRows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - SYSMON (kuruluysa)
# ============================================================================

Register-DModule -Name 'Event: Sysmon' -Phase 2 -RequiresCap 'WinEvent' `
    -Description 'Process, ag, pipe, LSASS erisimi, WMI - en zengin telemetri' `
    -HuntTags @('Beacon','CredentialAccess','Persistence') -Body {

    if (-not $Script:Caps.Sysmon) {
        Write-DLog '  No Sysmon channel, skipped' -Level DEBUG
        return
    }

    $ch = 'Microsoft-Windows-Sysmon/Operational'

    # --- Event 10: LSASS'a handle acma = credential dump ---
    $pa = Get-DWinEvents -LogName $ch -Id 10 -Max 20000
    $paRows = @(foreach ($e in $pa) {
        # Sysmon 13+ RuleName ile basliyor, eski surumler baslamiyor
        $off = if ($e.Properties.Count -ge 11) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc       = ConvertTo-DUtcString $e.TimeCreated
            SourceImage   = Get-DProp $e (4 + $off)
            TargetImage   = Get-DProp $e (7 + $off)
            GrantedAccess = Get-DProp $e (8 + $off)
            CallTrace     = Get-DProp $e (9 + $off)
        }
    })
    $lsassAccess = @($paRows | Where-Object { $_.TargetImage -match '(?i)lsass\.exe' })
    Export-DArtifact -Name '11_sysmon_10_lsass' -Data $lsassAccess -SubDir events

    foreach ($r in $lsassAccess) {
        # 0x1010 / 0x1410 / 0x143a = bellek okuma haklari
        if ($r.GrantedAccess -match '(?i)0x(1010|1410|143a|1438|1fffff)') {
            Add-DFinding -RuleId 'DGL-210' -Severity CRITICAL `
                -Title 'LSASS bellegine erisim (credential dump)' `
                -Evidence "$($r.TimeUtc) $($r.SourceImage) -> lsass.exe [$($r.GrantedAccess)]" `
                -Mitre 'T1003.001' -Artifact '11_sysmon_10_lsass' -Timestamp $r.TimeUtc `
                -Why 'Bu erisim maskesi LSASS bellegini okumak icin kullanilir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'Sysmon10' `
                -Description 'LSASS erisimi' -Detail $r.SourceImage -Severity CRITICAL
        }
    }

    # --- Event 8: CreateRemoteThread = injection ---
    $crt = Get-DWinEvents -LogName $ch -Id 8 -Max 10000
    $crtRows = @(foreach ($e in $crt) {
        $off = if ($e.Properties.Count -ge 12) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            SourceImage = Get-DProp $e (3 + $off)
            TargetImage = Get-DProp $e (6 + $off)
            StartModule = Get-DProp $e (8 + $off)
            StartFunction = Get-DProp $e (9 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_08_injection' -Data $crtRows -SubDir events
    foreach ($r in ($crtRows | Select-Object -First 50)) {
        Add-DFinding -RuleId 'DGL-211' -Severity HIGH `
            -Title 'CreateRemoteThread (process injection)' `
            -Evidence "$($r.TimeUtc) $($r.SourceImage) -> $($r.TargetImage)" `
            -Mitre 'T1055' -Artifact '11_sysmon_08_injection' -Timestamp $r.TimeUtc `
            -Why 'Process injection tespit kacirma ve mesru process icinde calisma icin kullanilir'
    }

    # --- Event 17/18: named pipe ---
    $pipes = Get-DWinEvents -LogName $ch -Id 17, 18 -Max 20000
    $pipeRows = @(foreach ($e in $pipes) {
        $off = if ($e.Properties.Count -ge 8) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc   = ConvertTo-DUtcString $e.TimeCreated
            EventId   = $e.Id
            PipeName  = Get-DProp $e (4 + $off)
            Image     = Get-DProp $e (5 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_17_pipes' -Data $pipeRows -SubDir events
    foreach ($r in $pipeRows) {
        if (-not $r.PipeName) { continue }
        foreach ($pat in $Script:BadPipePatterns) {
            if ($r.PipeName -match $pat) {
                Add-DFinding -RuleId 'DGL-212' -Severity HIGH `
                    -Title 'C2 patterni ile eslesen named pipe olusturuldu' `
                    -Evidence "$($r.TimeUtc) $($r.PipeName) <- $($r.Image)" `
                    -Mitre 'T1071' -Artifact '11_sysmon_17_pipes' -Timestamp $r.TimeUtc `
                    -Why 'Cobalt Strike ve benzeri cerceveler varsayilan pipe adlariyla haberlesir'
                break
            }
        }
    }

    # --- Event 3: ag baglantilari (F1.5: beaconing tespiti icin GECMIS baglanti) ---
    # Anlik Get-NetTCPConnection periyodik C2'yi kacirir; Sysmon 3 gecmis TUM
    # baglantilari tutar. Hedef IP basina check-in araliklarindan jitter hesapla.
    $net3 = Get-DWinEvents -LogName $ch -Id 3 -Max 50000
    $net3Rows = @(foreach ($e in $net3) {
        $off = if ($e.Properties.Count -ge 17) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            Image       = Get-DProp $e (3 + $off)
            SrcIp       = Get-DProp $e (8 + $off)
            DstIp       = Get-DProp $e (13 + $off)
            DstPort     = Get-DProp $e (15 + $off)
            DstHost     = Get-DProp $e (16 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_3_network' -Data $net3Rows -SubDir events

    # beaconing: (Image + DstIp) basina zaman serisi, ardisik aralik jitter'i
    $priv = '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1$|fe80:)'
    $groups = $net3Rows | Where-Object { $_.DstIp -and $_.DstIp -notmatch $priv } |
              Group-Object { "$($_.Image)|$($_.DstIp):$($_.DstPort)" }
    foreach ($g in $groups) {
        if ($g.Count -lt 6) { continue }   # anlamli desen icin en az 6 check-in
        $times = @($g.Group | ForEach-Object {
            try { ([DateTime]$_.TimeUtc).ToUniversalTime() } catch { }
        } | Where-Object { $_ } | Sort-Object)
        if ($times.Count -lt 6) { continue }
        $deltas = for ($i = 1; $i -lt $times.Count; $i++) {
            ($times[$i] - $times[$i-1]).TotalSeconds
        }
        $deltas = @($deltas | Where-Object { $_ -gt 0 })
        if ($deltas.Count -lt 5) { continue }
        $mean = ($deltas | Measure-Object -Average).Average
        if ($mean -le 0 -or $mean -gt 86400) { continue }
        $var  = ($deltas | ForEach-Object { [math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum / $deltas.Count
        $std  = [math]::Sqrt($var)
        $jitterPct = if ($mean -gt 0) { [math]::Round(($std / $mean) * 100, 1) } else { 100 }
        # Duzenli aralik (dusuk jitter) = otomatik beacon. Insan trafigi duzensizdir.
        if ($jitterPct -le 30) {
            $parts = $g.Name -split '\|'
            $img = $parts[0]; $dst = $parts[1]
            $sev = if ($jitterPct -le 15) { 'CRITICAL' } else { 'HIGH' }
            Add-DFinding -RuleId 'DGL-058' -Severity $sev `
                -Title 'Duzenli aralikli dis baglanti (beaconing supheli)' `
                -Evidence "$img -> $dst : $($g.Count) check-in, ort $([math]::Round($mean,1))sn, jitter %$jitterPct" `
                -Mitre 'T1071' -Artifact '11_sysmon_3_network' -Timestamp $times[0].ToString('o') `
                -Why 'Sabit araliklarla tekrar eden dis baglanti otomatik C2 beacon imzasidir; insan trafigi duzensizdir'
            Add-DTimelineEvent -Timestamp $times[0].ToString('o') -Source 'Beacon' `
                -Description "Beaconing: $(Split-Path $img -Leaf) -> $dst" `
                -Detail "jitter %$jitterPct, $($g.Count) baglanti" -Severity $sev
        }
        # hedef IOC eslemesi
        $null = Test-DIoc -Value ($g.Name -split '\|')[1].Split(':')[0] -Context $g.Name -Artifact '11_sysmon_3_network'
    }

    # --- Event 22: DNS sorgulari ---
    $dnsq = Get-DWinEvents -LogName $ch -Id 22 -Max 20000
    $dnsRows = @(foreach ($e in $dnsq) {
        $off = if ($e.Properties.Count -ge 8) { 1 } else { 0 }
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            QueryName   = Get-DProp $e (3 + $off)
            QueryResults = Get-DProp $e (5 + $off)
            Image       = Get-DProp $e (6 + $off)
        }
    })
    Export-DArtifact -Name '11_sysmon_22_dns' -Data $dnsRows -SubDir events
    foreach ($r in $dnsRows) {
        if ($r.QueryName) {
            $null = Test-DIoc -Value $r.QueryName -Context "DNS by $($r.Image)" `
                    -Artifact '11_sysmon_22_dns'
        }
    }

    # --- Event 25: process tampering (hollowing / herpaderping) ---
    $tamper = Get-DWinEvents -LogName $ch -Id 25 -Max 5000
    $tamperRows = @(foreach ($e in $tamper) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            Detail  = try { ($e.Message -replace '\s+', ' ').Trim() } catch { $null }
        }
    })
    Export-DArtifact -Name '11_sysmon_25_tampering' -Data $tamperRows -SubDir events
    foreach ($r in $tamperRows) {
        Add-DFinding -RuleId 'DGL-213' -Severity CRITICAL `
            -Title 'Process tampering (hollowing/herpaderping)' `
            -Evidence "$($r.TimeUtc) :: $($r.Detail)" `
            -Mitre 'T1055.012' -Artifact '11_sysmon_25_tampering' -Timestamp $r.TimeUtc `
            -Why 'Hollowing ve herpaderping diskteki dosya ile bellekteki kodu birbirinden ayirir'
    }

    # --- Event 19/20/21: WMI ---
    $wmiSys = Get-DWinEvents -LogName $ch -Id 19, 20, 21 -Max 5000
    $wmiSysRows = @(foreach ($e in $wmiSys) {
        [PSCustomObject]@{
            TimeUtc = ConvertTo-DUtcString $e.TimeCreated
            EventId = $e.Id
            Detail  = try { ($e.Message -replace '\s+', ' ').Trim() } catch { $null }
        }
    })
    Export-DArtifact -Name '11_sysmon_19_wmi' -Data $wmiSysRows -SubDir events
    foreach ($r in $wmiSysRows) {
        Add-DFinding -RuleId 'DGL-214' -Severity CRITICAL `
            -Title 'Sysmon WMI event kaydi (kalicilik)' `
            -Evidence "$($r.TimeUtc) ID$($r.EventId) :: $($r.Detail)" `
            -Mitre 'T1546.003' -Artifact '11_sysmon_19_wmi' -Timestamp $r.TimeUtc `
            -Why 'WMI abonelikleri diskte dosya birakmadan kalicilik saglar'
    }

    Write-DLog "  Sysmon - lsass:$($lsassAccess.Count) inject:$($crtRows.Count) pipe:$($pipeRows.Count) dns:$($dnsRows.Count) net:$($net3Rows.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: EVENT - KERBEROS (SADECE DC)
# ============================================================================

Register-DModule -Name 'Event: Kerberos (DC)' -Phase 2 -Scope 'DC' -RequiresCap 'WinEvent' `
    -Description '4768/4769/4771 - Kerberoasting, AS-REP, downgrade' `
    -HuntTags @('CredentialAccess') -Body {

    # --- 4769: service ticket - RC4 + hacim = Kerberoasting ---
    $tgs = Get-DWinEvents -LogName 'Security' -Id 4769
    $tgsRows = @(foreach ($e in $tgs) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Domain      = Get-DProp $e 1
            ServiceName = Get-DProp $e 2
            TicketEnc   = Get-DProp $e 5
            IpAddress   = Get-DProp $e 6
            Status      = Get-DProp $e 8
        }
    })
    Export-DArtifact -Name '11_evt_4769_kerberos' -Data $tgsRows -SubDir events

    # 0x17 = RC4-HMAC (Kerberoasting icin tercih edilir, kirilabilir)
    $rc4 = @($tgsRows | Where-Object { $_.TicketEnc -eq '0x17' -and $_.ServiceName -notmatch '\$$' })
    $byUser = $rc4 | Group-Object AccountName | Sort-Object Count -Descending
    foreach ($g in ($byUser | Select-Object -First 10)) {
        $svcCount = @($g.Group | Select-Object -ExpandProperty ServiceName -Unique).Count
        if ($g.Count -ge 10 -or $svcCount -ge 5) {
            Add-DFinding -RuleId 'DGL-220' -Severity CRITICAL `
                -Title 'Kerberoasting supheli (RC4 service ticket yogunlugu)' `
                -Evidence "$($g.Name): $($g.Count) RC4 bilet, $svcCount farkli servis, kaynak: $($g.Group[0].IpAddress)" `
                -Mitre 'T1558.003' -Artifact '11_evt_4769_kerberos' `
                -Why 'Tek hesabin cok sayida servise RC4 bileti almasi Kerberoast saldirisinin imzasidir'
        }
    }

    # --- 4768: TGT - RC4 downgrade ---
    $tgt = Get-DWinEvents -LogName 'Security' -Id 4768
    $tgtRows = @(foreach ($e in $tgt) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Domain      = Get-DProp $e 1
            TicketEnc   = Get-DProp $e 7
            PreAuthType = Get-DProp $e 8
            IpAddress   = Get-DProp $e 9
            Status      = Get-DProp $e 6
        }
    })
    Export-DArtifact -Name '11_evt_4768_tgt' -Data $tgtRows -SubDir events

    # PreAuthType 0 = pre-auth yok = AS-REP roastable hesap
    foreach ($r in @($tgtRows | Where-Object { $_.PreAuthType -eq '0' } |
                     Group-Object AccountName | Select-Object -First 10)) {
        Add-DFinding -RuleId 'DGL-221' -Severity HIGH `
            -Title 'Kerberos pre-authentication olmadan TGT istegi (AS-REP roast)' `
            -Evidence "$($r.Name): $($r.Count) istek, kaynak: $($r.Group[0].IpAddress)" `
            -Mitre 'T1558.004' -Artifact '11_evt_4768_tgt' `
            -Why 'Pre-auth devre disi hesaplar cevrimdisi parola kirmaya aciktir'
    }

    foreach ($r in @($tgtRows | Where-Object { $_.TicketEnc -eq '0x17' } |
                     Group-Object AccountName | Select-Object -First 10)) {
        Add-DFinding -RuleId 'DGL-222' -Severity MEDIUM `
            -Title 'RC4 sifreleme ile TGT (encryption downgrade)' `
            -Evidence "$($r.Name): $($r.Count) RC4 TGT" `
            -Mitre 'T1558' -Artifact '11_evt_4768_tgt' `
            -Why 'Overpass-the-hash saldirilari RC4 kullanir'
    }

    # --- 4771: pre-auth basarisiz = parola deneme ---
    $preauth = Get-DWinEvents -LogName 'Security' -Id 4771
    $paRows = @(foreach ($e in $preauth) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            AccountName = Get-DProp $e 0
            Status      = Get-DProp $e 4
            PreAuthType = Get-DProp $e 5
            IpAddress   = Get-DProp $e 6
        }
    })
    Export-DArtifact -Name '11_evt_4771_preauth' -Data $paRows -SubDir events

    foreach ($g in @($paRows | Group-Object IpAddress | Sort-Object Count -Descending |
                     Select-Object -First 5)) {
        if ($g.Count -ge 20) {
            $u = @($g.Group | Select-Object -ExpandProperty AccountName -Unique).Count
            Add-DFinding -RuleId 'DGL-223' -Severity HIGH `
                -Title 'Kerberos parola deneme saldirisi (4771 yogunlugu)' `
                -Evidence "$($g.Name): $($g.Count) basarisiz pre-auth, $u farkli hesap" `
                -Mitre 'T1110.003' -Artifact '11_evt_4771_preauth' `
                -Why 'Yogun 4771 password spraying veya brute force gostergesidir'
        }
    }

    # --- 4662: DCSync tespiti ---
    $ds = Get-DWinEvents -LogName 'Security' -Id 4662 -Max 50000
    $dcsync = @(foreach ($e in $ds) {
        $props = Get-DProp $e 8
        if ($props -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
            [PSCustomObject]@{
                TimeUtc = ConvertTo-DUtcString $e.TimeCreated
                User    = "$(Get-DProp $e 2)\$(Get-DProp $e 1)"
                Sid     = Get-DProp $e 0
                Properties = $props
            }
        }
    })
    Export-DArtifact -Name '11_evt_4662_dcsync' -Data $dcsync -SubDir events

    foreach ($r in $dcsync) {
        # DC makine hesaplari normaldir, kullanici hesaplari degildir
        if ($r.User -notmatch '\$$') {
            Add-DFinding -RuleId 'DGL-224' -Severity CRITICAL `
                -Title 'DCSync girisimi (dizin replikasyon hakki kullanildi)' `
                -Evidence "$($r.TimeUtc) $($r.User)" `
                -Mitre 'T1003.006' -Artifact '11_evt_4662_dcsync' -Timestamp $r.TimeUtc `
                -Why 'DC olmayan bir principal replikasyon hakki kullaniyor - tum parola hashlerini cekebilir'
            Add-DTimelineEvent -Timestamp $r.TimeUtc -Source 'DCSync' `
                -Description "DCSync: $($r.User)" -Severity CRITICAL
        }
    }

    # --- 4776: NTLM ---
    $ntlm = Get-DWinEvents -LogName 'Security' -Id 4776
    $ntlmRows = @(foreach ($e in $ntlm) {
        [PSCustomObject]@{
            TimeUtc     = ConvertTo-DUtcString $e.TimeCreated
            Package     = Get-DProp $e 0
            AccountName = Get-DProp $e 1
            Workstation = Get-DProp $e 2
            Status      = Get-DProp $e 3
        }
    })
    Export-DArtifact -Name '11_evt_4776_ntlm' -Data $ntlmRows -SubDir events

    Write-DLog "  4769:$($tgsRows.Count) 4768:$($tgtRows.Count) 4771:$($paRows.Count) DCSync:$($dcsync.Count)" -Level DEBUG
}

Register-DModule -Name 'Event: Collection Statistics' -Phase 2 -Body {
    Export-DArtifact -Name '11_event_stats' -Data @($Script:EventStats) -SubDir events
    $capped = @($Script:EventStats | Where-Object Capped)
    $missing = @($Script:EventStats | Where-Object Status -eq 'CHANNEL_NOT_FOUND')
    Write-DLog "  $($Script:EventStats.Count) channel queries ($($capped.Count) capped, $($missing.Count) missing)" -Level DEBUG
}

# ============================================================================
#  MODUL: DOSYA SISTEMI - SUPHELI DOSYALAR
# ============================================================================

Register-DModule -Name 'File System Scan' -Phase 3 -SkipOnQuick `
    -Description 'Hedefli dizinlerde yeni yazilmis calistirilabilir dosyalar' -Body {

    # NOT: C:\ recurse ASLA yapilmaz. Bu 12 dizin gercek bulgularin %95'ini icerir.
    $cutoff = $Script:Ctx.WindowStart
    $found  = New-Object System.Collections.ArrayList
    $scanned = 0

    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            $rootSusp = Test-DSuspiciousPath -Path ($root.TrimEnd('\') + '\')
            Get-DFilesNoReparse -Root $root -Limit 20000 |
                Where-Object {
                    $_.LastWriteTime -ge $cutoff -and (
                        # F1.5-10: supheli dizinde uzanti fark etmez (uzantisiz/.dat/.log
                        # payload'lar da yakalanir); guvenli dizinde ilginc uzanti sart.
                        (Test-DSuspiciousPath -Path $_.FullName) -or
                        ($Script:InterestingExt -contains $_.Extension.ToLowerInvariant())
                    ) -and $_.Length -lt 100MB
                } | ForEach-Object {
                    $scanned++
                    if ($scanned -gt 8000) { return }
                    $f = $_
                    $sig = Get-DSignature -Path $f.FullName

                    # MOTW / Zone.Identifier - dosya nereden indirildi
                    $zone = $null; $refUrl = $null
                    try {
                        $ads = Get-Content -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction Stop
                        if ($ads) {
                            $zone = ($ads | Where-Object { $_ -match 'ZoneId=(\d)' } |
                                     ForEach-Object { $Matches[1] }) -join ''
                            $refUrl = ($ads | Where-Object { $_ -match '^(HostUrl|ReferrerUrl)=(.+)' } |
                                       ForEach-Object { $Matches[2] }) -join ' | '
                        }
                    } catch { }

                    # Timestomp gostergesi: olusturma > degistirme, veya .000 ms
                    # Timestomp: GUCLU gosterge = olusturma zamani degistirme
                    # zamanindan SONRA (mantiksal imkansizlik, >5dk fark). Millisecond=0
                    # tek basina cok yaygin (normal kopyalama/extract) - yaniltici,
                    # bu yuzden tek basina timestomp sayilmaz.
                    $stomped = $false
                    try {
                        if ($f.CreationTime -gt $f.LastWriteTime.AddMinutes(5)) { $stomped = $true }
                    } catch { }

                    # F1.5-11: alternatif veri akislari (ADS)
                    $adsList = Get-DAlternateStreams -Path $f.FullName
                    $null = $found.Add([PSCustomObject]@{
                        FullName     = $f.FullName
                        Extension    = $f.Extension
                        SizeKB       = [math]::Round($f.Length / 1KB, 2)
                        CreatedUtc   = ConvertTo-DUtcString $f.CreationTime
                        ModifiedUtc  = ConvertTo-DUtcString $f.LastWriteTime
                        AccessedUtc  = ConvertTo-DUtcString $f.LastAccessTime
                        Signed       = $sig.IsValid
                        Signer       = $sig.Signer
                        SigStatus    = $sig.Status
                        IsMicrosoft  = $sig.IsMicrosoft
                        SHA256       = Get-DFileHashSafe -Path $f.FullName
                        ZoneId       = $zone
                        DownloadUrl  = $refUrl
                        TimestompSuspect = $stomped
                        SuspiciousPath   = Test-DSuspiciousPath -Path $f.FullName
                        AltStreams   = ($adsList | ForEach-Object { "$($_.Stream) ($($_.Size)b)" }) -join '; '
                    })
                    # F1.5-11: yurutulebilir/kod iceren ADS ayri bulgu
                    foreach ($a in $adsList) {
                        $sevAds = if ($a.Stream -match '(?i)\.(ps1|exe|dll|bat|vbs|js|hta|cmd)$' -or $a.Size -gt 1024) { 'HIGH' } else { 'MEDIUM' }
                        Add-DFinding -RuleId 'DGL-236' -Severity $sevAds `
                            -Title 'Alternatif veri akisi (ADS) tespit edildi' `
                            -Evidence "$($f.FullName):$($a.Stream) ($($a.Size) byte)" `
                            -Mitre 'T1564.004' -Artifact '13_recent_files' -Timestamp (ConvertTo-DUtcString $f.LastWriteTime) `
                            -Why 'Varsayilan disi veri akislari kod/payload gizlemek icin kullanilir'
                    }
                }
        } catch { }
    }

    $arr = @($found)
    Export-DArtifact -Name '13_recent_files' -Data $arr

    if ($scanned -ge 5000) {
        Add-DFinding -RuleId 'DGL-019' -Severity INFO `
            -Title 'Dosya tarama limiti asildi' `
            -Evidence "5000 dosyada durduruldu (-Days $Days)" -Artifact '13_recent_files' `
            -Why 'Analiz penceresini daraltin'
    }

    # --- TRIAGE ---
    foreach ($f in $arr) {
        if ($f.SuspiciousPath -and $f.Extension -match '(?i)\.(exe|dll|scr|sys)$' -and -not $f.IsMicrosoft) {
            Add-DFinding -RuleId 'DGL-230' -Severity HIGH `
                -Title 'Supheli dizinde yeni calistirilabilir dosya' `
                -Evidence "$($f.FullName) @ $($f.ModifiedUtc) [$($f.SizeKB) KB]" `
                -Mitre 'T1105' -Artifact '13_recent_files' -Timestamp $f.ModifiedUtc `
                -Why 'Analiz penceresi icinde Temp/AppData altina yazilan calistirilabilir dosya payload olabilir'
            Add-DTimelineEvent -Timestamp $f.ModifiedUtc -Source 'FileSystem' `
                -Description "File written: $(Split-Path $f.FullName -Leaf)" `
                -Detail $f.FullName -Severity HIGH
        }

        if ($f.DownloadUrl) {
            Add-DFinding -RuleId 'DGL-231' -Severity MEDIUM `
                -Title 'Internetten indirilmis dosya (MOTW)' `
                -Evidence "$($f.FullName) <- $($f.DownloadUrl)" `
                -Mitre 'T1105' -Artifact '13_recent_files' -Timestamp $f.ModifiedUtc `
                -Why 'Zone.Identifier alternatif veri akisi indirme kaynagini tasir'
            $null = Test-DIoc -Value $f.DownloadUrl -Context $f.FullName -Artifact '13_recent_files'
        }

        if ($f.TimestompSuspect -and -not $f.IsMicrosoft) {
            $tsSev = if ($f.SuspiciousPath) { 'HIGH' } else { 'LOW' }
            Add-DFinding -RuleId 'DGL-232' -Severity $tsSev `
                -Title 'Zaman damgasi manipulasyonu supheli' `
                -Evidence "$($f.FullName) olusturma:$($f.CreatedUtc) degistirme:$($f.ModifiedUtc)" `
                -Mitre 'T1070.006' -Artifact '13_recent_files' `
                -Why 'Olusturma zamani degistirme zamanindan SONRA (>5dk) - zaman damgasi geriye alinmis olabilir'
        }

        if ($f.SHA256) {
            $null = Test-DIoc -Value $f.SHA256 -Context $f.FullName -Artifact '13_recent_files'
        }

        # F1.5-10: uzantidan bagimsiz icerik/entropi/PE analizi.
        # update.dat, creds.txt, uzantisiz payload burada yakalanir.
        foreach ($o in (Test-DFileArtifact -Path $f.FullName -WindowStartUtc $Script:Ctx.WindowStartUtc)) {
            # DGL-230'u yukarida zaten urettik; tekrar etme
            if ($o.Rule -eq 'DGL-230') { continue }
            Add-DFinding -RuleId $o.Rule -Severity $o.Sev -Title $o.Title `
                -Evidence $o.Detail -Mitre $o.Mitre -Artifact '13_recent_files' `
                -Timestamp $f.ModifiedUtc -Why $o.Why
        }
    }

    Write-DLog "  $($arr.Count) new files found (incl. ADS + content analysis)" -Level DEBUG
}

# ============================================================================
#  MODUL: WEBSHELL AVI
# ============================================================================

# NOT: -Scope 'Server' kaldirildi. Modul zaten web kokunu kendi ariyor ve
# bulamazsa cikiyor; rol filtresi IIS kurulu is istasyonlarinda DGL-240'i
# (CRITICAL webshell kurali) sessizce devre disi birakiyordu.
Register-DModule -Name 'Webshell Hunt' -Phase 3 -SkipOnQuick `
    -Description 'Web koklerinde script dosyalari + icerik pattern taramasi' -Body {

    # Web kok dizinlerini bul
    $webRoots = New-Object System.Collections.ArrayList
    foreach ($p in @('C:\inetpub\wwwroot', 'C:\inetpub', "$env:SystemDrive\wwwroot",
                     'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy',
                     'C:\Program Files\Microsoft\Exchange Server\V15\ClientAccess',
                     'C:\xampp\htdocs', 'C:\Apache24\htdocs', 'C:\tomcat\webapps')) {
        if (Test-Path $p) { $null = $webRoots.Add($p) }
    }

    # IIS site yollarini metabase'den al
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Get-Website -ErrorAction Stop | ForEach-Object {
            $ph = $_.PhysicalPath
            if ($ph) {
                $ph = [Environment]::ExpandEnvironmentVariables($ph)
                if ((Test-Path $ph) -and ($webRoots -notcontains $ph)) { $null = $webRoots.Add($ph) }
            }
        }
    } catch { }

    if ($webRoots.Count -eq 0) {
        Write-DLog '  No web root found, skipped' -Level DEBUG
        return
    }

    # Webshell icerik imzalari
    $shellPatterns = @(
        @{ P = '(?i)eval\s*\(\s*(request|base64_decode|\$_(POST|GET|REQUEST))'; N = 'eval + user input'; S = 'CRITICAL' }
        @{ P = '(?i)Request\.(Item|Form|QueryString)\s*\[.{1,40}\].{0,80}(Execute|Eval|Process)'; N = 'ASPX command execution'; S = 'CRITICAL' }
        @{ P = '(?i)System\.Diagnostics\.Process.{0,60}Start'; N = 'Process.Start (ASPX)'; S = 'HIGH' }
        @{ P = '(?i)(cmd\.exe|/c\s+|powershell).{0,60}(Request|param)'; N = 'Command line + request parameter'; S = 'CRITICAL' }
        @{ P = '(?i)\$_(POST|GET|REQUEST)\s*\[.{1,30}\]\s*\)?\s*;?\s*$'; N = 'PHP direct input execution'; S = 'HIGH' }
        @{ P = '(?i)(shell_exec|passthru|proc_open|popen|system)\s*\('; N = 'PHP shell function'; S = 'HIGH' }
        @{ P = '(?i)Runtime\.getRuntime\(\)\.exec'; N = 'JSP command execution'; S = 'CRITICAL' }
        @{ P = '(?i)FromBase64String.{0,60}(Load|Invoke|Assembly)'; N = '.NET assembly load'; S = 'CRITICAL' }
        @{ P = '(?i)(Chopper|China\s?Chopper|antsword|behinder|godzilla|weevely)'; N = 'Known webshell filename'; S = 'CRITICAL' }
        @{ P = '(?i)Server\.CreateObject\s*\(\s*.WScript\.Shell'; N = 'ASP WScript.Shell'; S = 'CRITICAL' }
    )

    $webExt = @('.aspx', '.asp', '.ashx', '.asmx', '.php', '.jsp', '.jspx', '.war', '.cfm', '.cshtml')
    $hits   = New-Object System.Collections.ArrayList
    $allWeb = New-Object System.Collections.ArrayList

    foreach ($root in $webRoots) {
        try {
            Get-DFilesNoReparse -Root $root -Limit 20000 |
                Where-Object { $webExt -contains $_.Extension.ToLowerInvariant() } |
                ForEach-Object {
                    $f = $f = $_
                    $isNew = ($f.LastWriteTime -ge $Script:Ctx.WindowStart)

                    $null = $allWeb.Add([PSCustomObject]@{
                        FullName    = $f.FullName
                        SizeKB      = [math]::Round($f.Length / 1KB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $f.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $f.LastWriteTime
                        IsNew       = $isNew
                        SHA256      = Get-DFileHashSafe -Path $f.FullName
                    })

                    # Icerik taramasi - 2 MB ustu dosyayi okuma
                    if ($f.Length -gt 2MB) { return }
                    $content = $null
                    try {
                        $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    } catch { return }
                    if (-not $content) { return }

                    foreach ($sp in $shellPatterns) {
                        if ($content -match $sp.P) {
                            $snippet = $Matches[0]
                            if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0, 200) }
                            $null = $hits.Add([PSCustomObject]@{
                                FullName    = $f.FullName
                                Pattern     = $sp.N
                                Severity    = $sp.S
                                Snippet     = ($snippet -replace '\s+', ' ')
                                ModifiedUtc = ConvertTo-DUtcString $f.LastWriteTime
                                IsNew       = $isNew
                                SHA256      = Get-DFileHashSafe -Path $f.FullName
                            })
                            break
                        }
                    }
                }
        } catch { }
    }

    Export-DArtifact -Name '13_web_files' -Data @($allWeb)
    Export-DArtifact -Name '13_webshell_hits' -Data @($hits)

    foreach ($h in $hits) {
        $sev = if ($h.IsNew) { 'CRITICAL' } else { $h.Severity }
        Add-DFinding -RuleId 'DGL-240' -Severity $sev `
            -Title "WEBSHELL supheli: $($h.Pattern)" `
            -Evidence "$($h.FullName) @ $($h.ModifiedUtc) :: $($h.Snippet)" `
            -Mitre 'T1505.003' -Artifact '13_webshell_hits' -Timestamp $h.ModifiedUtc `
            -Why 'Command execution pattern matched in the web root'
        Add-DTimelineEvent -Timestamp $h.ModifiedUtc -Source 'Webshell' `
            -Description "Webshell supheli: $(Split-Path $h.FullName -Leaf)" `
            -Detail $h.FullName -Severity CRITICAL
    }

    # Pattern eslesmese bile analiz penceresi icinde YENI web dosyasi supheli
    foreach ($w in @($allWeb | Where-Object IsNew)) {
        if ($hits.FullName -contains $w.FullName) { continue }
        Add-DFinding -RuleId 'DGL-241' -Severity HIGH `
            -Title 'Web kokune analiz penceresi icinde yeni dosya yazilmis' `
            -Evidence "$($w.FullName) @ $($w.ModifiedUtc) [$($w.SizeKB) KB]" `
            -Mitre 'T1505.003' -Artifact '13_web_files' -Timestamp $w.ModifiedUtc `
            -Why 'Deployment disi web dosyasi degisimi webshell yerlestirmesini gosterebilir'
    }

    Write-DLog "  $($webRoots.Count) web roots, $($allWeb.Count) files, $($hits.Count) pattern matches" -Level DEBUG
}

# ============================================================================
#  MODUL: EXFIL IZLERI
# ============================================================================

Register-DModule -Name 'Exfiltration Traces' -Phase 3 -SkipOnQuick `
    -Description 'Arsivler, exfil araclari, SRUM ag kullanimi' -Body {

    # --- Buyuk / yeni arsiv dosyalari ---
    $archExt = @('.rar', '.7z', '.zip', '.tar', '.gz', '.cab', '.iso', '.bak')
    $arch = New-Object System.Collections.ArrayList

    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-DFilesNoReparse -Root $root -Limit 15000 |
                Where-Object {
                    $archExt -contains $_.Extension.ToLowerInvariant() -and
                    $_.LastWriteTime -ge $Script:Ctx.WindowStart
                } | ForEach-Object {
                    $null = $arch.Add([PSCustomObject]@{
                        FullName    = $_.FullName
                        SizeMB      = [math]::Round($_.Length / 1MB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                        SuspiciousPath = Test-DSuspiciousPath -Path $_.FullName
                    })
                }
        } catch { }
    }
    $archArr = @($arch)
    Export-DArtifact -Name '13_archives' -Data $archArr

    foreach ($a in $archArr) {
        $sev = if ($a.SizeMB -gt 100 -or $a.SuspiciousPath) { 'HIGH' } else { 'MEDIUM' }
        Add-DFinding -RuleId 'DGL-250' -Severity $sev `
            -Title 'Analiz penceresi icinde olusturulmus arsiv' `
            -Evidence "$($a.FullName) [$($a.SizeMB) MB] @ $($a.ModifiedUtc)" `
            -Mitre 'T1560' -Artifact '13_archives' -Timestamp $a.ModifiedUtc `
            -Why 'Veri toplama asamasinda saldirgan dosyalari arsivler'
        Add-DTimelineEvent -Timestamp $a.ModifiedUtc -Source 'Exfil' `
            -Description "Arsiv olusturuldu: $(Split-Path $a.FullName -Leaf)" `
            -Detail "$($a.SizeMB) MB" -Severity $sev
    }

    # --- Exfil / tunel araclarinin diskteki varligi ---
    $toolNames = $Script:ExfilBins + @('psexec.exe', 'psexec64.exe', 'mimikatz.exe',
                 'procdump.exe', 'procdump64.exe', 'nmap.exe', 'advanced_port_scanner.exe',
                 'netscan.exe', 'anydesk.exe', 'teamviewer.exe', 'screenconnect.exe',
                 'atera.exe', 'splashtop.exe', 'rustdesk.exe', 'putty.exe')
    $tools = New-Object System.Collections.ArrayList

    foreach ($root in $Script:ScanPaths) {
        if (-not (Test-Path $root)) { continue }
        try {
            Get-DFilesNoReparse -Root $root -Limit 15000 |
                Where-Object { $toolNames -contains $_.Name.ToLowerInvariant() } |
                ForEach-Object {
                    $null = $tools.Add([PSCustomObject]@{
                        FullName    = $_.FullName
                        SizeKB      = [math]::Round($_.Length / 1KB, 2)
                        CreatedUtc  = ConvertTo-DUtcString $_.CreationTime
                        ModifiedUtc = ConvertTo-DUtcString $_.LastWriteTime
                        SHA256      = Get-DFileHashSafe -Path $_.FullName
                    })
                }
        } catch { }
    }
    $toolArr = @($tools)
    Export-DArtifact -Name '13_attacker_tools' -Data $toolArr

    foreach ($t in $toolArr) {
        Add-DFinding -RuleId 'DGL-251' -Severity CRITICAL `
            -Title 'Saldirgan/uzaktan erisim araci diskte bulundu' `
            -Evidence "$($t.FullName) @ $($t.ModifiedUtc)" `
            -Mitre 'T1219' -Artifact '13_attacker_tools' -Timestamp $t.ModifiedUtc `
            -Why 'Bu araclar kullanici dizinlerinde mesru olarak bulunmaz'
    }

    # --- SRUM: uygulama basina ag kullanimi (exfil hacminin kaniti) ---
    $srum = "$env:SystemRoot\System32\sru\SRUDB.dat"
    if (Test-Path $srum) {
        try {
            $si = Get-Item $srum -Force -ErrorAction Stop
            Export-DArtifact -Name '13_srum_info' -Data ([PSCustomObject]@{
                Path        = $srum
                SizeMB      = [math]::Round($si.Length / 1MB, 2)
                ModifiedUtc = ConvertTo-DUtcString $si.LastWriteTime
                Note        = 'Uygulama basina gonderilen/alinan byte. Cevrimdisi parse gerekir (srum-dump / KAPE).'
            })
        } catch { }
    }

    Write-DLog "  $($archArr.Count) archives, $($toolArr.Count) attack tools" -Level DEBUG
}

# ============================================================================
#  MODUL: KULLANICI AKTIVITESI
# ============================================================================

Register-DModule -Name 'User Activity' -Phase 3 `
    -Description 'PSReadLine gecmisi (TUM kullanicilar), RDP gecmisi, USB, Prefetch' -Body {

    # --- PowerShell konsol gecmisi ---
    # ESKI SCRIPT BUGU: Get-History kullaniyordu, script kendi oturumunda calistigi
    # icin DAIMA BOS donuyordu. Gercek hedef PSReadLine dosyalari.
    $hist = New-Object System.Collections.ArrayList
    try {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_.Name
            $hf = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (-not (Test-Path $hf)) { return }
            try {
                $fi = Get-Item $hf -Force -ErrorAction Stop
                $ln = 0
                Get-Content $hf -ErrorAction Stop | ForEach-Object {
                    $ln++
                    if ($_.Trim()) {
                        $null = $hist.Add([PSCustomObject]@{
                            User        = $u
                            LineNumber  = $ln
                            Command     = $_
                            FileModifiedUtc = ConvertTo-DUtcString $fi.LastWriteTime
                        })
                    }
                }
            } catch { }
        }
    } catch { }
    $histArr = @($hist)
    Export-DArtifact -Name '14_ps_history' -Data $histArr

    foreach ($h in $histArr) {
        Test-DEventCmdLine -CommandLine $h.Command -RuleId 'DGL-260' `
            -Context "PSReadLine [$($h.User)] satir $($h.LineNumber)" `
            -Artifact '14_ps_history' -Timestamp $h.FileModifiedUtc
        # F1.5-7: merkezi coz+tara (encoded + concat + char-array + obfuscation)
        $null = Invoke-DDeobfuscateAndScan -Text $h.Command `
            -Context "PSReadLine [$($h.User)]" -Artifact '14_ps_history' `
            -Timestamp $h.FileModifiedUtc -DecodeRule 'DGL-261'
    }

    # --- RDP baglanti gecmisi (bu hosttan nereye baglanildi) ---
    $rdpHist = New-Object System.Collections.ArrayList
    foreach ($hive in (Get-DUserHives)) {
        $base = "$($hive.RegRoot)\Software\Microsoft\Terminal Server Client\Servers"
        try {
            Get-ChildItem $base -ErrorAction Stop | ForEach-Object {
                $un = (Get-DRegValues -Path $_.PSPath | Where-Object Name -eq 'UsernameHint')
                $null = $rdpHist.Add([PSCustomObject]@{
                    User         = $hive.User
                    RemoteHost   = $_.PSChildName
                    UsernameHint = if ($un) { $un.Value } else { $null }
                })
            }
        } catch { }
        # Default MRU
        foreach ($v in (Get-DRegValues -Path "$($hive.RegRoot)\Software\Microsoft\Terminal Server Client\Default")) {
            if ($v.Name -match '^MRU\d+$') {
                $null = $rdpHist.Add([PSCustomObject]@{
                    User = $hive.User; RemoteHost = $v.Value; UsernameHint = "(MRU:$($v.Name))"
                })
            }
        }
    }
    $rdpArr = @($rdpHist)
    Export-DArtifact -Name '14_rdp_history' -Data $rdpArr

    foreach ($r in $rdpArr) {
        Add-DFinding -RuleId 'DGL-262' -Severity MEDIUM `
            -Title 'Bu hosttan RDP baglanti gecmisi kaydi' `
            -Evidence "$($r.User) -> $($r.RemoteHost) [$($r.UsernameHint)]" `
            -Mitre 'T1021.001' -Artifact '14_rdp_history' `
            -Why 'Yayilim haritasi: bu makineden hangi sistemlere baglanilmis'
    }

    # --- Eslenmis surucu gecmisi ---
    $mounts = New-Object System.Collections.ArrayList
    foreach ($hive in (Get-DUserHives)) {
        try {
            Get-ChildItem "$($hive.RegRoot)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" `
                -ErrorAction Stop | Where-Object { $_.PSChildName -match '^##' } | ForEach-Object {
                    $null = $mounts.Add([PSCustomObject]@{
                        User = $hive.User
                        RemotePath = ($_.PSChildName -replace '^##', '\\' -replace '#', '\')
                    })
                }
        } catch { }
    }
    Export-DArtifact -Name '14_mounted_shares' -Data @($mounts)

    # --- USB cihazlar ---
    $usb = @()
    try {
        $usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop |
            ForEach-Object {
                $devClass = $_.PSChildName
                Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                    $v = Get-DRegValues -Path $_.PSPath
                    [PSCustomObject]@{
                        DeviceClass  = $devClass
                        Serial       = $_.PSChildName
                        FriendlyName = ($v | Where-Object Name -eq 'FriendlyName').Value
                        Service      = ($v | Where-Object Name -eq 'Service').Value
                    }
                }
            })
    } catch { }
    Export-DArtifact -Name '14_usb_devices' -Data $usb

    # --- Prefetch (calistirma kaniti) - FAZ 4: GERCEK PARSE ---
    # Artik sadece dosya adi degil; .pf ICERIGI cozuluyor (Win8+ MAM sikistirmasi
    # dahil): calisma sayisi, son 8 calisma zamani, yuklenen dosya listesi.
    $pf = @()
    try {
        $pfFiles = @(Get-ChildItem "$env:SystemRoot\Prefetch" -Filter '*.pf' -ErrorAction Stop)
        $parsedOk = 0
        $pf = @(foreach ($file in $pfFiles) {
            $p = Read-DPrefetchFile -Path $file.FullName
            if ($p) {
                $parsedOk++
                [PSCustomObject]@{
                    Name        = $file.Name
                    Program     = if ($p.Executable) { $p.Executable } else { ($file.BaseName -split '-')[0] }
                    RunCount    = $p.RunCount
                    LastRunUtc  = $p.LastRunUtc
                    AllRunTimes = $p.AllRunTimes
                    LoadedCount = $p.LoadedCount
                    LoadedFiles = $p.LoadedFiles
                    PfVersion   = $p.Version
                    CreatedUtc  = ConvertTo-DUtcString $file.CreationTime
                    ModifiedUtc = ConvertTo-DUtcString $file.LastWriteTime
                    SizeKB      = [math]::Round($file.Length / 1KB, 2)
                }
            } else {
                # parse edilemedi - en azindan dosya adi bilgisini koru
                [PSCustomObject]@{
                    Name        = $file.Name
                    Program     = ($file.BaseName -split '-')[0]
                    RunCount    = $null; LastRunUtc = $null; AllRunTimes = $null
                    LoadedCount = $null; LoadedFiles = $null; PfVersion = 'parse-failed'
                    CreatedUtc  = ConvertTo-DUtcString $file.CreationTime
                    ModifiedUtc = ConvertTo-DUtcString $file.LastWriteTime
                    SizeKB      = [math]::Round($file.Length / 1KB, 2)
                }
            }
        })
        if ($pfFiles.Count -gt 0) {
            Write-DLog "  Prefetch: $parsedOk/$($pfFiles.Count) files parsed by content" -Level DEBUG
        }
    } catch { }
    Export-DArtifact -Name '14_prefetch' -Data $pf

    # Prefetch icinde supheli yuklenen dosya yolu (payload'in nereden calistigi)
    foreach ($p in @($pf | Where-Object { $_.LoadedFiles })) {
        if ($p.LoadedFiles -match '(?i)\\(TEMP|APPDATA|PROGRAMDATA|PUBLIC|USERS\\[^\\]+\\DOWNLOADS)\\') {
            Add-DFinding -RuleId 'DGL-265' -Severity MEDIUM `
                -Title 'Prefetch: program supheli dizinden dosya yuklemis' `
                -Evidence "$($p.Program) (calisma: $($p.RunCount)) :: $(Format-DEvidence -Text $p.LoadedFiles -Max 600)" `
                -Mitre 'T1204' -Artifact '14_prefetch' -Timestamp $p.LastRunUtc `
                -Why 'Prefetch yuklenen dosya listesi, payload''in diskteki gercek konumunu gosterir'
        }
    }

    if ($pf.Count -eq 0 -and $Script:Ctx.IsWorkstation) {
        Add-DFinding -RuleId 'DGL-263' -Severity MEDIUM `
            -Title 'Prefetch kayitlari yok' -Evidence 'Prefetch dizini bos veya devre disi' `
            -Mitre 'T1070' -Artifact '14_prefetch' `
            -Why 'Prefetch kapatilmis olabilir - calistirma kaniti kaybi'
    }

    # Analiz penceresi icinde ilk kez calistirilan supheli programlar
    foreach ($p in @($pf | Where-Object { $_.CreatedUtc })) {
        try {
            if (((Get-Date) - [DateTime]$p.CreatedUtc).TotalDays -lt $Days) {
                $prog = $p.Program.ToLowerInvariant()
                if (($Script:ExfilBins -contains $prog) -or ($Script:LolBasExec -contains $prog) -or
                    $prog -match '(?i)(psexec|mimikatz|procdump|nmap|rclone|anydesk|rustdesk)') {
                    Add-DFinding -RuleId 'DGL-264' -Severity HIGH `
                        -Title 'Supheli program analiz penceresi icinde calistirilmis (Prefetch)' `
                        -Evidence "$($p.Program) ilk: $($p.CreatedUtc), son calisma: $(if($p.LastRunUtc){$p.LastRunUtc}else{$p.ModifiedUtc}), calisma sayisi: $(if($p.RunCount){$p.RunCount}else{'?'})" `
                        -Mitre 'T1204' -Artifact '14_prefetch' -Timestamp $p.CreatedUtc `
                        -Why 'Prefetch, process sonlansa bile calistirma kanitini korur'
                    Add-DTimelineEvent -Timestamp $p.CreatedUtc -Source 'Prefetch' `
                        -Description "Program executed: $($p.Program)" -Severity HIGH
                }
            }
        } catch { }
    }

    # --- Geri donusum kutusu ---
    $recycle = @()
    try {
        $recycle = @(Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $Script:Ctx.WindowStart } |
            Select-Object -First 500 | ForEach-Object {
                [PSCustomObject]@{
                    FullName    = $_.FullName
                    SizeKB      = [math]::Round($_.Length / 1KB, 2)
                    DeletedUtc  = ConvertTo-DUtcString $_.LastWriteTime
                }
            })
    } catch { }
    Export-DArtifact -Name '14_recycle_bin' -Data $recycle

    Write-DLog "  gecmis:$($histArr.Count) rdp:$($rdpArr.Count) usb:$($usb.Count) prefetch:$($pf.Count)" -Level DEBUG
}

# ============================================================================
#  MODUL: SERTIFIKA DEPOSU
# ============================================================================

Register-DModule -Name 'Certificate Store' -Phase 3 `
    -Description 'Rogue root CA tespiti' -Body {

    $certs = New-Object System.Collections.ArrayList
    foreach ($store in 'Root', 'CA', 'TrustedPublisher') {
        try {
            Get-ChildItem "Cert:\LocalMachine\$store" -ErrorAction Stop | ForEach-Object {
                $null = $certs.Add([PSCustomObject]@{
                    Store       = $store
                    Subject     = $_.Subject
                    Issuer      = $_.Issuer
                    Thumbprint  = $_.Thumbprint
                    NotBeforeUtc = ConvertTo-DUtcString $_.NotBefore
                    NotAfterUtc  = ConvertTo-DUtcString $_.NotAfter
                    SelfSigned  = ($_.Subject -eq $_.Issuer)
                })
            }
        } catch { }
    }
    $arr = @($certs)
    Export-DArtifact -Name '15_certificates' -Data $arr

    $knownCA = 'Microsoft|VeriSign|DigiCert|GlobalSign|Thawte|GeoTrust|Baltimore|Entrust|' +
               'COMODO|Sectigo|GoDaddy|Symantec|Starfield|AddTrust|USERTrust|Certum|' +
               'QuoVadis|SwissSign|T-TeleSec|Amazon|Google|ISRG|Let.s Encrypt|Actalis|Buypass|' +
               'D-TRUST|E-Tugra|TUBITAK|Hellenic|SecureTrust|Network Solutions|Go Daddy|' +
               'Staat der Nederlanden|Certigna|AffirmTrust|Chambers|Autoridad|NetLock|TeliaSonera'

    foreach ($c in @($arr | Where-Object { $_.Store -eq 'Root' -and $_.SelfSigned })) {
        if ($c.Subject -notmatch "(?i)($knownCA)") {
            $sev = 'MEDIUM'
            try {
                if ($c.NotBeforeUtc -and
                    ((Get-Date) - [DateTime]$c.NotBeforeUtc).TotalDays -lt 365) { $sev = 'HIGH' }
            } catch { }
            Add-DFinding -RuleId 'DGL-270' -Severity $sev `
                -Title 'Guvenilir kok deposunda taninmayan sertifika' `
                -Evidence "$($c.Subject) [gecerlilik: $($c.NotBeforeUtc)] $($c.Thumbprint)" `
                -Mitre 'T1553.004' -Artifact '15_certificates' `
                -Why 'Sahte kok CA, TLS kesme ve kod imzalama sahteciligine imkan verir'
        }
    }

    Write-DLog "  $($arr.Count) sertifika" -Level DEBUG
}

# ============================================================================
#  HTML RAPOR URETICI
# ============================================================================

function ConvertTo-DHtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' `
                  -replace '"', '&quot;' -replace "'", '&#39;')
}

function New-DHtmlReport {
    <#
        Tek dosya, tamamen offline HTML. CDN yok - IR ortami cogu zaman izole.
        Boyut kontrolu: artefakt basina ilk 500 satir gomulur, tam veri CSV'de kalir.
    #>
    $ctx  = $Script:Ctx
    $out  = Join-Path $ctx.OutputDir 'REPORT.html'

    $sevOrder = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }
    # F1.5-4: rapor benzersiz (ozetlenmis) listeyi gosterir; tam liste FINDINGS.csv'de
    $srcFindings = if ($Script:FindingsDedup) { $Script:FindingsDedup } else { $Script:Findings }
    # -Language EN ise kural metinlerini Ingilizceye cevir (kayipsiz fallback)
    # Bulgular Add-DFinding icinde zaten Ingilizce uretiliyor.
    $findings = @($srcFindings | Sort-Object @{E = { $sevOrder[$_.Severity] } }, TimeUtc)

    $crit = @($findings | Where-Object Severity -eq 'CRITICAL').Count
    $high = @($findings | Where-Object Severity -eq 'HIGH').Count
    $med  = @($findings | Where-Object Severity -eq 'MEDIUM').Count
    $low  = @($findings | Where-Object Severity -eq 'LOW').Count
    $info = @($findings | Where-Object Severity -eq 'INFO').Count

    $riskColor = switch ($ctx.RiskLevel) {
        'CRITICAL' { '#ff3b30' } 'HIGH' { '#ff6b35' } 'MEDIUM' { '#ffb340' }
        'LOW' { '#4aa8ff' } default { '#34c759' }
    }

    # --- Bulgu satirlari ---
    $sbF = New-Object System.Text.StringBuilder
    foreach ($f in $findings) {
        $null = $sbF.Append('<tr class="f" data-sev="' + $f.Severity + '">')
        $null = $sbF.Append('<td><span class="badge s-' + $f.Severity + '">' + $f.Severity + '</span></td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.RuleId) + '</td>')
        $null = $sbF.Append('<td><b>' + (ConvertTo-DHtmlSafe $f.Title) + '</b>')
        if ($f.Why) { $null = $sbF.Append('<div class="why">' + (ConvertTo-DHtmlSafe $f.Why) + '</div>') }
        $null = $sbF.Append('</td>')
        $null = $sbF.Append('<td class="mono ev">' + (ConvertTo-DHtmlSafe $f.Evidence) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.Mitre) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.TimeUtc) + '</td>')
        $null = $sbF.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $f.Artifact) + '</td>')
        $null = $sbF.Append('</tr>')
    }
    if ($findings.Count -eq 0) {
        $null = $sbF.Append('<tr><td colspan="7" class="dim">Bulgu yok.</td></tr>')
    }

    # --- Timeline: saat bazli yogunluk ---
    $tl = @($Script:Timeline | Sort-Object TimeUtc)
    $buckets = @{}
    foreach ($t in $tl) {
        try {
            $k = ([DateTime]$t.TimeUtc).ToString('yyyy-MM-dd HH:00')
            if (-not $buckets.ContainsKey($k)) { $buckets[$k] = 0 }
            $buckets[$k]++
        } catch { }
    }
    $sorted = @($buckets.GetEnumerator() | Sort-Object Name)
    $maxB   = 1
    if ($sorted.Count -gt 0) {
        $maxB = ($sorted | Measure-Object -Property Value -Maximum).Maximum
        if ($maxB -lt 1) { $maxB = 1 }
    }

    $sbChart = New-Object System.Text.StringBuilder
    $barW = if ($sorted.Count -gt 0) { [math]::Max(2, [math]::Floor(1100 / [math]::Max(1, $sorted.Count))) } else { 4 }
    $x = 0
    foreach ($b in $sorted) {
        $h = [math]::Max(2, [math]::Round(($b.Value / $maxB) * 130))
        $y = 140 - $h
        $null = $sbChart.Append('<rect x="' + $x + '" y="' + $y + '" width="' + ($barW - 1) +
                '" height="' + $h + '" fill="#4aa8ff"><title>' + $b.Name + ' : ' + $b.Value +
                ' olay</title></rect>')
        $x += $barW
    }

    # --- Timeline satirlari (en kritik 800) ---
    $tlShow = @($tl | Where-Object { $_.Severity -in 'CRITICAL', 'HIGH', 'MEDIUM' } |
                Select-Object -First 800)
    if ($tlShow.Count -lt 200) {
        $tlShow = @($tl | Select-Object -First 400)
    }
    $sbT = New-Object System.Text.StringBuilder
    foreach ($t in $tlShow) {
        $null = $sbT.Append('<tr class="f" data-sev="' + $t.Severity + '">')
        $null = $sbT.Append('<td class="mono">' + (ConvertTo-DHtmlSafe $t.TimeUtc) + '</td>')
        $null = $sbT.Append('<td><span class="badge s-' + $t.Severity + '">' + $t.Severity + '</span></td>')
        $null = $sbT.Append('<td class="mono dim">' + (ConvertTo-DHtmlSafe $t.Source) + '</td>')
        $null = $sbT.Append('<td>' + (ConvertTo-DHtmlSafe $t.Description) + '</td>')
        $null = $sbT.Append('<td class="mono ev">' + (ConvertTo-DHtmlSafe $t.Detail) + '</td>')
        $null = $sbT.Append('</tr>')
    }

    # --- Artefakt tablolari (her biri ilk 500 satir) ---
    $sbA = New-Object System.Text.StringBuilder
    $artDirs = @(
        (Join-Path $ctx.OutputDir 'artifacts'),
        (Join-Path $ctx.OutputDir 'events')
    )
    $tabList = New-Object System.Collections.ArrayList

    foreach ($dir in $artDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($csv in (Get-ChildItem $dir -Filter '*.csv' | Sort-Object Name)) {
            $rows = @()
            try { $rows = @(Import-Csv -Path $csv.FullName -ErrorAction Stop) } catch { continue }
            if ($rows.Count -eq 0) { continue }

            $id = ($csv.BaseName -replace '[^a-zA-Z0-9]', '_')
            $null = $tabList.Add([PSCustomObject]@{ Id = $id; Name = $csv.BaseName; Count = $rows.Count })

            $cols = $rows[0].PSObject.Properties.Name
            $null = $sbA.Append('<div class="pane" id="p_' + $id + '">')
            $null = $sbA.Append('<div class="ptitle">' + (ConvertTo-DHtmlSafe $csv.BaseName) +
                    ' <span class="dim">(' + $rows.Count + ' kayit')
            if ($rows.Count -gt 500) {
                $null = $sbA.Append(' - ilk 500 gosteriliyor, tam veri: ' + $csv.Name)
            }
            $null = $sbA.Append(')</span></div>')
            $null = $sbA.Append('<input class="tblsearch" placeholder="Bu tabloda ara..." ' +
                    'oninput="filterTable(this,' + "'t_$id'" + ')"><div class="scroll"><table id="t_' + $id + '"><thead><tr>')
            foreach ($c in $cols) { $null = $sbA.Append('<th>' + (ConvertTo-DHtmlSafe $c) + '</th>') }
            $null = $sbA.Append('</tr></thead><tbody>')

            foreach ($r in ($rows | Select-Object -First 500)) {
                $cls = ''
                if ($r.PSObject.Properties.Name -contains 'SuspiciousPath' -and
                    $r.SuspiciousPath -eq 'True') { $cls = ' class="hl-bad"' }
                elseif ($r.PSObject.Properties.Name -contains 'Signed' -and
                        $r.Signed -eq 'False') { $cls = ' class="hl-warn"' }
                $null = $sbA.Append('<tr' + $cls + '>')
                foreach ($c in $cols) {
                    $v = [string]$r.$c
                    if ($v.Length -gt 300) { $v = $v.Substring(0, 300) + '...' }
                    $null = $sbA.Append('<td class="mono">' + (ConvertTo-DHtmlSafe $v) + '</td>')
                }
                $null = $sbA.Append('</tr>')
            }
            $null = $sbA.Append('</tbody></table></div></div>')
        }
    }

    # --- F1.5-9: Korelasyon (saldiri varliklari) ---
    $sbCorr = New-Object System.Text.StringBuilder
    $ents = @($Script:Entities)
    if ($ents.Count -eq 0) {
        $null = $sbCorr.Append('<div class="empty">No correlatable entities (no file, IP or hash shared by 2+ findings).</div>')
    } else {
        foreach ($en in ($ents | Select-Object -First 40)) {
            $icon = switch ($en.Type) { 'file' {'FILE'} 'ip' {'IP'} 'hash' {'HASH'} default {'?'} }
            $null = $sbCorr.Append('<div class="ent"><div class="enth"><span class="badge s-' +
                $en.MaxSev + '">' + $en.MaxSev + '</span> <span class="etype">' + $icon +
                '</span> <b class="mono">' + (ConvertTo-DHtmlSafe $en.Value) + '</b>' +
                ' <span class="dim">' + (T 'rep.nfindings' @([string]$en.Findings.Count, [string]$en.Tactics.Count)) + '</span></div>')
            $null = $sbCorr.Append('<div class="entb">')
            foreach ($ef0 in ($en.Findings | Sort-Object @{E={ @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;INFO=4}[$_.Severity] }})) {
                $ef = $ef0
                $null = $sbCorr.Append('<div class="entrow"><span class="badge s-' + $ef.Severity +
                    '">' + $ef.Severity + '</span> <span class="mono dim">' + (ConvertTo-DHtmlSafe $ef.RuleId) +
                    '</span> ' + (ConvertTo-DHtmlSafe $ef.Title) +
                    ' <span class="mono dim">' + (ConvertTo-DHtmlSafe $ef.Mitre) + '</span></div>')
            }
            $null = $sbCorr.Append('</div></div>')
        }
    }

    # --- FAZ 5: Sigma eslesmeleri (AYRI bolum, risk skorundan bagimsiz) ---
    $sbSigma = New-Object System.Text.StringBuilder
    $sigHits = @($Script:SigmaHits)
    if ($sigHits.Count -eq 0) {
        $null = $sbSigma.Append('<div class="empty">' + (T 'rep.no_sigma') + '</div>')
    } else {
        $lvlRank = @{ critical=0; high=1; medium=2; low=3; informational=4 }
        $null = $sbSigma.Append('<div class="scroll" style="max-height:420px"><table id="sigma"><thead><tr>' +
            '<th>Seviye</th><th>Kural</th><th>Kategori</th><th>Kanit</th><th>Etiket</th></tr></thead><tbody>')
        foreach ($h in ($sigHits | Sort-Object @{E={ $lvlRank[[string]$_.Level] }}, Title)) {
            $lv = ([string]$h.Level).ToUpperInvariant(); if (-not $lv) { $lv = 'INFO' }
            $cls = switch ($lv) { 'CRITICAL' {'s-CRITICAL'} 'HIGH' {'s-HIGH'} 'MEDIUM' {'s-MEDIUM'} 'LOW' {'s-LOW'} default {'s-INFO'} }
            $null = $sbSigma.Append('<tr><td><span class="badge ' + $cls + '">' + (ConvertTo-DHtmlSafe $lv) + '</span></td>' +
                '<td>' + (ConvertTo-DHtmlSafe ([string]$h.Title)) +
                '<div class="why">' + (ConvertTo-DHtmlSafe ([string]$h.Description)) + '</div></td>' +
                '<td class="mono dim">' + (ConvertTo-DHtmlSafe ([string]$h.Category)) + '</td>' +
                '<td class="ev">' + (ConvertTo-DHtmlSafe ([string]$h.Evidence)) + '</td>' +
                '<td class="mono dim">' + (ConvertTo-DHtmlSafe ([string]$h.Tags)) + '</td></tr>')
        }
        $null = $sbSigma.Append('</tbody></table></div>')
    }

    # --- FAZ 2: ATT&CK kapsam izgarasi ---
    $tacticOrder = @('Initial Access','Execution','Persistence','Privilege Escalation',
                     'Credential Access','Discovery','Lateral Movement','Collection',
                     'Command and Control','Exfiltration','Impact','Stealth','Defense Impairment')
    $techMeta = @{}   # id -> @{Name; Tactic; MaxSev}
    foreach ($f in $findings) {
        if (-not $f.Mitre) { continue }
        foreach ($tid in ($f.Mitre -split ',')) {
            $tid = $tid.Trim(); if (-not $tid) { continue }
            if (-not $techMeta.ContainsKey($tid)) {
                $meta = $null
                if ($Script:MitreDetails -and $Script:MitreDetails.ContainsKey($tid)) { $meta = $Script:MitreDetails[$tid] }
                $techMeta[$tid] = @{
                    Name   = if ($meta) { $meta.name } else { $tid }
                    Tactic = if ($meta -and $meta.tactics) { @($meta.tactics)[0] } else { 'Other' }
                    MaxSev = $f.Severity
                }
            } else {
                $sr = @{CRITICAL=4;HIGH=3;MEDIUM=2;LOW=1;INFO=0}
                if ($sr[$f.Severity] -gt $sr[$techMeta[$tid].MaxSev]) { $techMeta[$tid].MaxSev = $f.Severity }
            }
        }
    }
    $sbAttck = New-Object System.Text.StringBuilder
    $byTactic = @{}
    foreach ($tid in $techMeta.Keys) {
        $tac = $techMeta[$tid].Tactic
        if (-not $byTactic.ContainsKey($tac)) { $byTactic[$tac] = New-Object System.Collections.ArrayList }
        $null = $byTactic[$tac].Add($tid)
    }
    $orderedTactics = @($tacticOrder | Where-Object { $byTactic.ContainsKey($_) }) +
                      @($byTactic.Keys | Where-Object { $_ -notin $tacticOrder })
    foreach ($tac in $orderedTactics) {
        $null = $sbAttck.Append('<div class="tcol"><h3>' + (ConvertTo-DHtmlSafe $tac) + '</h3>')
        $sr = @{CRITICAL=0;HIGH=1;MEDIUM=2;LOW=3;INFO=4}
        foreach ($tid in ($byTactic[$tac] | Sort-Object { $sr[$techMeta[$_].MaxSev] })) {
            $m = $techMeta[$tid]
            $cls = switch ($m.MaxSev) { 'CRITICAL' {'h1'} 'HIGH' {'h2'} 'MEDIUM' {'h3'} default {''} }
            # Ad yoksa (mitre-v19.json bulunamadi) ID'yi ikinci kez yazma -
            # "T1547 T1547" gibi cirkin tekrar olusuyordu.
            $nm = ''
            if ($m.Name -and $m.Name -ne $tid) {
                $nm = if ($m.Name.Length -gt 30) { $m.Name.Substring(0,30) + '...' } else { $m.Name }
            }
            $ttl = if ($nm) { "$($m.Name) ($($m.Tactic))" } else { $tid }
            $null = $sbAttck.Append('<span class="tcell ' + $cls + '" title="' +
                (ConvertTo-DHtmlSafe $ttl) + '"><b>' + (ConvertTo-DHtmlSafe $tid) + '</b>' +
                $(if ($nm) { ' <span class="tnm">' + (ConvertTo-DHtmlSafe $nm) + '</span>' } else { '' }) + '</span>')
        }
        $null = $sbAttck.Append('</div>')
    }
    if ($techMeta.Count -eq 0) {
        $null = $sbAttck.Append('<div class="empty">' + (T 'rep.no_attack') + '</div>')
    } elseif ($Script:MitreDetails.Count -eq 0) {
        # mitre-v19.json yok: teknik adlari cozulemedi, kullaniciya SOYLE
        $sbAttck.Insert(0, '<div class="note" style="margin-bottom:10px">' + (T 'rep.mitre_missing') + '</div>') | Out-Null
    }

    $sbTabs = New-Object System.Text.StringBuilder
    foreach ($t in $tabList) {
        $null = $sbTabs.Append('<button class="tab" onclick="showPane(' + "'$($t.Id)'" + ',this)">' +
                (ConvertTo-DHtmlSafe $t.Name) + ' <span class="cnt">' + $t.Count + '</span></button>')
    }

    # --- Hatalar / kapsam ---
    $sbE = New-Object System.Text.StringBuilder
    foreach ($e in @($Script:Errors | Select-Object -First 200)) {
        $null = $sbE.Append('<tr><td class="mono">' + (ConvertTo-DHtmlSafe $e.Module) +
                '</td><td class="mono dim">' + (ConvertTo-DHtmlSafe $e.Type) +
                '</td><td class="mono ev">' + (ConvertTo-DHtmlSafe $e.Message) + '</td></tr>')
    }

    $sbM = New-Object System.Text.StringBuilder
    foreach ($m in @($Script:ModuleStats | Sort-Object DurationMs -Descending)) {
        $null = $sbM.Append('<tr><td class="mono">' + (ConvertTo-DHtmlSafe $m.Module) +
                '</td><td class="mono">' + $m.Phase + '</td><td class="mono">' +
                (ConvertTo-DHtmlSafe $m.Status) + '</td><td class="mono">' +
                [math]::Round($m.DurationMs / 1000, 1) + ' sn</td><td class="mono">' +
                $m.ErrorCount + '</td></tr>')
    }

    $ips = ($ctx.IPAddresses -join ', ')
    $dur = [math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)

    # --- Sablon ---
    $html = @'
<!DOCTYPE html><html lang="{{LANGCODE}}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Douglas-042 :: {{HOST}}</title>
<style>
*{box-sizing:border-box}
:root{--bg:#050b18;--bg2:#0a1428;--panel:#0d1b33;--line:#152744;--line2:#1e3557;
--fg:#dbe6f5;--dim:#7f93b3;--dim2:#5b7093;--acc:#00d8f0;--acc2:#0090f0;
--crit:#ff3355;--high:#ff7a29;--med:#e0a020;--low:#3a8fdd;--info:#5b7093;--ok:#22cc88}
body{margin:0;background:radial-gradient(1200px 400px at 15% -80px,#0e2244 0,transparent 60%),var(--bg);
color:var(--fg);font:14px/1.55 -apple-system,"Segoe UI",Roboto,sans-serif}
.mono{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:12px}
.dim{color:var(--dim)}
header{background:linear-gradient(180deg,#0a1730 0%,#071022 100%);border-bottom:1px solid var(--line2)}
.hwrap{display:flex;align-items:center;gap:22px;padding:18px 26px 14px;flex-wrap:wrap}
.logo{height:52px;width:auto;flex:none;filter:drop-shadow(0 0 14px rgba(0,168,240,.35))}
.htitle{flex:1;min-width:240px}
.htitle .k{font-size:11px;letter-spacing:2.4px;text-transform:uppercase;color:var(--acc);font-weight:700}
.htitle .h{font-size:19px;font-weight:600;margin-top:2px}
.hostchip{display:flex;flex-direction:column;align-items:flex-end;gap:2px}
.hostchip .n{font-size:17px;font-weight:700;color:#fff;font-family:ui-monospace,monospace}
.hostchip .s{font-size:11px;color:var(--dim)}
.meta{display:flex;flex-wrap:wrap;border-top:1px solid var(--line);background:rgba(0,0,0,.22)}
.meta div{padding:9px 18px;font-size:11.5px;color:var(--dim);border-right:1px solid var(--line)}
.meta b{color:var(--fg);font-weight:600;font-family:ui-monospace,monospace}
.riskbar{display:flex;align-items:stretch;flex-wrap:wrap;border-bottom:1px solid var(--line2)}
.riskbox{padding:16px 26px;min-width:230px;display:flex;flex-direction:column;justify-content:center;
background:linear-gradient(135deg,{{RISKCOLOR}} 0%,rgba(0,0,0,.45) 190%)}
.riskbox .l{font-size:10.5px;letter-spacing:2px;text-transform:uppercase;opacity:.8;color:#04101f;font-weight:700}
.riskbox .v{font-size:26px;font-weight:800;line-height:1.05;color:#04101f}
.riskbox .s{font-size:11.5px;color:#04101f;opacity:.85;font-weight:600}
.counts{display:flex;flex:1;flex-wrap:wrap;background:var(--bg2)}
.counts button{flex:1;min-width:96px;border:0;border-right:1px solid var(--line);background:transparent;
color:var(--dim);cursor:pointer;font-family:inherit;padding:12px 8px;text-align:center;border-bottom:2px solid transparent}
.counts button:hover{background:rgba(0,144,240,.08);color:var(--fg)}
.counts button.on{background:rgba(0,144,240,.13);border-bottom-color:var(--acc)}
.counts button .n{display:block;font-size:21px;font-weight:800;font-family:ui-monospace,monospace}
.counts button .t{display:block;font-size:9.5px;letter-spacing:1.4px;margin-top:2px}
.b-CRITICAL .n{color:var(--crit)}.b-HIGH .n{color:var(--high)}.b-MEDIUM .n{color:var(--med)}
.b-LOW .n{color:var(--low)}.b-INFO .n{color:var(--info)}.b-ALL .n{color:var(--fg)}
main{padding:22px 26px 40px;max-width:1900px;margin:0 auto}
section{margin-bottom:30px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:2px;color:var(--acc);margin:0 0 12px;
display:flex;align-items:center;gap:12px;font-weight:700}
h2:after{content:"";flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;padding:9px 11px;background:#091428;color:var(--dim);font-weight:600;position:sticky;top:0;z-index:2;
border-bottom:1px solid var(--line2);white-space:nowrap;cursor:pointer;font-size:10.5px;letter-spacing:1px;text-transform:uppercase}
th:hover{color:var(--acc)}
td{padding:8px 11px;border-bottom:1px solid rgba(21,39,68,.7);vertical-align:top}
tr:hover td{background:rgba(0,144,240,.055)}
.scroll{max-height:70vh;overflow:auto;border:1px solid var(--line2);border-radius:8px;background:var(--bg2)}
.badge{padding:2.5px 8px;border-radius:3px;font-size:10px;font-weight:800;color:#04101f;white-space:nowrap;letter-spacing:.6px}
.s-CRITICAL{background:var(--crit);color:#fff}.s-HIGH{background:var(--high)}.s-MEDIUM{background:var(--med)}
.s-LOW{background:var(--low);color:#fff}.s-INFO{background:var(--info);color:#fff}
.why{color:var(--dim);font-size:11.5px;margin-top:3px;max-width:520px}
.ev{word-break:break-all;max-width:600px;color:#8fd4ff;font-family:ui-monospace,monospace;font-size:11.5px}
.hl-bad td{background:rgba(255,51,85,.09)}.hl-warn td{background:rgba(224,160,32,.09)}
#search,.tblsearch{width:100%;padding:10px 14px;background:var(--bg2);border:1px solid var(--line2);
border-radius:6px;color:var(--fg);font-size:13px;margin-bottom:12px;font-family:inherit}
.tblsearch{padding:7px 12px;font-size:12px;margin-bottom:9px}
input:focus{outline:none;border-color:var(--acc)}
.tabs{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:14px}
.tab{background:var(--bg2);border:1px solid var(--line2);color:var(--dim);padding:6px 11px;border-radius:4px;
cursor:pointer;font-size:11.5px;font-family:ui-monospace,monospace}
.tab:hover{border-color:var(--acc2);color:var(--fg)}
.tab.on{background:linear-gradient(180deg,var(--acc2),#0068c0);color:#fff;border-color:var(--acc2)}
.cnt{opacity:.62;font-size:10px}.pane{display:none}.pane.on{display:block}
.ptitle{font-size:13px;font-weight:600;margin-bottom:8px}
.exec{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px}
.card{background:linear-gradient(160deg,var(--panel),var(--bg2));border:1px solid var(--line2);border-radius:8px;
padding:14px 16px;position:relative;overflow:hidden}
.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--acc2)}
.card.bad:before{background:var(--crit)}.card.warn:before{background:var(--high)}.card.good:before{background:var(--ok)}
.card .l{font-size:10px;letter-spacing:1.6px;text-transform:uppercase;color:var(--dim2);font-weight:700}
.card .v{font-size:22px;font-weight:800;font-family:ui-monospace,monospace;margin-top:5px;color:#fff}
.card .s{font-size:11.5px;color:var(--dim);margin-top:3px}
.ent{background:var(--bg2);border:1px solid var(--line2);border-radius:7px;margin-bottom:10px;overflow:hidden}
.enth{padding:9px 13px;background:rgba(0,144,240,.06);display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.etype{font-size:9px;letter-spacing:1px;background:var(--line2);color:var(--dim);padding:2px 6px;border-radius:3px}
.entb{padding:4px 13px 9px}
.entrow{padding:5px 0;border-top:1px solid var(--line);display:flex;align-items:center;gap:8px;font-size:12px}
.entrow:first-child{border-top:0}
.empty{padding:22px;text-align:center;color:var(--dim2);font-size:12.5px;
background:var(--bg2);border:1px dashed var(--line2);border-radius:7px}
.tnm{color:var(--dim)}
.attck{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px;align-items:start}
.tcol{min-width:0;background:var(--bg2);border:1px solid var(--line2);border-radius:7px;padding:10px}
.tcol{max-height:420px;overflow:auto}
.tcol h3{margin:0 0 8px;position:sticky;top:0;background:var(--bg2);padding-bottom:4px;font-size:10px;letter-spacing:1.3px;text-transform:uppercase;color:var(--dim2)}
.tcell{display:block;padding:5px 8px;margin-bottom:4px;border-radius:4px;font-size:11px;
font-family:ui-monospace,monospace;background:#0b1830;border:1px solid var(--line);color:var(--dim)}
.tcell b{color:#fff}
.tcell.h1{background:rgba(255,51,85,.16);border-color:rgba(255,51,85,.4);color:#ffc0cc}
.tcell.h2{background:rgba(255,122,41,.14);border-color:rgba(255,122,41,.35);color:#ffd6b8}
.tcell.h3{background:rgba(224,160,32,.12);border-color:rgba(224,160,32,.3);color:#f0dcae}
svg.tl{width:100%;height:150px;display:block;background:var(--bg2);border:1px solid var(--line2);border-radius:8px}
.note{background:linear-gradient(90deg,rgba(0,144,240,.09),transparent);border-left:2px solid var(--acc2);
padding:11px 15px;font-size:12.5px;border-radius:0 4px 4px 0;color:var(--dim);margin-bottom:13px}
footer{padding:18px 26px;color:var(--dim2);font-size:11px;border-top:1px solid var(--line);
display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center}
footer img{height:22px;opacity:.55}
@media print{
/* Yazdirmada KOYU kimlik korunur: header/risk/rozetler renkli basilir.
   Govde beyaz kalir (murekkep + okunabilirlik), ama artik "her sey beyaz"
   degil - marka ve severity renkleri gorunur. Tarayicida arka plan
   grafiklerini acmayi unutmayin (Chrome: Background graphics). */
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{background:#fff;color:#111;font-size:10.5pt}
header{background:linear-gradient(180deg,#0a1730,#071022)!important;color:#dbe6f5;border-bottom:3px solid #0090f0}
.htitle .k{color:#00d8f0}.htitle .h{color:#fff}.hostchip .n{color:#fff}.hostchip .s{color:#9fb4d4}
.meta{background:rgba(0,0,0,.25)}.meta div{color:#b9c9e2;border-right-color:#20365a}.meta b{color:#fff}
.riskbar{border-bottom:2px solid #1e3557}.riskbox{color:#04101f}
.counts{background:#f2f6fb}.counts button{color:#333;border-right:1px solid #ccd}
.counts button .n{color:#04101f}
.tabs,#search,.tblsearch{display:none}
.scroll{max-height:none;overflow:visible;border:1px solid #bbc;background:#fff}
h2{color:#04101f;border-bottom:1px solid #ccd;padding-bottom:3px}
h2:after{display:none}
th{background:#e8eef7;color:#111;border-bottom:1px solid #99a}
td{border-bottom:1px solid #ddd;color:#111}
tr:hover td{background:transparent}
.badge{color:#fff!important;border:1px solid rgba(0,0,0,.2)}
.s-CRITICAL{background:#d32036!important}.s-HIGH{background:#e06010!important}
.s-MEDIUM{background:#b8860b!important}.s-LOW{background:#2a6fb0!important}.s-INFO{background:#5b7093!important}
.ev{color:#0b4a80}.why{color:#555}.dim{color:#666}
.ent{border:1px solid #bbc;background:#fbfcfe;page-break-inside:avoid}
.enth{background:#eaf2fb}.etype{background:#dde5f0;color:#445}
.entrow{border-top:1px solid #e2e6ee}
.tcol{background:#fbfcfe;border:1px solid #bbc}.tcol h3{color:#445}
.tcell{background:#f2f5fa;border:1px solid #ccd;color:#333}.tcell b{color:#04101f}
.tcell.h1{background:#ffdfe4!important;border-color:#e08a98;color:#7a1020}
.tcell.h2{background:#ffe8d5!important;border-color:#e0a878;color:#7a3a10}
.tcell.h3{background:#fdf3d5!important;border-color:#ccb069;color:#6a5210}
.card{background:#f6f9fd;border:1px solid #ccd}.card .v{color:#04101f}
.pane{display:block!important;page-break-inside:avoid}
.pane .ptitle{margin-top:10px;font-weight:700;color:#04101f}
section{page-break-inside:avoid}
svg.tl{background:#f0f4fa;border:1px solid #ccd}
footer{border-top:1px solid #ccd;color:#555}
a{color:#0b4a80}
}
</style></head><body>
<header>
<div class="hwrap">
<img class="logo" alt="Douglas-042" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOUAAABACAYAAADlGLBLAAAzP0lEQVR42u29d5xdZbX//17Ps/c+bSaTmSSTHlKAQAKBkNBLQhUIKAiJoghiARULWLBcdQhW1HtVQK8gFuwSehcCyYQSBEJJg/Q+yWR6OX3vZ/3+2CchdPD6+n3v1fPJ67xy5pyzy7P3s57VPmttqKKKKqqooooqqqiiiiqqqKKKKqqo4l8C8r/g2PoOzk9fZ1t5k++qqKIqlP+r0KQGMExGmY1DpCqoVVTxxlCBJvMWilFe+ZLKb1TAVN4bXvmdvGJvtvIC4Ga1qEr12ldR1ZQATU2GuXMd06+aiuqfpbG2oC60UhJHFKLlnFLqgyjvcJFBRcQ5SxgpYBSL2CDCJMBLGWxCsSmnQdpIkIZkrcNLo8k68YIanJ8qOrE70cQyTPopkn6z+Vldh9ulQeeKq97+Kv7dzVeBJuGYZB3d/XfbE2cenTntIAqjoNwVobkI6QYpOMiHkA0hHyFlIAQwqBHwPAg8SPqQ9DE1Fuo8TK2FgYaoxjA8ZWg0hoPLQk0/rNsMi1YXdvRtD3/LkK4fyhfGdGrTAo+5x4fVKVDFv7lPqQKivPuOWtatbJbhk6eq5wq0vuBRbgOnSJiHKA+uLIhVjA/GgnhgE+DXgj8QTTQgyUGQaYRMIzpwMDTUIMN9zHDBHwHJ4UZHNzo9LOVkTN74f3/e8MBD2bVue9uH5BfjntQm9ZgrVcGs4t890NNkYK7jyB/uRW/XAgYdPI6uljItt1rC3viERGLXTwwiHlgfNQnEpiGoBS8TC2bQCKlGSA2DmqFQMwwaaqHeg8ECQwWGCDSCP0L1xMEaDdnqB3f+qb/Qu7HtEvnv8b+raswq/rfB/v9/yGZl9s2Wv13cxYiz51PYOoeGvWuJgpDCZiPGoGJABIxFrA/GAxsgXhK8JHhpCAYgfm3l71oI0pBIQ8KLt3WIhCLiwDohzIusLYjpHOXCYw/wg9b1/tn5kR9pkZ9Oe4Ym9WieW/Uxq/h3FUpg5TxlRpPH37/WSu1Rj1LqeD+DpwfiVDW/RVAFk0BsArUJ8DKIPwAN6pHkUDQ1AlIjIDUKasfDwPFQOxwyAwTjC05BHVgR1KAh4MBGQk9WzJZBuKnTfde3Ofme3PAP9co1jU8wY4HHppuqglnFv6lQAmxqdsxo8nju25sZcMQKwt73M3iao5AXCjsE4yEogkOMD9ZHjIBEiBQQm0NsD2JawL0E3hok1YFpsDCoAVIJKBghKgEGIkEjEBVKWWRHDTQeHrjiWjmt3PDBTu4/8smqYFbx7+VTqgrz5hnmverzFSssK+eWGPvFj1M34gbqpxbZ9AB0LjREvbHGc1Gs6nAVno7Gn2kkaBjnOsUHa5GaATBsFEw5WZj+QbDDVHNlqAFSArUgDaBpYIxQP0Bd74/avWjppsu584ifMGOBR/O/uo/ZZGCu8LqMqNkC86KqaPxbBXpeBzOaPJrnhoz97DcYMuUqBh0BPS8hvS9CuQsknjsahaBRrDnFojYAR0SxzUl2g9VSF5SzUMqBKyGjx4ic+Sn0oA+rdkSQDCFtIQ1kgBqE8cbZgZG6H27xdMmmS5l/ws857l9fMK0BMRZUd0umU4er2gn/DkJZSYM81FlHV80ktpUd3XmhuyBsbzNsWbeVxedugtkW5kWM/drFuI4TcEULxhDlwFUSldYTxBOM7zBBLdbbm6BhLwYeiIgfadtj0LvUSLlLNcohpTxa6ENOPRd573+hXQk0CCFpIKkidUY1pcI446QhUr3yRY+X1n+cR86+kdk3W+bN+RfTGE0G5mr68M8ektu6/j/I93ixVEZxyimRDoKa9MOlNbf/qDI3qrTEf0mhnKEezRLyue5v0pqfS9vzZfIdPtltEaWcJdn4E5679PKKtoze0UQY+oUMtusIgvQnqBt7rtQdoNqx3NG1SKTYBeU2UIf2dSAzT0Eu/DVuu48kIzRlIAnUCpJWdJynks4rX3xUtL3nFBbMeeRfUDCtsTZydYfe8+mPvXfWycdNpVAoYq2H5/s8sugprv3lXUtN79MHRVH4ryGUqsKceYadK954rjdOVubNcW9/vCrMnhe7Tbv22zg53nbXfmbPtuyc9Nby9ertAO+fug5rTABfCboTpHkhsBphoSb4VPe55AFqfVweqLEEGUiOnM+MBR6ppZYZTbCtwcJaCHa8fIFKfUJQq6xkDwGZp7T+ZxZ4GHiYcZefr1H+Road6CGBasfDgjqk1IHUNaIL54P3CcwFN+JaDIgDZ0Bi8401ZeGglPKRSZamv/0Y1WkI/0IC2WRgbpSY9oVRyfanZ3zz8xeGQ4Y2uj0W5vD++YsC7en9azzsGRaa/++a8E1NhrmAiIO3eR9nz7bMewt/uqkppmjOe9N9ylvu5w33PdfJP3VFerMqjBnbx1IT1BCilDqhUBaiguOpQ1b+zzT9bMO0esOSG8qM/9rZ1A+9hYGHKduahZ7FSLkbzbcgBrSvHXnPB5D3XYfbWIqDPwkT+5i1AjUg+6py2W+sLtt2OGvmPvWvoy1neFaaw2jAMVece9ZhV8/77X+W87m8J8bge562tXdy0Mz3aVd/wyHhtluX6i6Sx/9JVFwhAa7uH8biuw6mu7sBZ2LtpmWHhArWYr2QmpoN3Pmhp2MBfpNx75oLP++u5867jyLXl0ScxYVKf6/iFbIc+eFHuHZikXffeDjt7WPxkkoyLRjPoU7AQnzRhbDsUBORsVu45bxnEImgycg/Rx5VREQ/0tJ73IBMMLUzjAprjXFLnK/FPBF9EUZsVno1ZGdE1JpXduYgl4f2vgz9OTF9XUp/t6PYLRRySjmnlHoNpZziyr5AX7R+1F0w9/VX72kX+yy5ocz+V/6RsTM+QI8rsf0Oj/wGKHZAcTvYAPp2Iud/SuQ931G3uQQZg6QFrVFIK7KvH/HtX/p65+IP0THmT8zYGNC8MYTGt2Ha7BRmAM3NFTO8ycBC81r5AJpfTwvNtszYKTS/xsbROCLaZJix0MTfv/p8dh1713c75eVtdwr0i+ozKgMOfvYvN1514PvmvDssFkvWGFHf990f/nKH96GLvvzczflVR8yRme7lbd/pmPfQzK85153y1vvc9Zt/OAJsAMeH7zmKF5ZcZkx0ogxvbND6WtTYStTegTGgEWT7YdtOyOaf11Ejv8wDn3/wtYKpAnMMzIt4/80nsHn7jWbUwHGakHjEpRy4AmzbAm3rVoB2SLrxOBk/GZeoAS8VE1rkZWKMEIErQxRCaxfaFy1l3KjP8dfzFso/TUsuXGhrZh77bIA9sAyUgFIXaCtIC7AdtAVkRx7t6ITenUiuDc3uhHwHFDqQUheUe9ByFqICEmZByyABGgzfzJQP7csDp5deGcLfcxVboYwdcCBjBj/NoGMs6xZA5wJwOehdGV8460FfF/LZr8IJXxRtKSl1BlLAIIM0lCL55Hd8aWs/1636xa1G4uv5tjxzBefi5M2uG2tftb0qRPqGe1HvldVne/7eAM4C8mox17c4LxE0UqKRZx4xsrbniWWP3xHVN9SbMAxRp/iBH57zwUuDO/505+W+t+0nkcbz+hX7fpNS8pfH/PIR3/BcXzPiV/7tot37+sc0pLktYsa3r7Q7W7+ZOOEw8c+ZSmHymLBUm1TiYHOFylkZY+iQ7T2iv3rE464nIh05diYPXPY4s2cb5s2Ldlc3WQMn/dcVsrP/u+b8mZZPHVmKbEWpSYQ4C+d+Cxbf6atNkJlxZmR+d4XrixxSmQBx0WAc96xYlYJTpCMv+ssnPe5+vJ9J+x3p/RME0iDieKZrSv8OeyCOuKojD3QBnQ7dGSIdYYHWktO2NqGnDbKdaK4DKXZDsRMt9UKUR6MShDmICqgLnURF8JIBqb0u4YHTi7tNk1djl4m5UZcx8tcvypCaKdo2OST7kiHsQIIGNL8tnkGZgei1V2Pq6+G4j6I7ChAYpN7DrF6H2/gi/mD/qOKBn9wYbd02A4km4PkpvITFeBJHLNXhnCAlQ6EfSsUIp33UD35mxo9vu615jvTXT//EAV1rV51PNg9B0uAKgu/73oiRaw7KHH/DkiWXhPG0jCPUwcEfP620fv2JlIsOnFAqOGrrEplxez1VWP77P9lDLptUWrXiXfjBPmgUgApe0uLXaByRNgpOEBHCnFLoVcr9QjHrMXRITjrbps5670nUN9STz5cQIwQJn9bWdtP82BJl9L7vLvaMmUy5GGATiucrNogXBOdARBCJZ5lzgqqjFGVJBksP/Pjnbl72/TO6AKwVTR72zQOyq144Ee2dCJKqFBUoVjyiUIkihxEDRDgxWPEolyMyaePXD3iwvOJPv+edmNCzZ1tumRdx7FXfkb6uryW/8b5Q33eE6wELkdlT+uN3EZQVfEHHDUK+PbvAzp4kCxZ/DSOnM29SzDqbOzdkudbIRVf+XHLhh+Tb74vc6XuHGkXebq3r+7C0HVasBK8cUkpreMZxtpgwlnIo6lteTrBXElBOY0/XKjqyBrnypKIuXVvDsuWffGdCOVstk/ZYxxcClyDMWGC4PdtGV/8PxKmHRpGWspDLeoQFpZQdot2dHyLXA6UOKPVBKdaGShTnFF0BwjwSFUDLqLo4curVQ2LUNaz7/gNvKJCv8CUkIvrVeq2LpjBkf6V3PyisRktdkN8WXxOjkB6A++431AwfCoecIdqWV2rAzX/cmmKrK7ZEn6+t7fn8SWdN4+AD9qMmnQQbV6uoKi4K0SjESIV1pBFdvVnufmgxzZcc+tVhx33ygh0rnr7uwvNOP+ygA/enWArxjNLTl+cnv7mTlf6mO4BtcXBBopqDPzPE9ay89StfOy9VV5shcuB7wtp1G7nhplsKUcPh7wm2P3PWOe89Kjj4wMmkUknUOcQmkEQGkxmACXzKPd2gDglLEBVx5TwJ33DrPfNpvucpzn331a5yBVCnGODB+c2mY8sqTTQMPf6yyy4+fujQRsJIECOYXW6Y09jsEirjd4hANlfgvvmP8dQvv3XF0GM/fdJ7fnxt6w3vOf1XbmvzuWfOOtybfvAkalKJ2HRD0N2JUOVl7oIQOUcyMCxa/Dy33/XoZGPN7100923Oy4qvd8r3T5atm75mfvCJUnbWFEuh5BEYKHvQFsZKCuJz8IAhXrxIF0toOvCZOUXl3gen6A2P1vKxh7I0zw356J/3l/d+7o8yeb+p/OADpWjvOktYNmBiwXKxiEvzCrR7K2rKRuobMPuOh9ZQKEscVDQSv8SCi4QAqK0kifMlNBVYJo5Rlr808Z0J5Tx5rUA07/5/C/DlN3QYpv3qBoq5fQhLEWIFLy0Y4wh7QqK8qlEPz7d4PriyUiqAOMXWlBk8+S5aEJjn3mK1hHnzBM9XRljI1kHrWNBeKLRWfAkf0djHVy+Ju+ILmJsa0f0OQ/r7kGefI+rv5pR3HRtd94MvyT77jAvfwuh6Bb5x+QWcdMb5+z3+9BOLhg0b4P/3j75cSqXTu752Dzy4yPvO9657yq25t0Xku8LOnWIFcisWvueUM45Izf3yR/PsQX/86XU3Um5b408/euacG6+9Sg+aOqX0jxg0v7rxRvbae5Q56qjDTK4QVpRdfDnvuOt+RHMcMmlC+P25n3d7jPFtpUWarvioO/3sj41/YP6jf7rhlGk6/YC9j/zNz/4zOuCA/d/Oue55jPCZp59NaG/nnS6MRGRmAI3lt9zD+vkGVWXCRf8h7zlBddYUob8gpHxYX4LvPATrV0FUABch1kCUga++G84ci5aLlaM7ISpGbHleYa7j5KZz5bEnr5czjmvQq84uacZ4EMFWh3QU0WkpKApSBF2wBLQHIkUL7eQvaYKgXvHS8e30g0qRhSBaVOr3gR+/G93Lg4IgoHT1i1rX/TaFskIA+FLuPCJvMOVySISl6CBfVkqRUuxXwryhnI+gJIRZQ9inRFmh2KcU2jop9ffQ12ko9QlRHihVbkYg2FJIVFDCgsWFjro6EONRd1QHL3wxh3zprYMOu3I9AxqHydg02kVc6uU3gq2trPQVU0IVSSTRYhn3qc+qmX8bpqWPcOkSTpk1g3v+fI2IMXT3FT11Sl3KYERwIEZEEYgc9OZfltkwDBnSUMP757wnfPThSxJnnv9pTaXTXntXFhFh0MB0+IvfzPO0HDzkGVGY4dHc7PA8nKcXnnfOqQBee1fW+r4HLuK/fnYTw/cap/fe/qty45BBpqu34DmFTCAk/diS3nN+d+edKKiIEEURNTVJHnv0KV54+jG+fuVcyaST2tWTx1iD7ydYt2EbCx59AiXgYxd90ACmFIFnX/YR9VWea+Qg21+IreQwZHB9hgs/+O7w/jtuPWL8pAO575aflwcNGWQ7egqeNcLA2sQr8gevvpEugsCi6zds47Z75qs/fsrtEvtchbflyy8h4oTGieKKx7o5xzjAYgxiLfx4Pnrb98DrAufiY1sDMgKyx8e7cBoLxQtrUZfr5cxLLXes+o5s2PY1Lns/eumJZS2VPTDICzn46VL4+sGxm5bw4fk2WPo0mBAJI7RvJ/S3VY5TOUnxEBOzuTWMYL+zkZr3xia0Z6A9hFWbIJV57u0J5WwM84gomDEU/O/T6ccBmHIhprWFWSj3xGZp2A9RDqL+yvsslPvB5WLfdkQN6iWACNEQJTZTKYex2aVR7LK1tUJyNPgNzczhYWjSN/UvdqVkDlg8lOF2f8YmYCMGOwQSBYgW7q7VjMMmNo6d1A6Ejm70C98iGjqe2lTIf33nCkJn6O/LYz1LKulxw7M9PLy5gAusUnZorsxp4wI+MH0QhdBhRGLaGtDautMAbs65Z0vJgVMhnUqybmOL9+iTz4X+iH1uK29YAtMmiixpdtGgMw8YMbD78JNPPM715Z1VMdTWJHjooUfZ/NJifnzNL6RxyCC7o70fPwhIJwxPbyty96oCZc/D+h6IwafEJQckqfXiYIkqJDzDLXfeD2KYdfq7tK8AxRBcOaKxBv720AK6treQqGvkN3+8g7/cPp/Q7QoWWo3nrCKA5/lE2RynnXkyl37ifHr7CqgaHNDZ1WegJ/zqFy6hfsggu621j1QyQaEc8dm5v2Pl8uVY63DlEioGYwwiYI2J7z8qLa2dQb6sj39z1Z+Xzz3joHpZ/sJVGDdSvVQZ41f6MgVgawzWF8pFpdTtSSK3gzVP7cPBx4k5aJxz2bKQ8GB1Hyy4DUxbLEC7oq6lENlrFBw1Di25OPjXERqeWOLE9uyjZ5y8XEYdMMpc/6XInbAvmi1aMgm4ZQP69V/D6YfB+Ax0F2GghUeWQvuG2CSuaENKDgoOErWIl0BdHOzFGsQMhNknoIMsdBWhPgGPv2TZsiHPlAPvfGuhjDvCCbOXB1ybvJoP9w/B9y6mlMvhhRZViwsNViM8q0ggEIHLx/azoogKRoyWiiIDUmm55ApVNzBm1PgOfIdk4lxhzagM5a//Qgt/+TMyeJ9eHXj4h2Kzucm86XnOXGiBkNrg+MQBoweG4/xy9LizlMqCFJXc2rhzgcTDkV3cWXxoHIVtrSd89HZOn3MK48eNYWdHFs9aGlIev2vezCe/8QdofTIOQqlCMcHOj36eDx5+Cvn+HMYaVKEn57jtrgcZu89+cvDUqbR1FglDx4CBxt37t0Ve5/bup7Xw2DKRvwhLVqk1EHav/+BZHzzHHzRscKllR9YzAqGDm/44j0S6gVNOPZ2WzjJhZPAVVm4rcOqnf0PuxYUgYRzNKxSYOus8vnzNRdrTk4utAuOxYVsPt8ybx0HTj2Dc3vuzoz2LZ4XIKf1Zx+133APiU+zp5bGH78dLZfCDABVvt2W5K3poDLhsN4dM25diCL252AxO5OH2O++hduAYM/PEd7GttUS5LPiJgGeeX8q1V30VXDam8lEJR+uu4oKSAobU6I0EyWtq95p831xjHCNm/5gjD7lQph2NliNIBkgyQNIBmg4gaUn5EVFvkeIPf4G0rIOZU50mMLRFkPFh/lLY9mKs9l0cUxMUDT048jAYVlMRrAT8fQ1sWQ25ciCHHTyK675cjsYNtvSG4CWQ7z6FXn8NlDqQEy9AS0AkSC/w8BOgfSgmNk9LARx6BHLS0bD3ODSVQXSPaHZDAxwyFjrCeD7mCfldc6CmPJ87L13+1kIZN5h6WUP9tuaLNOn3ySbibbvxKGIQIiIcEQI5yFVerlPo3WgYPV2Zf96tWjz2MLk3CunaZLS2BlJJqEuhDRY7NUH/vQ+iN10fMuLIQBNjL+fRA7e8jQS+0DhTURU769nPDz5pAC3dCE9sg/6VSnElFHaATcVXRQQ1AdgU4gdQNxU3/kBkw72cc/YZ7Oxx9OZdvKhGEddc9wfMC7/C94pETjECYZhgzpQ0nVno7I8wEpGpyfD0sytY/sxivvLNJgokaevqxrOWoBd3290Pg03eYY0o06b5LGkOJ13+t8yLv/vqeaef+i627MT0ZyOSqQTrNrVz11338a7T303t4BFsb+uJFxMvzc//cDe5v/2QZKpAGKlaIxLmQy454jN09kN3b4gIZAakWLRgPu0tL3H5ZZ8hG/p092exRvATKZ5+7iWeeGwBYkM+fvElnPO+91E/qBFrLFEUm3rxwh+bXZFzeJ5HOjOAdVuzqDrSqRSr125hwSPNnHDCsURePTvbevE8S2e2j+GjxvDIYw9SKisqlZwEiqjDWMGFRVnUvCi65mc3DfXqRqzrXvr71bbx1LOjQeYCnXJuQZdGBusgU4vWDYSGDDoEyEBhKsgzG5AdW2DQcOHIg622AyVBOoAHFqFRN4hDVFVVREUgqIeZh6I5oE+RJMgjT6GdXfCRi1W+ebFzWEtbCD1l5Ad3onddD7oVmXgi7D8GWkMkGcDzLeizT4IXB9ElMRS56gvoB05DMwbKFUNgt60OlIHOEqQCpI6Ibz3o6fPPldl336+zJl4O39wc/Hl2Gp1MY2dHRG8pJJsVFj/9MA8etuUdZXRXHHKpG7PvYTLhvLJuXWrFF+jLQDGD5pKC7EO0aKHyiy9E1I8LCEbN49k5f4Qmj3lz3pzuNelmn3lSYuYTn6mZNebQngmJsv60YFnxZJwgbV8EJl4nEYMYD0wi7lZADTJhJm7nQiZPGMXYfaeydks/giOTTvDcshd56Ym7ISGUNAlGCUshjePGM3XyRNZv60edI4wcQzzDn/50M55vmXnSLNZvK1AqOJLptK55ern/1DPPFIO9Dr619OIzQs9pRpsQ+d5XTp12xPi9ho09sLxpa7c14qgxA5h/1y1ku9Yx68yfsrUtItsb4vk+uZY+HrzlN4jNUzI1qIEwdAzbdyz7HXIE6zb3oc7h1NHoOebdcifJ2r2YdtQpvLgxiysrkSszeHAdDz+ykFxfLz/6yc9417kfYUd7gY58Cd/3SaZSsZ6s5CGJG0HQk82yo7sQGxwaMWjwAB64737CfCsg9BQs2zsVa0OMxFrR98fFBhSKCHjWVLaPJ+kFl07Tzs7u9C+uu+krU86/9e/LHvrJNebUj0BnwnP+FkNNHSYZockCBIAJEM8gPZbo1/dA7xaYPgsZPgK2l6EmgaxpRZ//O3gR4hzEBBcIHTp2HEzeH7YDzoftJdz8RcglF8BXP4HbHgp+GekowXUL0BX3w5hapG8/OOn42BzdUYRGD55ciiQCNNmI9CvyvavQs45Bt1c6vtUGsWGwK/9ccQ1IBOjGrohfz/d5uFkZ0fhpHrhiKbNnW+8NNU98RxJ8tudPtJt96WmFns0Q1MDw6ceAbmUGlmZ5ExJ5kwdzQ0Z/8FgNt/+Y/S+OdPMWg+sEF0C5iBazkBimZF8U7vqSw0t6JIdvIjHp4tjpuzKCuW/MFbxnhGXJnBJHzz/Zjg5+5D4wJOy/E8O9iyFcC30robAFMUFlZvkxs8dLx6/MNGTfUfCbhZzwsQvYkU3S2d6BGEOjWO65935cz3a8jE8URXiepVzMceLRh5GlgdYdHSR8DxVDOerk7jtv59CjjiPKjGPNlh6MEQbZwD38yAKb7+pf4LXftEb4LbqWov9dD2zxklNPncXW3gSd7b0YI4wwZW677TaGjtqf4XsfxsoN3XjiSNcGvLSkmZZ1L2Iz9YqLxFiRUn87R00/i87SQLq74/Px/IDs+k0sfOh2jj72eLp0JK1bu0gnvdhH9LNyxy1/ZuphR+uk4y6kecl2EoEhkUzhsi20rF+OsZYoiioaMzaGxuwzjf4ojWcdYQRF1899996L2CE88fiT3HvLr5l0+BkUyhEiFmMELZSwolgrIAEdfSEuihAjOBfRnhssg0dMANdv1q76+1SSg0Zp82MhutjgpVT8FOr54CcMyTqRRI3iWdVCN6xZqgQDkJkzhRxx6sP30fl/R9s3QMKgVJL11gh5RY48HAlq4/z0wCT8fQX0diFzzkVXE/uDSYOGglx6DJKYiTjQKESDJLoxhMii5RCOOwY5cjp89FNw8hTR445BXyioZHzwFL1nGdrZG0dfXQiFHFrsRdralZWbfM12r2FYw6U89q2HdnFvvTfwI4W54rihbRzGhnhdK6hLK2ZwAP5T/HnI4/ANQ/OVEderx3LG0LMTentg51qINkWEPV0sWdLPGc+kWfzZG/XQT/rkvDKl7VYE0bCk2CKESUgPgQe+rnTtRAZNEXWZT/HC2T3wmQBmRjADZszc4wQXxrSuuXMdBsd+f5ol9bk/8qXpft+KIOLXjwkdi6C0GXpXxP6jxsHcWCBTkKhDGYwcdjZR2yJqwxzjDzmBZRv60NCBsWTzrSxcsBDEEpZiG6TcX8QmLdNnvIflm3JEJYfTIpmagaxY8gDtLau46FNXsLLF0dddxqkn6hV4YsEDUE6sDCd8ehRtXT6Z2jBsWXTmmAkNJ4w7+ORo6dpOa3FYP0VX50s8u3gBZ73vAjb11tLa1o5nDSN9y7Jnn8Dlt+KKAyvF34rxfY4+6WzWtuQoFh1okbqBGVY99iClXBtHnHgOa1od/T0R1jr8ZIbO1uW6avkSvvit61myvki+r4wXJGnMdPFfX7uY9SuXxQEQF8X52bCP8ftO5LKr72FrVxHfKsZP09GylKXPP48GKfpzIVd99as0jv4ZfiJVMbY8xFgER1ToY+zYkXzg89ezrRusiSiFEaOToqtXvaR4A3LZp66eL3tfeADLNvlkhimUUWlVylbxBwipgoVWyLYbTboSmeL5DB19BQdMLes2LKGH6Y7QJx4HvxQ7wlJRUwYIMnDkcejOmNwiSeCBR5CJ44TyYNVtZQhsbGZ6SdSm42D9rkSRc7uyvDEbqK4Gtm6Fjm7kXaejm1F6BQKL3HAL+tdfgl98ufZDI9Cy02TSMmL/q1n1q6+wrhDn2Cskdu9N/Ei45LrVLLjyIGbW72GH2hB1MGOmoVlCbv375+l8cS7ZNSVKPYbiTpWgMdABk8+AeQ+xaOtP5KBZ+2rqkLLseNaqTYIrqaBoOQd1I2H1jdCyJJKB433F/yabfnxffLBriy/nQ5tfS3Ec+Z2DGJC6zBxb/2EuOYZodSLi53cbtjwCpS3Qux7RcI+ueIlYIIOB4NfBkFnYg+oJf3Azkw6ZRq/Ziw3b+kh4EBJRrAkZ1uBT6EpjfB+AGhNy2nmfos0/gI4tPQS+oVCGickyd/3lhihT12iTw6exYmM/vsZpkpIU7YR993OtLVs/7SVfulhHGwi3msaRI9Onnf9591xLhkIuizEwsD7Btice0Kjcq8PGTzdrdxTJ9jkQ2N7Xw/ipp3BWoZuSQ3w/hbgyIyZMpd07gO7tfYgI5bKTCYkSjz5ynzYM2w9v6OEs39CDT2xmD2r02fzwXTQMHsHA8TNZta0fCRWT8Nm24hHWr3wUEnXgSmDjjLuP45SzL2JFW4a+ng5EDI1DE7z45EMU+rpJNwwhmUzhFPr7u9Dejt2cNlXFGIstFRl29JFs6PbZ3pYl8CFXtiS87frE44uE2rEPGJEIWAFA7m34RY2n1XDYoZAerGwpQ8pHt7eJrnpRKXkQxiWjGISSIqecgkw4ELe1jJgA05EjenJRJJ+4CC0jeMRj9ozu7nZhjEGdUA6hvxLMMYKmbPz7hx9RxoxFRxyouqWMpHzMhp24u+eB2w7F4OU5awOwgRAlYEv7sex1/oOkEv/NCz+7fReD6S0CPXMdx79eGkKFZgn5qg5lwW1fp3tzgrA7Qbk9/tZmHuL5Tz7EgFM/yLgRH9f9LyizdpPV5EAkLKLGj9k76RHQ+Qy69nbFr/G0b2sO3VwkNfEzmKTDpgQ8QROCXyckagXFkkmPYXDjoTJm8KGcdIzHfuMi99fNcP/fhO7HobgDCl3xama8Ss9YH7UJJBiEJgchZhpyzunokmsjWjbqoBOPsJs6rbR2hfieJdIy7b0BR37wJ0zPdqMIgSckMwPoDAexYn0PVhzZfMQ+E0bokgeu0WXPrPDH7jPUteeTbNleJJ1SVER3bsoyePoVvPuQj/jGSmAQokjx0oPDNdnAZLf341mhFAlBMsdzix+0kKCQz4Xdnb7pbcsTJBNEUS/bgnEMOvpbGIkQEVQNHXlHy5Y+PCtxSslPa+u21ax49lGOP+MDrOpsYEd7B4FvKJYNdXX9vPDkA4ydMIG13QPYsqObwANHluEDp3De5b+kUCphjSBiiCJHzYDB9A06jG0bugg8QzEU0qlOnl78CH6mlgs+dzVdZh8kKuB5FmvjfL6ROKXinJJJJSgFI1iyOo/ViHxJ2XufYW7Jg1fZrVt7uofM/MTv2+5bIHHZ2MzXT381Vf6/5x7LM2dEDH12gjQ0Ir2I9imUIrShTvnSF5C2dvArPAx1UJuBqUehO3ykM4+O9nF/u9vR1+Hr3YuRh1ZVOKJU5o0PBqTch7qEk49+AMoj0f4SMtzCnX9GVz0LG5Yhc96P9PvQUwJncH6IfuyCOFps4hJBrEECD8SKqqr43lHc0oxu3LgRuJ0ZGJpx3tsjDrzC3VSaEOaidLePYvD4+0nVlij1QK4lIgwt6fFfp/Gi8dQVfyGnXhHpet+QTCBhHSqlOI+ZGSKq7cqKnyGpIcKgyUrtqKR4yasJknFUNuXHq1bKg5okmkjGF3nQQKR+OBQSzj27o6w/+5ulbRniNqKlbiQqg/HiAHjFhxQvCckRaKYRwolwznnA804fftJn8Fi2rV+tex1vo82daeO5QhyhdRGrXQYxtYgqxjM4dRj6CYKA9IC07j82iHY+ea1/xx9/KXb09ObWjjVHhd1rpBicKO07W8WIwTll49YQ8RsVEeecw1iL72O01I9iEHX4mYHUbn6Sdes2Z039ga1Pzr9l/MkfPzF6acBoyZfKiCeUI8eG7eWYhup7pIMQU+qlN2swxhFFEYMaA1585iGiMGT4xDN5ZnUZE4FohEsMoHvrs2zd3BINGNigxbK1W7pSkjJFnMK2jgaC4CzUxtRMhyC+xRSV/Es9JDwPIcJLD6Rz60Ld9OJSphxxoqyTd7FyXZZkYOJmgrtyKCIxsxGN/0UlUskEQXqA7r1XKsouu9E8dP9D1h9zzGVt9316R4VKGfLaUpmKntidPBfMXMeoC7P0ZZ1alB4g5ZCyRSfMQA+I05q7OUMlYHsE/SXMyBS0rCtzz90JGifcRXd0m0bbBaWMNYrxDepbPEJtf/4iRo49gcSgSNtDI3gxQaD5lojudUJmtDD5WLQFyCtaLkN6GBw4C/WBdGwmaxC/EKAW1FKSPz7tkR70lz0Lnt+GUL5OjeQu8/a/hywB5rxO5NZj1B1PyrkX1mAmlvF2WGoGoaUshAXQITAgUnn4a3HTZWMhtwOK3ajYMoJizct8QVvxByp/a9mh/Xmhp98Q5S1+BNahzsS5UZuIw+9iwQTg16Dp8ZAeDDoROecMmNLp9Fu3eJoZ+CcZ0LBt6epVl41+5Lv+IYd/OGwp1mgkQiiCSVjEGNT3MEDCOIJI8fq7jex81j731zvt08+uCM3gQ77Glpt/mK878pcP/P4HHzvyrNDlRh7ssmIrQUbVyDmMQNIzROV+MybR7ba50ZoLIzFE1DfacPO9DyVLhcQdqwtPfnTfuqkPZa/5yDGTjpgV+TZtRBXr+SQUFIeGBUYMTtIz6CzWtpRJJ4RC6DGUfp5b/LDbZ9rxrv/wd9GzBmr9gRSIGNXo03LHQlFviL96fRujnruOA6Z/LGyNalQ9S2QMWRSxhkCgzhpcT79MqMvr+vIQOgplnIYMGZJk/c3NHqaekad+INw8soYgVcKmAhJWsL7gWYOxgkUwAp5zmDKYbL9kOp73WubfZ5/6+xJMw8FfjlZdf9Nbc5tfQ6mEEZNv56Ut7+Wlp1UOPjTUbgwVRptqpXxFFCKJeenDrWKs6vPLDH/4S0JrRj/Mb793LtPljel8oz5+ppz5HmVcMiTESiPCY6vV5Ys+Qa3K1OkR++wrugWlLlHp8VBJf9iKS+u5uHJLnKgFbfQcd26x2lbcwJdPeoKLvrOLkfY/bQdSaYswD2Ae7D3MY+21RUZf8QM569AvMePckj5e9Agd5MtQKiAlB/VpWPAJWPcYmqoDFyIaxRfxFRyqPSqBdsWUpZLMtjauj9v15C2pvBcvNj1MIvYhU2OhZr/K1ZkAHzhR5eAO5Tu3etqV/RbLv/RNFDjoslm0rrumYVBq/ID6BtT4RDaBeAH4AyDZEEcTNY9m28l2dtDe2t5KWR/39j706vDRLzwFmL1/qv7aH8z5kUfHR4YOHZImSMSNMlVR8RHr4WtIrreLcqHEgCGNcaFEVAKU9h29pTBo+IRrWTYZT/cj13saYVuFhyp7pIwt0MeZF36bNfWXUuzvxFoDiYHsW7tE77v2C3b45KOoOeI4QvFJ2CTOGpIux4YHHqS/q+uPZOp3aM+2Dw0fOajRG1CPMz5qawn9NPgpfLGkrdK1YytazJMZUk+pkMdpEaIy7Zt3hKpeNGDUyIRNxQuhsQmsl8L6GTwvhfESEIZQzmK0gJb6yfX20NGyrSfKR4vt+KOujh7/zMLKgN5hDWWTQa9Upn3rlyL2o3Lc4ei4sZAO0CCAZEAy6eEbQ1/JIfkC2taHPLcKlixxmsz8ilmXf5650s+0i33Gn+TYuUJonKys7zKMr3eEtpGXXthsZp/hyf4TiHryoCW4dwGseHQT6oaYQ49Nc/wMtC9ErRdXjXg+4ts4aORbNOmRTvkMSnj0lCPyxSzh3WvR55ddyzMf/+zu5nH8M3v07ErwT/7ZKTKp8X6+/u5In7OWdgc9AnmFbIQ0JOHJ78Kjv4FMfRxM2FXRUjFxdvM5BUUlTs/IHkIqux6BZ15OoO0pjCYD6UZM7cEQHIArRjByJPLJvSOx2z33g/uEjr6vsPzyq9EZHtMmCktuKE/5nWaWfu8Hh9Dd1oBnwabZ3cLS4eK8pgUtlEnXdnHyZavMT21nhdi9a21UEdBTbh/Li817U+rzwBdMYPEqhkmYA1wHNTVpevqTuFKIlgx+XYLxk9ew7KbLDzr8sI8OHj0Z0WLk+SmJ84WKQzFEWCJS9aPZnpzBupYc1kI+LwybOCIKXrjSLnt85WMMGHY3bTtTeDXgBXHS0NmAwcM2s6LpetRRM3vRkP4l90+hlKvFpg1+yuBsRfIjiEogUQc1qQx5AqLIEeYMfuQzZORqP1l25S07JuK8CJsCSSrGF6LKtopBUjF/UkODyzsGDOlj0tmrza3jtjkX8Y405OuxX8UoJ940h9bt5yLpsSTrhKDWYNOCScWlMOUclHJCmOvGlJ5iWOMt3DXrmVdwu1+zb4UZCzOw4WfkdX+iRIhEQilvSdLGxKkXsOGpk8mXL6O/oPiBYFKClxAkAC8peGmDJBTxHJ6vGKOEBSHfD8mom4bEp7jjtPU0XSnMnev+eULZ1GSYe6Vm3v9kYz4fPss3Dx7ukjURa0NDr0CfQo9DagNkxe3oH76NpmshKu7q34qoq5Rr6S46VEVMdzN648CGVITR2MrjDJKxRrS1kBiGSY2Dusm49H6QT0NdAe/4eufPyrji4vWB3vj3rDr3SZ48//fozRZ2NSyKI1/v5ILo7pBaE3vwcnetGJG8je1f80TOiXfU1robNh9+0Y8yz23bh0D7rGJit8jY3ZXrxkChGFEo5Ag8S64saONApo5eHy7/7+8F5cReR0XPNS1+dZ2HvFw0Jbv68Pyjk+DV9c78Q9fun9Jn9uVRWrvHCekeC36lsPkVVdRNBq7U13XRXsN+kd1sMHZVI+x5dGNfla7XPRRIRdG8olpN3rTa/Z8glJXnPZ6z7DY+PvFsTvJLrC179BnoB3ocJHxkcyvMvQbdpeRKO0DzcWcAV44VzS7mrujLg9nlH6qJNaIkYy0mabCDlGC4kBgCqb2gdjQMq1V/34QeeLTnBk81pmNn5L3023XkFr30qA73P83dpy/dTWx4jTk+x8Dst1nKNtu98Q1tMsxeKa9m9lc2hHm88jDP9Xmzp9aG8/6Wu3jizCk/7z3wW6Xt67q9IGlevp9GUGNQA2oN+BIHw+qMDh7r6YghLtx87a+T3Ws3/05WfedCHX9pgpENrz/hm3eN/e2M+dUnS9zFrbkyvWdgdndle9tlgCv0n9oDaPbNlnnz2KO8T9+wXciMJsPMK93bf0Zp3JrzVZ9JLNBXymu/e8u1l5cVwWsXBflnXAwzb07kzlv16Rlnjrx28nmZ4p1h5HU4SzGsRJgjYEeI/roV9g1AEyLdeSVXgGwZcmFcJVIOoVzJ0pYjtBTGQ7IekgjAi4M+mvKRdBCTjtMW6pJIfYpMvcc+g0QmDcY0epa+TbBgfivrntixTMPSdcw/9EZE3P/SZliGm1XM585ZNO7THz1y05ATQ9eftWrs7pXV+AaTslhPsAmjdRkYNhAZnYxM35pelvz1aXo2brhv6GWfmdN6geQrK1q1d+v/MfzPAz3AjKaFtnn72Bf2O2LYpPp0idaOkB2FiHwuB8XYMdb1HbGEDlUkm4N8AYoFKJagUIrNishBWAZXhCgCtyuIU3lYrBc/UwQ/AYkAkklI1UIyjUnXkbEp6lSVKNXb0hlsjlpzT5PN385PDvrb7ujarp4r/6tQ8WlOur5ONi99gZrEXvjOIWIwHmoCxKQQLxm/TALjZ0j4KfwgpcUcvdmd2bX4/FIWv/96Dctv5CdV8a8vlHvgP7aOZo0ZRqGs2FDIl6E3q5R7Y0GrLQjZgrCxS9EuIcwq9IAfKeIULQphQSEH5VDxVVAriFEIFXwgJWhS8BMCNUqYVOxAi9QoXr3gN0A6U0CidlYds93uqtSDuJXJPHkHDXf/n9wL5bCfjqKjZygFQjzf4Pvgp+OEmxGHJgTrGfyEIEnFBhGpTIc8fvRWDSPeJHBRxb+rhBv+3z2gRF6VSGG2WmarfS0B4l90VZ19s63OwqqmfGUEduXkd7i/yiO45k1SWCkw6VWr++t9Vvl8NjDpZmXlvFcec9Js5crdQdv/g9pij2Luptf7/srX/2xu9aG3VVRRRRVVVFFFFVVUUUUVVVRRRRVVVFFFFVVUUUUVVVRRRRVVVFFFFVVUUUUVVVRRRRVVVFFFFVVUUUUVVVRRRRVVVFFFFVVUUUUVVVRRRRX/9/H/AXAJevgz8YZJAAAAAElFTkSuQmCC">
<div class="htitle"><div class="k">{{SUBTITLE}}</div><div class="h">{{REPTITLE}}</div></div>
<div class="hostchip"><div class="n">{{HOST}}</div>
<div class="s">{{IP}} | {{ROLE}} | {{DOMAIN}}</div></div>
</div>
<div class="meta">
<div>OS <b>{{OS}}</b> build {{BUILD}}</div>
<div>{{L_COLLECTED}} <b>{{COLLECTED}}</b> UTC</div>
<div>{{L_WINDOW}} <b>{{DAYS}}</b> {{L_DAYS}}</div>
<div>{{L_DURATION}} <b>{{DURATION}}</b> {{L_SEC}}</div>
<div>Operator <b>{{OPERATOR}}</b></div>
</div>
</header>
<div class="riskbar">
<div class="riskbox"><div class="l">{{L_RISK}}</div><div class="v">{{RISKLEVEL}}</div>
<div class="s">{{L_SCORE}} {{RISKSCORE}}/100</div></div>
<div class="counts">
<button class="b-ALL on" onclick="fsev('',this)"><span class="n">{{TOTAL}}</span><span class="t">{{L_ALL}}</span></button>
<button class="b-CRITICAL" onclick="fsev('CRITICAL',this)"><span class="n">{{CRIT}}</span><span class="t">CRITICAL</span></button>
<button class="b-HIGH" onclick="fsev('HIGH',this)"><span class="n">{{HIGH}}</span><span class="t">HIGH</span></button>
<button class="b-MEDIUM" onclick="fsev('MEDIUM',this)"><span class="n">{{MED}}</span><span class="t">MEDIUM</span></button>
<button class="b-LOW" onclick="fsev('LOW',this)"><span class="n">{{LOW}}</span><span class="t">LOW</span></button>
<button class="b-INFO" onclick="fsev('INFO',this)"><span class="n">{{INFO}}</span><span class="t">INFO</span></button>
</div></div>
<main>
<section><h2>{{L_CORRELATION}}</h2>
<div class="note">{{L_CORR_NOTE}}</div>
{{CORRELATION}}</section>
<section><h2>{{L_FINDINGS}} <span class="dim" style="font-size:11px;letter-spacing:0">({{L_UNIQRAW}})</span></h2>
<input id="search" placeholder="{{L_SEARCH_PH}}" oninput="gsearch(this.value)">
<div class="scroll"><table id="findings"><thead><tr>
<th onclick="sortT('findings',0)">{{L_SEV}}</th><th onclick="sortT('findings',1)">{{L_RULE}}</th>
<th onclick="sortT('findings',2)">{{L_TITLE}}</th><th>{{L_EV}}</th>
<th onclick="sortT('findings',4)">{{L_MITRE}}</th><th onclick="sortT('findings',5)">{{L_TIME}}</th>
<th onclick="sortT('findings',6)">{{L_ART}}</th>
</tr></thead><tbody>{{FINDINGS}}</tbody></table></div></section>
<section><h2>{{L_ATTACK}}</h2>
<div class="attck">{{ATTACK}}</div></section>
<section><h2>{{L_SIGMA}}</h2>
<div class="note">{{L_SIGMA_NOTE}}</div>
{{SIGMA}}</section>
<section><h2>{{L_TIMELINE}}</h2>
<div class="note">{{L_TL_NOTE}}</div>
<svg class="tl" viewBox="0 0 1100 150" preserveAspectRatio="none">{{CHART}}</svg>
<div class="scroll" style="margin-top:12px"><table id="timeline"><thead><tr>
<th onclick="sortT('timeline',0)">{{L_TIME}}</th><th onclick="sortT('timeline',1)">{{L_SEV}}</th>
<th onclick="sortT('timeline',2)">{{L_SOURCE}}</th><th>{{L_DESC}}</th><th>{{L_EV}}</th>
</tr></thead><tbody>{{TIMELINE}}</tbody></table></div></section>
<section><h2>{{L_ARTIFACTS}}</h2><div class="tabs">{{TABS}}</div>{{PANES}}</section>
<section><h2>{{L_MODPERF}}</h2>
<div class="scroll" style="max-height:300px"><table><thead><tr>
<th>Module</th><th>Phase</th><th>Status</th><th>Duration</th><th>Errors</th>
</tr></thead><tbody>{{MODSTATS}}</tbody></table></div></section>
<section><h2>{{L_ERRORS}}</h2>
<div class="note">{{L_ERR_NOTE}}</div>
<div class="scroll" style="max-height:300px"><table><thead><tr>
<th>Module</th><th>Type</th><th>Message</th></tr></thead><tbody>{{ERRORS}}</tbody></table></div></section>
</main>
<footer>
<div>Douglas-042 v{{VERSION}} | {{ARTCOUNT}} artefakt | ATT&CK v19 | FINDINGS.csv &amp; MANIFEST.json</div>
<img alt="" src="data:image/png;base64,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"></div>
</footer>
<script>
function fsev(s,btn){
document.querySelectorAll('.counts button').forEach(function(b){b.classList.remove('on')});
if(btn)btn.classList.add('on');
document.querySelectorAll('tr.f').forEach(function(r){
var b=r.querySelector('.badge');
r.style.display=(!s||(b&&b.textContent.trim()===s))?'':'none';});}
function gsearch(q){q=q.toLowerCase();
document.querySelectorAll('tr.f').forEach(function(r){
r.style.display=(!q||r.innerText.toLowerCase().indexOf(q)>-1)?'':'none';});}
function filterTable(inp,tid){var q=inp.value.toLowerCase();var t=document.getElementById(tid);if(!t)return;
t.querySelectorAll('tbody tr').forEach(function(r){r.style.display=(!q||r.innerText.toLowerCase().indexOf(q)>-1)?'':'none';});}
function showPane(id,btn){document.querySelectorAll('.pane').forEach(function(p){p.classList.remove('on')});
document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('on')});
var p=document.getElementById('p_'+id);if(p)p.classList.add('on');if(btn)btn.classList.add('on');}
var sortDir={};
function sortT(tid,col){var t=document.getElementById(tid);if(!t)return;var tb=t.tBodies[0];
var rows=Array.prototype.slice.call(tb.rows);var k=tid+'_'+col;sortDir[k]=!sortDir[k];var d=sortDir[k]?1:-1;
rows.sort(function(a,b){var x=(a.cells[col]?a.cells[col].innerText:'').trim();
var y=(b.cells[col]?b.cells[col].innerText:'').trim();var nx=parseFloat(x),ny=parseFloat(y);
if(!isNaN(nx)&&!isNaN(ny))return(nx-ny)*d;return x.localeCompare(y)*d;});
rows.forEach(function(r){tb.appendChild(r)});}
var ft=document.querySelector('.tab');if(ft)ft.click();
</script></body></html>
'@

    $repl = [ordered]@{
        '{{HOST}}'      = (ConvertTo-DHtmlSafe $ctx.ComputerName)
        '{{IP}}'        = (ConvertTo-DHtmlSafe $ips)
        '{{ROLE}}'      = (ConvertTo-DHtmlSafe $ctx.DomainRole)
        '{{DOMAIN}}'    = (ConvertTo-DHtmlSafe ([string]$ctx.Domain))
        '{{OS}}'        = (ConvertTo-DHtmlSafe ([string]$ctx.OSCaption))
        '{{BUILD}}'     = (ConvertTo-DHtmlSafe ([string]$ctx.OSBuild))
        '{{COLLECTED}}' = $Script:StartTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        '{{DAYS}}'      = [string]$Days
        '{{DURATION}}'  = [string]$dur
        '{{OPERATOR}}'  = (ConvertTo-DHtmlSafe ([string]$ctx.Operator))
        '{{RISKLEVEL}}' = [string]$ctx.RiskLevel
        '{{RISKSCORE}}' = [string]$ctx.RiskScore
        '{{RISKCOLOR}}' = $riskColor
        '{{TOTAL}}'     = [string]$findings.Count
        '{{CRIT}}'      = [string]$crit
        '{{HIGH}}'      = [string]$high
        '{{MED}}'       = [string]$med
        '{{LOW}}'       = [string]$low
        '{{INFO}}'      = [string]$info
        '{{FINDINGS}}'  = $(if ($sbF.Length -gt 0) { $sbF.ToString() } else { '<tr><td colspan="7" class="empty">' + (T 'rep.no_finding') + '</td></tr>' })
        '{{CORRELATION}}' = $sbCorr.ToString()
        '{{UNIQUECOUNT}}' = [string]$ctx.UniqueFindingCount
        '{{RAWCOUNT}}'    = [string]$ctx.RawFindingCount
        '{{CHART}}'     = $sbChart.ToString()
        '{{TIMELINE}}'  = $(if ($sbT.Length -gt 0) { $sbT.ToString() } else { '<tr><td colspan="5" class="empty">' + (T 'rep.no_timeline') + '</td></tr>' })
        '{{TABS}}'      = $sbTabs.ToString()
        '{{PANES}}'     = $(if ($sbA.Length -gt 0) { $sbA.ToString() } else { '<div class="empty">' + (T 'rep.no_artifacts') + '</div>' })
        '{{MODSTATS}}'  = $sbM.ToString()
        '{{ERRORS}}'    = $(if ($sbE.Length -gt 0) { $sbE.ToString() } else { '<tr><td colspan="3" class="empty">' + (T 'rep.no_errors') + '</td></tr>' })
        '{{VERSION}}'   = $Script:Version
        '{{ARTCOUNT}}'  = [string]$Script:Manifest.Count
        '{{ATTACK}}'    = $sbAttck.ToString()
        '{{SIGMA}}'     = $sbSigma.ToString()
        '{{L_SIGMA}}'   = 'Sigma Matches'
        '{{L_SIGMA_NOTE}}' = 'Community Sigma rules vary in quality. This section is EXCLUDED from the risk score; treat entries as leads requiring verification.'
        '{{LANGCODE}}'  = $Script:Lang.ToLower()
        '{{SUBTITLE}}'  = (T 'rep.subtitle')
        '{{REPTITLE}}'  = (T 'rep.title')
        '{{L_COLLECTED}}' = (T 'ui.report_at')
        '{{L_WINDOW}}'  = 'Window'
        '{{L_DAYS}}'    = 'days'
        '{{L_DURATION}}'= 'Duration'
        '{{L_SEC}}'     = 's'
        '{{L_RISK}}'    = (T 'rep.risk')
        '{{L_SCORE}}'   = (T 'rep.score')
        '{{L_ALL}}'     = (T 'rep.all')
        '{{L_CORRELATION}}' = (T 'rep.correlation')
        '{{L_CORR_NOTE}}' = (T 'rep.corr_note')
        '{{L_FINDINGS}}' = (T 'rep.findings')
        '{{L_UNIQRAW}}' = (T 'rep.uniq_raw' @([string]$ctx.UniqueFindingCount, [string]$ctx.RawFindingCount))
        '{{L_ATTACK}}'  = (T 'rep.attack')
        '{{L_TIMELINE}}'= (T 'rep.timeline')
        '{{L_TL_NOTE}}' = (T 'rep.tl_note')
        '{{L_ARTIFACTS}}' = (T 'rep.artifacts')
        '{{L_MODPERF}}' = (T 'rep.modperf')
        '{{L_ERRORS}}'  = (T 'rep.errors')
        '{{L_ERR_NOTE}}'= (T 'rep.err_note')
        '{{L_SEV}}'     = (T 'rep.col_sev')
        '{{L_RULE}}'    = (T 'rep.col_rule')
        '{{L_TITLE}}'   = (T 'rep.col_title')
        '{{L_EV}}'      = (T 'rep.col_ev')
        '{{L_MITRE}}'   = (T 'rep.col_mitre')
        '{{L_TIME}}'    = (T 'rep.col_time')
        '{{L_ART}}'     = (T 'rep.col_art')
        '{{L_SOURCE}}'  = (T 'rep.col_source')
        '{{L_DESC}}'    = (T 'rep.col_desc')
        '{{L_SEARCH_PH}}' = (T 'rep.search_ph')
    }
    foreach ($k in $repl.Keys) { $html = $html.Replace($k, $repl[$k]) }

    try {
        [IO.File]::WriteAllText($out, $html, [Text.UTF8Encoding]::new($true))
        $sizeMB = [math]::Round((Get-Item $out).Length / 1MB, 2)
        Write-DLog "HTML report created ($sizeMB MB)" -Level OK
        return $out
    } catch {
        Write-DLog "HTML report failed: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

# ============================================================================
#  MODUL: HAM ADLI ARTEFAKT (-CollectRaw)
# ============================================================================

Register-DModule -Name 'Raw Forensic Artifacts' -Phase 4 `
    -Description 'VSS snapshot uzerinden kilitli dosyalarin kopyalanmasi' -Body {

    $rawDir = Join-Path $Script:Ctx.OutputDir 'raw'
    $copied = New-Object System.Collections.ArrayList
    $shadow = $null
    $shadowPath = $null

    # --- VSS snapshot olustur (kilitli dosyalara erisim icin) ---
    try {
        Write-DLog '  Creating VSS snapshot...' -Level INFO
        $res = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create `
               -Arguments @{ Volume = 'C:\'; Context = 'ClientAccessible' } -ErrorAction Stop
        if ($res.ReturnValue -eq 0 -and $res.ShadowID) {
            $shadow = Get-CimInstance Win32_ShadowCopy -Filter "ID='$($res.ShadowID)'" -ErrorAction Stop
            if ($shadow) {
                $shadowPath = $shadow.DeviceObject + '\'
                Write-DLog "  VSS snapshot hazir: $($res.ShadowID)" -Level OK
            }
        } else {
            Write-DLog "  VSS snapshot could not be created (code: $($res.ReturnValue))" -Level WARN
        }
    } catch {
        Write-DLog "  VSS kullanilamiyor: $($_.Exception.Message)" -Level WARN
    }

    function Copy-DRaw {
        param([string]$Relative, [string]$DestName, [switch]$Directory)

        $src = if ($shadowPath) { Join-Path $shadowPath $Relative } else { "C:\$Relative" }
        $dst = Join-Path $rawDir $DestName

        try {
            if ($Directory) {
                if (-not (Test-Path $src)) { return }
                $null = New-Item -Path $dst -ItemType Directory -Force -ErrorAction Stop
                $n = 0; $bytes = 0
                Get-ChildItem -LiteralPath $src -File -Force -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        try {
                            Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction Stop
                            $n++; $bytes += $_.Length
                        } catch { }
                    }
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = $DestName; Source = $Relative; Type = 'Directory'
                    Files = $n; SizeMB = [math]::Round($bytes / 1MB, 2); SHA256 = $null
                })
            } else {
                if (-not (Test-Path $src)) { return }
                Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
                $fi = Get-Item $dst -ErrorAction Stop
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = $DestName; Source = $Relative; Type = 'File'
                    Files = 1; SizeMB = [math]::Round($fi.Length / 1MB, 2)
                    SHA256 = Get-DFileHashSafe -Path $dst -MaxSizeMB 2000
                })
            }
            Write-DLog "    + $DestName" -Level DEBUG
        } catch {
            Write-DLog "    - $DestName kopyalanamadi: $($_.Exception.Message)" -Level WARN
        }
    }

    # --- Registry hive'lari ---
    foreach ($h in 'SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY') {
        Copy-DRaw -Relative "Windows\System32\config\$h" -DestName "hive_$h"
    }

    # --- Amcache: calistirilmis her binary'nin SHA1'i, DOSYA SILINMIS OLSA BILE ---
    Copy-DRaw -Relative 'Windows\AppCompat\Programs\Amcache.hve' -DestName 'Amcache.hve'
    Copy-DRaw -Relative 'Windows\AppCompat\Programs\RecentFileCache.bcf' -DestName 'RecentFileCache.bcf'

    # --- SRUM: uygulama basina ag kullanimi = exfil hacmi ---
    Copy-DRaw -Relative 'Windows\System32\sru\SRUDB.dat' -DestName 'SRUDB.dat'

    # --- Kullanici hive'lari ---
    try {
        Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | ForEach-Object {
            $u = $_.Name
            Copy-DRaw -Relative "Users\$u\NTUSER.DAT" -DestName "NTUSER_$u.dat"
            Copy-DRaw -Relative "Users\$u\AppData\Local\Microsoft\Windows\UsrClass.dat" `
                      -DestName "UsrClass_$u.dat"
            Copy-DRaw -Relative "Users\$u\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" `
                      -DestName "WebCache_$u.dat"
        }
    } catch { }

    # --- Event loglari ---
    Copy-DRaw -Relative 'Windows\System32\winevt\Logs' -DestName 'evtx' -Directory

    # --- Prefetch ---
    Copy-DRaw -Relative 'Windows\Prefetch' -DestName 'Prefetch' -Directory

    # --- Scheduled task XML'leri ---
    Copy-DRaw -Relative 'Windows\System32\Tasks' -DestName 'Tasks' -Directory

    # --- IIS loglari (sunucu) ---
    if ($Script:Ctx.IsServer) {
        try {
            $iisLog = 'C:\inetpub\logs\LogFiles'
            if (Test-Path $iisLog) {
                $dst = Join-Path $rawDir 'IISLogs'
                $null = New-Item -Path $dst -ItemType Directory -Force -ErrorAction Stop
                $n = 0; $bytes = 0
                Get-ChildItem $iisLog -Recurse -File -Filter '*.log' -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -ge $Script:Ctx.WindowStart } |
                    ForEach-Object {
                        try {
                            Copy-Item -LiteralPath $_.FullName `
                                -Destination (Join-Path $dst "$($_.Directory.Name)_$($_.Name)") `
                                -Force -ErrorAction Stop
                            $n++; $bytes += $_.Length
                        } catch { }
                    }
                $null = $copied.Add([PSCustomObject]@{
                    Artifact = 'IISLogs'; Source = $iisLog; Type = 'Directory'
                    Files = $n; SizeMB = [math]::Round($bytes / 1MB, 2); SHA256 = $null
                })
            }
        } catch { }
    }

    # --- $MFT ve $UsnJrnl:$J ---
    # NOT: Bunlar ozel NTFS akislaridir, Copy-Item ile alinamaz.
    # Adli olarak dogru yontem RawCopy/KAPE'dir. Sadece not dusuyoruz.
    $null = $copied.Add([PSCustomObject]@{
        Artifact = 'MFT_UsnJrnl'; Source = 'C:\$MFT , C:\$Extend\$UsnJrnl:$J'
        Type = 'NOT_COLLECTED'; Files = 0; SizeMB = 0
        SHA256 = 'NTFS ozel akislari - RawCopy.exe / KAPE / FTK Imager ile alinmalidir'
    })

    # --- VSS snapshot temizligi ---
    if ($shadow) {
        try {
            Remove-CimInstance -InputObject $shadow -ErrorAction Stop
            Write-DLog '  VSS snapshot temizlendi' -Level DEBUG
        } catch {
            Write-DLog "  VSS snapshot silinemedi (elle silin: $($shadow.ID))" -Level WARN
        }
    }

    $arr = @($copied)
    Export-DArtifact -Name '16_raw_collection' -Data $arr
    $totalMB = ($arr | Measure-Object -Property SizeMB -Sum).Sum
    Write-DLog "  $($arr.Count) artefakt, toplam $([math]::Round($totalMB, 1)) MB" -Level OK
}

# ============================================================================
#  UZAKTAN TOPLU TARAMA (FAN-OUT)
# ============================================================================

function Invoke-DRemoteCollection {
    <#
        -ComputerName verildiginde calisir. Script kendini hedeflere gonderir,
        her host kendi klasorunu uretir, sonra frekans analizi yapilir.
    #>
    param([string[]]$Targets)

    Write-Host ''
    Write-Host '  === UZAKTAN TOPLU TARAMA ===' -ForegroundColor White -BackgroundColor DarkMagenta
    Write-DLog "$($Targets.Count) hedef, throttle: $ThrottleLimit" -Level INFO

    $scriptPath = $PSCommandPath
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        Write-DLog 'Script yolu belirlenemedi - uzaktan tarama yapilamiyor' -Level ERROR
        return
    }
    $scriptText = Get-Content -Path $scriptPath -Raw -Encoding UTF8

    $base = if ($OutputPath) { $OutputPath }
            else { Join-Path (Split-Path $scriptPath -Parent) 'Output' }
    $null = New-Item -Path $base -ItemType Directory -Force -ErrorAction SilentlyContinue

    # --- Erisilebilirlik on kontrolu ---
    Write-DLog 'Hedefler kontrol ediliyor...' -Level INFO
    $reachable = New-Object System.Collections.ArrayList
    $dead      = New-Object System.Collections.ArrayList

    foreach ($t in $Targets) {
        $ok = $false
        try {
            $null = Test-WSMan -ComputerName $t -ErrorAction Stop
            $ok = $true
        } catch { }
        if ($ok) { $null = $reachable.Add($t) }
        else { $null = $dead.Add([PSCustomObject]@{ Computer = $t; Reason = 'WinRM erisilemiyor' }) }
    }
    Write-DLog "Erisilebilir: $($reachable.Count) / $($Targets.Count)" -Level OK
    if ($dead.Count -gt 0) {
        $dead | Export-Csv -Path (Join-Path $base 'UNREACHABLE.csv') `
                -NoTypeInformation -Encoding UTF8 -Force
        Write-DLog "$($dead.Count) host erisilemedi -> UNREACHABLE.csv" -Level WARN
    }
    if ($reachable.Count -eq 0) { return }

    # --- Uzak calistirma ---
    $remoteBlock = {
        param($ScriptText, $Days, $MaxEvents, $Quick, $NoResolve)

        $tmp = Join-Path $env:TEMP "Douglas-042_$([guid]::NewGuid().ToString('N')).ps1"
        $localOut = Join-Path $env:TEMP 'DouglasOut'
        try {
            [IO.File]::WriteAllText($tmp, $ScriptText, [Text.UTF8Encoding]::new($true))

            $splat = @{ Days = $Days; OutputPath = $localOut; MaxEventsPerChannel = $MaxEvents }
            if ($Quick)     { $splat['Quick'] = $true }
            if ($NoResolve) { $splat['NoResolve'] = $true }

            & $tmp @splat *> $null

            # Uretilen zip'i bul ve byte olarak dondur
            $zip = Get-ChildItem $localOut -Filter '*.zip' -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($zip) {
                $bytes = [IO.File]::ReadAllBytes($zip.FullName)
                return [PSCustomObject]@{
                    Computer = $env:COMPUTERNAME; Status = 'OK'
                    ZipName = $zip.Name; ZipBytes = $bytes; Error = $null
                }
            }
            return [PSCustomObject]@{
                Computer = $env:COMPUTERNAME; Status = 'NO_OUTPUT'
                ZipName = $null; ZipBytes = $null; Error = 'Zip uretilmedi'
            }
        } catch {
            return [PSCustomObject]@{
                Computer = $env:COMPUTERNAME; Status = 'FAILED'
                ZipName = $null; ZipBytes = $null; Error = $_.Exception.Message
            }
        } finally {
            Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            Remove-Item $localOut -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $icmArgs = @{
        ComputerName  = $reachable.ToArray()
        ScriptBlock   = $remoteBlock
        ArgumentList  = @($scriptText, $Days, $MaxEventsPerChannel, [bool]$Quick, [bool]$NoResolve)
        ThrottleLimit = $ThrottleLimit
        ErrorAction   = 'SilentlyContinue'
    }
    if ($Credential) { $icmArgs['Credential'] = $Credential }

    Write-DLog 'Uzak toplama basladi (hedef basina birkac dakika surebilir)...' -Level INFO
    $results = @(Invoke-Command @icmArgs)

    # --- Sonuclari kaydet ---
    $summary = New-Object System.Collections.ArrayList
    foreach ($r in $results) {
        if ($r.Status -eq 'OK' -and $r.ZipBytes) {
            try {
                $dst = Join-Path $base $r.ZipName
                [IO.File]::WriteAllBytes($dst, $r.ZipBytes)
                $null = $summary.Add([PSCustomObject]@{
                    Computer = $r.Computer; Status = 'OK'; File = $r.ZipName
                    SizeMB = [math]::Round($r.ZipBytes.Length / 1MB, 2); Error = $null
                })
                Write-DLog "  $($r.Computer) OK -> $($r.ZipName)" -Level OK
            } catch {
                $null = $summary.Add([PSCustomObject]@{
                    Computer = $r.Computer; Status = 'SAVE_FAILED'; File = $null
                    SizeMB = 0; Error = $_.Exception.Message
                })
            }
        } else {
            $null = $summary.Add([PSCustomObject]@{
                Computer = $r.Computer; Status = $r.Status; File = $null
                SizeMB = 0; Error = $r.Error
            })
            Write-DLog "  $($r.Computer) $($r.Status): $($r.Error)" -Level WARN
        }
    }
    $summary | Export-Csv -Path (Join-Path $base 'SWEEP_SUMMARY.csv') `
               -NoTypeInformation -Encoding UTF8 -Force

    # --- Frekans analizi (stack counting) ---
    # IR'de en hizli sonuc veren teknik: 1 makinede gorulen sey supheli.
    Write-DLog 'Frekans analizi yapiliyor...' -Level INFO
    $extract = Join-Path $base '_extract'
    $null = New-Item -Path $extract -ItemType Directory -Force -ErrorAction SilentlyContinue

    $allFindings = New-Object System.Collections.ArrayList
    $stackData   = @{ services = @{}; autoruns = @{}; tasks = @{} }

    foreach ($s in @($summary | Where-Object Status -eq 'OK')) {
        $zp  = Join-Path $base $s.File
        $dst = Join-Path $extract ($s.File -replace '\.zip$', '')
        try {
            Expand-Archive -Path $zp -DestinationPath $dst -Force -ErrorAction Stop
        } catch { continue }

        $fcsv = Join-Path $dst 'FINDINGS.csv'
        if (Test-Path $fcsv) {
            try {
                Import-Csv $fcsv -ErrorAction Stop | ForEach-Object { $null = $allFindings.Add($_) }
            } catch { }
        }

        $map = @{
            services = @{ File = 'artifacts\05_services.csv';  Key = { "$($_.Name) | $($_.BinaryPath)" } }
            autoruns = @{ File = 'artifacts\07_autoruns.csv';   Key = { "$($_.Category) | $($_.Name) | $($_.BinaryPath)" } }
            tasks    = @{ File = 'artifacts\06_scheduled_tasks.csv'; Key = { "$($_.TaskPath)$($_.TaskName) | $($_.BinaryPath)" } }
        }
        foreach ($k in $map.Keys) {
            $p = Join-Path $dst $map[$k].File
            if (-not (Test-Path $p)) { continue }
            try {
                Import-Csv $p -ErrorAction Stop | ForEach-Object {
                    $key = & $map[$k].Key
                    if (-not $key -or $key -match '^\s*\|\s*\|?\s*$') { return }
                    if (-not $stackData[$k].ContainsKey($key)) {
                        $stackData[$k][$key] = New-Object System.Collections.ArrayList
                    }
                    $null = $stackData[$k][$key].Add($s.Computer)
                }
            } catch { }
        }
    }

    $hostCount = @($summary | Where-Object Status -eq 'OK').Count
    foreach ($k in $stackData.Keys) {
        $stack = @($stackData[$k].GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Item       = $_.Key
                HostCount  = $_.Value.Count
                Percent    = if ($hostCount -gt 0) {
                                 [math]::Round(($_.Value.Count / $hostCount) * 100, 1) } else { 0 }
                Hosts      = (($_.Value | Select-Object -First 10) -join ', ')
                Rarity     = if ($_.Value.Count -eq 1) { 'TEKIL - INCELE' }
                             elseif ($_.Value.Count -le 3) { 'NADIR' }
                             else { 'YAYGIN' }
            }
        } | Sort-Object HostCount)
        $stack | Export-Csv -Path (Join-Path $base "STACK_$k.csv") `
                 -NoTypeInformation -Encoding UTF8 -Force
        $rare = @($stack | Where-Object HostCount -eq 1).Count
        Write-DLog "  STACK_$k : $($stack.Count) benzersiz, $rare tekil" -Level OK
    }

    $allFindings | Export-Csv -Path (Join-Path $base 'ALL_FINDINGS.csv') `
                   -NoTypeInformation -Encoding UTF8 -Force

    # Host risk siralamasi
    $ranking = @($allFindings | Group-Object Host | ForEach-Object {
        $c = @($_.Group | Where-Object Severity -eq 'CRITICAL').Count
        $h = @($_.Group | Where-Object Severity -eq 'HIGH').Count
        $m = @($_.Group | Where-Object Severity -eq 'MEDIUM').Count
        $l = @($_.Group | Where-Object Severity -eq 'LOW').Count
        [PSCustomObject]@{
            Host = $_.Name; Score = ($c * 10) + ($h * 5) + ($m * 2) + $l
            CRITICAL = $c; HIGH = $h; MEDIUM = $m; LOW = $l; TOTAL = $_.Count
        }
    } | Sort-Object Score -Descending)
    $ranking | Export-Csv -Path (Join-Path $base 'HOST_RANKING.csv') `
               -NoTypeInformation -Encoding UTF8 -Force

    Write-Host ''
    Write-Host '  === TARAMA OZETI ===' -ForegroundColor White -BackgroundColor DarkMagenta
    Write-Host ("   Hedef: {0}  |  Basarili: {1}  |  Erisilemedi: {2}" -f `
                $Targets.Count, $hostCount, $dead.Count)
    Write-Host ''
    Write-Host '   HIGHEST RISK HOSTS:' -ForegroundColor Red
    foreach ($r in ($ranking | Select-Object -First 15)) {
        $col = if ($r.CRITICAL -gt 0) { 'Red' } elseif ($r.HIGH -gt 0) { 'Yellow' } else { 'Gray' }
        Write-Host ("     {0,-20} score {1,-5} C:{2} H:{3} M:{4}" -f `
                    $r.Host, $r.Score, $r.CRITICAL, $r.HIGH, $r.MEDIUM) -ForegroundColor $col
    }
    Write-Host ''
    Write-Host ("   CIKTI: {0}" -f $base) -ForegroundColor Green
    Write-Host '   Rows with HostCount=1 in STACK_*.csv are the priority investigation targets.' -ForegroundColor DarkGray
    Write-Host ''
}

# ============================================================================
#  ANA AKIS
# ============================================================================

Show-Banner

# --- FAZ 2: DIL SECIMI ---
Select-DLanguage -Requested $Language

# --- FAZ 2: YARDIM ---
if ($Help) { Show-DUsage; exit 0 }

# --- Katalog disa aktarimi (yonetici gerekmez, toplama yapilmaz) ---
if ($ExportRuleCatalog) {
    $p = Export-DRuleCatalog
    Write-Host ("  Rule catalog written: {0}  ({1} rules, ATT&CK {2})" -f `
                $p, $Script:RuleCatalog.Count, $Script:MitreVersion) -ForegroundColor Green
    exit 0
}

# --- FAZ 2: MENU (sadece parametresiz + interaktif) ---
# -Language ve -NoMenu disinda parametre verilmediyse ve konsol interaktifse acilir.
$uiOnlyParams = @($PSBoundParameters.Keys | Where-Object { $_ -notin 'Language','NoMenu' })
if (-not $NoMenu -and $uiOnlyParams.Count -eq 0 -and (Test-DInteractive)) {
    $sel = Show-DMenu
    if ($null -eq $sel) { exit 0 }
    $Days = $sel.Days
    if ($sel.Quick)        { $Quick        = [switch]$true }
    if ($sel.CollectRaw)   { $CollectRaw   = [switch]$true }
    if ($sel.NoResolve)    { $NoResolve    = [switch]$true }
    if ($sel.ThrottleLimit){ $ThrottleLimit = $sel.ThrottleLimit }
    if ($sel.SigmaPath)    { $SigmaPath    = $sel.SigmaPath }
    if ($sel.OutputPath)   { $OutputPath   = $sel.OutputPath }
    if ($sel.ComputerName) { $ComputerName = $sel.ComputerName }
    if ($sel.Credential)   { $Credential   = $sel.Credential }
    if ($sel.Baseline)     { $Baseline     = $sel.Baseline }
    if ($sel.Hunt)         { $Hunt         = $sel.Hunt }
}

# --- Onkosul: yonetici ---
$adminInfo = Test-DAdmin
if (-not $adminInfo.IsAdmin) {
    Write-Host '  [x] Douglas-042 must be run with Administrator rights.' -ForegroundColor Red
    Write-Host '      Example: Start-Process powershell -Verb RunAs' -ForegroundColor DarkGray
    exit 1
}

# --- Onkosul: PS surumu ---
$Script:Caps = Get-DCapabilities
if ($Script:Caps.PSMajor -lt 4) {
    Write-Host '  [x] PowerShell 4.0+ is required. Current: ' -NoNewline -ForegroundColor Red
    Write-Host $Script:Caps.PSVersion -ForegroundColor Red
    exit 1
}
if (-not $Script:Caps.IsPS5Plus) {
    Write-Host '  [!] PowerShell 4.0 detected - fallback mode active.' -ForegroundColor Yellow
    Write-Host '      Some modules will collect limited data (2012 R2 compatibility).' -ForegroundColor DarkGray
    Write-Host ''
}

# --- UZAKTAN TOPLU TARAMA MODU ---
# -ComputerName verildiyse lokal toplama yapilmaz; script hedeflere gonderilir.
if ($ComputerName -and $ComputerName.Count -gt 0) {
    $Script:Ctx = @{ ComputerName = $env:COMPUTERNAME; OutputDir = $null; LogFile = $null }
    Invoke-DRemoteCollection -Targets $ComputerName
    exit 0
}

# --- Baglam ---
$Script:Ctx = Get-DHostContext -AdminInfo $adminInfo
$Script:Ctx.OutputDir = Initialize-DOutput -Root $OutputPath
$Script:Ctx.LogFile   = Join-Path $Script:Ctx.OutputDir 'logs\douglas.log'

Write-DLog ("Collection started: {0} ({1}) | Role: {2} | Operator: {3}" -f `
            $Script:Ctx.ComputerName, $Script:Ctx.PrimaryIP,
            $Script:Ctx.DomainRole, $Script:Ctx.Operator) -Level OK
Write-DLog ("Window: last {0} days (>= {1} UTC)" -f `
            $Days, $Script:Ctx.WindowStartUtc.ToString('yyyy-MM-dd HH:mm')) -Level INFO
Write-DLog ("Output: {0}" -f $Script:Ctx.OutputDir) -Level INFO
if ($Quick)      { Write-DLog 'QUICK MODE - Phase 3 will be skipped' -Level WARN }
if ($CollectRaw) { Write-DLog 'RAW COLLECTION active - may be several GB' -Level WARN }

# --- IOC ---
if ($IocFile) { Import-DIocs -Path $IocFile }

# --- Transcript ---
try {
    Start-Transcript -Path (Join-Path $Script:Ctx.OutputDir 'logs\transcript.log') `
                     -Force -ErrorAction SilentlyContinue | Out-Null
} catch { }

# --- Fazlar ---
try {
    Invoke-DPhase -Phase 0 -Title 'HOST IDENTITY'
    Invoke-DPhase -Phase 1 -Title 'VOLATILE DATA'
    Invoke-DPhase -Phase 2 -Title 'EVENT LOG'
    if (-not $Quick) {
        Invoke-DPhase -Phase 3 -Title 'FILE SYSTEM & ARTIFACTS'
    }
    if ($CollectRaw) {
        Invoke-DPhase -Phase 4 -Title 'RAW FORENSIC ARTIFACTS'
    }
} catch {
    Write-DLog "CRITICAL: phase engine stopped - $($_.Exception.Message)" -Level ERROR
} finally {
    Complete-DCollection
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    try {
        [Threading.Thread]::CurrentThread.CurrentCulture = $Script:OriginalCulture
    } catch { }
}
