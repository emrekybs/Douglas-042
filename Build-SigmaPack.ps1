<#
    Build-SigmaPack.ps1 - Douglas-042 Sigma paket derleyicisi

    Sigma kurallarini (YAML) Douglas-042'nin okuyabilecegi sigma-pack.json
    formatina cevirir. Kaynak olarak hem klasor dolusu .yml dosyasi hem de
    Detections.ai JSON export'u kabul eder.

    Neden derleme? Douglas tek dosya ve sifir bagimlilik olarak tasarlandi;
    calisma aninda YAML ayristirmak (powershell-yaml modulu) bunu bozardi.
    Derleme bir kez burada yapilir, Douglas sadece JSON okur.

    KULLANIM
      # Sigma repo klasorunden
      .\Build-SigmaPack.ps1 -SigmaRoot .\sigma\rules\windows -Out .\sigma-pack.json

      # Detections.ai JSON export'undan
      .\Build-SigmaPack.ps1 -JsonExport .\detections_sigma_full.json -Out .\sigma-pack.json

      # Sonra
      .\Douglas-042.ps1 -SigmaPath .\sigma-pack.json

    DESTEKLENEN
      field|contains / |startswith / |endswith / |re / |all
      selection listeleri (OR), coklu selection (AND)
      condition: and / or / not / parantez / "all of them" / "1 of sel*"

    DESTEKLENMEYEN (atlanir, sayilir)
      aggregation (| count() > N), near/temporal korelasyon,
      Windows disi logsource
#>
[CmdletBinding()]
param(
    [string]$SigmaRoot,
    [string]$JsonExport,
    [string]$Out = '.\sigma-pack.json',
    [ValidateSet('windows','all')]
    [string]$Platform = 'windows',
    [string[]]$Categories = @(
        'process_creation','network_connection','registry_set','registry_add','registry_event',
        'file_event','ps_script','ps_module','ps_classic_start','image_load','driver_load',
        'pipe_created','wmi_event','dns_query','create_remote_thread','service_creation','scheduled_task'
    )
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-DSigmaYaml {
    <# Sigma icin YETERLI, minimal YAML ayristirici. Tam YAML degildir;
       Sigma'nin kullandigi alt kume: ic ice map, liste, blok skaler (>- / |).
       Donen: hashtable agaci #>
    param([string]$Text)
    if (-not $Text) { return $null }
    $lines = $Text -split "`r?`n"
    $root  = @{}
    # (indent, container, isList) yigini
    $stack = New-Object System.Collections.Stack
    $stack.Push(@{ Indent = -1; Node = $root })

    $i = 0
    while ($i -lt $lines.Count) {
        $raw = $lines[$i]
        $i++
        if ($raw -match '^\s*#' -or $raw.Trim() -eq '') { continue }
        $indent = ($raw -replace '^(\s*).*$', '$1').Length
        $line = $raw.Trim()

        # uygun ebeveyni bul
        while ($stack.Count -gt 1 -and $stack.Peek().Indent -ge $indent) { $null = $stack.Pop() }
        $parent = $stack.Peek().Node

        # liste elemani
        if ($line -match '^-\s*(.*)$') {
            $val = $Matches[1].Trim()
            if ($parent -is [System.Collections.ArrayList]) {
                if ($val -match '^([A-Za-z0-9_\|\.\-]+):\s*(.*)$') {
                    $ikey = $Matches[1]; $ival = $Matches[2].Trim()
                    $h = @{}
                    $null = $parent.Add($h)
                    $stack.Push(@{ Indent = $indent; Node = $h })
                    if ($ival -ne '') {
                        $h[$ikey] = ConvertFrom-DSigmaScalar $ival
                    } else {
                        # "- Key:" ardindan IC ICE yapi geliyor. Onceki surumde
                        # bu durum bos deger birakiyor, bu da op=exists'e donusup
                        # kuralin HER kayitla eslesmesine yol aciyordu.
                        $nx = $i
                        while ($nx -lt $lines.Count -and $lines[$nx].Trim() -eq '') { $nx++ }
                        if ($nx -lt $lines.Count) {
                            $nRaw = $lines[$nx]
                            $nInd = ($nRaw -replace '^(\s*).*$', '$1').Length
                            $nLine = $nRaw.Trim()
                            if ($nInd -gt $indent -and $nLine -match '^-') {
                                $lst = New-Object System.Collections.ArrayList
                                $h[$ikey] = $lst
                                $stack.Push(@{ Indent = $nInd - 1; Node = $lst })
                            } elseif ($nInd -gt $indent) {
                                $hh = @{}
                                $h[$ikey] = $hh
                                $stack.Push(@{ Indent = $nInd - 1; Node = $hh })
                            } else {
                                $h[$ikey] = ''
                            }
                        } else { $h[$ikey] = '' }
                    }
                } else {
                    $null = $parent.Add((ConvertFrom-DSigmaScalar $val))
                }
            }
            continue
        }

        # anahtar: deger
        if ($line -match '^([^:]+):\s*(.*)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()

            if ($val -eq '' -or $val -eq '|' -or $val -eq '>-' -or $val -eq '>' -or $val -eq '|-') {
                # blok skaler mi yoksa ic ice yapi mi? sonraki satira bak
                $nextIdx = $i
                while ($nextIdx -lt $lines.Count -and $lines[$nextIdx].Trim() -eq '') { $nextIdx++ }
                if ($nextIdx -ge $lines.Count) { $parent[$key] = ''; continue }
                $nextRaw = $lines[$nextIdx]
                $nextIndent = ($nextRaw -replace '^(\s*).*$', '$1').Length
                $nextLine = $nextRaw.Trim()

                if ($val -in '|','>-','>','|-') {
                    # blok skaler: daha derin girintili tum satirlari birlestir
                    $sb = New-Object System.Text.StringBuilder
                    while ($i -lt $lines.Count) {
                        $r = $lines[$i]
                        if ($r.Trim() -eq '') { $i++; continue }
                        $ind = ($r -replace '^(\s*).*$', '$1').Length
                        if ($ind -le $indent) { break }
                        if ($sb.Length -gt 0) { $null = $sb.Append(' ') }
                        $null = $sb.Append($r.Trim())
                        $i++
                    }
                    $parent[$key] = $sb.ToString()
                    continue
                }
                if ($nextIndent -gt $indent -and $nextLine -match '^-') {
                    $lst = New-Object System.Collections.ArrayList
                    $parent[$key] = $lst
                    $stack.Push(@{ Indent = $indent; Node = $lst })
                } elseif ($nextIndent -gt $indent) {
                    $h = @{}
                    $parent[$key] = $h
                    $stack.Push(@{ Indent = $indent; Node = $h })
                } else {
                    $parent[$key] = ''
                }
                continue
            }
            $parent[$key] = ConvertFrom-DSigmaScalar $val
            continue
        }
    }
    return $root
}

function ConvertFrom-DSigmaScalar {
    param([string]$v)
    if ($null -eq $v) { return $null }
    $v = $v.Trim()
    if ($v -match '^["''](.*)["'']$') { return $Matches[1] }
    if ($v -eq 'true')  { return $true }
    if ($v -eq 'false') { return $false }
    if ($v -eq 'null' -or $v -eq '~') { return $null }
    # satir ici liste [a, b]
    if ($v -match '^\[(.*)\]$') {
        return @($Matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"',"'") } | Where-Object { $_ })
    }
    return $v
}

function ConvertTo-DPackDetection {
    <# Sigma detection blogunu motorun anladigi sema haline getirir:
       selName -> @( @{field; op; values[]} ) #>
    param($Detection)
    $out = @{}
    foreach ($sel in $Detection.Keys) {
        if ($sel -eq 'condition') { continue }
        $body = $Detection[$sel]

        # liste-of-map (OR) durumu
        if ($body -is [System.Collections.ArrayList] -or $body -is [object[]]) {
            $alts = New-Object System.Collections.ArrayList
            $plainValues = New-Object System.Collections.ArrayList
            foreach ($item in $body) {
                if ($item -is [hashtable]) {
                    $conds = ConvertTo-DPackConditions $item
                    if ($conds.Count -gt 0) { $null = $alts.Add($conds) }
                } else {
                    $null = $plainValues.Add([string]$item)
                }
            }
            if ($plainValues.Count -gt 0) {
                # keywords benzeri: serbest metin listesi
                $null = $alts.Add(@(@{ field = '__keywords__'; op = 'contains'; values = @($plainValues) }))
            }
            if ($alts.Count -gt 0) { $out[$sel] = @($alts) }
            continue
        }
        if ($body -is [hashtable]) {
            $conds = ConvertTo-DPackConditions $body
            if ($conds.Count -gt 0) { $out[$sel] = @($conds) }
        }
    }
    return $out
}

function ConvertTo-DPackConditions {
    param([hashtable]$Map)
    $list = New-Object System.Collections.ArrayList
    foreach ($k in $Map.Keys) {
        $field = $k; $op = 'equals'
        if ($k -match '^([^|]+)\|(.+)$') {
            $field = $Matches[1]
            $mods = $Matches[2].ToLowerInvariant() -split '\|'
            foreach ($m in $mods) {
                switch ($m) {
                    'contains'   { $op = 'contains' }
                    'startswith' { $op = 'startswith' }
                    'endswith'   { $op = 'endswith' }
                    're'         { $op = 're' }
                    'gt'         { $op = 'gt' }
                    'lt'         { $op = 'lt' }
                    'all'        { }   # motor OR uygular; all yaklasik
                }
            }
        }
        $raw = $Map[$k]
        # ic ice liste/map duzlestir
        $flat = New-Object System.Collections.ArrayList
        foreach ($x in @($raw)) {
            if ($x -is [hashtable]) { foreach ($vv in $x.Values) { $null = $flat.Add($vv) } }
            elseif ($x -is [System.Collections.ArrayList] -or $x -is [object[]]) { foreach ($vv in $x) { $null = $flat.Add($vv) } }
            else { $null = $flat.Add($x) }
        }
        $vals = @($flat | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })

        if ($vals.Count -eq 0) {
            # GUVENLIK: "Image|endswith:" gibi bir karsilastirma degersiz kaldiysa
            # bu bir AYRISTIRMA HATASIDIR. exists'e cevirmek kurali her kayitla
            # eslestirir (yanlis pozitif selı). Kurali gecersiz isaretle.
            if ($k -match '\|') { throw "degersiz karsilastirma: $k" }
            $vals = @(''); $op = 'exists'
        }
        $null = $list.Add(@{ field = $field; op = $op; values = @($vals) })
    }
    return @($list)
}

# ---------------- ana akis ----------------
$rulesYaml = New-Object System.Collections.ArrayList

if ($JsonExport) {
    if (-not (Test-Path $JsonExport)) { throw "JSON export bulunamadi: $JsonExport" }
    Write-Host "JSON export okunuyor: $JsonExport" -ForegroundColor Cyan
    $items = Get-Content $JsonExport -Raw | ConvertFrom-Json
    foreach ($it in $items) {
        if ($it.content) { $null = $rulesYaml.Add([string]$it.content) }
    }
    Write-Host "  $($rulesYaml.Count) kural icerigi cikarildi" -ForegroundColor Gray
}
elseif ($SigmaRoot) {
    if (-not (Test-Path $SigmaRoot)) { throw "Sigma kok dizini bulunamadi: $SigmaRoot" }
    Write-Host "Sigma klasoru taraniyor: $SigmaRoot" -ForegroundColor Cyan
    foreach ($f in (Get-ChildItem $SigmaRoot -Recurse -Include '*.yml','*.yaml' -File)) {
        $null = $rulesYaml.Add((Get-Content $f.FullName -Raw))
    }
    Write-Host "  $($rulesYaml.Count) YAML dosyasi bulundu" -ForegroundColor Gray
}
else { throw '-SigmaRoot veya -JsonExport vermelisiniz.' }

$compiled = New-Object System.Collections.ArrayList
$stats = @{ Total = $rulesYaml.Count; Ok = 0; NoDetection = 0; BadCategory = 0
            Aggregation = 0; NotWindows = 0; ParseFail = 0 }

foreach ($y in $rulesYaml) {
    $r = $null
    try { $r = ConvertFrom-DSigmaYaml -Text $y } catch { $stats.ParseFail++; continue }
    if (-not $r -or -not $r.detection) { $stats.NoDetection++; continue }

    $cat = $null; $prod = $null
    if ($r.logsource -is [hashtable]) {
        $cat  = [string]$r.logsource.category
        $prod = [string]$r.logsource.product
        if (-not $cat) { $cat = [string]$r.logsource.service }
    }
    if ($Platform -eq 'windows' -and $prod -and $prod -notmatch '(?i)windows') { $stats.NotWindows++; continue }
    if (-not $cat -or ($Categories -notcontains $cat)) { $stats.BadCategory++; continue }

    $cond = ''
    if ($r.detection -is [hashtable] -and $r.detection.ContainsKey('condition')) { $cond = [string]$r.detection.condition }
    if (-not $cond) { $stats.NoDetection++; continue }
    if ($cond -match '\|') { $stats.Aggregation++; continue }   # aggregation destegi yok

    $det = $null
    try { $det = ConvertTo-DPackDetection -Detection $r.detection }
    catch { $stats.ParseFail++; continue }
    if (-not $det -or $det.Keys.Count -eq 0) { $stats.NoDetection++; continue }

    $null = $compiled.Add([ordered]@{
        id          = if ($r.id) { [string]$r.id } else { [guid]::NewGuid().ToString() }
        title       = [string]$r.title
        description = [string]$r.description
        level       = if ($r.level) { [string]$r.level } else { 'medium' }
        status      = [string]$r.status
        tags        = @($r.tags)
        logsource   = @{ category = $cat; product = $prod }
        detection   = $det
        condition   = $cond
    })
    $stats.Ok++
}

$pack = [ordered]@{
    meta = [ordered]@{
        generator   = 'Build-SigmaPack.ps1'
        generatedAt = (Get-Date).ToUniversalTime().ToString('o')
        source      = if ($JsonExport) { Split-Path $JsonExport -Leaf } else { $SigmaRoot }
        platform    = $Platform
        stats       = $stats
    }
    rules = @($compiled)
}

$json = $pack | ConvertTo-Json -Depth 12 -Compress
[IO.File]::WriteAllText((Resolve-Path -LiteralPath (Split-Path $Out -Parent) -ErrorAction SilentlyContinue).Path + [IO.Path]::DirectorySeparatorChar + (Split-Path $Out -Leaf), $json, [Text.UTF8Encoding]::new($false))

Write-Host ''
Write-Host 'DERLEME TAMAMLANDI' -ForegroundColor Green
Write-Host ("  toplam kural      : {0}" -f $stats.Total)
Write-Host ("  derlenen          : {0}" -f $stats.Ok) -ForegroundColor Green
Write-Host ("  kategori disi     : {0}" -f $stats.BadCategory) -ForegroundColor DarkGray
Write-Host ("  aggregation (atl.): {0}" -f $stats.Aggregation) -ForegroundColor DarkGray
Write-Host ("  Windows disi      : {0}" -f $stats.NotWindows) -ForegroundColor DarkGray
Write-Host ("  detection yok     : {0}" -f $stats.NoDetection) -ForegroundColor DarkGray
Write-Host ("  parse hatasi      : {0}" -f $stats.ParseFail) -ForegroundColor DarkGray
Write-Host ("  cikti             : {0}" -f $Out) -ForegroundColor Cyan
Write-Host ''
Write-Host 'Kullanim: .\Douglas-042.ps1 -SigmaPath ' -NoNewline; Write-Host $Out -ForegroundColor Cyan
