# Douglas-042
<img src="docs/images/douglas.png" width="400">

Menu-driven, single-file Windows incident response and threat hunting collector.
No external modules required. Works on PowerShell 5.1+ and PowerShell 7.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Douglas-042.ps1
```

| Script | Purpose |
|---|---|
| `Douglas-042.ps1` | Full IR: 153 detection rules, risk scoring, HTML report |
| `Douglas-Lite.ps1` | Fast text snapshot, no analysis - run and read |
That's it — a menu opens. Run as **Administrator**.

Example report: [docs/REPORT-example.html](docs/REPORT-example.html)

---

## What it does

Collects volatile and forensic artifacts from a live Windows host, evaluates them
against 151 built-in detection rules, and produces a single-file offline HTML report.

- **Collection** — process tree, network connections joined to owning process,
  services, scheduled tasks, autoruns (all ASEP locations), WMI persistence,
  drivers, event logs, Sysmon telemetry, file system, webshell hunt
- **Forensic parsers** — Prefetch (incl. Win8+ MAM decompression: run count,
  last 8 run times, loaded files), ShimCache, Amcache
- **Hunting** — baseline diff, rarity scoring, jitter-based beaconing detection,
  entity correlation
- **Optional** — Sigma rule matching, YARA scanning

## Menu

```
   Sigma: ready   YARA: none   MITRE: ready

  -- COLLECTION MODES --
   [1] Standard collection   Phase 0-3, last 14 days
   [2] Quick triage          skips Phase 3 (~1-2 min)
   [3] Wide scope + raw      30 days + VSS artifacts
   [4] Sigma-assisted        Sigma rule matching
   [5] Remote sweep          WinRM fan-out

  -- TOOLS --
   [6] Advanced / custom   [7] Usage guide   [8] Rule catalog
   [9] Update center
```

Parameters work too (`-Help` for the full list). The menu only opens when run
interactively with no parameters, so automation is unaffected.

## Output

```
Output\DOUGLAS_<host>_<time>\
  REPORT.html      <- open this first (single file, offline)
  FINDINGS.csv     <- full evidence list
  TIMELINE.csv  MANIFEST.json  DELTA.csv  RARITY.csv  SIGMA.csv
  artifacts\  events\  logs\
```

The report shows unique findings; the complete evidence list is in FINDINGS.csv.

## Updating rule sets

This repo ships no third-party rules. Menu **[9] Update center** downloads current
versions into a `data\` folder next to the script:

| Source | What | Why this one |
|---|---|---|
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Sigma rules | The only official upstream; downloaded YAML is auto-compiled |
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | YARA rules (core) | Merges and deduplicates dozens of sources with a quality filter |
| [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) | MITRE ATT&CK | MITRE's own official STIX release |
| [VirusTotal/yara](https://github.com/VirusTotal/yara) | yara64.exe | Engine required for YARA scanning |

Files are found in `data\`, next to the script, or in the working directory —
no paths to configure. **Nothing needs downloading to work offline**; all
collection and the 151 built-in rules run regardless.

## Design notes

**Sigma findings are excluded from the risk score.** Community rules vary in
quality and are presented separately as leads requiring verification. Most Sigma
rules assume a Sysmon/EDR field schema — rules relying on fields Douglas does not
collect are reported as "outside field coverage" rather than silently producing
wrong answers.

**Missing components are never silently skipped.** Without the YARA engine the
report states "scan not performed, component missing" (DGL-410). An analyst
believing a scan ran when it did not is the most dangerous failure mode.

**PowerShell has no YARA engine.** VirusTotal's official binary is used — a
deliberate, optional exception to the zero-dependency rule.

## Things to know

- **Administrator rights are required.**
- **Live-system impact:** running this touches file access times and Prefetch.
  Image the disk first if forensic soundness is critical.
- **ShimCache is not execution evidence** — it shows a file was *seen* by the
  system. This is a common misreading.
- Prefetch/ShimCache/Amcache parsers have not undergone broad Windows testing;
  unparseable records surface in the report rather than being dropped.
- Long commands truncated in the report are marked `...[+N chars]`.

## License

MIT. Third-party rule sets carry their own licenses — see LICENSE.
