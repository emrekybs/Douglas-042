# Douglas-042 - 
# Offense By Defense Blue Team -  Incident Response - PowerShell Hunting
[![EmreKybs](https://img.shields.io/badge/MadeBy-EmreKybs-blue)

<img src="https://github.com/emrekybs/Douglas-042/blob/main/blue.jpg">

DOUGLAS-042 stands as an ingenious embodiment of a PowerShell script meticulously designed to expedite the triage process and facilitate the meticulous collection of crucial evidence derived from both forensic artifacts and the ephemeral landscape of volatile data. Its fundamental mission revolves around providing indispensable aid in the arduous task of pinpointing potential security breaches within Windows ecosystems. With an overarching focus on expediency, DOUGLAS-042 orchestrates the efficient prioritization and methodical aggregation of data, ensuring that no vital piece of information eludes scrutiny when investigating a possible compromise. As a testament to its organized approach, the amalgamated data finds its sanctuary within the confines of a meticulously named text file, bearing the nomenclature of the host system's very own hostname. This practice of meticulous data archival emerges not just as a systematic convention, but as a cornerstone that paves the way for seamless transitions into subsequent stages of the Forensic journey.

### Queries
* General information
* ACCOUNT AND GROUP INFORMATION
* Network
* Process Information
* OS BUILD AND HOTFIXES
* Persistence
* HARDWARE Information
* Encryption information
* FIREWALL INFORMATION
* Services
* History
* SMB Queries
* Remoting queries
* REGISTRY Analysis
* LOG queries
* Instllation of Software
* User activity
* Prefetch file information
* DLL List
* WMI filters and consumers
* Named pipes

# Usage
Using administrative privileges, just run the script from a PowerShell console, then the results will be saved in the directory as a txt file.

    $ PS >./douglas.ps1
    
# Advance usage
    $ PS >./douglas.ps1 -a

<img src="https://github.com/emrekybs/Douglas-042/blob/main/png.jpg">
