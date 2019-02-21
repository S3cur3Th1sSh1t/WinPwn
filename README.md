# WinPwn
Still much work to do - Automation for internal Windows Penetrationtest. Different local recon modules, domain recon modules, pivilege escalation and exploitation modules. Any suggestions, feedback and comments are welcome!

Just Import the Modules with "Import-Module .\WinPwn_v0.6.ps1" or with 
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.6.ps1')

Functions available after Import:
1) #### `isadmin` -> Checks for local admin access
2) #### `Inveigh` -> Executes Inveigh in a new Console window (https://github.com/Kevin-Robertson/Inveigh)
3) #### `sessionGopher` -> Executes Sessiongopher in memory (https://github.com/Arvanaghi/SessionGopher)
4) #### `Mimikatzlocal` -> Executes Invoke-WCMDump and Invoke-Mimikatz after with admin rights (https://github.com/PowerShellMafia/PowerSploit)
5) #### `localreconmodules` -> Executes different Get-Computerdetails and Just another Windows Privilege escalation script + Winspect (https://github.com/PowerShellMafia/PowerSploit, https://github.com/A-mIn3/WINspect, https://github.com/411Hall/JAWS)
6) #### `JAWS` -> Just another Windows Privilege Escalation script gets executed
7) #### `domainreconmodules` -> Different Powerview situal awareness functions get executed and the output stored on disk. In Addition a Userlist for DomainpasswordSpray gets stored on disk. An AD-Report is generated as CSV Files (or XLS if excel is installed) with ADRecon. (https://github.com/sense-of-security/ADRecon, https://github.com/PowerShellMafia/PowerSploit, https://github.com/dafthack/DomainPasswordSpray)
8) #### `Privescmodules` -> Executes different privesc scripts in memory (Sherlock https://github.com/rasta-mouse/Sherlock, PowerUp, GPP-Files, WCMDump)
9) #### `lazagnemodule` -> Downloads and executes lazagne.exe (if not detected by AV) (https://github.com/AlessandroZ/LaZagne)
10) #### `latmov` -> Searches for Systems with Admin-Access in the domain for lateral movement. Mass-Mimikatz can be used after for the found systems. Domainpassword-Spray for new Credentials can also be done here.
11) #### `empirelauncher` -> Launch powershell empire oneliner for remote Systems (https://github.com/EmpireProject/Empire)
12) #### `shareenumeration` -> Invoke-Filefinder and Invoke-Sharefinder from Powerview (Powersploit)
13) #### `groupsearch` -> FindGPOLocation (Powerview / Powersploit)
14) #### `Kerberoasting` -> Executes Invoke-Kerberoast in a new window and stores the hashes for later cracking
15) #### `WinPwn` -> Guides the user through all functions/Modules with simple questions.


The "oBEJHzXyARrq.exe"-Executable is an obfuscated Version of jaredhaights PSAttack Tool for Applocker/PS-Restriction Bypass (https://github.com/jaredhaight/PSAttack).

![alt text](https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/Pwn.png)


## Legal disclaimer:
Usage of WinPwn for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.
