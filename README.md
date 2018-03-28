# WinPwn
Still much work to do - Automation for internal Windows Penetrationtest. 

	1) Automatic Proxy Detection
	2) Elevated or unelevated Detection
  	3) Forensic Mode oder Pentest Mode 
		a. Forensik -> Loki + PSRECON + Todo: Threathunting functions
		b. Pentest -> Internal Windows Domain System 
			i. Inveigh NBNS/SMB/HTTPS Spoofing
			ii. Local Reconing -> Hostenum, SessionGopher, FileSearch, PSRecon
			iii. Domain Reconing -> GetExploitableSystems, Powerview functions, ACL-Analysis, ADRecon
				1) Todo: Grouper for Group Policy overview
			iv. Privilege Escalation -> Powersploit (Allchecks), GPP-Passwords,  MS-Exploit Search (Sherlock)
			v. Lazagne Password recovery
			vi. Exploitation -> Kerberoasting, Mimikittenz, Mimikatz with Admin-rights
			vii. LateralMovement ->  FindLocalAdminAccess 
				1) Invoke-MassMimikatz || Powershell Empire Remote Launcher Execution over WMI
				2) DomainPasswordspray
				
			viii. Share Enumeration
			ix. FindGPOLocation --> Search for user/group rights 
			x. Find-Fruit

Just Import the Modules with "Import-Module .\WinPwn_v0.3.ps1"
And Start the automatic Script with "WinPwn".



disclaimer:

I'm not responsible for anything you do with this program, so please only use it for good and educational purposes.
