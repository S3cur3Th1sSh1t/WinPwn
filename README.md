# WinPwn
Still much work to do - many error messages - Automation for internal Windows Penetrationtest

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
			vii. LateralMovement ->  FindLocalAdminAccess --> Invoke-MassMimikatz --> DomainPasswordspray
				1) Todo: Powershell Empire Integration
			viii. Share Enumeration
			ix. FindGPOLocation --> Search for user/group rights 
			x. Find-Fruit
