#cs ----------------------------------------------------------------------------

 AutoIt Version: 3.3.14.5
 Author:         Dave Klatka

 Script Function:
	Template AutoIt script.

#ce ----------------------------------------------------------------------------

; Script Start - Add your code below here
#RequireAdmin
#pragma compile(FileVersion, 1.0)
#pragma compile(ProductVersion, 1.0)
#pragma compile(LegalCopyright, Quality IP, LLC)
#pragma compile(ProductName, Qi-Installer)
#pragma compile(FileDescription, QiInstaller is a technician installer to be useed by Qi Technicians.)
#NoTrayIcon
$Server = "Automate.QualityIP.com"
$Pass = "BndOZpmJrChvdODpKIbdiA=="
$Host = "https://qi-host.nyc3.digitaloceanspaces.com"
$Command = "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -command $ScriptPath = '" &@ScriptDir & "';$AutomateServer = '" &$Server & "';$AutomatePass = '" &$Pass & "';$DownloadHost = '" &$Host & "';(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/master/Qi_Installer.ps1') | Invoke-Expression;"
runwait($Command)