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
$Command = "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -windowstyle Hidden -executionpolicy bypass -command $AuthServer = 'Automate.QualityIP.com'; $ScriptPath = '" &@ScriptDir & "';(New-Object System.Net.WebClient).DownloadString('https://gitlab.com/api/v4/projects/14874591/repository/files/Qi_Installer%2Eps1/raw?ref=master') | Invoke-Expression;"
runwait($Command)