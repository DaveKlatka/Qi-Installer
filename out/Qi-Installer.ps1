
$ScriptPath = 'C:\QiInstaller'
. (Join-Path 'C:\Users\dklatka\source\repos\Qi-Installer' 'Qi_Installer.ps1')
Start-QiInstaller -AutomateServer 'Automate.QualityIP.com' -AutomatePass 'BndOZpmJrChvdODpKIbdiA==' -DownloadHost 'https://qi-host.nyc3.digitaloceanspaces.com'
