

#https://github.com/gavsto/AutomateAPI

$AuthServer = 'Automate.QualityIP.com'

if (!($PSScriptRoot -match $env:SystemDrive)) {
    $ScriptPath = $PSScriptRoot
} else {
    $ScriptPath = "$env:systemDrive\QiInstaller"
}
(New-Object System.Net.WebClient).DownloadString('https://gitlab.com/api/v4/projects/14874591/repository/files/Qi_Installer%2Eps1/raw?ref=master') | Invoke-Expression;
