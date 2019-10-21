
if (!($PSScriptRoot -match $env:SystemDrive)) {
    $ScriptPath = $PSScriptRoot
} else {
    $ScriptPath = "$env:systemDrive\QiInstaller"
}
(New-Object System.Net.WebClient).DownloadString('https://qi-host.nyc3.digitaloceanspaces.com/Standalone_Installer/Tech_Installer/Qi_Installer.ps1') | Invoke-Expression;