$AuthServer = 'Automate.QualityIP.com'

#Set Default Path
if (!($PSScriptRoot -match $env:SystemDrive)) {
    $ScriptPath = $PSScriptRoot
} else {
    $ScriptPath = "$env:systemDrive\QiInstaller"
}
if (!(Test-Path $ScriptPath\logs)) {
    New-Item -ItemType Directory -Path $ScriptPath\logs | Out-Null
}
Install-Module AutomateAPI -force
Import-Module AutomateAPI
(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/gavsto/AutomateAPI/master/Public/Connect-AutomateAPI.ps1') | Invoke-Expression;
Connect-AutomateAPI -credential $Credential -Server $authServer -TwoFactorToken $2FAAuth.Text -ErrorAction stop

(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/gavsto/AutomateAPI/master/Public/Get-AutomateClient.ps1') | Invoke-Expression;
(New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/gavsto/AutomateAPI/master/Public/Get-AutomateAPIGeneric.ps1') | Invoke-Expression;