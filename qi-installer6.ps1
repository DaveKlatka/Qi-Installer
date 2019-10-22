Import-Module BitsTransfer


Start-BitsTransfer -Source 'https://qi-host.nyc3.digitaloceanspaces.com/Standalone_Installer/Windows_Update/PackageManagement.zip' -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement.zip"
Start-BitsTransfer -Source 'https://qi-host.nyc3.digitaloceanspaces.com/Standalone_Installer/Windows_Update/PowerShellGet.zip' -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\PowerShellGet.zip"

$ArgumentList = "&$($7zip) x '$($file)' -aoa -o'$ExtractTo'"
    $RunLog = "$ScriptPath\logs\Extract log.txt"
    if ((Get-Host).Version.Major -gt 3){
        $process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $ArgumentList" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
start-extract -file "$env:ProgramFiles\WindowsPowerShell\Modules\PackageManagement.zip" -ExtractTo "$env:ProgramFiles\WindowsPowerShell\Modules"
$7zip = "$Scriptpath\7za.exe"
$ArgumentList = "&$($7zip) x '$($file)' -aoa -o'$ExtractTo'"