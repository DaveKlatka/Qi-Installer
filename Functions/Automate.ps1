$LTPoSH = "(New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression"

Function Invoke-Install_Automate {
    #Install Command
    $RunLog = "$ScriptPath\logs\Automate_Install.txt"
    if (!((Get-WMIObject win32_operatingsystem).name -like 'Server')) {
        if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
            $dotnet35.performclick()
        }

        if ($DotNetInstalled -eq $true) {
            if ((Get-Host).Version.Major -gt 3){
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            } 
            else {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID" -RedirectStandardOutput $RunLog -PassThru)
            }
        }
        else {
            if ((Get-Host).Version.Major -gt 3){
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            } 
            else {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
            }
        }
    }
    else {
        if ((Get-Host).Version.Major -gt 3){
            $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
        } 
        else {
            $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; Install-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
        }
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID

    if (Test-Path $env:windir\LTSVC) {
        $ReInstall_Automate.Enabled = $true
        $UnInstall_Automate.Enabled = $true
        $Install_Automate.Enabled = $false
    }
}
Function Invoke-ReInstall_Automate {
    #Re-Install Command
    $RunLog = "$ScriptPath\logs\Automate_Re-Install.txt"
    if ((Get-Host).Version.Major -gt 3){
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; ReInstall-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle hidden -PassThru)
    } 
    else {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; ReInstall-LTService -Server 'https://automate.qualityip.com' -Password 'BndOZpmJrChvdODpKIbdiA==' -LocationID $LocationID -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID
}
Function Invoke-UnInstall_Automate {
    #Un-Install Command
    $RunLog = "$ScriptPath\logs\Automate_Un-Install.txt"
    if ((Get-Host).Version.Major -gt 3){
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; UnInstall-LTService -Server 'https://automate.qualityip.com'" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
    } 
    else {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $LTPoSH; UnInstall-LTService -Server 'https://automate.qualityip.com'" -RedirectStandardOutput $RunLog -PassThru)
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID

    if (!(Test-Path $env:windir\LTSVC)) {
        $ReInstall_Automate.Enabled = $false
        $UnInstall_Automate.Enabled = $false
        $install_Automate.Enabled = $true
    }
}