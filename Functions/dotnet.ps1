if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
    update-Textbox ".NET 3.5 installation needed."
    #Install-WindowsFeature Net-Framework-Core

    if ([version][System.Environment]::OSVersion.Version -gt [version]'6.2') {
        try {
            
            $output = $ScriptPath + '\dotnet3_5'
            if (!(Test-Path $output)) {
                New-Item -ItemType Directory -Path $output | Out-Null
            }
            
            Get-Files -Source "$DownloadHost/AutoMate/Microsoft/Windows/DotNet/Win10_sxs.zip" -Destination "$output\Win10_sxs.zip" -NumberOfFiles 1 -Software '.NET 3.5'
            Start-Extract -File "$output\Win10_sxs.zip" -ExtractTo $output

            #Install Command
            $RunLog = "$ScriptPath\logs\DotNet3_5_Install.txt"
            $arguments = '/online /enable-feature /featurename:NetFX3 /All /source:' + $output + '\sxs'
            $Process = (Start-Process -filepath $env:windir\system32\dism.exe -ArgumentList $arguments -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            start-sleep 1
            Get-ProgressBar -Runlog $RunLog -ProcessID $Process.id -Tracker
            
        }
        catch {
            if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
                update-Textbox "ERROR: .NET 3.5 install failed." -Color 'Red'
            }
        }
    }
    Else {

        Try { $Result = (Start-Process -FilePath "$env:windir\system32\Dism.exe" -ArgumentList '/online Enable /get-featureinfo /featurename:NetFx3') } 
        Catch { update-Textbox "Error calling Dism.exe." -Color 'Red'; $Result = $Null }
        If ($Result -contains "State : Enabled") {
            update-Textbox ".Net Framework 3.5 has been installed and enabled." -Color 'Green'
        }
        Else { 
            update-Textbox "ERROR: .NET 3.5 install failed." -Color 'Red'
        }#End If
        
    }#End If

    if ((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.') {
        update-Textbox ".net 3.5 installed succesfully" -Color 'Green'
        if ($dotnet35.Enabled -eq $true) {
            $dotnet35.Enabled = $false
        } 
        $DotNetInstalled = $true
    }
    else {
        update-Textbox ".net 3.5 failed to install" -color 'Red'
    }
}
else {
    update-Textbox ".Net 3.5 already installed" -color 'Yellow'
    if ($dotnet35.Enabled -eq $true) {
        $dotnet35.Enabled = $false
    } 
    $DotNetInstalled = $true
}