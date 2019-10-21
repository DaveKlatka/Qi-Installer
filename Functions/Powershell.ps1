function Test-Compatibility {
    $Script:ReturnValue = $true

    $BuildVersion = [System.Environment]::OSVersion.Version

    if ($BuildVersion.Major -ge '10') {
        update-Textbox 'WMF 5.1 is not supported for Windows 10 and above.' -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## OS is below Windows Vista
    if ($BuildVersion.Major -lt '6') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## OS is Windows Vista
    if ($BuildVersion.Major -eq '6' -and $BuildVersion.Minor -le '0') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }
    ## OS 7 is missing Service Pack 1
    if ($BuildVersion.Major -eq '6' -and $BuildVersion.Build -eq '7600') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## Check if WMF 3 is installed
    $wmf3 = Get-WmiObject -Query "select * from Win32_QuickFixEngineering where HotFixID = 'KB2506143'"

    if ($wmf3) {
        update-Textbox "WMF 5.1 is not supported when WMF 3.0 is installed." -color "Yellow"
        Add-Type -AssemblyName PresentationFramework
        $msgBoxInput = [System.Windows.MessageBox]::Show('Powershell 3 detected. PS 4 Must be installed prior to 5 Would you like to install Powershell 4 now?', 'WMF 4.0', 'YesNo', 'Warning')

        switch ($msgBoxInput) {
            'Yes' {
                Install-Software -Application "powershell4"
            }
            'No' {
                update-Textbox "Powershell Upgrade Canceled" -color "Yellow"
            }
        }
        $Script:ReturnValue = $false
    }

    # Check if .Net 4.5 or above is installed

    $release = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Release -ErrorAction SilentlyContinue -ErrorVariable evRelease).release
    $installed = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Install -ErrorAction SilentlyContinue -ErrorVariable evInstalled).install

    if ($evRelease -or $evInstalled) {
        Update-Text "WMF 5.1 requires .Net 4.5" -color 'Yellow'
        $Script:ReturnValue = $false
    }
    elseif (($installed -ne 1) -or ($release -lt 378389)) {
        Update-Text "WMF 5.1 requires .Net 4.5" -color 'Yellow'
        $Script:ReturnValue = $false
    }
}

Test-Compatibility

if ($ReturnValue) {
    if (((Get-WmiObject win32_OperatingSystem).Caption) -match 'Windows 7') {
        if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
            $msu = "$($ScriptPath)\Win7AndW2K8R2-KB3191566-x64.msu"
            Get-Files -Source "https://qi-host.nyc3.digitaloceanspaces.com/AutoMate/Microsoft/Windows/PoSH/Win7AndW2K8R2-KB3191566-x64.msu" -Destination $msu -NumberOfFiles 1 -Software "Powershell 5"
        }
        else {
            $msu = "$($ScriptPath)\Win7-KB3191566-x86.msu"
            Get-Files -Source "https://qi-host.nyc3.digitaloceanspaces.com/AutoMate/Microsoft/Windows/PoSH/Win7-KB3191566-x86.msu" -Destination $msu -NumberOfFiles 1 -Software "Powershell 5"
        } 
        $wusaExe = "$env:windir\system32\wusa.exe"
        $wusaParameters = @("`"{0}`"" -f $msu)
        $wusaParameters += @("/quiet", "/norestart")
        $wusaParameterString = $wusaParameters -join " "
        net.exe stop wuauserv
        $RunLog = "$ScriptPath\logs\Powershell.txt"
        update-Textbox "Installing powershell 5"
        $Process = (Start-Process -FilePath $wusaExe -ArgumentList $wusaParameterString -PassThru)
        start-sleep 1
        Get-ProgressBar -RunLog $RunLog -ProcessID $Process.Id

        Add-Type -AssemblyName PresentationFramework
        $msgBoxInput = [System.Windows.MessageBox]::Show('A reboot is required to finish Powershell 5 install. Would you like to restart now?', 'Reboot Required', 'YesNo', 'Warning')

        switch ($msgBoxInput) {
            'Yes' {
                shutdown.exe -r -t 30
                update-Textbox "System Rebooting" -color "Yellow"
            }
            'No' {
                update-Textbox "Please reboot at your earliest convenience" -color "Yellow"
            }
        }
    }
}