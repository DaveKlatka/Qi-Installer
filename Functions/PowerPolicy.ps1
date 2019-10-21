function Get-HardwareType {
    $hardwaretype = (Get-WmiObject -Class Win32_ComputerSystem).PCSystemType
    If ($hardwaretype -ne 2) {
        return $true
    }
    Else {
        return $false
    }
}

Try {
    If (Get-HardwareType) {
        $Script:comp = "Desktop"
    }
    Else {
        $Script:comp = "Laptop"
    }
        
    $match = [string](powercfg.exe -list) -match "([0-f]+-[0-f]+-[0-f]+-[0-f]+-[0-f]+)\s+.Qi - $comp Power Policy."
    if ($match) {
        $QiGUID = $matches[1]
        $current = [string](powercfg.exe /getactivescheme) -match "(.Qi - $comp Power Policy.)"
        if (!($current)) {
            powercfg.exe -setactive $QiGUID
        }
    }
    else {
        $Output = $ScriptPath + '\PowerPolicy'
        if (!(Test-Path $output)) { New-Item -ItemType Directory -Path $output | Out-Null }
        get-files -source 'https://qi-host.nyc3.digitaloceanspaces.com/Standalone_Installer/Tech_Installer/PowerPolicy/Qi%20-%20Power%20Policy.zip' -Destination "$Output\Qi - Power Policy.zip" -NumberOfFiles 1 -Software "PowerPolicy"
        Start-Extract -File "$Output\Qi - Power Policy.zip" -ExtractTo $Output
        
        if (Test-Path -path "$output\Qi - $comp Power Policy.pow") {
            $import = [string](powercfg.exe import "$output\Qi - $comp Power Policy.pow") -match 'Imported Power Scheme Successfully. GUID: ([0-f]+-[0-f]+-[0-f]+-[0-f]+-[0-f]+)'
            if ($import) {
                powercfg.exe -setactive $matches[1]
            }
        }
    }
}
Finally {
    $match = [string](powercfg.exe -list) -match "([0-f]+-[0-f]+-[0-f]+-[0-f]+-[0-f]+\s+.Qi - $comp Power Policy.\s*)"
    if ($match) {
        update-Textbox "Qi - $comp Power Policy configured" -color "Green"
    }
}