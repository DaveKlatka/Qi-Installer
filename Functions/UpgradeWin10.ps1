if (((Get-Host).version).major -gt 2) {
    $version = $Win10Version
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        $Source = "$DownloadHost/AutoMate/Microsoft/Windows/$($version)_Upgrade/Win10_$($version)_x64.zip"
        $Destination = "$($ScriptPath)\Win10_Upgrade\$($Version)_x64.zip"
        $zip = "$($Destination).001"
        $NumberOfFiles = 51
    }
    else {
        $Source = "$DownloadHost/AutoMate/Microsoft/Windows/$($version)_Upgrade/Win10_$($version)_x86.zip"
        $Destination = "$ScriptPath\Win10_Upgrade\$($Version)_x86.zip"
        $zip = "$($Destination).001"
        $NumberOfFiles = 35
    }
    
    <# 
    if ((Get-WmiObject Win32_diskdrive | Where-Object { $_.interfacetype -eq "USB" } | ForEach-Object { Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID="$($_.DeviceID.replace('\', '\\'))"} WHERE AssocClass = Win32_DiskDriveToDiskPartition" } | ForEach-Object { Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID="$($_.DeviceID)"} WHERE AssocClass = Win32_LogicalDiskToPartition" } | ForEach-Object { $_.deviceid }).count -eq 0) {
    #>
    if (([Math]::Round((Get-PSDrive C | Select-Object Free -expandproperty free) / 1GB)) -gt 32) {
        $software = "Win10 $($Version) Upgrade"
        if (!(Test-Path ((Split-Path -path $Destination) + "\setup.exe"))) {
            Get-Files -Source $Source -Destination $Destination -NumberOfFiles $NumberOfFiles -Software $software
            Start-Extract -File $Zip -ExtractTo (Split-Path -path $Destination)

            Start-Sleep -seconds 5
            Start-CleanUp -File $Destination
        }
            
        if (Test-Path ((Split-Path -path $Destination) + "\setup.exe")) {
            Set-RestorePoint -Description "Win 10 $($Version) Upgrade"
            update-Textbox "Upgrading to Win10 $($Version)"
            $ArgumentList = "/auto upgrade /Compat IgnoreWarning /DynamicUpdate disable /copylogs $env:SystemDrive\wti\Windows10UpgradeLogs /migratedrivers all"
            Start-Process -FilePath ((Split-Path -path $Destination) + "\setup.exe") -ArgumentList $ArgumentList
            Start-Sleep -Seconds 5

        }
        else {
            update-Textbox "Extraction Failed" -color "Red"
        }
    }
    else {
        update-Textbox "Not enough freespace" -Color "Red"
    }
    <#
    }
    else {
        update-Textbox "Unable to update with USB Device connected" -Color "Red"
    }
    #>
}
else {
    update-Textbox "Please upgrade powershell before updating windows" -Color "Yellow"
}
