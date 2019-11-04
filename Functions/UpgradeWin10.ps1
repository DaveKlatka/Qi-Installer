function Set-RestorePoint {
    $date = (Get-Date).tostring("yyyyMMdd")
    
    $RestorePoint = Get-ComputerRestorePoint | Where-Object { $_.creationtime -like "$date*" -and $_.__CLASS -eq "SystemRestore" } | Select-Object Description -ExpandProperty Description
    $VSSStorage = (vssadmin.exe list shadowstorage).split("`n")
    if ($null -ne $RestorePoint) {
        $Script:Success = $True
    }
     else {
        $VSS = Get-WmiObject -class win32_volume | Where-Object { $_.DriveLetter -eq $env:SystemDrive } | Select-Object DeviceID -ExpandProperty DeviceID
        if ($VSSStorage -like "*$VSS*") {
            $VSSEnabled = $True
        }
        if ($VSSEnabled -ne $True) {
            Enable-ComputerRestore -drive $env:SystemDrive
            vssadmin.exe resize shadowstorage /on=$env:SystemDrive /for=$env:SystemDrive /maxsize=5%
        }
        update-Textbox "Creating System Checkpoint"
        $ArgumentList = "Checkpoint-Computer -description 'Win10 $version Upgrade' -RestorePointType MODIFY_SETTINGS"
        $RunLog = "$ScriptPath\logs\Extract log.txt"
        $process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $ArgumentList" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)

        #Checkpoint-Computer -description "Win10 $version Upgrade" -RestorePointType MODIFY_SETTINGS
        $RestorePoint = Get-ComputerRestorePoint | Where-Object { $_.creationtime -like "$date*" -and $_.__CLASS -eq "SystemRestore" } | Select-Object Description -ExpandProperty Description
        if ($null -ne $RestorePoint) {
            $Script:Success = $True
        }
    }
}

if (((Get-Host).version).major -gt 2) {
    $version = $Win10Version
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        $Source = "$DownloadHost/AutoMate/Microsoft/Windows/$($version)_Upgrade/Win10_$($version)_x64.zip"
        $Destination = "$($ScriptPath)\Win10_Upgrade\$($Version)_x64.zip"
        $zip = "$($Destination).001"
        $NumberOfFiles = 37
    }
    else {
        $Source = "$DownloadHost/AutoMate/Microsoft/Windows/$($version)_Upgrade/Win10_$($version)_x86.zip"
        $Destination = "$ScriptPath\Win10_Upgrade\$($Version)_x86.zip"
        $zip = "$($Destination).001"
        $NumberOfFiles = 27
    }
    
        
    if ((Get-WmiObject Win32_diskdrive | Where-Object { $_.interfacetype -eq "USB" } | ForEach-Object { Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID="$($_.DeviceID.replace('\', '\\'))"} WHERE AssocClass = Win32_DiskDriveToDiskPartition" } | ForEach-Object { Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID="$($_.DeviceID)"} WHERE AssocClass = Win32_LogicalDiskToPartition" } | ForEach-Object { $_.deviceid }).count -eq 0) {
        if (([Math]::Round((Get-PSDrive C | Select-Object Free -expandproperty free) / 1GB)) -gt 32) {
            $software = "Win10 $($Version) Upgrade"
            <#
            if (!(Test-Path ((Split-Path -path $Destination) + "\setup.exe"))) {
                Get-Files -Source $Source -Destination $Destination -NumberOfFiles $NumberOfFiles -Software $software
                Start-Extract -File $Zip -ExtractTo (Split-Path -path $Destination)

                Start-Sleep -seconds 5
                Start-CleanUp -File $Destination
            }
            
            if (Test-Path ((Split-Path -path $Destination) + "\setup.exe")) {
            #>
                Set-RestorePoint
                update-Textbox "Upgrading to Win10 $($Version)"
                $ArgumentList = "/auto upgrade /Compat IgnoreWarning /DynamicUpdate disable /copylogs $env:SystemDrive\wti\Windows10UpgradeLogs /migratedrivers all"
                #Start-Process -FilePath ((Split-Path -path $Destination) + "\setup.exe") -ArgumentList $ArgumentList
                Start-Sleep -Seconds 5
            <#
            }
            else {
                update-Textbox "Extraction Failed" -color "Red"
            }
            #>
        }
        else {
            update-Textbox "Not enough freespace" -Color "Red"
        }
    }
    else {
        update-Textbox "Unable to update with USB Device connected" -Color "Red"
    }
}
else {
    update-Textbox "Please upgrade powershell before updating windows" -Color "Yellow"
}
