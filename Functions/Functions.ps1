function update-Textbox {
    param(
        [string] $Message,
        [string] $Color = 'White',
        [switch] $NoNewLine
    )
    $LogBox.SelectionColor = $Color
    $LogBox.AppendText("$Message")
    $LogBox
    if (-not $NoNewLine) {
        $LogBox.AppendText("`n")
    }
    $LogBox.Update()
    $LogBox.ScrollToCaret()
    $LogBox.ScrollToCaret()
}

function Get-Files {
    param(
        [string] $Source,
        [string] $Destination,
        [string] $NumberOfFiles,
        [string] $Software
    )
    $TotalProgress.Value = 0
    $CurrentFile.Value = 0
    update-Textbox "Downloading Installer for $($Software) to $(Split-Path -path $Destination)"
    if (!(Test-Path (Split-Path -path $Destination))) { New-Item -ItemType Directory -Path (Split-Path -path $Destination) }
    Import-Module BitsTransfer
    $DCount = 0
    if ($NumberOfFiles -eq 1) {
        $CurrentFile.Visible = $true
        $bits = (Start-BitsTransfer -Source $Source -Destination $Destination -Asynchronous)
        start-sleep -Milliseconds 1000
        While ($bits.jobstate -ne 'Transferred') {
            $CurrentFile.Value = ([math]::Round(($bits.BytesTransferred / $bits.BytesTotal) * 100))
            start-sleep -Milliseconds 100
        }

        $CurrentFile.Visible = $false
        $CurrentFile.Value = 0
        $bits.jobid | Complete-BitsTransfer
        
        if ($bits.jobstate) {
            $bits.jobid | Remove-BitsTransfer
        }
    }
    else {
        for ($i = 1; $i -le $NumberOfFiles; $i++) {
            if ($Dcount -ge 100) {
                Break
            }
            else {
                if ($i -le 9) {
                    $File = $Source + ".00" + $i
                    $Location = $Destination + ".00" + $i
                    while (!(Test-Path $Location)) {
                        $DCount = $Dcount + 1
                        if ($Dcount -ge 100) {
                            Break
                        }
                        else {
                            $CurrentFile.Visible = $true
                            $TotalProgress.Visible = $true
                            $bits = (Start-BitsTransfer -Source $File -Destination $Location -Asynchronous)

                            $Tpct = ($i / $NumberOfFiles) * 100
                            $TotalProgress.Value = $Tpct
                            start-sleep -Milliseconds 1000

                            While ($bits.jobstate -ne 'Transferred') {
                                $CurrentFile.Value = ([math]::Round(($bits.BytesTransferred / $bits.BytesTotal) * 100))
                                start-sleep -Milliseconds 100
                            }

                            $CurrentFile.Value = 0
                            $bits.jobid | Complete-BitsTransfer
                            
                            if ($bits.jobstate) {
                                $bits.jobid | Remove-BitsTransfer
                            }
                        }
                    }
                }
                else {
                    $File = $Source + ".0" + $i
                    $Location = $Destination + ".0" + $i
                    while (!(Test-Path $Location)) {
                        $DCount = $Dcount + 1
                        if ($Dcount -ge 100) {
                            Break
                        }
                        else {
                            $CurrentFile.Visible = $true
                            $TotalProgress.Visible = $true
                            $bits = (Start-BitsTransfer -Source $File -Destination $Location -Asynchronous)

                            $Tpct = ($i / $NumberOfFiles) * 100
                            $TotalProgress.Value = $Tpct
                            start-sleep -Milliseconds 1000

                            While ($bits.jobstate -ne 'Transferred') {
                                $CurrentFile.Value = ([math]::Round(($bits.BytesTransferred / $bits.BytesTotal) * 100))
                                start-sleep -Milliseconds 100
                            }

                            $CurrentFile.Value = 0
                            $bits.jobid | Complete-BitsTransfer
                            
                            if ($bits.jobstate) {
                                $bits.jobid | Remove-BitsTransfer
                            }
                        }
                    }
                }
            }
        }
    }
    if ($CurrentFile.Visible -eq $true) {
        $CurrentFile.Visible = $false
    }
    if ($TotalProgress.Visible -eq $true) {
        $TotalProgress.Visible = $false
    }
}

function Start-Extract {
    param(
        [string] $File,
        [string] $ExtractTo
    )
    $Source = "$DownloadHost/AutoMate/Tools/7za.exe"
    $7zip = "$Scriptpath\7za.exe"
    if (!(Test-Path $7zip)) {
        update-Textbox "Downloading 7zip extractor"
        $CurrentFile.Value = 0
        $CurrentFile.Visible = $true
        $bits = (Start-BitsTransfer -Source $Source -Destination $7zip -Asynchronous)
        start-sleep -Milliseconds 1000
        While ($bits.jobstate -ne 'Transferred') {
            $CurrentFile.Value = ([math]::Round(($bits.BytesTransferred / $bits.BytesTotal) * 100))
            start-sleep -Milliseconds 100
        }

        $CurrentFile.Visible = $false
        $bits.jobid | Complete-BitsTransfer
        
        if ($bits.jobstate) {
            $bits.jobid | Remove-BitsTransfer
        }
    }
    update-Textbox "Extracting $file to $ExtractTo"
    $ArgumentList = "&$($7zip) x '$($file)' -aoa -o'$ExtractTo'"
    $RunLog = "$ScriptPath\logs\Extract log.txt"
    if ((Get-Host).Version.Major -gt 3) {
        $process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $ArgumentList" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
    } 
    else {
        $process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $ArgumentList" -RedirectStandardOutput $RunLog -PassThru)
    }
    start-sleep 1
    Get-ProgressBar -RunLog $RunLog -ProcessID $Process.ID
}

function Start-CleanUp {
    param(
        [string] $File
    )
    update-Textbox "Removing $File"
    Remove-Item -Path "$File*" -Recurse
}

function Install-Software {
    Param (
        [string] $Application
    )
    if ($Application -ne "") {
        if (!(Test-Path $env:ProgramData\chocolatey\bin\choco.exe -ErrorAction SilentlyContinue)) {
            New-Item $env:ALLUSERSPROFILE\choco-cache -ItemType Directory -Force 
            $env:TEMP = "$env:ALLUSERSPROFILE\choco-cache" 
            $RunLog = "$ScriptPath\logs\Chocolatey log.txt"
            $process = (start-process powershell -ArgumentList "Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://bit.ly/2NjIHtz'))" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            Start-Sleep -Seconds 1
            Get-ProgressBar -RunLog $RunLog -ProcessID $Process.ID
        }
        $RunLog = "$ScriptPath\logs\$Application Install.txt"
        $Process = (Start-Process -filepath C:\ProgramData\chocolatey\choco.exe -argumentlist "Upgrade $Application -ignore-checksums -y" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
        start-sleep 1
        Get-ProgressBar -RunLog $RunLog -ProcessID $Process.ID -Tracker
    }
}

Function Get-ProgressBar {
    Param(
        [String] $Runlog,
        [String] $ProcessID,
        [Switch] $Tracker
    )
    if ($Lastline) {
        Clear-Variable -name LastLine
    }
    if ($Promptcheck) {
        Clear-Variable -name Promptcheck
    }
    
    if (-not $Tracker) {
        if ($CurrentFile.visible -eq $false) {
            $CurrentFile.Value = 0
            $CurrentFile.Visible = $true
        }
        if ($TotalProgress.Visible -eq $false) {
            $TotalProgress.Value = 0
            $TotalProgress.Visible = $true
        }
    
        while (get-process -id $ProcessID -ErrorAction SilentlyContinue) {
            if ($Runlog -match '.xml') {
                if (!($Promptcheck)) {
                    foreach ($line in ($lines = ([xml](get-content $RunLog)).logentries.logentry.message)) {
                        $lastline += "$line`n"
                    }
                }
                else {
                    Clear-Variable -name LastLine
                    foreach ($line in ($lines = ([xml](get-content $RunLog)).logentries.logentry.message)) {
                        if (!($promptcheck -contains $line)) {
                            $lastline += "$line`n"
                        }
                    } 
                }
                $Promptcheck = $lines
            }
            else {
                if (!($Promptcheck)) {
                    $LastLine = get-content $RunLog
                    $Promptcheck = $lastline
                } 
                else {
                    Clear-Variable -name LastLine
                    foreach ($line in ($lines = get-content $RunLog)) {
                        if (!($promptcheck -contains $line)) {
                            $lastline += "$line`n"
                        }
                    }
                    $Promptcheck = $lines
                }
            }
            if (!($null -eq $lastline) -and $lastline.TrimEnd() -ne '.') {
                if ($lastline.TrimEnd() -match 'ERROR' -or $lastline.TrimEnd() -match 'not successful') {
                    Update-Textbox $lastline.TrimEnd() -Color 'Red'
                }
                elseif ($lastline.TrimEnd() -match 'WARNING') {
                    Update-Textbox $lastline.TrimEnd() -Color 'Yellow'
                }
                elseif ($lastline.TrimEnd() -match 'successful' -or $lastline.TrimEnd() -match 'completed' -or $lastline.TrimEnd() -match 'installed') {
                    Update-Textbox $lastline.TrimEnd() -color 'Green'
                }
                elseif ($lastline.TrimEnd() -match 'Waiting') {
                    if (!($wait)) {
                        $Wait = $true
                        update-Textbox $lastline.TrimEnd()
                    }
                }
                else {
                    $Wait = $false
                    Update-Textbox $lastline.TrimEnd()
                }
            }

            if ($CurrentFile.Value -lt 100) {
                $CurrentFile.Value++
            }
            else {
                if ($Totalprogress.Value -lt 100) {
                    $TotalProgress.Value++
                }
                else {
                    $TotalProgress.Value = 0
                }
                $CurrentFile.Value = 0
            }
            start-sleep -Milliseconds 5
        }
        if ($CurrentFile.Visible -eq $true) {
            $CurrentFile.Visible = $false
        }
        if ($TotalProgress.Visible -eq $true) {
            $TotalProgress.Visible = $false
        }
    }
    else {
        if ($CurrentFile.visible -eq $false) {
            $CurrentFile.Value = 0
            $CurrentFile.Visible = $true
        }
        while (get-process -id $ProcessID -ErrorAction SilentlyContinue) {
            if ($Runlog -match '.xml') {
                if (!($Promptcheck)) {
                    foreach ($line in ($lines = ([xml](get-content $RunLog)).logentries.logentry.message)) {
                        $lastline += "$line`n"
                    }
                }
                else {
                    Clear-Variable -name LastLine
                    foreach ($line in ($lines = ([xml](get-content $RunLog)).logentries.logentry.message)) {
                        if (!($promptcheck -contains $line)) {
                            $lastline += "$line`n"
                        }
                    } 
                }
                $Promptcheck = $lines
            }
            else {
                if (!($Promptcheck)) {
                    $LastLine = get-content $RunLog
                    $Promptcheck = $lastline
                } 
                else {
                    Clear-Variable -name LastLine
                    foreach ($line in ($lines = get-content $RunLog)) {
                        if (!($promptcheck -contains $line)) {
                            if ($line -match '\d{2}\s[a-zA-Z]+\s\d{4}\,\s\d{2}\:\d{2}\:\d{2}') {
                                $LastLine += "($LastLine.Split(',', 4)[3]).TrimStart()`n"
                            }
                            else {
                                $lastline += "$line`n"
                            }
                        }
                    }
                    $Promptcheck = $lines
                }
            }
            if (!($null -eq $lastline) -and $lastline.TrimEnd() -ne '.') {
                if ($lastline.TrimEnd() -match '([\d]+)\.\d\%') {
                    $CurrentFile.Value = $matches[1]
                }
                elseif ($lastline.TrimEnd() -match 'Progress.+\s([\d]+)\%') {
                    $CurrentFile.Value = $matches[1]
                }
                elseif ($lastline.TrimEnd() -match 'ERROR' -or $lastline.TrimEnd() -match 'not successful') {
                    Update-Textbox $lastline.TrimEnd() -Color 'Red'
                }
                elseif ($lastline.TrimEnd() -match 'WARNING') {
                    Update-Textbox $lastline.TrimEnd() -Color 'Yellow'
                }
                elseif ($lastline.TrimEnd() -match 'successful' -or $lastline.TrimEnd() -match 'completed' -or $lastline.TrimEnd() -match 'installed') {
                    Update-Textbox $lastline.TrimEnd() -color 'Green'
                }
                elseif ($lastline.TrimEnd() -match 'Waiting') {
                    if (!($wait)) {
                        $Wait = $true
                        update-Textbox $lastline.TrimEnd()
                    }
                }
                else {
                    $Wait = $false
                    Update-Textbox $lastline.TrimEnd()
                }
            }
            start-sleep -Milliseconds 50
        }
        if ($CurrentFile.Visible -eq $true) {
            $CurrentFile.Visible = $false
        }
        if ($TotalProgress.Visible -eq $true) {
            $TotalProgress.Visible = $false
        }
    }  
}

function Set-RestorePoint {
    Param(
        [string] $Description
    )
    $date = (Get-Date).tostring("yyyyMMdd")

    $VSSStorage = (vssadmin.exe list shadowstorage).split("`n")
    $VSS = Get-WmiObject -class win32_volume | Where-Object { $_.DriveLetter -eq $env:SystemDrive }
    if (!($VSSStorage -like "*$($VSS.DeviceID)*")) {
        Update-Textbox "Enabling and configuring System Restore"
        Enable-ComputerRestore -drive $env:SystemDrive -ErrorAction stop
        vssadmin.exe resize shadowstorage /on=$env:SystemDrive /for=$env:SystemDrive /maxsize=5%
    }

    Update-Textbox "Creating Restore Point '$Description'"
    $RunLog = "$ScriptPath\logs\SystemRestorePoint.txt"
    if ((Get-Host).Version.Major -gt 3) {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command Checkpoint-Computer -description '$Description' -RestorePointType MODIFY_SETTINGS" -RedirectStandardOutput $RunLog -WindowStyle hidden -PassThru)
    } 
    else {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command Checkpoint-Computer -description '$Description' -RestorePointType MODIFY_SETTINGS" -RedirectStandardOutput $RunLog -PassThru)
    }

    #start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID

    if (!((get-content $RunLog) -match 'WARNING')) {
        $RestorePoint = Get-ComputerRestorePoint -ErrorAction stop | Where-Object { $_.creationtime -like "$date*" -and $_.__CLASS -eq "SystemRestore" }
        if ($null -ne $RestorePoint) {
            update-Textbox "Restore Point '$($RestorePoint.Description)' has been created" -Color 'Green'
        }
    }
}