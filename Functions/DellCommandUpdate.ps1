Function Get-DellCommandexe {

    if ($null -ne (Get-ChildItem 'C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe' -ErrorAction SilentlyContinue)) {
        $Script:Executable = "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe"
    }
    elseif ($null -ne (Get-ChildItem 'C:\Program Files\Dell\CommandUpdate\dcu-cli.exe' -ErrorAction SilentlyContinue)) {
        $Script:Executable = "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe"
    }
    else {
        $Script:Executable = ""
    }
}
Function Install-DellCommand { 

    Uninstall-DellCommand
    Install-Software -Application "DellCommandUpdate"
    Get-DellCommandexe
}

Function Uninstall-DellCommand {

    $WinVersion = ([System.Environment]::OSVersion.Version).Major
    if ($WinVersion -eq "10") {
        if ((Get-AppxPackage | Where-Object { $_.name -eq "dellInc.Dellcommandupdate" } | Select-Object name -expandproperty name) -eq "DellInc.DellCommandUpdate") {
            Write-Output "-----Removing Command 3.0 Win 10 App-----"
            Get-AppxPackage | Where-Object { $_.name -eq "dellInc.Dellcommandupdate" } | Remove-AppxPackage
        }
    }

    $array = @()
    $UninstallKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" 
    $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME) 
    $regkey = $reg.OpenSubKey($UninstallKey) 
    $subkeys = $regkey.GetSubKeyNames() 
    foreach ($key in $subkeys) {

        $thisKey = $UninstallKey + "\\" + $key 
        $thisSubKey = $reg.OpenSubKey($thisKey) 
        $obj = New-Object PSObject
        $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
        $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
        $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))
        $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))
        $obj | Add-Member -MemberType NoteProperty -Name "SilentUninstall" -Value $($thisSubKey.GetValue("QuietUninstallString"))
        $obj | Add-Member -MemberType NoteProperty -Name "UninstallString" -Value $($thisSubKey.GetValue("UninstallString"))
        $array += $obj
    }
    $uninstaller = $array | Where-Object { $_.DisplayName -like "Dell Command | Update*" } | Select-Object UninstallString -ExpandProperty UninstallString
    if (($array | Where-Object { $_.DisplayName -like "Dell Command | Update*" } | Select-Object DisplayVersion -ExpandProperty DisplayVersion) -like "3*") {
        $Uninstaller = $uninstaller.split(" ")
        $param = $uninstaller[1], "/qn", "/norestart"
        
        Write-Output "---Removing Command 3.0 Win 10 config----"
        Start-Process $uninstaller[0] -argumentList $param
        Wait-Process -name msiexec -Timeout 300 -ErrorAction SilentlyContinue
    }
}

function Invoke-DriverUpdate {  
    $Log = "$ScriptPath\logs\DellCommand"
    $Arguments = "/log" + [char]32 + [char]34 + $Log + [char]34
    $Process = (start-process -FilePath $Executable -ArgumentList $Arguments -WindowStyle Hidden -PassThru)
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID
} 

Function Get-Logs {
    if ((Test-Path "$Log\ActivityLog.xml") -eq $true) {
        [xml]$Results = Get-Content "$Log\ActivityLog.xml"
        if ($null -ne (($Results.LogEntries.LogEntry | Where-Object { $_.message -like "*Install*" }).data | Where-Object { $_.type -eq "install" })) {
            update-Textbox "(($($Results.LogEntries.LogEntry) | Where-Object { $($_.message) -like "*Install*" }).data | Where-Object { $($_.type) -eq "install" }).name"
        }
        else {
            update-Textbox "No Updates availaible"
        }
    }
}

if ((get-wmiobject win32_computersystem).Manufacturer -match 'Dell') {
    $RunLog = "$ScriptPath\logs\DellCommand\ActivityLog.xml"
    Get-DellCommandexe
    if ($Executable.length -le 0) {
        Update-Textbox "Command Update 2.4 is not Installed" -Color "Red"
        Install-DellCommand
        Invoke-DriverUpdate
    }
    else {
        Invoke-DriverUpdate
    }
    if (!((([xml](get-content $RunLog)).logentries.logentry.message | Where-Object {$_.message -like "*Install*"}).data | Where-Object {$_.type -eq "install"})) {
        Update-Textbox "No Updates Availaible" -Color "Green"
    }
}
else {
    update-Textbox "Dell Hardware Not Detected"
}