function Start-QiInstaller {
    param(
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $AutomateServer,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $AutomatePass,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $DownloadHost,
        [switch] $QiDebug
    )

    $TechInstaller_Load = {
    }
    $Close_Click = {
        $TechInstaller.Close()
    }
    #Set Default Path
    if (($ScriptPath -match $env:SystemDrive)) {
        $ScriptPath = "$env:systemDrive\QiInstaller"
    }
    else {
        $ScriptPath = "$ScriptPath\QiInstaller"
    }
    if (!(Test-Path $ScriptPath)) {
        New-Item -ItemType Directory -Path $ScriptPath | Out-Null
    }
    if (!(Test-Path $ScriptPath\logs)) {
        New-Item -ItemType Directory -Path $ScriptPath\logs | Out-Null
    }
    #Debug Options
    $DebugConsole_Click = {
        $DebugCommandButton.Visible = -not $DebugCommandButton.Visible
        $DebugCommand.Visible = -not $DebugCommand.Visible
    }

    $DebugCommandButton_Click = {
        #$DebugResult = Invoke-Expression $DebugCommand.Text
        write-output $($DebugCommand.Text)
        Write-Error (ivnoke-expression $DebugCommand.Text)
        Write-Error (ivnoke-expression $($DebugCommand.Text))
        Write-Error "$($DebugCommand.Text)"
        $test = invoke-expression $DebugCommand.Text
        Write-Output $($Test.value)
        Update-Textbox $($test.value)

        $DebugCommand.Text = ''
        

    }

    #Authenticator
    $AuthSubmit_Click = {
        #https://github.com/gavsto/AutomateAPI
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Connect-AutomateAPI.ps1') | Invoke-Expression;
        }
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2WIZQzW') | Invoke-Expression;
        }
        Try {
            $secpasswd = ConvertTo-SecureString $AuthPass.Text -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential ($AuthUser.Text, $secpasswd)
            Connect-AutomateAPI -credential $Credential -Server $AutomateServer -TwoFactorToken $2FAAuth.Text -ErrorAction stop
            if ($AuthUser.text -eq 'dklatkaadm') {
                $Script:Location = (get-automateclient -clientname "QualityIP").Locations | Where-Object { $_.ScriptExtra1 -eq $AuthUser.text }
            }
            else {
                $Script:Location = (get-automateclient -clientname "1_Technician Catchall").Locations | Where-Object { $_.ScriptExtra1 -eq $AuthUser.text }
            }
            $TechInstaller.Text = [System.String]"Tech Installer ($($Location.name))"
    
            if (!($null -eq $Location.ID)) {
                $AuthPanel.Visible = $false
            }
        }
        catch {
            $AuthError.Text = 'Failed to login with supplied credentials.'
            $AuthError.Visible = $true
        }
    
    }
    #Authenticator Cancel
    $AuthCancel_Click = {
        $TechInstaller.Close()
    }
    
    $AlphaButton_Click = {
        $AlphaButton.Visible = $false
    }
    $Beta3_Click = {
        $Beta3.Visible = $false
    }
    $BetaButton2_Click = {
        $BetaButton2.Visible = $false
    }
    
    #Run Automate Buttons
    $ReInstall_Automate_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/Automate.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Automate.ps1') | Invoke-Expression;
        }
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2pIY85I') | Invoke-Expression; 
        }
        Invoke-ReInstall_Automate  
    }
    $UnInstall_Automate_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/Automate.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Automate.ps1') | Invoke-Expression;
        } 
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2pIY85I') | Invoke-Expression; 
        }
        Invoke-UnInstall_Automate
    }
    $Install_Automate_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/Automate.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Automate.ps1') | Invoke-Expression;
        } 
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2pIY85I') | Invoke-Expression; 
        }
        Invoke-Install_Automate
    }
    
    $dotnet35_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/dotnet.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/dotnet.ps1') | Invoke-Expression;
        } 
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/34BQtET') | Invoke-Expression; 
        }
    }
    
    $InstallSoftware_Click = {
        if ((Get-Host).Version.Major -gt 3) {
            if ($SoftwareList.CheckedItems.count -gt 0 -and $SoftwareList.enabled) {
                foreach ($object in $SoftwareList.CheckedItems) {
                    Install-Software -Application $object
                } 
                foreach ($i in $SoftwareList.CheckedIndices) {
                    $SoftwareList.SetItemChecked($i, $false);
                }
            }
        }
        else {
            Add-Type -AssemblyName PresentationFramework
            $msgBoxInput = [System.Windows.MessageBox]::Show("Powershell $((Get-Host).Version.Major) detected. Would you like to upgrade Powershell?", 'Powershell Upgrade', 'YesNo', 'Warning')
            switch ($msgBoxInput) {
                'Yes' {
                    #. (Join-Path $PSScriptRoot 'Functions/Powershell.ps1')
                    if ($QiDebug) {
                        (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Powershell.ps1') | Invoke-Expression;
                    } 
                    else {
                        (New-Object System.Net.WebClient).DownloadString('http://bit.ly/33jsDh9') | Invoke-Expression; 
                    }
                }
            
                'No' {
                    update-Textbox "Wrong version of Powershell for install." -color 'Red'
                    foreach ($i in $SoftwareList.CheckedIndices) {
                        $SoftwareList.SetItemChecked($i, $false);
                    }
                }
            }
        }
    
        
        if ($365checkbox.checked -and $365checkbox.enabled) {
            #. (Join-Path $PSScriptRoot 'Functions/Office.ps1')
            if ($QiDebug) {
                (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Office.ps1') | Invoke-Expression;
            } 
            else {
                (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2pHCBKw') | Invoke-Expression; 
            }
        }
    }
    
    #Qi Power Policy
    $PowerPolicy_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/PowerPolicy.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/PowerPolicy.ps1') | Invoke-Expression;
        } 
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/36EXy9U') | Invoke-Expression; 
        }
    }
    
    #Dell Command Update
    $DellUpdate_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/DellCommandUpdate.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/DellCommandUpdate.ps1') | Invoke-Expression;
        }
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2NLQ6kF') | Invoke-Expression; 
        }
    }
    
    #Powershell 5
    $Powershell5_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/Powershell.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Powershell.ps1') | Invoke-Expression;
        }
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/33jsDh9') | Invoke-Expression; 
        }
    }
    
    #Win10 Upgrade
    $Win10Upgrade_Click = {
        Add-Type -AssemblyName PresentationFramework
        $msgBoxInput = [System.Windows.MessageBox]::Show('Options selected will reboot your computer. Would you like to continue?', 'Reboot Required', 'YesNo', 'Warning')
        switch ($msgBoxInput) {
            'Yes' {
                #. (Join-Path $PSScriptRoot 'Functions/UpgradeWin10.ps1')
                if ($QiDebug) {
                    (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/UpgradeWin10.ps1') | Invoke-Expression;
                }
                else {
                    (New-Object System.Net.WebClient).DownloadString('http://bit.ly/33vEKHO') | Invoke-Expression; 
                }
            }
            
            'No' {
                update-Textbox "Win10 Upgrade Canceled." -color 'Red'
            }
        }
    }

    $SystemRestorePoint_Click = {
        Set-RestorePoint -Description 'Qi-Installer'
    }
    
    #Rename Computer/ Join Domain
    $RenameDomain_Click = {
        #. (Join-Path $PSScriptRoot 'Functions/Rename.ps1')
        if ($QiDebug) {
            (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Rename.ps1') | Invoke-Expression;
        }
        else {
            (New-Object System.Net.WebClient).DownloadString('http://bit.ly/32fCO56') | Invoke-Expression; 
        }
    }
    
    #Download Icons
    Import-Module BitsTransfer
    $Images = "$ScriptPath\images"
    $png = $Images + '\Qi_logo_HIRES.png'
    $ico = $Images + '\Qi_ico.ico'
    if (!(Test-Path $Images)) {
        New-Item -ItemType Directory -Path $Images | Out-Null
    }
    if (!(Test-Path -path $png)) {
        Start-BitsTransfer -Source 'http://bit.ly/2qtUqN9' -Destination $png
    }
    if (!(Test-Path -path $ico)) {
        Start-BitsTransfer -Source 'http://bit.ly/2POjxFd' -Destination $ico
    }
    
    #GUI interactions
    $365Checkbox_CheckedChanged = {
        $365ComboBox.Enabled = -not $365ComboBox.Enabled
    }

    #USMT_Profile Select
    $Profiles_Click = {
        $Script:SelectedProfile = Get-UserProfiles | Out-GridView -Title 'Profile Selection' -OutputMode Multiple
        update-Textbox "Profile(s) selected for migration:"
        $SelectedProfile | ForEach-Object { 
            update-Textbox "$($_.UserName)"
        }
    }
    $AddDirectory_Click = {
        Add-ExtraDirectory
    }
    $RemoveDirectory_Click = {
        Remove-ExtraDirectory
    }
    $ExportLocationButton_Click = {
        Set-SaveDirectory -Type Destination
    }
    $Export_Click = {
        Save-UserState
    }
    $ImportSelect_Click = {
        Set-SaveDirectory -Type Source
    }
    $ImportButton_Click = {
        Restore-UserState
    }
    $TestConnection_Click = {
        $TestComputerConnectionParams = @{
            ComputerNameTextBox = $OldComputerText
            ComputerIPTextBox   = $OldIPAddressText
            ConnectionCheckBox  = $ConnectionCheckBox
        }
        Test-ComputerConnection @TestComputerConnectionParams
    }
    $RunNetMig_Click = {
        if ($ConnectionCheckBox.Checked -and $UNCVerified.Checked) {
            Invoke-USMT -SourceComputer $OldComputerText.Text -Credential $Creds
        }
        else {
            Update-Textbox "Connection not Verified. Please Test Connection first" -color 'Orange'
        }
    }

    $Cancel_Click = {
        $TechInstaller.Close()
    }

    #GUI
    Add-Type -AssemblyName System.Windows.Forms
    #. (Join-Path $PSScriptRoot 'Qi_Installer.designer.ps1')
    if ($QiDebug) {
        (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Qi_Installer.designer.ps1') | Invoke-Expression;
    }
    else {
        (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2JRPhoW') | Invoke-Expression; 
    }

    #USMT Functions
    #. (Join-Path $PSScriptRoot 'Functions/User_Migration.ps1')
    if ($QiDebug) {
        (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/User_Migration.ps1') | Invoke-Expression;
    }
    else {
        (New-Object System.Net.WebClient).DownloadString('http://bit.ly/2JTVAbJ') | Invoke-Expression; 
    }
    
    #Univeral Functions
    #. (Join-Path $PSScriptRoot 'Functions/Functions.ps1')
    if ($QiDebug) {
        (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Functions/Functions.ps1') | Invoke-Expression;
    }
    else {
        (New-Object System.Net.WebClient).DownloadString('http://bit.ly/32j0NQX') | Invoke-Expression; 
    }

    #Debug Options
    if ($QiDebug) {
        $DebugConsole.Visible = -not $DebugCommandButton.Visible
    }
    
    #Check Automate Installed
    if (Test-Path $env:windir\LTSVC) {
        $ReInstall_Automate.Enabled = $true
        $UnInstall_Automate.Enabled = $true
        $Install_Automate.Enabled = $false
    }
    
    #Check .net 3.5 Installed
    if ((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.') {
        $dotnet35.Enabled = $false
    }
    #Check Powershell 5
    if (((get-host).version.major) -ge 5) {
        $Powershell5.Enabled = $false
    }
    #Check Win 10 Version
    $Win10Version = "1903"
    if (((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseID -erroraction SilentlyContinue).ReleaseID) -eq $Win10Version -and (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).producttype -eq 1) {
        $Win10Upgrade.Enabled = $false
    }
    
    #SystemInfo
    $ComputerSystemInfo = Get-CimInstance Win32_ComputerSystem
    $OperatingSystemInfo = Get-CimInstance Win32_OperatingSystem
    $DiskInfo = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$($env:homedrive)'"
    
    $SystemInfo.ColumnCount = 2
    $SystemInfo.Rows.Add('ComputerName', $ComputerSystemInfo.name) | Out-Null
    $SystemInfo.Rows.Add('Domain', $ComputerSystemInfo.Domain) | Out-Null
    $SystemInfo.Rows.Add('Manufacturer', $ComputerSystemInfo.Manufacturer) | Out-Null
    $SystemInfo.Rows.Add('System Family', $ComputerSystemInfo.SystemFamily) | Out-Null
    $SystemInfo.Rows.Add('Model', $ComputerSystemInfo.Model) | Out-Null
    $SystemInfo.Rows.Add('OS', $OperatingSystemInfo.Caption) | Out-Null
    $SystemInfo.Rows.Add('Version', $OperatingSystemInfo.Version) | Out-Null
    $SystemInfo.Rows.Add('RAM', "$(((Get-CimInstance win32_physicalmemory).capacity | measure-object -sum).sum /1GB) GB") | Out-Null
    $SystemInfo.Rows.Add('Disk ' + $env:homedrive + ' Size', "$([Math]::Round(($DiskInfo.Size) / 1GB)) GB") | Out-Null
    $SystemInfo.Rows.Add('Disk ' + $env:homedrive + ' FreeSpace', "$([Math]::Round(($DiskInfo.FreeSpace) / 1GB)) GB") | Out-Null
    
    $SystemInfo.DefaultCellStyle.SelectionBackColor = $SystemInfo.BackgroundColor
    $SystemInfo.DefaultCellStyle.SelectionForeColor = 'Black'
    foreach ($row in $SystemInfo.Rows) {
        $row.DefaultCellStyle.BackColor = $SystemInfo.BackgroundColor
    }

    $ExtraDataGridView.ColumnCount = 1
    $TechInstaller.icon = $ico
    $picturebox1.imageLocation = $png
    
    $365ComboBox.Enabled = -not $365ComboBox.Enabled
    
    $TechInstaller.ShowDialog()
}
