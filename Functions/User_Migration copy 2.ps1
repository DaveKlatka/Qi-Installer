<#
.SYNOPSIS
Migrate user state from one PC to another using USMT.

.DESCRIPTION
Migrate user state from one PC to another using USMT. Intended for domain joined computers.
By default, all user profile data except Favorites and Documents will be included.
Tool also allows for user to specify additional folders to include.

.NOTES
USMT environmental variables: https://technet.microsoft.com/en-us/library/cc749104(v=ws.10).aspx
#>

begin {
    # Define the script version
    $ScriptVersion = "3.4.4"

    # Set ScripRoot variable to the path which the script is executed from
    $ScriptRoot = if ($PSVersionTable.PSVersion.Major -lt 3) {
        Split-Path -Path $MyInvocation.MyCommand.Path
    }
    else {
        $PSScriptRoot
    }

    # Load the options in the Config file
    . "$ScriptRoot\Config.ps1"

    # Set a value for the wscript comobject
    $WScriptShell = New-Object -ComObject wscript.shell



    function Get-IPAddress { (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString }

    function Get-UserProfileLastLogin {
        param(
            [string]$Domain,
            [string]$UserName
        )

        $CurrentUser = try { ([ADSI]"WinNT://$Domain/$UserName") } catch { }
        if ($CurrentUser.Properties.LastLogin) {
            try {
                [datetime](-join $CurrentUser.Properties.LastLogin)
            }
            catch {
                -join $CurrentUser.Properties.LastLogin
            }
        }
        elseif ($CurrentUser.Properties.Name) {
        }
        else {
            'N/A'
        }
    }

    





    function Show-DomainInfo {
        # Populate old user data if DomainMigration.txt file exists, otherwise disable group box
        if (Test-Path "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt") {
            $OldUser = Get-Content "$MigrationStorePath\$($OldComputerNameTextBox_NewPage.Text)\DomainMigration.txt"
            $OldDomainTextBox.Text = $OldUser.Split('\')[0]
            $OldUserNameTextBox.Text = $OldUser.Split('\')[1]
        }
        else {
            $CrossDomainMigrationGroupBox.Enabled = $false
            $CrossDomainMigrationGroupBox.Hide()
        }
    }

    





    function Set-Logo {
        Update-Log "             __  __ _                 _   _             " -Color 'LightBlue'
        Update-Log "            |  \/  (_) __ _ _ __ __ _| |_(_) ___  _ __  " -Color 'LightBlue'
        Update-Log "            | |\/| | |/ _`` | '__/ _`` | __| |/ _ \| '_ \ " -Color 'LightBlue'
        Update-Log "            | |  | | | (_| | | | (_| | |_| | (_) | | | |" -Color 'LightBlue'
        Update-Log "            |_|  |_|_|\__, |_|  \__,_|\__|_|\___/|_| |_|" -Color 'LightBlue'
        Update-Log "                _     |___/  _     _              _     " -Color 'LightBlue'
        Update-Log "               / \   ___ ___(_)___| |_ __ _ _ __ | |_   " -Color 'LightBlue'
        Update-Log "              / _ \ / __/ __| / __| __/ _`` | '_ \| __|  " -Color 'LightBlue'
        Update-Log "             / ___ \\__ \__ \ \__ \ || (_| | | | | |_   " -Color 'LightBlue'
        Update-Log "            /_/   \_\___/___/_|___/\__\__,_|_| |_|\__| $ScriptVersion" -Color 'LightBlue'
        Update-Log
        Update-Log '                        by Nick Rodriguez' -Color 'Gold'
        Update-Log
    }

    function Test-IsISE { if ($psISE) { $true } else { $false } }

    function Test-PSVersion {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Update-Log "You are running a version of PowerShell less than 3.0 - some features have been disabled."
            $ChangeSaveDestinationButton.Enabled = $false
            $ChangeSaveSourceButton.Enabled = $false
            $AddExtraDirectoryButton.Enabled = $false
            $SelectProfileButton.Enabled = $false
            $IncludeCustomXMLButton.Enabled = $false
        }
    }

    function Test-Email {
        $EmailSubject = "Migration Assistant Email Test"
        if ($SMTPConnectionCheckBox.Checked -or (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
            $SMTPConnectionCheckBox.Checked = $true

            $EmailRecipients = @()

            $EmailRecipientsDataGridView.Rows | ForEach-Object {
                $CurrentRowIndex = $_.Index
                $EmailRecipients += $EmailRecipientsDataGridView.Item(0, $CurrentRowIndex).Value
            }

            Update-Log "Sending test email to: $EmailRecipients"

            try {
                $SendMailMessageParams = @{
                    From        = $EmailSenderTextBox.Text
                    To          = $EmailRecipients
                    Subject     = $EmailSubject
                    Body        = $LogTextBox.Text
                    SmtpServer  = $SMTPServerTextBox.Text
                    ErrorAction = 'Stop'
                }
                Send-MailMessage @SendMailMessageParams
            }
            catch {
                Update-Log "Error occurred sending email: $($_.Exception.Message)" -Color 'Red'
            }
        }
        else {
            Update-Log "Unable to send email of results because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
        }
    }

    function Read-Password {
        # Set the password set flag to false.
        $Script:EncryptionPasswordSet = $Null
        # Clear the password reset flag.
        $Script:EncryptionPasswordRetry = $Null

        # Prompt the user for an encryption password.
        $Script:EncryptionPassword = $Null
        $Script:EncryptionPassword = Get-Credential -Message "Enter the encryption password" -UserName "Enter a password Below"
        # Prompt the user again for confirmation.
        $Script:EncryptionPasswordConfirm = $Null
        $Script:EncryptionPasswordConfirm = Get-Credential -Message "Please confirm the encryption password" -UserName "Enter a password Below"

        # Convert the password strings to plain text so that they can be compared.
        if ($Script:EncryptionPassword.Password) {
            $Script:EncryptionPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:EncryptionPassword.Password))
        }

        if ($Script:EncryptionPasswordConfirm.Password) {
            $Script:EncryptionPasswordConfirm = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:EncryptionPasswordConfirm.Password))
        }

        # Compare the password strings and verify that they match
        if ($Script:EncryptionPassword -ne $Script:EncryptionPasswordConfirm -or
            $Script:EncryptionPassword -eq "" -or
            $null -eq $Script:EncryptionPassword) {
            Update-Log "Password did not match or was blank." -Color 'Yellow'
        }
        else {
            # Set a flag that the password was successfully set
            $Script:EncryptionPasswordSet = $True
        }

        # Prompt the user to try again if the strings did not match.
        if ($Script:EncryptionPasswordSet -ne $True -and $Script:EncryptionPasswordRetry -ne '7') {
            do {
                $Script:EncryptionPasswordRetry = $WScriptShell.Popup(
                    'Encryption password was not successfully set, try again?',
                    0,
                    'Retry Password',
                    4
                )

                # Prompt again if the user opted to retry
                if ($Script:EncryptionPasswordRetry -ne '7') {
                    Update-Log 'Retrying password prompt.' -Color Yellow
                    Read-Password
                }

            } while ($Script:EncryptionPasswordSet -ne $True -and $Script:EncryptionPasswordRetry -ne '7')
        }
    }

    # Hide parent PowerShell window unless run from ISE or set $HidePowershellWindow to false
    if ((-not $(Test-IsISE)) -and ($HidePowershellWindow) ) {
        $ShowWindowAsync = Add-Type -MemberDefinition @"
    [DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32ShowWindowAsync" -Namespace Win32Functions -PassThru
        $ShowWindowAsync::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle, 0) | Out-Null
    }

    # Load assemblies for building forms
    # [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null
    # [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $Script:Destination = ''
}

process {
    # Create form
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = 'Migration Assistant by Nick Rodriguez'
    $Form.Size = New-Object System.Drawing.Size(1000, 550)
    $Form.SizeGripStyle = 'Hide'
    $Form.FormBorderStyle = 'FixedSingle'
    $Form.MaximizeBox = $false
    $Form.StartPosition = "CenterScreen"
    $Icon = [system.drawing.icon]::ExtractAssociatedIcon($PSHOME + "\powershell.exe")
    $Form.Icon = $Icon

    # Create tab controls
    $TabControl = New-object System.Windows.Forms.TabControl
    $TabControl.DataBindings.DefaultDataSourceUpdateMode = 0
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(480, 490)

    $Form.Controls.Add($TabControl)

    # Log output text box
    $LogTextBox = New-Object System.Windows.Forms.RichTextBox
    $LogTextBox.Location = New-Object System.Drawing.Size(500, 30)
    $LogTextBox.Size = New-Object System.Drawing.Size(475, 472)
    $LogTextBox.ReadOnly = 'True'
    $LogTextBox.BackColor = 'Black'
    $LogTextBox.ForeColor = 'White'
    $LogTextBox.Font = 'Consolas, 10'
    $LogTextBox.DetectUrls = $false
    Set-Logo
    $Form.Controls.Add($LogTextBox)

    # Clear log button
    $ClearLogButton = New-Object System.Windows.Forms.Button
    $ClearLogButton.Location = New-Object System.Drawing.Size(370, 505)
    $ClearLogButton.Size = New-Object System.Drawing.Size(80, 20)
    $ClearLogButton.FlatStyle = 1
    $ClearLogButton.BackColor = 'White'
    $ClearLogButton.ForeColor = 'Black'
    $ClearLogButton.Text = 'Clear'
    $ClearLogButton.Add_Click({ $LogTextBox.Clear() })
    $LogTextBox.Controls.Add($ClearLogButton)

    # Create old computer tab
    $OldComputerTabPage = New-Object System.Windows.Forms.TabPage
    $OldComputerTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $OldComputerTabPage.UseVisualStyleBackColor = $true
    $OldComputerTabPage.Text = 'Old Computer'
    $TabControl.Controls.Add($OldComputerTabPage)

    # Computer info group
    $OldComputerInfoGroupBox = New-Object System.Windows.Forms.GroupBox
    $OldComputerInfoGroupBox.Location = New-Object System.Drawing.Size(10, 10)
    $OldComputerInfoGroupBox.Size = New-Object System.Drawing.Size(450, 87)
    $OldComputerInfoGroupBox.Text = 'Computer Info'
    $OldComputerTabPage.Controls.Add($OldComputerInfoGroupBox)

    # Name label
    $ComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $ComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(100, 12)
    $ComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(100, 22)
    $ComputerNameLabel_OldPage.Text = 'Computer Name'
    $OldComputerInfoGroupBox.Controls.Add($ComputerNameLabel_OldPage)

    # IP label
    $ComputerIPLabel_OldPage = New-Object System.Windows.Forms.Label
    $ComputerIPLabel_OldPage.Location = New-Object System.Drawing.Size(230, 12)
    $ComputerIPLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $ComputerIPLabel_OldPage.Text = 'IP Address'
    $OldComputerInfoGroupBox.Controls.Add($ComputerIPLabel_OldPage)

    # Old Computer name label
    $OldComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $OldComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(12, 35)
    $OldComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $OldComputerNameLabel_OldPage.Text = 'Old Computer'
    $OldComputerInfoGroupBox.Controls.Add($OldComputerNameLabel_OldPage)

    # Old Computer name text box
    $OldComputerNameTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $OldComputerNameTextBox_OldPage.ReadOnly = $false
    $OldComputerNameTextBox_OldPage.Location = New-Object System.Drawing.Size(100, 34)
    $OldComputerNameTextBox_OldPage.Size = New-Object System.Drawing.Size(120, 20)
    $OldComputerNameTextBox_OldPage.Text = $env:COMPUTERNAME
    $OldComputerInfoGroupBox.Controls.Add($OldComputerNameTextBox_OldPage)

    # Old Computer IP text box
    $OldComputerIPTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $OldComputerIPTextBox_OldPage.ReadOnly = $true
    $OldComputerIPTextBox_OldPage.Location = New-Object System.Drawing.Size(230, 34)
    $OldComputerIPTextBox_OldPage.Size = New-Object System.Drawing.Size(90, 20)
    $OldComputerIPTextBox_OldPage.Text = Get-IPAddress
    $OldComputerInfoGroupBox.Controls.Add($OldComputerIPTextBox_OldPage)

    # New Computer name label
    $NewComputerNameLabel_OldPage = New-Object System.Windows.Forms.Label
    $NewComputerNameLabel_OldPage.Location = New-Object System.Drawing.Size(12, 57)
    $NewComputerNameLabel_OldPage.Size = New-Object System.Drawing.Size(80, 22)
    $NewComputerNameLabel_OldPage.Text = 'New Computer'
    $OldComputerInfoGroupBox.Controls.Add($NewComputerNameLabel_OldPage)

    # New Computer name text box
    $NewComputerNameTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $NewComputerNameTextBox_OldPage.Location = New-Object System.Drawing.Size(100, 56)
    $NewComputerNameTextBox_OldPage.Size = New-Object System.Drawing.Size(120, 20)
    $NewComputerNameTextBox_OldPage.Add_TextChanged({
            if ($ConnectionCheckBox_OldPage.Checked) {
                Update-Log 'Computer name changed, connection status unverified.' -Color 'Yellow'
                $ConnectionCheckBox_OldPage.Checked = $false
            }
        })
    $OldComputerInfoGroupBox.Controls.Add($NewComputerNameTextBox_OldPage)

    # New Computer IP text box
    $NewComputerIPTextBox_OldPage = New-Object System.Windows.Forms.TextBox
    $NewComputerIPTextBox_OldPage.Location = New-Object System.Drawing.Size(230, 56)
    $NewComputerIPTextBox_OldPage.Size = New-Object System.Drawing.Size(90, 20)
    $NewComputerIPTextBox_OldPage.Add_TextChanged({
            if ($ConnectionCheckBox_OldPage.Checked) {
                Update-Log 'Computer IP address changed, connection status unverified.' -Color 'Yellow'
                $ConnectionCheckBox_OldPage.Checked = $false
            }
        })
    $OldComputerInfoGroupBox.Controls.Add($NewComputerIPTextBox_OldPage)

    # Button to test connection to new computer
    $TestConnectionButton_OldPage = New-Object System.Windows.Forms.Button
    $TestConnectionButton_OldPage.Location = New-Object System.Drawing.Size(335, 33)
    $TestConnectionButton_OldPage.Size = New-Object System.Drawing.Size(100, 22)
    $TestConnectionButton_OldPage.Text = 'Test Connection'
    $TestConnectionButton_OldPage.Add_Click({
            $TestComputerConnectionParams = @{
                ComputerNameTextBox = $NewComputerNameTextBox_OldPage
                ComputerIPTextBox   = $NewComputerIPTextBox_OldPage
                ConnectionCheckBox  = $ConnectionCheckBox_OldPage
            }
            Test-ComputerConnection @TestComputerConnectionParams
        })
    $OldComputerInfoGroupBox.Controls.Add($TestConnectionButton_OldPage)

    # Connected check box
    $ConnectionCheckBox_OldPage = New-Object System.Windows.Forms.CheckBox
    $ConnectionCheckBox_OldPage.Enabled = $false
    $ConnectionCheckBox_OldPage.Text = 'Connected'
    $ConnectionCheckBox_OldPage.Location = New-Object System.Drawing.Size(336, 58)
    $ConnectionCheckBox_OldPage.Size = New-Object System.Drawing.Size(100, 20)
    $OldComputerInfoGroupBox.Controls.Add($ConnectionCheckBox_OldPage)

    # Profile selection group box
    $SelectProfileGroupBox = New-Object System.Windows.Forms.GroupBox
    $SelectProfileGroupBox.Location = New-Object System.Drawing.Size(240, 220)
    $SelectProfileGroupBox.Size = New-Object System.Drawing.Size(220, 100)
    $SelectProfileGroupBox.Text = 'Profile Selection'
    $OldComputerTabPage.Controls.Add($SelectProfileGroupBox)

    # Select profile(s) button
    $SelectProfileButton = New-Object System.Windows.Forms.Button
    $SelectProfileButton.Location = New-Object System.Drawing.Size(30, 20)
    $SelectProfileButton.Size = New-Object System.Drawing.Size(160, 20)
    $SelectProfileButton.Text = 'Select Profile(s) to Migrate'
    $SelectProfileButton.Add_Click({
            Update-Log "Please wait while profiles are found..."
            $Script:SelectedProfile = Get-UserProfiles |
                Out-GridView -Title 'Profile Selection' -OutputMode Multiple
            Update-Log "Profile(s) selected for migration:"
            $Script:SelectedProfile | ForEach-Object { Update-Log $_.UserName }
        })
    $SelectProfileGroupBox.Controls.Add($SelectProfileButton)

    # Recent profile day limit text box
    $RecentProfilesDaysTextBox = New-Object System.Windows.Forms.TextBox
    $RecentProfilesDaysTextBox.Location = New-Object System.Drawing.Size(165, 70)
    $RecentProfilesDaysTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $RecentProfilesDaysTextBox.Text = $DefaultRecentProfilesDays
    $SelectProfileGroupBox.Controls.Add($RecentProfilesDaysTextBox)

    # Only recent profiles check box
    $RecentProfilesCheckBox = New-Object System.Windows.Forms.CheckBox
    $RecentProfilesCheckBox.Text = 'Migrate all profiles logged into within this amount of days:'
    $RecentProfilesCheckBox.Location = New-Object System.Drawing.Size(15, 50)
    $RecentProfilesCheckBox.Size = New-Object System.Drawing.Size(200, 40)
    $RecentProfilesCheckBox.Checked = $DefaultRecentProfiles
    $RecentProfilesCheckBox.Add_Click({
            if ($RecentProfilesCheckBox.Checked -eq $true) {
                Update-Log "All profiles logged into within the last $($RecentProfilesDaysTextBox.Text) days will be saved."
                $SelectProfileButton.Enabled = $false
            }
            else {
                Update-Log "Recent profile save disabled." -Color Yellow
                $SelectProfileButton.Enabled = $true
            }
        })
    $SelectProfileGroupBox.Controls.Add($RecentProfilesCheckBox)

    # Alternative save location group box
    $SaveDestinationGroupBox = New-Object System.Windows.Forms.GroupBox
    $SaveDestinationGroupBox.Location = New-Object System.Drawing.Size(240, 110)
    $SaveDestinationGroupBox.Size = New-Object System.Drawing.Size(220, 100)
    $SaveDestinationGroupBox.Text = 'Save State Destination'
    $OldComputerTabPage.Controls.Add($SaveDestinationGroupBox)

    # Save path
    $SaveDestinationTextBox = New-Object System.Windows.Forms.TextBox
    $SaveDestinationTextBox.Text = $MigrationStorePath
    $SaveDestinationTextBox.Location = New-Object System.Drawing.Size(5, 20)
    $SaveDestinationTextBox.Size = New-Object System.Drawing.Size(210, 20)
    $SaveDestinationGroupBox.Controls.Add($SaveDestinationTextBox)

    # Alternative save check box
    $SaveRemotelyCheckBox = New-Object System.Windows.Forms.CheckBox
    $SaveRemotelyCheckBox.Text = 'Save on new computer'
    $SaveRemotelyCheckBox.Checked = $DefaultSaveRemotely
    $SaveRemotelyCheckBox.Location = New-Object System.Drawing.Size(45, 45)
    $SaveRemotelyCheckBox.Size = New-Object System.Drawing.Size(150, 20)
    if ($SaveRemotelyCheckBox.Checked -eq $true) {
        $OldComputerInfoGroupBox.Enabled = $true
    }
    else {
        $OldComputerInfoGroupBox.Enabled = $false
    }
    # Toggle when checkbox clicked
    $SaveRemotelyCheckBox.Add_Click({
            if ($SaveRemotelyCheckBox.Checked -eq $true) {
                $OldComputerInfoGroupBox.Enabled = $true
                Update-Log 'Local save destination disabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Save state will be stored on the new computer and network checks will be processed normally.'
            }
            else {
                $OldComputerInfoGroupBox.Enabled = $false
                Update-Log 'Local save destination enabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Save state will be stored locally and network checks will be skipped.'
            }
        })
    $SaveDestinationGroupBox.Controls.Add($SaveRemotelyCheckBox)

    # Change save destination button
    $ChangeSaveDestinationButton = New-Object System.Windows.Forms.Button
    $ChangeSaveDestinationButton.Location = New-Object System.Drawing.Size(35, 70)
    $ChangeSaveDestinationButton.Size = New-Object System.Drawing.Size(60, 20)
    $ChangeSaveDestinationButton.Text = 'Change'
    $ChangeSaveDestinationButton.Add_Click({ Set-SaveDirectory -Type Destination })
    $SaveDestinationGroupBox.Controls.Add($ChangeSaveDestinationButton)

    # Reset save destination button
    $ResetSaveDestinationButton = New-Object System.Windows.Forms.Button
    $ResetSaveDestinationButton.Location = New-Object System.Drawing.Size(120, 70)
    $ResetSaveDestinationButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveDestinationButton.Text = 'Reset'
    $ResetSaveDestinationButton.Add_Click({
            Update-Log "Resetting save directory to [$MigrationStorePath]."
            $SaveDestinationTextBox.Text = $MigrationStorePath
        })
    $SaveDestinationGroupBox.Controls.Add($ResetSaveDestinationButton)

    # Inclusions group box
    $InclusionsGroupBox = New-Object System.Windows.Forms.GroupBox
    $InclusionsGroupBox.Location = New-Object System.Drawing.Size(10, 110)
    $InclusionsGroupBox.Size = New-Object System.Drawing.Size(220, 140)
    $InclusionsGroupBox.Text = 'Data to Include'
    $OldComputerTabPage.Controls.Add($InclusionsGroupBox)

    # AppData check box CSIDL_APPDATA
    $IncludeAppDataCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeAppDataCheckBox.Checked = $DefaultIncludeAppData
    $IncludeAppDataCheckBox.Text = 'AppData'
    $IncludeAppDataCheckBox.Location = New-Object System.Drawing.Size(10, 15)
    $IncludeAppDataCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeAppDataCheckBox.Add_Click({
            $ComponentName = $IncludeAppDataCheckBox.Text
            if ($IncludeAppDataCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included."
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeAppDataCheckBox)

    # Local AppData check box CSIDL_LOCAL_APPDATA
    $IncludeLocalAppDataCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeLocalAppDataCheckBox.Checked = $DefaultIncludeLocalAppData
    $IncludeLocalAppDataCheckBox.Text = 'Local AppData'
    $IncludeLocalAppDataCheckBox.Location = New-Object System.Drawing.Size(10, 35)
    $IncludeLocalAppDataCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeLocalAppDataCheckBox.Add_Click({
            $ComponentName = $IncludeLocalAppDataCheckBox.Text
            if ($IncludeLocalAppDataCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeLocalAppDataCheckBox)

    # Printers check box CSIDL_PRINTERS
    $IncludePrintersCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludePrintersCheckBox.Checked = $DefaultIncludePrinters
    $IncludePrintersCheckBox.Text = 'Printers'
    $IncludePrintersCheckBox.Location = New-Object System.Drawing.Size(10, 55)
    $IncludePrintersCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludePrintersCheckBox.Add_Click({
            $ComponentName = $IncludePrintersCheckBox.Text
            if ($IncludePrintersCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludePrintersCheckBox)

    # Recycle Bin check box CSIDL_BITBUCKET
    $IncludeRecycleBinCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeRecycleBinCheckBox.Checked = $DefaultIncludeRecycleBin
    $IncludeRecycleBinCheckBox.Text = 'Recycle Bin'
    $IncludeRecycleBinCheckBox.Location = New-Object System.Drawing.Size(10, 75)
    $IncludeRecycleBinCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeRecycleBinCheckBox.Add_Click({
            $ComponentName = $IncludeRecycleBinCheckBox.Text
            if ($IncludeRecycleBinCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeRecycleBinCheckBox)

    # My Documents check box CSIDL_MYDOCUMENTS and CSIDL_PERSONAL
    $IncludeMyDocumentsCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyDocumentsCheckBox.Checked = $DefaultIncludeMyDocuments
    $IncludeMyDocumentsCheckBox.Text = 'My Documents'
    $IncludeMyDocumentsCheckBox.Location = New-Object System.Drawing.Size(10, 95)
    $IncludeMyDocumentsCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyDocumentsCheckBox.Add_Click({
            $ComponentName = $IncludeMyDocumentsCheckBox.Text
            if ($IncludeMyDocumentsCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeMyDocumentsCheckBox)

    # Wallpapers
    $IncludeWallpapersCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeWallpapersCheckBox.Checked = $DefaultIncludeWallpapers
    $IncludeWallpapersCheckBox.Text = 'Wallpapers'
    $IncludeWallpapersCheckBox.Location = New-Object System.Drawing.Size(10, 115)
    $IncludeWallpapersCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeWallpapersCheckBox.Add_Click({
            $ComponentName = $IncludeWallpapersCheckBox.Text
            if ($IncludeWallpapersCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeWallpapersCheckBox)

    # Desktop check box CSIDL_DESKTOP and CSIDL_DESKTOPDIRECTORY
    $IncludeDesktopCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeDesktopCheckBox.Checked = $DefaultIncludeDesktop
    $IncludeDesktopCheckBox.Text = 'Desktop'
    $IncludeDesktopCheckBox.Location = New-Object System.Drawing.Size(110, 115)
    $IncludeDesktopCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeDesktopCheckBox.Add_Click({
            $ComponentName = $IncludeDesktopCheckBox.Text
            if ($IncludeDesktopCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeDesktopCheckBox)

    # Downloads check box CSIDL_DOWNLOADS
    $IncludeDownloadsCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeDownloadsCheckBox.Checked = $DefaultIncludeDownloads
    $IncludeDownloadsCheckBox.Text = 'Downloads'
    $IncludeDownloadsCheckBox.Location = New-Object System.Drawing.Size(110, 15)
    $IncludeDownloadsCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeDownloadsCheckBox.Add_Click({
            $ComponentName = $IncludeDownloadsCheckBox.Text
            if ($IncludeDownloadsCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeDownloadsCheckBox)

    # Favorites check box CSIDL_FAVORITES
    $IncludeFavoritesCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeFavoritesCheckBox.Checked = $DefaultIncludeFavorites
    $IncludeFavoritesCheckBox.Text = 'Favorites'
    $IncludeFavoritesCheckBox.Location = New-Object System.Drawing.Size(110, 35)
    $IncludeFavoritesCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeFavoritesCheckBox.Add_Click({
            $ComponentName = $IncludeFavoritesCheckBox.Text
            if ($IncludeFavoritesCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeFavoritesCheckBox)

    # My Music check box CSIDL_MYMUSIC
    $IncludeMyMusicCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyMusicCheckBox.Checked = $DefaultIncludeMyMusic
    $IncludeMyMusicCheckBox.Text = 'My Music'
    $IncludeMyMusicCheckBox.Location = New-Object System.Drawing.Size(110, 55)
    $IncludeMyMusicCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyMusicCheckBox.Add_Click({
            $ComponentName = $IncludeMyMusicCheckBox.Text
            if ($IncludeMyMusicCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeMyMusicCheckBox)

    # My Pictures check box CSIDL_MYPICTURES
    $IncludeMyPicturesCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyPicturesCheckBox.Checked = $DefaultIncludeMyPictures
    $IncludeMyPicturesCheckBox.Text = 'My Pictures'
    $IncludeMyPicturesCheckBox.Location = New-Object System.Drawing.Size(110, 75)
    $IncludeMyPicturesCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyPicturesCheckBox.Add_Click({
            $ComponentName = $IncludeMyPicturesCheckBox.Text
            if ($IncludeMyPicturesCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeMyPicturesCheckBox)

    # My Video check box CSIDL_MYVIDEO
    $IncludeMyVideoCheckBox = New-Object System.Windows.Forms.CheckBox
    $IncludeMyVideoCheckBox.Checked = $DefaultIncludeMyVideo
    $IncludeMyVideoCheckBox.Text = 'My Video'
    $IncludeMyVideoCheckBox.Location = New-Object System.Drawing.Size(110, 95)
    $IncludeMyVideoCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeMyVideoCheckBox.Add_Click({
            $ComponentName = $IncludeMyVideoCheckBox.Text
            if ($IncludeMyVideoCheckBox.Checked -eq $true) {
                Update-Log "$ComponentName will be included."
                if ($SelectedXMLS) {
                    Remove-variable -Name SelectedXMLS -Scope Script -Force
                    Update-Log "Checkbox selection was made, removed Custom XML list." -Color Yellow
                }
            }
            else {
                Update-Log "$ComponentName will not be included." -Color Yellow
            }
        })
    $InclusionsGroupBox.Controls.Add($IncludeMyVideoCheckBox)

    # Custom XML Box
    $IncludeCustomXMLButton = New-Object System.Windows.Forms.Button
    $IncludeCustomXMLButton.Text = 'Custom XML(s)'
    $IncludeCustomXMLButton.Location = New-Object System.Drawing.Size(300, 325)
    $IncludeCustomXMLButton.Size = New-Object System.Drawing.Size(100, 20)
    $IncludeCustomXMLButton.Add_Click({
            # Create an array object as well as clear any existing Custom XML list if present
            $Script:DiscoveredXMLS = @()
            $Script:SelectedXMLS = @()
            Update-Log "Please wait while Custom XML Files are found..."
            $Script:DiscoveredXMLS = Get-ChildItem "$Script:USMTPath\*.xml"  -Exclude "MigLog.xml"

            # Create a Description property
            $Script:DiscoveredXMLS | Add-Member -NotePropertyName Description -NotePropertyValue "No Description Available"
            foreach ($XMLFile in $Script:DiscoveredXMLS) {
                $XMLDescriptionFile = $XmlFIle -Replace ".xml", ".txt"
                if (Test-path $XMLDescriptionFIle) {
                    $XMLDescription = get-content $XMLDescriptionFile
                    $XmlFile.Description = $XMLDescription
                }
            }

            $Script:DiscoveredXMLS | Select-Object -Property Name, Description |
                Out-GridView -Title 'Custom XML file selection' -OutputMode Multiple |
                ForEach-Object { $Script:SelectedXMLS += $_.Name }

            Update-Log "Xmls(s) selected for migration:"
            foreach ($XML in $Script:SelectedXMLS) { Update-Log $XML }

            # Uncheck other Selections
            $IncludeAppDataCheckBox.Checked = $False
            $IncludeLocalAppDataCheckBox.Checked = $False
            $IncludePrintersCheckBox.Checked = $False
            $IncludeRecycleBinCheckBox.Checked = $False
            $IncludeWallpapersCheckBox.Checked = $False
            $IncludeMyDocumentsCheckBox.Checked = $False
            $IncludeDesktopCheckBox.Checked = $False
            $IncludeFavoritesCheckBox.Checked = $False
            $IncludeMyMusicCheckBox.Checked = $False
            $IncludeMyPicturesCheckBox.Checked = $False
            $IncludeMyPicturesCheckBox.Checked = $False
            $IncludeMyVideoCheckBox.Checked = $False
        })
    $OldComputerTabPage.Controls.Add($IncludeCustomXMLButton)

    # Extra directories selection group box
    $ExtraDirectoriesGroupBox = New-Object System.Windows.Forms.GroupBox
    $ExtraDirectoriesGroupBox.Location = New-Object System.Drawing.Size(10, 260)
    $ExtraDirectoriesGroupBox.Size = New-Object System.Drawing.Size(220, 200)
    $ExtraDirectoriesGroupBox.Text = 'Extra Directories to Include'
    $OldComputerTabPage.Controls.Add($ExtraDirectoriesGroupBox)

    # Extra directories data table
    $ExtraDirectoriesDataGridView = New-Object System.Windows.Forms.DataGridView
    $ExtraDirectoriesDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $ExtraDirectoriesDataGridView.Size = New-Object System.Drawing.Size(210, 170)
    $ExtraDirectoriesDataGridView.ReadOnly = $true
    $ExtraDirectoriesDataGridView.AllowUserToAddRows = $false
    $ExtraDirectoriesDataGridView.AllowUserToResizeRows = $false
    $ExtraDirectoriesDataGridView.AllowUserToResizeColumns = $false
    $ExtraDirectoriesDataGridView.MultiSelect = $false
    $ExtraDirectoriesDataGridView.ColumnCount = 1
    $ExtraDirectoriesDataGridView.AutoSizeColumnsMode = 'Fill'
    $ExtraDirectoriesDataGridView.ColumnHeadersVisible = $false
    $ExtraDirectoriesDataGridView.RowHeadersVisible = $false
    foreach ($directory in $DefaultExtraDirectories) {
        if (Test-Path $directory) {
            $ExtraDirectoriesDataGridView.Rows.Add($directory) | Out-Null
        }
        else {
            Update-Log "Extra default directory [$directory] not found. Ensure it exists before running migration." -Color 'Yellow'
        }
    }
    $ExtraDirectoriesGroupBox.Controls.Add($ExtraDirectoriesDataGridView)

    # Remove Extra directory button
    $RemoveExtraDirectoryButton = New-Object System.Windows.Forms.Button
    $RemoveExtraDirectoryButton.Location = New-Object System.Drawing.Size(0, 150)
    $RemoveExtraDirectoryButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveExtraDirectoryButton.Text = '-'
    $RemoveExtraDirectoryButton.Font = 'Consolas, 14'
    $RemoveExtraDirectoryButton.Add_Click({ Remove-ExtraDirectory })
    $ExtraDirectoriesDataGridView.Controls.Add($RemoveExtraDirectoryButton)

    # Add Extra directory button
    $AddExtraDirectoryButton = New-Object System.Windows.Forms.Button
    $AddExtraDirectoryButton.Location = New-Object System.Drawing.Size(20, 150)
    $AddExtraDirectoryButton.Size = New-Object System.Drawing.Size(20, 20)
    $AddExtraDirectoryButton.Text = '+'
    $AddExtraDirectoryButton.Font = 'Consolas, 14'
    $AddExtraDirectoryButton.Add_Click({ Add-ExtraDirectory })
    $ExtraDirectoriesDataGridView.Controls.Add($AddExtraDirectoryButton)

    # Scanstate Encryption check box
    $ScanStateEncryptionCheckBox = New-Object System.Windows.Forms.CheckBox
    $ScanStateEncryptionCheckBox.Text = 'Encrypt captured Data.'
    $ScanStateEncryptionCheckBox.Location = New-Object System.Drawing.Size(280, 345)
    $ScanStateEncryptionCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $ScanStateEncryptionCheckBox.Add_Click({
            if ($ScanStateEncryptionCheckBox.Checked -eq $true) {
                # Prompt for Encryption password
                Update-Log 'Encryption for save state enabled, prompting for password.' -Color 'Yellow'
                Read-Password
                #Disable the use of the encryption password was not sucessfully set.
                if ($Script:EncryptionPasswordSet -NE $True) {
                    Update-Log "Encryption password was not set." -Color 'Yellow'
                    $ScanStateEncryptionCheckBox.Checked = $false
                }
                else {
                    Update-Log 'Encyption password successfully set.' -Color 'LightBlue'
                }
            }
        })
    $OldComputerTabPage.Controls.Add($ScanStateEncryptionCheckBox)

    # Uncompressed storage check box
    $UncompressedCheckBox = New-Object System.Windows.Forms.CheckBox
    $UncompressedCheckBox.Text = 'Uncompressed storage'
    $UncompressedCheckBox.Location = New-Object System.Drawing.Size(280, 370)
    $UncompressedCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $UncompressedCheckBox.Add_Click({
            if ($UncompressedCheckBox.Checked -eq $true) {
                Update-Log 'Uncompressed save state enabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Save state will be stored as uncompressed flat files.'
            }
            else {
                Update-Log 'Uncompressed save state disabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Save state will be stored as a compressed file.'
            }
        })
    $OldComputerTabPage.Controls.Add($UncompressedCheckBox)

    # Migrate button
    $MigrateButton_OldPage = New-Object System.Windows.Forms.Button
    $MigrateButton_OldPage.Location = New-Object System.Drawing.Size(300, 400)
    $MigrateButton_OldPage.Size = New-Object System.Drawing.Size(100, 40)
    $MigrateButton_OldPage.Font = New-Object System.Drawing.Font('Calibri', 16, [System.Drawing.FontStyle]::Bold)
    $MigrateButton_OldPage.Text = 'Migrate'
    $MigrateButton_OldPage.Add_Click({ Save-UserState })
    $OldComputerTabPage.Controls.Add($MigrateButton_OldPage)

    # Create new computer tab
    $NewComputerTabPage = New-Object System.Windows.Forms.TabPage
    $NewComputerTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $NewComputerTabPage.UseVisualStyleBackColor = $true
    $NewComputerTabPage.Text = 'New Computer'
    $TabControl.Controls.Add($NewComputerTabPage)

    # Computer info group
    $NewComputerInfoGroupBox = New-Object System.Windows.Forms.GroupBox
    $NewComputerInfoGroupBox.Location = New-Object System.Drawing.Size(10, 10)
    $NewComputerInfoGroupBox.Size = New-Object System.Drawing.Size(450, 87)
    $NewComputerInfoGroupBox.Text = 'Computer Info'
    $NewComputerTabPage.Controls.Add($NewComputerInfoGroupBox)

    # Alternative save location group box
    $SaveSourceGroupBox = New-Object System.Windows.Forms.GroupBox
    $SaveSourceGroupBox.Location = New-Object System.Drawing.Size(240, 110)
    $SaveSourceGroupBox.Size = New-Object System.Drawing.Size(220, 87)
    $SaveSourceGroupBox.Text = 'Save State Source'
    $NewComputerTabPage.Controls.Add($SaveSourceGroupBox)

    # Save path
    $SaveSourceTextBox = New-Object System.Windows.Forms.TextBox
    $SaveSourceTextBox.Text = $MigrationStorePath
    $SaveSourceTextBox.Location = New-Object System.Drawing.Size(5, 20)
    $SaveSourceTextBox.Size = New-Object System.Drawing.Size(210, 20)
    $SaveSourceGroupBox.Controls.Add($SaveSourceTextBox)

    # Change save destination button
    $ChangeSaveSourceButton = New-Object System.Windows.Forms.Button
    $ChangeSaveSourceButton.Location = New-Object System.Drawing.Size(5, 50)
    $ChangeSaveSourceButton.Size = New-Object System.Drawing.Size(60, 20)
    $ChangeSaveSourceButton.Text = 'Change'
    $ChangeSaveSourceButton.Add_Click({
            Set-SaveDirectory -Type Source
            $OldComputerNameTextBox_NewPage.Text = Get-SaveState
            Show-DomainInfo
        })
    $SaveSourceGroupBox.Controls.Add($ChangeSaveSourceButton)

    # Reset save destination button
    $ResetSaveSourceButton = New-Object System.Windows.Forms.Button
    $ResetSaveSourceButton.Location = New-Object System.Drawing.Size(75, 50)
    $ResetSaveSourceButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveSourceButton.Text = 'Reset'
    $ResetSaveSourceButton.Add_Click({
            Update-Log "Resetting save state directory to [$MigrationStorePath]."
            $SaveSourceTextBox.Text = $MigrationStorePath
            $OldComputerNameTextBox_NewPage.Text = Get-SaveState
            Show-DomainInfo
        })
    $SaveSourceGroupBox.Controls.Add($ResetSaveSourceButton)

    # Search for save state in given SaveSourceTextBox path
    $ResetSaveSourceButton = New-Object System.Windows.Forms.Button
    $ResetSaveSourceButton.Location = New-Object System.Drawing.Size(150, 50)
    $ResetSaveSourceButton.Size = New-Object System.Drawing.Size(65, 20)
    $ResetSaveSourceButton.Text = 'Search'
    $ResetSaveSourceButton.Add_Click({
            $OldComputerNameTextBox_NewPage.Text = Get-SaveState
            Show-DomainInfo
        })
    $SaveSourceGroupBox.Controls.Add($ResetSaveSourceButton)

    # Name label
    $ComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $ComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(100, 12)
    $ComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(100, 22)
    $ComputerNameLabel_NewPage.Text = 'Computer Name'
    $NewComputerInfoGroupBox.Controls.Add($ComputerNameLabel_NewPage)

    # IP label
    $ComputerIPLabel_NewPage = New-Object System.Windows.Forms.Label
    $ComputerIPLabel_NewPage.Location = New-Object System.Drawing.Size(230, 12)
    $ComputerIPLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $ComputerIPLabel_NewPage.Text = 'IP Address'
    $NewComputerInfoGroupBox.Controls.Add($ComputerIPLabel_NewPage)

    # Old Computer name label
    $OldComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $OldComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(12, 35)
    $OldComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $OldComputerNameLabel_NewPage.Text = 'Old Computer'
    $NewComputerInfoGroupBox.Controls.Add($OldComputerNameLabel_NewPage)

    # Old Computer name text box
    $OldComputerNameTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $OldComputerNameTextBox_NewPage.ReadOnly = $false
    $OldComputerNameTextBox_NewPage.Location = New-Object System.Drawing.Size(100, 34)
    $OldComputerNameTextBox_NewPage.Size = New-Object System.Drawing.Size(120, 20)
    $OldComputerNameTextBox_NewPage.Text = Get-SaveState
    $NewComputerInfoGroupBox.Controls.Add($OldComputerNameTextBox_NewPage)

    # Old Computer IP text box
    $OldComputerIPTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $OldComputerIPTextBox_NewPage.Location = New-Object System.Drawing.Size(230, 34)
    $OldComputerIPTextBox_NewPage.Size = New-Object System.Drawing.Size(90, 20)
    $OldComputerIPTextBox_NewPage.Add_TextChanged({
            if ($ConnectionCheckBox_NewPage.Checked) {
                Update-Log 'Computer IP address changed, connection status unverified.' -Color 'Yellow'
                $ConnectionCheckBox_NewPage.Checked = $false
            }
        })
    $NewComputerInfoGroupBox.Controls.Add($OldComputerIPTextBox_NewPage)

    # New Computer name label
    $NewComputerNameLabel_NewPage = New-Object System.Windows.Forms.Label
    $NewComputerNameLabel_NewPage.Location = New-Object System.Drawing.Size(12, 57)
    $NewComputerNameLabel_NewPage.Size = New-Object System.Drawing.Size(80, 22)
    $NewComputerNameLabel_NewPage.Text = 'New Computer'
    $NewComputerInfoGroupBox.Controls.Add($NewComputerNameLabel_NewPage)

    # New Computer name text box
    $NewComputerNameTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $NewComputerNameTextBox_NewPage.ReadOnly = $true
    $NewComputerNameTextBox_NewPage.Location = New-Object System.Drawing.Size(100, 56)
    $NewComputerNameTextBox_NewPage.Size = New-Object System.Drawing.Size(120, 20)
    $NewComputerNameTextBox_NewPage.Text = $env:COMPUTERNAME
    $NewComputerInfoGroupBox.Controls.Add($NewComputerNameTextBox_NewPage)

    # New Computer IP text box
    $NewComputerIPTextBox_NewPage = New-Object System.Windows.Forms.TextBox
    $NewComputerIPTextBox_NewPage.ReadOnly = $true
    $NewComputerIPTextBox_NewPage.Location = New-Object System.Drawing.Size(230, 56)
    $NewComputerIPTextBox_NewPage.Size = New-Object System.Drawing.Size(90, 20)
    $NewComputerIPTextBox_NewPage.Text = Get-IPAddress
    $NewComputerInfoGroupBox.Controls.Add($NewComputerIPTextBox_NewPage)

    # Button to test connection to new computer
    $TestConnectionButton_NewPage = New-Object System.Windows.Forms.Button
    $TestConnectionButton_NewPage.Location = New-Object System.Drawing.Size(335, 33)
    $TestConnectionButton_NewPage.Size = New-Object System.Drawing.Size(100, 22)
    $TestConnectionButton_NewPage.Text = 'Test Connection'
    $TestConnectionButton_NewPage.Add_Click({
            $TestComputerConnectionParams = @{
                ComputerNameTextBox = $OldComputerNameTextBox_NewPage
                ComputerIPTextBox   = $OldComputerIPTextBox_NewPage
                ConnectionCheckBox  = $ConnectionCheckBox_NewPage
            }
            Test-ComputerConnection @TestComputerConnectionParams
        })
    $NewComputerInfoGroupBox.Controls.Add($TestConnectionButton_NewPage)

    # Connected check box
    $ConnectionCheckBox_NewPage = New-Object System.Windows.Forms.CheckBox
    $ConnectionCheckBox_NewPage.Enabled = $false
    $ConnectionCheckBox_NewPage.Text = 'Connected'
    $ConnectionCheckBox_NewPage.Location = New-Object System.Drawing.Size(336, 58)
    $ConnectionCheckBox_NewPage.Size = New-Object System.Drawing.Size(100, 20)
    $NewComputerInfoGroupBox.Controls.Add($ConnectionCheckBox_NewPage)

    # Cross-domain migration group box
    $CrossDomainMigrationGroupBox = New-Object System.Windows.Forms.GroupBox
    $CrossDomainMigrationGroupBox.Location = New-Object System.Drawing.Size(10, 110)
    $CrossDomainMigrationGroupBox.Size = New-Object System.Drawing.Size(220, 87)
    $CrossDomainMigrationGroupBox.Text = 'Cross-Domain Migration'
    $NewComputerTabPage.Controls.Add($CrossDomainMigrationGroupBox)

    # Domain label
    $DomainLabel = New-Object System.Windows.Forms.Label
    $DomainLabel.Location = New-Object System.Drawing.Size(70, 12)
    $DomainLabel.Size = New-Object System.Drawing.Size(50, 22)
    $DomainLabel.Text = 'Domain'
    $CrossDomainMigrationGroupBox.Controls.Add($DomainLabel)

    # User name label
    $UserNameLabel = New-Object System.Windows.Forms.Label
    $UserNameLabel.Location = New-Object System.Drawing.Size(125, 12)
    $UserNameLabel.Size = New-Object System.Drawing.Size(80, 22)
    $UserNameLabel.Text = 'User Name'
    $CrossDomainMigrationGroupBox.Controls.Add($UserNameLabel)

    # Old user label
    $OldUserLabel = New-Object System.Windows.Forms.Label
    $OldUserLabel.Location = New-Object System.Drawing.Size(12, 35)
    $OldUserLabel.Size = New-Object System.Drawing.Size(50, 22)
    $OldUserLabel.Text = 'Old User'
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserLabel)

    # Old domain text box
    $OldDomainTextBox = New-Object System.Windows.Forms.TextBox
    $OldDomainTextBox.ReadOnly = $true
    $OldDomainTextBox.Location = New-Object System.Drawing.Size(70, 34)
    $OldDomainTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $OldDomainTextBox.Text = $OldComputerNameTextBox_NewPage.Text
    $CrossDomainMigrationGroupBox.Controls.Add($OldDomainTextBox)

    # Old user slash label
    $OldUserSlashLabel = New-Object System.Windows.Forms.Label
    $OldUserSlashLabel.Location = New-Object System.Drawing.Size(110, 33)
    $OldUserSlashLabel.Size = New-Object System.Drawing.Size(10, 20)
    $OldUserSlashLabel.Text = '\'
    $OldUserSlashLabel.Font = New-Object System.Drawing.Font('Calibri', 12)
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserSlashLabel)

    # Old user name text box
    $OldUserNameTextBox = New-Object System.Windows.Forms.TextBox
    $OldUserNameTextBox.ReadOnly = $true
    $OldUserNameTextBox.Location = New-Object System.Drawing.Size(125, 34)
    $OldUserNameTextBox.Size = New-Object System.Drawing.Size(80, 20)
    $CrossDomainMigrationGroupBox.Controls.Add($OldUserNameTextBox)

    # New user label
    $NewUserLabel = New-Object System.Windows.Forms.Label
    $NewUserLabel.Location = New-Object System.Drawing.Size(12, 57)
    $NewUserLabel.Size = New-Object System.Drawing.Size(55, 22)
    $NewUserLabel.Text = 'New User'
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserLabel)

    # New domain text box
    $NewDomainTextBox = New-Object System.Windows.Forms.TextBox
    $NewDomainTextBox.ReadOnly = $true
    $NewDomainTextBox.Location = New-Object System.Drawing.Size(70, 56)
    $NewDomainTextBox.Size = New-Object System.Drawing.Size(40, 20)
    $NewDomainTextBox.Text = $DefaultDomain
    $CrossDomainMigrationGroupBox.Controls.Add($NewDomainTextBox)

    # New user slash label
    $NewUserSlashLabel = New-Object System.Windows.Forms.Label
    $NewUserSlashLabel.Location = New-Object System.Drawing.Size(110, 56)
    $NewUserSlashLabel.Size = New-Object System.Drawing.Size(10, 20)
    $NewUserSlashLabel.Text = '\'
    $NewUserSlashLabel.Font = New-Object System.Drawing.Font('Calibri', 12)
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserSlashLabel)

    # New user name text box
    $NewUserNameTextBox = New-Object System.Windows.Forms.TextBox
    $NewUserNameTextBox.Location = New-Object System.Drawing.Size(125, 56)
    $NewUserNameTextBox.Size = New-Object System.Drawing.Size(80, 20)
    $NewUserNameTextBox.Text = $env:USERNAME
    $CrossDomainMigrationGroupBox.Controls.Add($NewUserNameTextBox)

    # Override check box
    $OverrideCheckBox = New-Object System.Windows.Forms.CheckBox
    $OverrideCheckBox.Text = 'Save state task completed'
    $OverrideCheckBox.Location = New-Object System.Drawing.Size(280, 225)
    $OverrideCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $OverrideCheckBox.Checked = $DefaultSaveStateTaskCompleted
    $OverrideCheckBox.Add_Click({
            if ($OverrideCheckBox.Checked -eq $true) {
                $NewComputerInfoGroupBox.Enabled = $false
                Update-Log 'Network connection override enabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Save state process on old computer is assumed to be completed and no network checks will be processed during load state.'
            }
            else {
                $NewComputerInfoGroupBox.Enabled = $true
                Update-Log 'Network connection override enabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Network checks will be processed during load state.'
            }
        })
    $NewComputerTabPage.Controls.Add($OverrideCheckBox)

    # LoadState Encryption check box
    $LoadStateEncryptionCheckBox = New-Object System.Windows.Forms.CheckBox
    $LoadStateEncryptionCheckBox.Text = 'Saved data was encrypted.'
    $LoadStateEncryptionCheckBox.Location = New-Object System.Drawing.Size(280, 250)
    $LoadStateEncryptionCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $LoadStateEncryptionCheckBox.Add_Click({
            if ($LoadStateEncryptionCheckBox.Checked -eq $true) {
                # Prompt for Encryption password
                Update-Log 'Encryption for load state enabled, prompting for password.' -Color 'Yellow'
                Read-Password
                # Disable the use of the encryption password was not sucessfully set.
                if ($Script:EncryptionPasswordSet -NE $True) {
                    Update-Log 'Encryption password was not set.' -Color 'Yellow'
                    $LoadStateEncryptionCheckBox.Checked = $false
                }
                else {
                    Update-Log 'Encyption password successfully set.' -Color 'LightBlue'
                }
            }
        })
    $NewComputerTabPage.Controls.Add($LoadStateEncryptionCheckBox)

    Show-DomainInfo

    # Migrate button
    $MigrateButton_NewPage = New-Object System.Windows.Forms.Button
    $MigrateButton_NewPage.Location = New-Object System.Drawing.Size(300, 400)
    $MigrateButton_NewPage.Size = New-Object System.Drawing.Size(100, 40)
    $MigrateButton_NewPage.Font = New-Object System.Drawing.Font('Calibri', 16, [System.Drawing.FontStyle]::Bold)
    $MigrateButton_NewPage.Text = 'Migrate'
    $MigrateButton_NewPage.Add_Click({ Restore-UserState })
    $NewComputerTabPage.Controls.Add($MigrateButton_NewPage)

    # Create email settings tab
    $EmailSettingsTabPage = New-Object System.Windows.Forms.TabPage
    $EmailSettingsTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $EmailSettingsTabPage.UseVisualStyleBackColor = $true
    $EmailSettingsTabPage.Text = 'Email Settings'
    $TabControl.Controls.Add($EmailSettingsTabPage)

    # Email enabled check box
    $EmailCheckBox = New-Object System.Windows.Forms.CheckBox
    $EmailCheckBox.Text = 'Enabled'
    $EmailCheckBox.Location = New-Object System.Drawing.Size(10, 10)
    $EmailCheckBox.Size = New-Object System.Drawing.Size(300, 30)
    $EmailCheckBox.Checked = $DefaultEmailEnabled
    $EmailCheckBox.Add_Click({
            if ($EmailCheckBox.Checked -eq $true) {
                Update-Log 'Email enabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - Results will be emailed to supplied email addresses (if your account has email relay access).'
            }
            else {
                Update-Log 'Email disabled' -Color 'Yellow' -NoNewLine
                Update-Log ' - No results will be emailed.'
            }
        })
    $EmailSettingsTabPage.Controls.Add($EmailCheckBox)

    # SMTP server group box
    $SMTPServerGroupBox = New-Object System.Windows.Forms.GroupBox
    $SMTPServerGroupBox.Location = New-Object System.Drawing.Size(10, 60)
    $SMTPServerGroupBox.Size = New-Object System.Drawing.Size(220, 80)
    $SMTPServerGroupBox.Text = 'SMTP Server'
    $EmailSettingsTabPage.Controls.Add($SMTPServerGroupBox)

    # SMTP server text box
    $SMTPServerTextBox = New-Object System.Windows.Forms.TextBox
    $SMTPServerTextBox.Location = New-Object System.Drawing.Size(5, 20)
    $SMTPServerTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $SMTPServerTextBox.Text = $DefaultSMTPServer
    $SMTPServerGroupBox.Controls.Add($SMTPServerTextBox)

    # Button to test connection to SMTP server
    $SMTPConnectionButton = New-Object System.Windows.Forms.Button
    $SMTPConnectionButton.Location = New-Object System.Drawing.Size(9, 50)
    $SMTPConnectionButton.Size = New-Object System.Drawing.Size(100, 22)
    $SMTPConnectionButton.Text = 'Test Connection'
    $SMTPConnectionButton.Add_Click({
            Update-Log "Testing connection to [$($SMTPServerTextBox.Text)]..." -NoNewLine
            if (Test-Connection $SMTPServerTextBox.Text -Quiet) {
                Update-Log "reachable."
                $SMTPConnectionCheckBox.Checked = $true
            }
            else {
                Update-Log "unreachable." -Color 'Yellow'
                $SMTPConnectionCheckBox.Checked = $false
            }
        })
    $SMTPServerGroupBox.Controls.Add($SMTPConnectionButton)

    # SMTP server reachable check box
    $SMTPConnectionCheckBox = New-Object System.Windows.Forms.CheckBox
    $SMTPConnectionCheckBox.Enabled = $false
    $SMTPConnectionCheckBox.Text = 'Reachable'
    $SMTPConnectionCheckBox.Location = New-Object System.Drawing.Size(135, 50)
    $SMTPConnectionCheckBox.Size = New-Object System.Drawing.Size(100, 20)
    $SMTPServerGroupBox.Controls.Add($SMTPConnectionCheckBox)

    # If email is enabled, check if SMTP server is reachable
    if ($DefaultEmailEnabled -and -not (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
        Update-Log "Email disabled because SMTP server [$($SMTPServerTextBox.Text)] is unreachable." -Color 'Yellow'
        $SMTPConnectionCheckBox.Checked = $false
    }
    elseif ($DefaultEmailEnabled -and (Test-Connection -ComputerName $SMTPServerTextBox.Text -Quiet)) {
        Update-Log "SMTP server [$($SMTPServerTextBox.Text)] is reachable."
        $SMTPConnectionCheckBox.Checked = $true
    }

    # Email sender group box
    $EmailSenderGroupBox = New-Object System.Windows.Forms.GroupBox
    $EmailSenderGroupBox.Location = New-Object System.Drawing.Size(10, 150)
    $EmailSenderGroupBox.Size = New-Object System.Drawing.Size(220, 50)
    $EmailSenderGroupBox.Text = 'Email Sender'
    $EmailSettingsTabPage.Controls.Add($EmailSenderGroupBox)

    # Email sender text box
    $EmailSenderTextBox = New-Object System.Windows.Forms.TextBox
    $EmailSenderTextBox.Location = New-Object System.Drawing.Size(5, 20)
    $EmailSenderTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $EmailSenderTextBox.Text = $DefaultEmailSender
    $EmailSenderGroupBox.Controls.Add($EmailSenderTextBox)

    # Email recipients selection group box
    $EmailRecipientsGroupBox = New-Object System.Windows.Forms.GroupBox
    $EmailRecipientsGroupBox.Location = New-Object System.Drawing.Size(10, 230)
    $EmailRecipientsGroupBox.Size = New-Object System.Drawing.Size(220, 230)
    $EmailRecipientsGroupBox.Text = 'Email Recipients'
    $EmailSettingsTabPage.Controls.Add($EmailRecipientsGroupBox)

    # Email recipients data table
    $EmailRecipientsDataGridView = New-Object System.Windows.Forms.DataGridView
    $EmailRecipientsDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $EmailRecipientsDataGridView.Size = New-Object System.Drawing.Size(210, 170)
    $EmailRecipientsDataGridView.ReadOnly = $true
    $EmailRecipientsDataGridView.AllowUserToAddRows = $false
    $EmailRecipientsDataGridView.AllowUserToResizeRows = $false
    $EmailRecipientsDataGridView.AllowUserToResizeColumns = $false
    $EmailRecipientsDataGridView.MultiSelect = $false
    $EmailRecipientsDataGridView.ColumnCount = 1
    $EmailRecipientsDataGridView.AutoSizeColumnsMode = 'Fill'
    $EmailRecipientsDataGridView.ColumnHeadersVisible = $false
    $EmailRecipientsDataGridView.RowHeadersVisible = $false
    $EmailRecipientsGroupBox.Controls.Add($EmailRecipientsDataGridView)

    # Add default email addresses to data grid view
    foreach ($Email in $DefaultEmailRecipients) { $EmailRecipientsDataGridView.Rows.Add($Email) }

    # Remove email recipient button
    $RemoveEmailRecipientButton = New-Object System.Windows.Forms.Button
    $RemoveEmailRecipientButton.Location = New-Object System.Drawing.Size(0, 150)
    $RemoveEmailRecipientButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveEmailRecipientButton.Text = '-'
    $RemoveEmailRecipientButton.Font = 'Consolas, 14'
    $RemoveEmailRecipientButton.Add_Click({
            # Remove selected cell from Email Recipients data grid view
            $CurrentCell = $EmailRecipientsDataGridView.CurrentCell
            Update-Log "Removed [$($CurrentCell.Value)] from email recipients."
            $CurrentRow = $EmailRecipientsDataGridView.Rows[$CurrentCell.RowIndex]
            $EmailRecipientsDataGridView.Rows.Remove($CurrentRow)
        })
    $EmailRecipientsDataGridView.Controls.Add($RemoveEmailRecipientButton)

    # Add email recipient button
    $AddEmailRecipientButton = New-Object System.Windows.Forms.Button
    $AddEmailRecipientButton.Location = New-Object System.Drawing.Size(20, 150)
    $AddEmailRecipientButton.Size = New-Object System.Drawing.Size(20, 20)
    $AddEmailRecipientButton.Text = '+'
    $AddEmailRecipientButton.Font = 'Consolas, 14'
    $AddEmailRecipientButton.Add_Click({
            Update-Log "Adding to email recipients: $($EmailRecipientToAddTextBox.Text)."
            $EmailRecipientsDataGridView.Rows.Add($EmailRecipientToAddTextBox.Text) | Out-Null
        })
    $EmailRecipientsDataGridView.Controls.Add($AddEmailRecipientButton)

    # Email recipient to add text box
    $EmailRecipientToAddTextBox = New-Object System.Windows.Forms.TextBox
    $EmailRecipientToAddTextBox.Location = New-Object System.Drawing.Size(5, 200)
    $EmailRecipientToAddTextBox.Size = New-Object System.Drawing.Size(210, 25)
    $EmailRecipientToAddTextBox.Text = 'Recipient@To.Add'
    $EmailRecipientsGroupBox.Controls.Add($EmailRecipientToAddTextBox)

    # Send test email button
    $TestEmailButton = New-Object System.Windows.Forms.Button
    $TestEmailButton.Location = New-Object System.Drawing.Size(300, 400)
    $TestEmailButton.Size = New-Object System.Drawing.Size(100, 40)
    $TestEmailButton.Font = New-Object System.Drawing.Font('Calibri', 14, [System.Drawing.FontStyle]::Bold)
    $TestEmailButton.Text = 'Test Email'
    $TestEmailButton.Add_Click({ Test-Email })
    $EmailSettingsTabPage.Controls.Add($TestEmailButton)

    # Create scripts tab
    $ScriptsTabPage = New-Object System.Windows.Forms.TabPage
    $ScriptsTabPage.DataBindings.DefaultDataSourceUpdateMode = 0
    $ScriptsTabPage.UseVisualStyleBackColor = $true
    $ScriptsTabPage.Text = 'Scripts'
    $TabControl.Controls.Add($ScriptsTabPage)

    # Old computer scripts selection group box
    $OldComputerScriptsGroupBox = New-Object System.Windows.Forms.GroupBox
    $OldComputerScriptsGroupBox.Location = New-Object System.Drawing.Size(10, 10)
    $OldComputerScriptsGroupBox.Size = New-Object System.Drawing.Size(450, 220)
    $OldComputerScriptsGroupBox.Text = 'Old Computer Scripts'
    $ScriptsTabPage.Controls.Add($OldComputerScriptsGroupBox)

    # Old computer scripts data table
    $OldComputerScriptsDataGridView = New-Object System.Windows.Forms.DataGridView
    $OldComputerScriptsDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $OldComputerScriptsDataGridView.Size = New-Object System.Drawing.Size(440, 190)
    $OldComputerScriptsDataGridView.ReadOnly = $true
    $OldComputerScriptsDataGridView.AllowUserToAddRows = $false
    $OldComputerScriptsDataGridView.AllowUserToResizeRows = $false
    $OldComputerScriptsDataGridView.AllowUserToResizeColumns = $false
    $OldComputerScriptsDataGridView.MultiSelect = $false
    $OldComputerScriptsDataGridView.ColumnCount = 1
    $OldComputerScriptsDataGridView.AutoSizeColumnsMode = 'Fill'
    $OldComputerScriptsDataGridView.ColumnHeadersVisible = $false
    $OldComputerScriptsDataGridView.RowHeadersVisible = $false
    $OldComputerScriptsGroupBox.Controls.Add($OldComputerScriptsDataGridView)

    # Add old computer script to data grid view
    $OldComputerScripts = Get-ChildItem -Path "$PSScriptRoot\USMT\Scripts\OldComputer" |
        Where-Object { -not $_.PSIsContainer }
    foreach ($Script in $OldComputerScripts) {
        if (!($Script.Name.Contains(".gitignore"))){
            $OldComputerScriptsDataGridView.Rows.Add($Script)
        }
    }

    # Remove old computer script button
    $RemoveOldComputerScriptButton = New-Object System.Windows.Forms.Button
    $RemoveOldComputerScriptButton.Location = New-Object System.Drawing.Size(0, 170)
    $RemoveOldComputerScriptButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveOldComputerScriptButton.Text = '-'
    $RemoveOldComputerScriptButton.Font = 'Consolas, 14'
    $RemoveOldComputerScriptButton.Add_Click({
            # Remove selected cell from new computer scripts data grid view
            $CurrentCell = $NewComputerScriptsDataGridView.CurrentCell
            Update-Log "Removed [$($CurrentCell.Value)] from old computer scripts."
            $CurrentRow = $NewComputerScriptsDataGridView.Rows[$CurrentCell.RowIndex]
            $NewComputerScriptsDataGridView.Rows.Remove($CurrentRow)
        })
    $OldComputerScriptsDataGridView.Controls.Add($RemoveOldComputerScriptButton)

    # New computer scripts selection group box
    $NewComputerScriptsGroupBox = New-Object System.Windows.Forms.GroupBox
    $NewComputerScriptsGroupBox.Location = New-Object System.Drawing.Size(10, 240)
    $NewComputerScriptsGroupBox.Size = New-Object System.Drawing.Size(450, 220)
    $NewComputerScriptsGroupBox.Text = 'New Computer Scripts'
    $ScriptsTabPage.Controls.Add($NewComputerScriptsGroupBox)

    # New computer scripts data table
    $NewComputerScriptsDataGridView = New-Object System.Windows.Forms.DataGridView
    $NewComputerScriptsDataGridView.Location = New-Object System.Drawing.Size(5, 20)
    $NewComputerScriptsDataGridView.Size = New-Object System.Drawing.Size(440, 190)
    $NewComputerScriptsDataGridView.ReadOnly = $true
    $NewComputerScriptsDataGridView.AllowUserToAddRows = $false
    $NewComputerScriptsDataGridView.AllowUserToResizeRows = $false
    $NewComputerScriptsDataGridView.AllowUserToResizeColumns = $false
    $NewComputerScriptsDataGridView.MultiSelect = $false
    $NewComputerScriptsDataGridView.ColumnCount = 1
    $NewComputerScriptsDataGridView.AutoSizeColumnsMode = 'Fill'
    $NewComputerScriptsDataGridView.ColumnHeadersVisible = $false
    $NewComputerScriptsDataGridView.RowHeadersVisible = $false
    $NewComputerScriptsGroupBox.Controls.Add($NewComputerScriptsDataGridView)

    # Add new computer script to data grid view
    $NewComputerScripts = Get-ChildItem -Path "$PSScriptRoot\USMT\Scripts\NewComputer" |
        Where-Object { -not $_.PSIsContainer }
    foreach ($Script in $NewComputerScripts) {
        if (!($Script.Name.Contains(".gitignore"))){
            $NewComputerScriptsDataGridView.Rows.Add($Script)
        }
    }

    # Remove new computer script button
    $RemoveNewComputerScriptButton = New-Object System.Windows.Forms.Button
    $RemoveNewComputerScriptButton.Location = New-Object System.Drawing.Size(0, 170)
    $RemoveNewComputerScriptButton.Size = New-Object System.Drawing.Size(20, 20)
    $RemoveNewComputerScriptButton.Text = '-'
    $RemoveNewComputerScriptButton.Font = 'Consolas, 14'
    $RemoveNewComputerScriptButton.Add_Click({
            # Remove selected cell from new computer scripts data grid view
            $CurrentCell = $NewComputerScriptsDataGridView.CurrentCell
            Update-Log "Removed [$($CurrentCell.Value)] from new computer scripts."
            $CurrentRow = $NewComputerScriptsDataGridView.Rows[$CurrentCell.RowIndex]
            $NewComputerScriptsDataGridView.Rows.Remove($CurrentRow)
        })
    $NewComputerScriptsDataGridView.Controls.Add($RemoveNewComputerScriptButton)

    # Debug button
    $DebugLabel = New-Object System.Windows.Forms.Label
    $DebugLabel.Location = New-Object System.Drawing.Size(974, 495)
    $DebugLabel.Size = New-Object System.Drawing.Size(10, 15)
    $DebugLabel.Text = '?'
    $DebugLabel.Add_Click( {
            if ($TabControl.SelectedIndex -eq 0) {
                Save-UserState -Debug
            }
            elseif ($TabControl.SelectedIndex -eq 1) {
                Restore-UserState -Debug
            }
        })
    $Form.Controls.Add($DebugLabel)

    # Test if user is using an admin account
    Test-IsAdmin

    # Test the version of PowerShell and disable incompatible features
    Test-PSVersion

    # Get the path to the USMT files
    Get-USMT

    # Show our form
    $Form.Add_Shown( {$Form.Activate()})
    $Form.ShowDialog() | Out-Null
}
