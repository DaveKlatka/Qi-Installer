$TechInstaller = New-Object -TypeName System.Windows.Forms.Form
[System.Windows.Forms.GroupBox]$GroupBox1 = $null
[System.Windows.Forms.CheckBox]$365Checkbox = $null
[System.Windows.Forms.ComboBox]$365ComboBox = $null
[System.Windows.Forms.CheckedListBox]$SoftwareList = $null
[System.Windows.Forms.GroupBox]$GroupBox2 = $null
[System.Windows.Forms.Button]$dotnet35 = $null
[System.Windows.Forms.Button]$UnInstall_Automate = $null
[System.Windows.Forms.Button]$ReInstall_Automate = $null
[System.Windows.Forms.Button]$Install_Automate = $null
[System.Windows.Forms.GroupBox]$GroupBox3 = $null
[System.Windows.Forms.Button]$SystemRestorePoint = $null
[System.Windows.Forms.DataGridView]$SystemInfo = $null
[System.Windows.Forms.Button]$RenameDomain = $null
[System.Windows.Forms.Button]$Win10Upgrade = $null
[System.Windows.Forms.Button]$Powershell5 = $null
[System.Windows.Forms.Button]$DellUpdate = $null
[System.Windows.Forms.Button]$PowerPolicy = $null
[System.Windows.Forms.Button]$Cancel = $null
[System.Windows.Forms.PictureBox]$PictureBox1 = $null
[System.Windows.Forms.TabControl]$TabControl1 = $null
[System.Windows.Forms.TabPage]$TabPage1 = $null
[System.Windows.Forms.TabPage]$TabPage2 = $null
[System.Windows.Forms.Button]$InstallSoftware = $null
[System.Windows.Forms.TabPage]$TabPage3 = $null
[System.Windows.Forms.TabPage]$TabPage4 = $null
[System.Windows.Forms.TabControl]$TabControl2 = $null
[System.Windows.Forms.TabPage]$TabPage5 = $null
[System.Windows.Forms.Button]$AlphaButton = $null
[System.Windows.Forms.Button]$Export = $null
[System.Windows.Forms.GroupBox]$SaveDestination = $null
[System.Windows.Forms.Button]$ExportLocationButton = $null
[System.Windows.Forms.TextBox]$ExportLocation = $null
[System.Windows.Forms.GroupBox]$GroupBox5 = $null
[System.Windows.Forms.Button]$AddDirectory = $null
[System.Windows.Forms.Button]$RemoveDirectory = $null
[System.Windows.Forms.DataGridView]$AdditionalLocations = $null
[System.Windows.Forms.GroupBox]$GroupBox4 = $null
[System.Windows.Forms.CheckedListBox]$USMTCheckList = $null
[System.Windows.Forms.Button]$Profiles = $null
[System.Windows.Forms.TabPage]$TabPage6 = $null
[System.Windows.Forms.Button]$BetaButton2 = $null
[System.Windows.Forms.Button]$ImportButton = $null
[System.Windows.Forms.GroupBox]$GroupBox7 = $null
[System.Windows.Forms.Button]$ImportSelect = $null
[System.Windows.Forms.TextBox]$ImportLocation = $null
[System.Windows.Forms.TabPage]$TabPage7 = $null
[System.Windows.Forms.Button]$Beta3 = $null
[System.Windows.Forms.Button]$RunNetMig = $null
[System.Windows.Forms.GroupBox]$ComputerInfo = $null
[System.Windows.Forms.CheckBox]$UNCVerified = $null
[System.Windows.Forms.CheckBox]$ConnectionCheckBox = $null
[System.Windows.Forms.Button]$TestConnection = $null
[System.Windows.Forms.Label]$NewIPLabel = $null
[System.Windows.Forms.TextBox]$SourceIPAddressText = $null
[System.Windows.Forms.Label]$NewComputerLabel = $null
[System.Windows.Forms.Label]$OldIPLabel = $null
[System.Windows.Forms.TextBox]$DestIpAddressText = $null
[System.Windows.Forms.TextBox]$SourceComputerText = $null
[System.Windows.Forms.TextBox]$DestComputerText = $null
[System.Windows.Forms.Label]$OldComputerLabel = $null
[System.Windows.Forms.RichTextBox]$LogBox = $null
[System.Windows.Forms.ProgressBar]$CurrentFile = $null
[System.Windows.Forms.ProgressBar]$TotalProgress = $null
[System.Windows.Forms.GroupBox]$GroupBox6 = $null
[System.Windows.Forms.Label]$Label4 = $null
[System.Windows.Forms.Label]$Label3 = $null
[System.Windows.Forms.Label]$Label2 = $null
[System.Windows.Forms.TextBox]$2FAAuth = $null
[System.Windows.Forms.TextBox]$AuthPass = $null
[System.Windows.Forms.Button]$AuthCancel = $null
[System.Windows.Forms.Button]$AuthSubmit = $null
[System.Windows.Forms.Label]$AuthError = $null
[System.Windows.Forms.TextBox]$AuthUser = $null
[System.Windows.Forms.Label]$Label1 = $null
[System.Windows.Forms.Button]$DebugConsole = $null
[System.Windows.Forms.TextBox]$DebugCommand = $null
[System.Windows.Forms.Button]$DebugCommandButton = $null
[System.Windows.Forms.Button]$Logout = $null
[System.Windows.Forms.Panel]$AuthPanel = $null
[System.Windows.Forms.Button]$AuthDebugButton = $null
function InitializeComponent
{
$GroupBox1 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$365Checkbox = (New-Object -TypeName System.Windows.Forms.CheckBox)
$365ComboBox = (New-Object -TypeName System.Windows.Forms.ComboBox)
$SoftwareList = (New-Object -TypeName System.Windows.Forms.CheckedListBox)
$GroupBox2 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$dotnet35 = (New-Object -TypeName System.Windows.Forms.Button)
$UnInstall_Automate = (New-Object -TypeName System.Windows.Forms.Button)
$ReInstall_Automate = (New-Object -TypeName System.Windows.Forms.Button)
$Install_Automate = (New-Object -TypeName System.Windows.Forms.Button)
$GroupBox3 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$SystemRestorePoint = (New-Object -TypeName System.Windows.Forms.Button)
$SystemInfo = (New-Object -TypeName System.Windows.Forms.DataGridView)
$RenameDomain = (New-Object -TypeName System.Windows.Forms.Button)
$Win10Upgrade = (New-Object -TypeName System.Windows.Forms.Button)
$Powershell5 = (New-Object -TypeName System.Windows.Forms.Button)
$DellUpdate = (New-Object -TypeName System.Windows.Forms.Button)
$PowerPolicy = (New-Object -TypeName System.Windows.Forms.Button)
$Cancel = (New-Object -TypeName System.Windows.Forms.Button)
$PictureBox1 = (New-Object -TypeName System.Windows.Forms.PictureBox)
$TabControl1 = (New-Object -TypeName System.Windows.Forms.TabControl)
$TabPage1 = (New-Object -TypeName System.Windows.Forms.TabPage)
$TabPage2 = (New-Object -TypeName System.Windows.Forms.TabPage)
$InstallSoftware = (New-Object -TypeName System.Windows.Forms.Button)
$TabPage3 = (New-Object -TypeName System.Windows.Forms.TabPage)
$TabPage4 = (New-Object -TypeName System.Windows.Forms.TabPage)
$TabControl2 = (New-Object -TypeName System.Windows.Forms.TabControl)
$TabPage5 = (New-Object -TypeName System.Windows.Forms.TabPage)
$AlphaButton = (New-Object -TypeName System.Windows.Forms.Button)
$Export = (New-Object -TypeName System.Windows.Forms.Button)
$SaveDestination = (New-Object -TypeName System.Windows.Forms.GroupBox)
$ExportLocationButton = (New-Object -TypeName System.Windows.Forms.Button)
$ExportLocation = (New-Object -TypeName System.Windows.Forms.TextBox)
$GroupBox5 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$AddDirectory = (New-Object -TypeName System.Windows.Forms.Button)
$RemoveDirectory = (New-Object -TypeName System.Windows.Forms.Button)
$AdditionalLocations = (New-Object -TypeName System.Windows.Forms.DataGridView)
$GroupBox4 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$USMTCheckList = (New-Object -TypeName System.Windows.Forms.CheckedListBox)
$Profiles = (New-Object -TypeName System.Windows.Forms.Button)
$TabPage6 = (New-Object -TypeName System.Windows.Forms.TabPage)
$BetaButton2 = (New-Object -TypeName System.Windows.Forms.Button)
$ImportButton = (New-Object -TypeName System.Windows.Forms.Button)
$GroupBox7 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$ImportSelect = (New-Object -TypeName System.Windows.Forms.Button)
$ImportLocation = (New-Object -TypeName System.Windows.Forms.TextBox)
$TabPage7 = (New-Object -TypeName System.Windows.Forms.TabPage)
$Beta3 = (New-Object -TypeName System.Windows.Forms.Button)
$RunNetMig = (New-Object -TypeName System.Windows.Forms.Button)
$ComputerInfo = (New-Object -TypeName System.Windows.Forms.GroupBox)
$UNCVerified = (New-Object -TypeName System.Windows.Forms.CheckBox)
$ConnectionCheckBox = (New-Object -TypeName System.Windows.Forms.CheckBox)
$TestConnection = (New-Object -TypeName System.Windows.Forms.Button)
$NewIPLabel = (New-Object -TypeName System.Windows.Forms.Label)
$SourceIPAddressText = (New-Object -TypeName System.Windows.Forms.TextBox)
$NewComputerLabel = (New-Object -TypeName System.Windows.Forms.Label)
$OldIPLabel = (New-Object -TypeName System.Windows.Forms.Label)
$DestIpAddressText = (New-Object -TypeName System.Windows.Forms.TextBox)
$SourceComputerText = (New-Object -TypeName System.Windows.Forms.TextBox)
$DestComputerText = (New-Object -TypeName System.Windows.Forms.TextBox)
$OldComputerLabel = (New-Object -TypeName System.Windows.Forms.Label)
$LogBox = (New-Object -TypeName System.Windows.Forms.RichTextBox)
$CurrentFile = (New-Object -TypeName System.Windows.Forms.ProgressBar)
$TotalProgress = (New-Object -TypeName System.Windows.Forms.ProgressBar)
$GroupBox6 = (New-Object -TypeName System.Windows.Forms.GroupBox)
$Label4 = (New-Object -TypeName System.Windows.Forms.Label)
$Label3 = (New-Object -TypeName System.Windows.Forms.Label)
$Label2 = (New-Object -TypeName System.Windows.Forms.Label)
$2FAAuth = (New-Object -TypeName System.Windows.Forms.TextBox)
$AuthPass = (New-Object -TypeName System.Windows.Forms.TextBox)
$AuthCancel = (New-Object -TypeName System.Windows.Forms.Button)
$AuthSubmit = (New-Object -TypeName System.Windows.Forms.Button)
$AuthError = (New-Object -TypeName System.Windows.Forms.Label)
$AuthUser = (New-Object -TypeName System.Windows.Forms.TextBox)
$Label1 = (New-Object -TypeName System.Windows.Forms.Label)
$DebugConsole = (New-Object -TypeName System.Windows.Forms.Button)
$DebugCommand = (New-Object -TypeName System.Windows.Forms.TextBox)
$DebugCommandButton = (New-Object -TypeName System.Windows.Forms.Button)
$Logout = (New-Object -TypeName System.Windows.Forms.Button)
$AuthPanel = (New-Object -TypeName System.Windows.Forms.Panel)
$AuthDebugButton = (New-Object -TypeName System.Windows.Forms.Button)
$GroupBox1.SuspendLayout()
$GroupBox2.SuspendLayout()
$GroupBox3.SuspendLayout()
([System.ComponentModel.ISupportInitialize]$SystemInfo).BeginInit()
([System.ComponentModel.ISupportInitialize]$PictureBox1).BeginInit()
$TabControl1.SuspendLayout()
$TabPage1.SuspendLayout()
$TabPage2.SuspendLayout()
$TabPage3.SuspendLayout()
$TabPage4.SuspendLayout()
$TabControl2.SuspendLayout()
$TabPage5.SuspendLayout()
$SaveDestination.SuspendLayout()
$GroupBox5.SuspendLayout()
([System.ComponentModel.ISupportInitialize]$AdditionalLocations).BeginInit()
$GroupBox4.SuspendLayout()
$TabPage6.SuspendLayout()
$GroupBox7.SuspendLayout()
$TabPage7.SuspendLayout()
$ComputerInfo.SuspendLayout()
$GroupBox6.SuspendLayout()
$AuthPanel.SuspendLayout()
$TechInstaller.SuspendLayout()
#
#GroupBox1
#
$GroupBox1.Controls.Add($365Checkbox)
$GroupBox1.Controls.Add($365ComboBox)
$GroupBox1.Controls.Add($SoftwareList)
$GroupBox1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]6))
$GroupBox1.Name = [System.String]'GroupBox1'
$GroupBox1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]206,[System.Int32]253))
$GroupBox1.TabIndex = [System.Int32]0
$GroupBox1.TabStop = $false
$GroupBox1.Text = [System.String]'Software'
$GroupBox1.UseCompatibleTextRendering = $true
#
#365Checkbox
#
$365Checkbox.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]201))
$365Checkbox.Name = [System.String]'365Checkbox'
$365Checkbox.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]137,[System.Int32]16))
$365Checkbox.TabIndex = [System.Int32]1
$365Checkbox.Text = [System.String]'Office 365'
$365Checkbox.UseCompatibleTextRendering = $true
$365Checkbox.UseVisualStyleBackColor = $true
$365Checkbox.add_CheckedChanged($365Checkbox_CheckedChanged)
#
#365ComboBox
#
$365ComboBox.FormattingEnabled = $true
$365ComboBox.Items.AddRange([System.Object[]]@([System.String]'--Select--',[System.String]'Office 365 Business',[System.String]'Office 365 ProPlus',[System.String]'Office 2019 Standard'))
$365ComboBox.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]219))
$365ComboBox.Name = [System.String]'365ComboBox'
$365ComboBox.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]185,[System.Int32]21))
$365ComboBox.TabIndex = [System.Int32]2
$365ComboBox.Text = [System.String]'--Select--'
#
#SoftwareList
#
$SoftwareList.CheckOnClick = $true
$SoftwareList.FormattingEnabled = $true
$SoftwareList.Items.AddRange([System.Object[]]@([System.String]'7Zip',[System.String]'AdobeReader',[System.String]'CrystalDiskInfo',[System.String]'FileZilla',[System.String]'FireFox',[System.String]'GoogleChrome',[System.String]'NotePadPlusPlus',[System.String]'Putty',[System.String]'SysInternals',[System.String]'TreeSizeFree',[System.String]'Wireshark'))
$SoftwareList.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]15))
$SoftwareList.Name = [System.String]'SoftwareList'
$SoftwareList.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]183,[System.Int32]180))
$SoftwareList.TabIndex = [System.Int32]0
$SoftwareList.UseCompatibleTextRendering = $true
#
#GroupBox2
#
$GroupBox2.Controls.Add($dotnet35)
$GroupBox2.Controls.Add($UnInstall_Automate)
$GroupBox2.Controls.Add($ReInstall_Automate)
$GroupBox2.Controls.Add($Install_Automate)
$GroupBox2.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]5,[System.Int32]3))
$GroupBox2.Name = [System.String]'GroupBox2'
$GroupBox2.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]285,[System.Int32]429))
$GroupBox2.TabIndex = [System.Int32]3
$GroupBox2.TabStop = $false
$GroupBox2.UseCompatibleTextRendering = $true
#
#dotnet35
#
$dotnet35.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]11,[System.Int32]125))
$dotnet35.Name = [System.String]'dotnet35'
$dotnet35.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]29))
$dotnet35.TabIndex = [System.Int32]11
$dotnet35.Text = [System.String]'Install .NET 3.5'
$dotnet35.UseCompatibleTextRendering = $true
$dotnet35.UseVisualStyleBackColor = $true
$dotnet35.add_Click($dotnet35_Click)
#
#UnInstall_Automate
#
$UnInstall_Automate.Enabled = $false
$UnInstall_Automate.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]11,[System.Int32]90))
$UnInstall_Automate.Name = [System.String]'UnInstall_Automate'
$UnInstall_Automate.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]29))
$UnInstall_Automate.TabIndex = [System.Int32]10
$UnInstall_Automate.Text = [System.String]'Un-Install Automate'
$UnInstall_Automate.UseCompatibleTextRendering = $true
$UnInstall_Automate.UseVisualStyleBackColor = $true
$UnInstall_Automate.add_Click($UnInstall_Automate_Click)
#
#ReInstall_Automate
#
$ReInstall_Automate.Enabled = $false
$ReInstall_Automate.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]11,[System.Int32]55))
$ReInstall_Automate.Name = [System.String]'ReInstall_Automate'
$ReInstall_Automate.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]29))
$ReInstall_Automate.TabIndex = [System.Int32]9
$ReInstall_Automate.Text = [System.String]'Re-Install Automate'
$ReInstall_Automate.UseCompatibleTextRendering = $true
$ReInstall_Automate.UseVisualStyleBackColor = $true
$ReInstall_Automate.add_Click($ReInstall_Automate_Click)
#
#Install_Automate
#
$Install_Automate.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]11,[System.Int32]20))
$Install_Automate.Name = [System.String]'Install_Automate'
$Install_Automate.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]29))
$Install_Automate.TabIndex = [System.Int32]8
$Install_Automate.Text = [System.String]'Install Automate'
$Install_Automate.UseCompatibleTextRendering = $true
$Install_Automate.UseVisualStyleBackColor = $true
$Install_Automate.add_Click($Install_Automate_Click)
#
#GroupBox3
#
$GroupBox3.Controls.Add($SystemRestorePoint)
$GroupBox3.Controls.Add($SystemInfo)
$GroupBox3.Controls.Add($RenameDomain)
$GroupBox3.Controls.Add($Win10Upgrade)
$GroupBox3.Controls.Add($Powershell5)
$GroupBox3.Controls.Add($DellUpdate)
$GroupBox3.Controls.Add($PowerPolicy)
$GroupBox3.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]3,[System.Int32]3))
$GroupBox3.Name = [System.String]'GroupBox3'
$GroupBox3.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]287,[System.Int32]425))
$GroupBox3.TabIndex = [System.Int32]4
$GroupBox3.TabStop = $false
$GroupBox3.Text = [System.String]'System'
$GroupBox3.UseCompatibleTextRendering = $true
#
#SystemRestorePoint
#
$SystemRestorePoint.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]180))
$SystemRestorePoint.Name = [System.String]'SystemRestorePoint'
$SystemRestorePoint.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$SystemRestorePoint.TabIndex = [System.Int32]19
$SystemRestorePoint.Text = [System.String]'Create Restore Point'
$SystemRestorePoint.UseCompatibleTextRendering = $true
$SystemRestorePoint.UseVisualStyleBackColor = $true
$SystemRestorePoint.add_Click($SystemRestorePoint_Click)
#
#SystemInfo
#
$SystemInfo.AllowUserToAddRows = $false
$SystemInfo.AllowUserToDeleteRows = $false
$SystemInfo.AllowUserToResizeColumns = $false
$SystemInfo.AllowUserToResizeRows = $false
$SystemInfo.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$SystemInfo.BackgroundColor = [System.Drawing.SystemColors]::Control
$SystemInfo.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$SystemInfo.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
$SystemInfo.ColumnHeadersVisible = $false
$SystemInfo.EditMode = [System.Windows.Forms.DataGridViewEditMode]::EditProgrammatically
$SystemInfo.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]1,[System.Int32]218))
$SystemInfo.MaximumSize = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]284,[System.Int32]210))
$SystemInfo.MinimumSize = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]284,[System.Int32]210))
$SystemInfo.MultiSelect = $false
$SystemInfo.Name = [System.String]'SystemInfo'
$SystemInfo.ReadOnly = $true
$SystemInfo.RowHeadersVisible = $false
$SystemInfo.RowTemplate.Height = [System.Int32]20
$SystemInfo.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]284,[System.Int32]210))
$SystemInfo.TabIndex = [System.Int32]5
#
#RenameDomain
#
$RenameDomain.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Tahoma',[System.Single]8.25,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$RenameDomain.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]147))
$RenameDomain.Name = [System.String]'RenameDomain'
$RenameDomain.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$RenameDomain.TabIndex = [System.Int32]18
$RenameDomain.Text = [System.String]'Rename Computer/Domain'
$RenameDomain.UseCompatibleTextRendering = $true
$RenameDomain.UseVisualStyleBackColor = $true
$RenameDomain.add_Click($RenameDomain_Click)
#
#Win10Upgrade
#
$Win10Upgrade.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]116))
$Win10Upgrade.Name = [System.String]'Win10Upgrade'
$Win10Upgrade.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$Win10Upgrade.TabIndex = [System.Int32]6
$Win10Upgrade.Text = [System.String]'Win10 1909 Upgrade'
$Win10Upgrade.UseCompatibleTextRendering = $true
$Win10Upgrade.UseVisualStyleBackColor = $true
$Win10Upgrade.add_Click($Win10Upgrade_Click)
#
#Powershell5
#
$Powershell5.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]83))
$Powershell5.Name = [System.String]'Powershell5'
$Powershell5.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$Powershell5.TabIndex = [System.Int32]7
$Powershell5.Text = [System.String]'Install Powershell 5'
$Powershell5.UseCompatibleTextRendering = $true
$Powershell5.UseVisualStyleBackColor = $true
$Powershell5.add_Click($Powershell5_Click)
#
#DellUpdate
#
$DellUpdate.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]50))
$DellUpdate.Name = [System.String]'DellUpdate'
$DellUpdate.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$DellUpdate.TabIndex = [System.Int32]17
$DellUpdate.Text = [System.String]'DellCMD | Update'
$DellUpdate.UseCompatibleTextRendering = $true
$DellUpdate.UseVisualStyleBackColor = $true
$DellUpdate.add_Click($DellUpdate_Click)
#
#PowerPolicy
#
$PowerPolicy.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]43,[System.Int32]17))
$PowerPolicy.Name = [System.String]'PowerPolicy'
$PowerPolicy.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]202,[System.Int32]27))
$PowerPolicy.TabIndex = [System.Int32]16
$PowerPolicy.Text = [System.String]'Apply Qi Power Policy'
$PowerPolicy.UseCompatibleTextRendering = $true
$PowerPolicy.UseVisualStyleBackColor = $true
$PowerPolicy.add_Click($PowerPolicy_Click)
#
#Cancel
#
$Cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$Cancel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]709,[System.Int32]452))
$Cancel.Name = [System.String]'Cancel'
$Cancel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]94,[System.Int32]27))
$Cancel.TabIndex = [System.Int32]17
$Cancel.Text = [System.String]'Close'
$Cancel.UseCompatibleTextRendering = $true
$Cancel.UseVisualStyleBackColor = $true
$Cancel.add_Click($Close_Click)
#
#PictureBox1
#
$PictureBox1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]429,[System.Int32]406))
$PictureBox1.Name = [System.String]'PictureBox1'
$PictureBox1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]247,[System.Int32]75))
$PictureBox1.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::StretchImage
$PictureBox1.TabIndex = [System.Int32]5
$PictureBox1.TabStop = $false
#
#TabControl1
#
$TabControl1.Controls.Add($TabPage1)
$TabControl1.Controls.Add($TabPage2)
$TabControl1.Controls.Add($TabPage3)
$TabControl1.Controls.Add($TabPage4)
$TabControl1.HotTrack = $true
$TabControl1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]8,[System.Int32]12))
$TabControl1.Multiline = $true
$TabControl1.Name = [System.String]'TabControl1'
$TabControl1.SelectedIndex = [System.Int32]0
$TabControl1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]301,[System.Int32]461))
$TabControl1.TabIndex = [System.Int32]20
#
#TabPage1
#
$TabPage1.Controls.Add($GroupBox2)
$TabPage1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage1.Name = [System.String]'TabPage1'
$TabPage1.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$TabPage1.RightToLeft = [System.Windows.Forms.RightToLeft]::No
$TabPage1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]293,[System.Int32]435))
$TabPage1.TabIndex = [System.Int32]0
$TabPage1.Text = [System.String]'Automate'
$TabPage1.UseVisualStyleBackColor = $true
#
#TabPage2
#
$TabPage2.Controls.Add($InstallSoftware)
$TabPage2.Controls.Add($GroupBox1)
$TabPage2.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage2.Name = [System.String]'TabPage2'
$TabPage2.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$TabPage2.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]293,[System.Int32]435))
$TabPage2.TabIndex = [System.Int32]1
$TabPage2.Text = [System.String]'Software'
$TabPage2.UseVisualStyleBackColor = $true
#
#InstallSoftware
#
$InstallSoftware.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]265))
$InstallSoftware.Name = [System.String]'InstallSoftware'
$InstallSoftware.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]29))
$InstallSoftware.TabIndex = [System.Int32]1
$InstallSoftware.Text = [System.String]'Install Software'
$InstallSoftware.UseCompatibleTextRendering = $true
$InstallSoftware.UseVisualStyleBackColor = $true
$InstallSoftware.add_Click($InstallSoftware_Click)
#
#TabPage3
#
$TabPage3.Controls.Add($GroupBox3)
$TabPage3.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage3.Name = [System.String]'TabPage3'
$TabPage3.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]293,[System.Int32]435))
$TabPage3.TabIndex = [System.Int32]2
$TabPage3.Text = [System.String]'System'
$TabPage3.UseVisualStyleBackColor = $true
$TabPage3.Visible = $false
#
#TabPage4
#
$TabPage4.Controls.Add($TabControl2)
$TabPage4.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage4.Name = [System.String]'TabPage4'
$TabPage4.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]293,[System.Int32]435))
$TabPage4.TabIndex = [System.Int32]3
$TabPage4.Text = [System.String]'Migration'
$TabPage4.UseVisualStyleBackColor = $true
$TabPage4.Visible = $false
#
#TabControl2
#
$TabControl2.Controls.Add($TabPage5)
$TabControl2.Controls.Add($TabPage6)
$TabControl2.Controls.Add($TabPage7)
$TabControl2.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]-4,[System.Int32]0))
$TabControl2.Name = [System.String]'TabControl2'
$TabControl2.SelectedIndex = [System.Int32]0
$TabControl2.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]299,[System.Int32]439))
$TabControl2.TabIndex = [System.Int32]3
#
#TabPage5
#
$TabPage5.Controls.Add($AlphaButton)
$TabPage5.Controls.Add($Export)
$TabPage5.Controls.Add($SaveDestination)
$TabPage5.Controls.Add($GroupBox5)
$TabPage5.Controls.Add($GroupBox4)
$TabPage5.Controls.Add($Profiles)
$TabPage5.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage5.Name = [System.String]'TabPage5'
$TabPage5.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$TabPage5.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]291,[System.Int32]413))
$TabPage5.TabIndex = [System.Int32]0
$TabPage5.Text = [System.String]'Export'
$TabPage5.UseVisualStyleBackColor = $true
#
#AlphaButton
#
$AlphaButton.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Tahoma',[System.Single]27.75,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$AlphaButton.ForeColor = [System.Drawing.Color]::DarkOrange
$AlphaButton.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]164,[System.Int32]371))
$AlphaButton.Name = [System.String]'AlphaButton'
$AlphaButton.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]124,[System.Int32]40))
$AlphaButton.TabIndex = [System.Int32]22
$AlphaButton.Text = [System.String]'Beta'
$AlphaButton.UseCompatibleTextRendering = $true
$AlphaButton.UseVisualStyleBackColor = $true
$AlphaButton.add_Click($AlphaButton_Click)
#
#Export
#
$Export.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]185,[System.Int32]373))
$Export.Name = [System.String]'Export'
$Export.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$Export.TabIndex = [System.Int32]6
$Export.Text = [System.String]'Run Export'
$Export.UseCompatibleTextRendering = $true
$Export.UseVisualStyleBackColor = $true
$Export.add_Click($Export_Click)
#
#SaveDestination
#
$SaveDestination.Controls.Add($ExportLocationButton)
$SaveDestination.Controls.Add($ExportLocation)
$SaveDestination.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]288))
$SaveDestination.Name = [System.String]'SaveDestination'
$SaveDestination.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]273,[System.Int32]77))
$SaveDestination.TabIndex = [System.Int32]5
$SaveDestination.TabStop = $false
$SaveDestination.Text = [System.String]'Save Destination'
$SaveDestination.UseCompatibleTextRendering = $true
#
#ExportLocationButton
#
$ExportLocationButton.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]47))
$ExportLocationButton.Name = [System.String]'ExportLocationButton'
$ExportLocationButton.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$ExportLocationButton.TabIndex = [System.Int32]5
$ExportLocationButton.Text = [System.String]'Change'
$ExportLocationButton.UseCompatibleTextRendering = $true
$ExportLocationButton.UseVisualStyleBackColor = $true
$ExportLocationButton.add_Click($ExportLocationButton_Click)
#
#ExportLocation
#
$ExportLocation.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]20))
$ExportLocation.Name = [System.String]'ExportLocation'
$ExportLocation.ReadOnly = $true
$ExportLocation.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]259,[System.Int32]21))
$ExportLocation.TabIndex = [System.Int32]4
#
#GroupBox5
#
$GroupBox5.Controls.Add($AddDirectory)
$GroupBox5.Controls.Add($RemoveDirectory)
$GroupBox5.Controls.Add($AdditionalLocations)
$GroupBox5.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]156))
$GroupBox5.Name = [System.String]'GroupBox5'
$GroupBox5.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]273,[System.Int32]130))
$GroupBox5.TabIndex = [System.Int32]3
$GroupBox5.TabStop = $false
$GroupBox5.Text = [System.String]'Additional Locations'
$GroupBox5.UseCompatibleTextRendering = $true
#
#AddDirectory
#
$AddDirectory.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]26,[System.Int32]105))
$AddDirectory.Name = [System.String]'AddDirectory'
$AddDirectory.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]25,[System.Int32]19))
$AddDirectory.TabIndex = [System.Int32]21
$AddDirectory.Text = [System.String]'+'
$AddDirectory.UseCompatibleTextRendering = $true
$AddDirectory.UseVisualStyleBackColor = $true
$AddDirectory.add_Click($AddDirectory_Click)
#
#RemoveDirectory
#
$RemoveDirectory.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]105))
$RemoveDirectory.Name = [System.String]'RemoveDirectory'
$RemoveDirectory.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]21,[System.Int32]19))
$RemoveDirectory.TabIndex = [System.Int32]4
$RemoveDirectory.Text = [System.String]'-'
$RemoveDirectory.UseCompatibleTextRendering = $true
$RemoveDirectory.UseVisualStyleBackColor = $true
$RemoveDirectory.add_Click($RemoveDirectory_Click)
#
#AdditionalLocations
#
$AdditionalLocations.AllowUserToAddRows = $false
$AdditionalLocations.AllowUserToDeleteRows = $false
$AdditionalLocations.AllowUserToResizeColumns = $false
$AdditionalLocations.AllowUserToResizeRows = $false
$AdditionalLocations.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
$AdditionalLocations.BackgroundColor = [System.Drawing.Color]::White
$AdditionalLocations.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::AutoSize
$AdditionalLocations.ColumnHeadersVisible = $false
$AdditionalLocations.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]20))
$AdditionalLocations.MultiSelect = $false
$AdditionalLocations.Name = [System.String]'AdditionalLocations'
$AdditionalLocations.ReadOnly = $true
$AdditionalLocations.RowHeadersVisible = $false
$AdditionalLocations.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]259,[System.Int32]104))
$AdditionalLocations.TabIndex = [System.Int32]3
#
#GroupBox4
#
$GroupBox4.Controls.Add($USMTCheckList)
$GroupBox4.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]6))
$GroupBox4.Name = [System.String]'GroupBox4'
$GroupBox4.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]273,[System.Int32]144))
$GroupBox4.TabIndex = [System.Int32]2
$GroupBox4.TabStop = $false
$GroupBox4.Text = [System.String]'Include with Migration'
$GroupBox4.UseCompatibleTextRendering = $true
#
#USMTCheckList
#
$USMTCheckList.CheckOnClick = $true
$USMTCheckList.ColumnWidth = [System.Int32]125
$USMTCheckList.FormattingEnabled = $true
$USMTCheckList.Items.AddRange([System.Object[]]@([System.String]'AppData',[System.String]'Local AppData',[System.String]'Printers',[System.String]'Recycle Bin',[System.String]'My Documents',[System.String]'Wallpapers',[System.String]'Downloads',[System.String]'Favorites',[System.String]'My Music',[System.String]'My Pictures',[System.String]'My Video',[System.String]'Desktop'))
$USMTCheckList.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]20))
$USMTCheckList.MultiColumn = $true
$USMTCheckList.Name = [System.String]'USMTCheckList'
$USMTCheckList.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]259,[System.Int32]116))
$USMTCheckList.TabIndex = [System.Int32]1
$USMTCheckList.UseCompatibleTextRendering = $true
#
#Profiles
#
$Profiles.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]371))
$Profiles.Name = [System.String]'Profiles'
$Profiles.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]154,[System.Int32]25))
$Profiles.TabIndex = [System.Int32]0
$Profiles.Text = [System.String]'Select Profile(s)'
$Profiles.UseCompatibleTextRendering = $true
$Profiles.UseVisualStyleBackColor = $true
$Profiles.add_Click($Profiles_Click)
#
#TabPage6
#
$TabPage6.Controls.Add($BetaButton2)
$TabPage6.Controls.Add($ImportButton)
$TabPage6.Controls.Add($GroupBox7)
$TabPage6.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage6.Name = [System.String]'TabPage6'
$TabPage6.Padding = (New-Object -TypeName System.Windows.Forms.Padding -ArgumentList @([System.Int32]3))
$TabPage6.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]291,[System.Int32]413))
$TabPage6.TabIndex = [System.Int32]1
$TabPage6.Text = [System.String]'Import'
$TabPage6.UseVisualStyleBackColor = $true
#
#BetaButton2
#
$BetaButton2.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Tahoma',[System.Single]27.75,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$BetaButton2.ForeColor = [System.Drawing.Color]::FromArgb(([System.Int32]([System.Byte][System.Byte]255)),([System.Int32]([System.Byte][System.Byte]128)),([System.Int32]([System.Byte][System.Byte]0)))

$BetaButton2.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]164,[System.Int32]371))
$BetaButton2.Name = [System.String]'BetaButton2'
$BetaButton2.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]124,[System.Int32]40))
$BetaButton2.TabIndex = [System.Int32]2
$BetaButton2.Text = [System.String]'Beta'
$BetaButton2.UseCompatibleTextRendering = $true
$BetaButton2.UseVisualStyleBackColor = $true
$BetaButton2.add_Click($BetaButton2_Click)
#
#ImportButton
#
$ImportButton.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]210,[System.Int32]381))
$ImportButton.Name = [System.String]'ImportButton'
$ImportButton.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$ImportButton.TabIndex = [System.Int32]1
$ImportButton.Text = [System.String]'Import'
$ImportButton.UseCompatibleTextRendering = $true
$ImportButton.UseVisualStyleBackColor = $true
$ImportButton.add_Click($ImportButton_Click)
#
#GroupBox7
#
$GroupBox7.Controls.Add($ImportSelect)
$GroupBox7.Controls.Add($ImportLocation)
$GroupBox7.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]6))
$GroupBox7.Name = [System.String]'GroupBox7'
$GroupBox7.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]279,[System.Int32]81))
$GroupBox7.TabIndex = [System.Int32]0
$GroupBox7.TabStop = $false
$GroupBox7.Text = [System.String]'Load State Source'
$GroupBox7.UseCompatibleTextRendering = $true
#
#ImportSelect
#
$ImportSelect.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]47))
$ImportSelect.Name = [System.String]'ImportSelect'
$ImportSelect.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$ImportSelect.TabIndex = [System.Int32]1
$ImportSelect.Text = [System.String]'Select'
$ImportSelect.UseCompatibleTextRendering = $true
$ImportSelect.UseVisualStyleBackColor = $true
$ImportSelect.add_Click($ImportSelect_Click)
#
#ImportLocation
#
$ImportLocation.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]20))
$ImportLocation.Name = [System.String]'ImportLocation'
$ImportLocation.ReadOnly = $true
$ImportLocation.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]267,[System.Int32]21))
$ImportLocation.TabIndex = [System.Int32]0
#
#TabPage7
#
$TabPage7.Controls.Add($Beta3)
$TabPage7.Controls.Add($RunNetMig)
$TabPage7.Controls.Add($ComputerInfo)
$TabPage7.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]22))
$TabPage7.Name = [System.String]'TabPage7'
$TabPage7.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]291,[System.Int32]413))
$TabPage7.TabIndex = [System.Int32]2
$TabPage7.Text = [System.String]'Network Migration'
$TabPage7.UseVisualStyleBackColor = $true
$TabPage7.Visible = $false
#
#Beta3
#
$Beta3.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Tahoma',[System.Single]27.75,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$Beta3.ForeColor = [System.Drawing.Color]::FromArgb(([System.Int32]([System.Byte][System.Byte]255)),([System.Int32]([System.Byte][System.Byte]128)),([System.Int32]([System.Byte][System.Byte]0)))

$Beta3.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]164,[System.Int32]371))
$Beta3.Name = [System.String]'Beta3'
$Beta3.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]124,[System.Int32]40))
$Beta3.TabIndex = [System.Int32]2
$Beta3.Text = [System.String]'Beta'
$Beta3.UseCompatibleTextRendering = $true
$Beta3.UseVisualStyleBackColor = $true
$Beta3.add_Click($Beta3_Click)
#
#RunNetMig
#
$RunNetMig.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]164,[System.Int32]381))
$RunNetMig.Name = [System.String]'RunNetMig'
$RunNetMig.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]23))
$RunNetMig.TabIndex = [System.Int32]1
$RunNetMig.Text = [System.String]'Network Migration'
$RunNetMig.UseCompatibleTextRendering = $true
$RunNetMig.UseVisualStyleBackColor = $true
$RunNetMig.add_Click($RunNetMig_Click)
#
#ComputerInfo
#
$ComputerInfo.Controls.Add($UNCVerified)
$ComputerInfo.Controls.Add($ConnectionCheckBox)
$ComputerInfo.Controls.Add($TestConnection)
$ComputerInfo.Controls.Add($NewIPLabel)
$ComputerInfo.Controls.Add($SourceIPAddressText)
$ComputerInfo.Controls.Add($NewComputerLabel)
$ComputerInfo.Controls.Add($OldIPLabel)
$ComputerInfo.Controls.Add($DestIpAddressText)
$ComputerInfo.Controls.Add($SourceComputerText)
$ComputerInfo.Controls.Add($DestComputerText)
$ComputerInfo.Controls.Add($OldComputerLabel)
$ComputerInfo.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]3,[System.Int32]3))
$ComputerInfo.Name = [System.String]'ComputerInfo'
$ComputerInfo.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]285,[System.Int32]150))
$ComputerInfo.TabIndex = [System.Int32]0
$ComputerInfo.TabStop = $false
$ComputerInfo.Text = [System.String]'Computer Info'
$ComputerInfo.UseCompatibleTextRendering = $true
#
#UNCVerified
#
$UNCVerified.Enabled = $false
$UNCVerified.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]123))
$UNCVerified.Name = [System.String]'UNCVerified'
$UNCVerified.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]104,[System.Int32]19))
$UNCVerified.TabIndex = [System.Int32]8
$UNCVerified.Text = [System.String]'UNC Verified'
$UNCVerified.UseCompatibleTextRendering = $true
$UNCVerified.UseVisualStyleBackColor = $true
#
#ConnectionCheckBox
#
$ConnectionCheckBox.Enabled = $false
$ConnectionCheckBox.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]104))
$ConnectionCheckBox.Name = [System.String]'ConnectionCheckBox'
$ConnectionCheckBox.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]13))
$ConnectionCheckBox.TabIndex = [System.Int32]7
$ConnectionCheckBox.Text = [System.String]'Connected'
$ConnectionCheckBox.UseCompatibleTextRendering = $true
$ConnectionCheckBox.UseVisualStyleBackColor = $true
#
#TestConnection
#
$TestConnection.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]103))
$TestConnection.Name = [System.String]'TestConnection'
$TestConnection.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]106,[System.Int32]23))
$TestConnection.TabIndex = [System.Int32]6
$TestConnection.Text = [System.String]'Test Connection'
$TestConnection.UseCompatibleTextRendering = $true
$TestConnection.UseVisualStyleBackColor = $true
$TestConnection.add_Click($TestConnection_Click)
#
#NewIPLabel
#
$NewIPLabel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]58))
$NewIPLabel.Name = [System.String]'NewIPLabel'
$NewIPLabel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]16))
$NewIPLabel.TabIndex = [System.Int32]5
$NewIPLabel.Text = [System.String]'Destination IP Address'
$NewIPLabel.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$NewIPLabel.UseCompatibleTextRendering = $true
#
#SourceIPAddressText
#
$SourceIPAddressText.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]36))
$SourceIPAddressText.Name = [System.String]'SourceIPAddressText'
$SourceIPAddressText.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]21))
$SourceIPAddressText.TabIndex = [System.Int32]1
#
#NewComputerLabel
#
$NewComputerLabel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]58))
$NewComputerLabel.Name = [System.String]'NewComputerLabel'
$NewComputerLabel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]16))
$NewComputerLabel.TabIndex = [System.Int32]4
$NewComputerLabel.Text = [System.String]'Destination Computer Name'
$NewComputerLabel.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$NewComputerLabel.UseCompatibleTextRendering = $true
#
#OldIPLabel
#
$OldIPLabel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]17))
$OldIPLabel.Name = [System.String]'OldIPLabel'
$OldIPLabel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]16))
$OldIPLabel.TabIndex = [System.Int32]5
$OldIPLabel.Text = [System.String]'Source IP Address'
$OldIPLabel.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$OldIPLabel.UseCompatibleTextRendering = $true
#
#DestIpAddressText
#
$DestIpAddressText.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]161,[System.Int32]77))
$DestIpAddressText.Name = [System.String]'DestIpAddressText'
$DestIpAddressText.ReadOnly = $true
$DestIpAddressText.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]118,[System.Int32]21))
$DestIpAddressText.TabIndex = [System.Int32]3
#
#SourceComputerText
#
$SourceComputerText.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]36))
$SourceComputerText.Name = [System.String]'SourceComputerText'
$SourceComputerText.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]21))
$SourceComputerText.TabIndex = [System.Int32]0
#
#DestComputerText
#
$DestComputerText.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]77))
$DestComputerText.Name = [System.String]'DestComputerText'
$DestComputerText.ReadOnly = $true
$DestComputerText.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]21))
$DestComputerText.TabIndex = [System.Int32]2
#
#OldComputerLabel
#
$OldComputerLabel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]17))
$OldComputerLabel.Name = [System.String]'OldComputerLabel'
$OldComputerLabel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]149,[System.Int32]16))
$OldComputerLabel.TabIndex = [System.Int32]4
$OldComputerLabel.Text = [System.String]'Source Computer Name'
$OldComputerLabel.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$OldComputerLabel.UseCompatibleTextRendering = $true
#
#LogBox
#
$LogBox.BackColor = [System.Drawing.Color]::Black
$LogBox.Font = (New-Object -TypeName System.Drawing.Font -ArgumentList @([System.String]'Franklin Gothic Book',[System.Single]9.75,[System.Drawing.FontStyle]::Regular,[System.Drawing.GraphicsUnit]::Point,([System.Byte][System.Byte]0)))
$LogBox.ForeColor = [System.Drawing.Color]::White
$LogBox.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]34))
$LogBox.Name = [System.String]'LogBox'
$LogBox.ReadOnly = $true
$LogBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$LogBox.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]489,[System.Int32]366))
$LogBox.TabIndex = [System.Int32]21
$LogBox.Text = [System.String]''
#
#CurrentFile
#
$CurrentFile.BackColor = [System.Drawing.Color]::Black
$CurrentFile.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]12))
$CurrentFile.Name = [System.String]'CurrentFile'
$CurrentFile.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]488,[System.Int32]23))
$CurrentFile.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$CurrentFile.TabIndex = [System.Int32]0
$CurrentFile.Visible = $false
#
#TotalProgress
#
$TotalProgress.BackColor = [System.Drawing.Color]::Black
$TotalProgress.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]4))
$TotalProgress.Name = [System.String]'TotalProgress'
$TotalProgress.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]488,[System.Int32]10))
$TotalProgress.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$TotalProgress.TabIndex = [System.Int32]22
$TotalProgress.Visible = $false
#
#GroupBox6
#
$GroupBox6.Controls.Add($Label4)
$GroupBox6.Controls.Add($Label3)
$GroupBox6.Controls.Add($Label2)
$GroupBox6.Controls.Add($2FAAuth)
$GroupBox6.Controls.Add($AuthPass)
$GroupBox6.Controls.Add($AuthCancel)
$GroupBox6.Controls.Add($AuthSubmit)
$GroupBox6.Controls.Add($AuthError)
$GroupBox6.Controls.Add($AuthUser)
$GroupBox6.Controls.Add($Label1)
$GroupBox6.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]297,[System.Int32]110))
$GroupBox6.Name = [System.String]'GroupBox6'
$GroupBox6.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]223,[System.Int32]255))
$GroupBox6.TabIndex = [System.Int32]1
$GroupBox6.TabStop = $false
$GroupBox6.Text = [System.String]'Authentication'
$GroupBox6.UseCompatibleTextRendering = $true
#
#Label4
#
$Label4.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]57))
$Label4.Name = [System.String]'Label4'
$Label4.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]100,[System.Int32]17))
$Label4.TabIndex = [System.Int32]8
$Label4.Text = [System.String]'Username:'
$Label4.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$Label4.UseCompatibleTextRendering = $true
#
#Label3
#
$Label3.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]101))
$Label3.Name = [System.String]'Label3'
$Label3.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]100,[System.Int32]20))
$Label3.TabIndex = [System.Int32]7
$Label3.Text = [System.String]'Password:'
$Label3.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$Label3.UseCompatibleTextRendering = $true
#
#Label2
#
$Label2.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]148))
$Label2.Name = [System.String]'Label2'
$Label2.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]100,[System.Int32]17))
$Label2.TabIndex = [System.Int32]6
$Label2.Text = [System.String]'Token:'
$Label2.TextAlign = [System.Drawing.ContentAlignment]::BottomLeft
$Label2.UseCompatibleTextRendering = $true
#
#2FAAuth
#
$2FAAuth.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]168))
$2FAAuth.Name = [System.String]'2FAAuth'
$2FAAuth.PasswordChar = [System.Char]'*'
$2FAAuth.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]175,[System.Int32]21))
$2FAAuth.TabIndex = [System.Int32]3
#
#AuthPass
#
$AuthPass.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]124))
$AuthPass.Name = [System.String]'AuthPass'
$AuthPass.PasswordChar = [System.Char]'*'
$AuthPass.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]176,[System.Int32]21))
$AuthPass.TabIndex = [System.Int32]2
#
#AuthCancel
#
$AuthCancel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]114,[System.Int32]215))
$AuthCancel.Name = [System.String]'AuthCancel'
$AuthCancel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$AuthCancel.TabIndex = [System.Int32]5
$AuthCancel.Text = [System.String]'Cancel'
$AuthCancel.UseCompatibleTextRendering = $true
$AuthCancel.UseVisualStyleBackColor = $true
$AuthCancel.add_Click($AuthCancel_Click)
#
#AuthSubmit
#
$AuthSubmit.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]33,[System.Int32]215))
$AuthSubmit.Name = [System.String]'AuthSubmit'
$AuthSubmit.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$AuthSubmit.TabIndex = [System.Int32]4
$AuthSubmit.Text = [System.String]'Submit'
$AuthSubmit.UseCompatibleTextRendering = $true
$AuthSubmit.UseVisualStyleBackColor = $true
$AuthSubmit.add_Click($AuthSubmit_Click)
#
#AuthError
#
$AuthError.ForeColor = [System.Drawing.Color]::Red
$AuthError.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]194))
$AuthError.Name = [System.String]'AuthError'
$AuthError.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]211,[System.Int32]18))
$AuthError.TabIndex = [System.Int32]2
$AuthError.Text = [System.String]'Invalid credentials, please try again.'
$AuthError.TextAlign = [System.Drawing.ContentAlignment]::BottomCenter
$AuthError.UseCompatibleTextRendering = $true
$AuthError.Visible = $false
#
#AuthUser
#
$AuthUser.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]16,[System.Int32]77))
$AuthUser.Name = [System.String]'AuthUser'
$AuthUser.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]176,[System.Int32]21))
$AuthUser.TabIndex = [System.Int32]1
#
#Label1
#
$Label1.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]6,[System.Int32]22))
$Label1.Name = [System.String]'Label1'
$Label1.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]211,[System.Int32]23))
$Label1.TabIndex = [System.Int32]0
$Label1.Text = [System.String]'Enter Your Automate Credentials'
$Label1.TextAlign = [System.Drawing.ContentAlignment]::BottomCenter
$Label1.UseCompatibleTextRendering = $true
#
#DebugConsole
#
$DebugConsole.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]450))
$DebugConsole.Name = [System.String]'DebugConsole'
$DebugConsole.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]108,[System.Int32]23))
$DebugConsole.TabIndex = [System.Int32]23
$DebugConsole.Text = [System.String]'Debug Console'
$DebugConsole.UseCompatibleTextRendering = $true
$DebugConsole.UseVisualStyleBackColor = $true
$DebugConsole.Visible = $false
$DebugConsole.add_Click($DebugConsole_Click)
#
#DebugCommand
#
$DebugCommand.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]397))
$DebugCommand.Name = [System.String]'DebugCommand'
$DebugCommand.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]488,[System.Int32]21))
$DebugCommand.TabIndex = [System.Int32]24
$DebugCommand.Visible = $false
#
#DebugCommandButton
#
$DebugCommandButton.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]315,[System.Int32]424))
$DebugCommandButton.Name = [System.String]'DebugCommandButton'
$DebugCommandButton.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]108,[System.Int32]23))
$DebugCommandButton.TabIndex = [System.Int32]25
$DebugCommandButton.Text = [System.String]'Submit Command'
$DebugCommandButton.UseCompatibleTextRendering = $true
$DebugCommandButton.UseVisualStyleBackColor = $true
$DebugCommandButton.Visible = $false
$DebugCommandButton.add_Click($DebugCommandButton_Click)
#
#Logout
#
$Logout.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]709,[System.Int32]422))
$Logout.Name = [System.String]'Logout'
$Logout.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]94,[System.Int32]27))
$Logout.TabIndex = [System.Int32]26
$Logout.Text = [System.String]'Logout'
$Logout.UseCompatibleTextRendering = $true
$Logout.UseVisualStyleBackColor = $true
$Logout.add_Click($Logout_Click)
#
#AuthPanel
#
$AuthPanel.Controls.Add($AuthDebugButton)
$AuthPanel.Controls.Add($GroupBox6)
$AuthPanel.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]4,[System.Int32]4))
$AuthPanel.Name = [System.String]'AuthPanel'
$AuthPanel.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]810,[System.Int32]477))
$AuthPanel.TabIndex = [System.Int32]2
#
#AuthDebugButton
#
$AuthDebugButton.Location = (New-Object -TypeName System.Drawing.Point -ArgumentList @([System.Int32]370,[System.Int32]371))
$AuthDebugButton.Name = [System.String]'AuthDebugButton'
$AuthDebugButton.Size = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]75,[System.Int32]23))
$AuthDebugButton.TabIndex = [System.Int32]2
$AuthDebugButton.Text = [System.String]'Debug'
$AuthDebugButton.UseCompatibleTextRendering = $true
$AuthDebugButton.UseVisualStyleBackColor = $true
$AuthDebugButton.Visible = $false
$AuthDebugButton.add_Click($AuthDebugButton_Click)
#
#TechInstaller
#
$TechInstaller.AcceptButton = $AuthSubmit
$TechInstaller.CancelButton = $Cancel
$TechInstaller.ClientSize = (New-Object -TypeName System.Drawing.Size -ArgumentList @([System.Int32]816,[System.Int32]485))
$TechInstaller.Controls.Add($AuthPanel)
$TechInstaller.Controls.Add($Logout)
$TechInstaller.Controls.Add($DebugCommandButton)
$TechInstaller.Controls.Add($DebugCommand)
$TechInstaller.Controls.Add($DebugConsole)
$TechInstaller.Controls.Add($TotalProgress)
$TechInstaller.Controls.Add($CurrentFile)
$TechInstaller.Controls.Add($LogBox)
$TechInstaller.Controls.Add($TabControl1)
$TechInstaller.Controls.Add($PictureBox1)
$TechInstaller.Controls.Add($Cancel)
$TechInstaller.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$TechInstaller.MaximizeBox = $false
$TechInstaller.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$TechInstaller.Text = [System.String]'Tech Installer'
$TechInstaller.TopMost = $true
$TechInstaller.add_Load($TechInstaller_Load)
$GroupBox1.ResumeLayout($false)
$GroupBox2.ResumeLayout($false)
$GroupBox3.ResumeLayout($false)
([System.ComponentModel.ISupportInitialize]$SystemInfo).EndInit()
([System.ComponentModel.ISupportInitialize]$PictureBox1).EndInit()
$TabControl1.ResumeLayout($false)
$TabPage1.ResumeLayout($false)
$TabPage2.ResumeLayout($false)
$TabPage3.ResumeLayout($false)
$TabPage4.ResumeLayout($false)
$TabControl2.ResumeLayout($false)
$TabPage5.ResumeLayout($false)
$SaveDestination.ResumeLayout($false)
$SaveDestination.PerformLayout()
$GroupBox5.ResumeLayout($false)
([System.ComponentModel.ISupportInitialize]$AdditionalLocations).EndInit()
$GroupBox4.ResumeLayout($false)
$TabPage6.ResumeLayout($false)
$GroupBox7.ResumeLayout($false)
$GroupBox7.PerformLayout()
$TabPage7.ResumeLayout($false)
$ComputerInfo.ResumeLayout($false)
$ComputerInfo.PerformLayout()
$GroupBox6.ResumeLayout($false)
$GroupBox6.PerformLayout()
$AuthPanel.ResumeLayout($false)
$TechInstaller.ResumeLayout($false)
$TechInstaller.PerformLayout()
Add-Member -InputObject $TechInstaller -Name base -Value $base -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox1 -Value $GroupBox1 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name 365Checkbox -Value $365Checkbox -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name 365ComboBox -Value $365ComboBox -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SoftwareList -Value $SoftwareList -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox2 -Value $GroupBox2 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name dotnet35 -Value $dotnet35 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name UnInstall_Automate -Value $UnInstall_Automate -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ReInstall_Automate -Value $ReInstall_Automate -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Install_Automate -Value $Install_Automate -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox3 -Value $GroupBox3 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SystemRestorePoint -Value $SystemRestorePoint -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SystemInfo -Value $SystemInfo -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name RenameDomain -Value $RenameDomain -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Win10Upgrade -Value $Win10Upgrade -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Powershell5 -Value $Powershell5 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DellUpdate -Value $DellUpdate -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name PowerPolicy -Value $PowerPolicy -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Cancel -Value $Cancel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name PictureBox1 -Value $PictureBox1 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabControl1 -Value $TabControl1 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage1 -Value $TabPage1 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage2 -Value $TabPage2 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name InstallSoftware -Value $InstallSoftware -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage3 -Value $TabPage3 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage4 -Value $TabPage4 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabControl2 -Value $TabControl2 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage5 -Value $TabPage5 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AlphaButton -Value $AlphaButton -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Export -Value $Export -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SaveDestination -Value $SaveDestination -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ExportLocationButton -Value $ExportLocationButton -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ExportLocation -Value $ExportLocation -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox5 -Value $GroupBox5 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AddDirectory -Value $AddDirectory -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name RemoveDirectory -Value $RemoveDirectory -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AdditionalLocations -Value $AdditionalLocations -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox4 -Value $GroupBox4 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name USMTCheckList -Value $USMTCheckList -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Profiles -Value $Profiles -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage6 -Value $TabPage6 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name BetaButton2 -Value $BetaButton2 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ImportButton -Value $ImportButton -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox7 -Value $GroupBox7 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ImportSelect -Value $ImportSelect -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ImportLocation -Value $ImportLocation -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TabPage7 -Value $TabPage7 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Beta3 -Value $Beta3 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name RunNetMig -Value $RunNetMig -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ComputerInfo -Value $ComputerInfo -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name UNCVerified -Value $UNCVerified -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name ConnectionCheckBox -Value $ConnectionCheckBox -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TestConnection -Value $TestConnection -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name NewIPLabel -Value $NewIPLabel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SourceIPAddressText -Value $SourceIPAddressText -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name NewComputerLabel -Value $NewComputerLabel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name OldIPLabel -Value $OldIPLabel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DestIpAddressText -Value $DestIpAddressText -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name SourceComputerText -Value $SourceComputerText -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DestComputerText -Value $DestComputerText -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name OldComputerLabel -Value $OldComputerLabel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name LogBox -Value $LogBox -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name CurrentFile -Value $CurrentFile -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name TotalProgress -Value $TotalProgress -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name GroupBox6 -Value $GroupBox6 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Label4 -Value $Label4 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Label3 -Value $Label3 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Label2 -Value $Label2 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name 2FAAuth -Value $2FAAuth -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthPass -Value $AuthPass -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthCancel -Value $AuthCancel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthSubmit -Value $AuthSubmit -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthError -Value $AuthError -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthUser -Value $AuthUser -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Label1 -Value $Label1 -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DebugConsole -Value $DebugConsole -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DebugCommand -Value $DebugCommand -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name DebugCommandButton -Value $DebugCommandButton -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name Logout -Value $Logout -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthPanel -Value $AuthPanel -MemberType NoteProperty
Add-Member -InputObject $TechInstaller -Name AuthDebugButton -Value $AuthDebugButton -MemberType NoteProperty
}
. InitializeComponent
