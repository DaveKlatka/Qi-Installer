#USMT Functions

$NewComputerText.Text = $env:COMPUTERNAME
$NewIpAddressText.Text = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
$ExportLocation.Text = $ScriptPath
function Save-UserState {
    param(
        [switch] $Debug
    )

    Get-USMT

    Update-Textbox "`nBeginning migration..."

    $OldComputer = $env:COMPUTERNAME

    # After connection has been verified, continue with save state

    # Get the selected profiles
    if ($SelectedProfile) {
        Update-Textbox "Profile(s) selected for save state:"
        $SelectedProfile | ForEach-Object { update-Textbox $_.UserName }
    }
    else {
        Update-Textbox "You must select a user profile." -Color 'Red'
        return
    }

    $Destination = "$($ExportLocation.Text)\$OldComputer"

    # Create destination folder
    if (!(Test-Path $Destination)) {
        try {
            New-Item $Destination -ItemType Directory -Force | Out-Null
        }
        catch {
            Update-Textbox "Error while creating migration store [$Destination]: $($_.Exception.Message)" -Color 'Yellow'
            return
        }
    }

    #Verify that the Destination folder is valid.
    if (Test-Path $Destination) {

        # If profile is a domain other than $DefaultDomain, save this info to text file

        $FullUserName = "$($Script:SelectedProfile.Domain)\$($SelectedProfile.UserName)"
        if ($SelectedProfile.Domain -ne $DefaultDomain) {
            New-Item "$Destination\DomainMigration.txt" -ItemType File -Value $FullUserName -Force | Out-Null
            Update-Textbox "Text file created with cross-domain information."
        }
        

        # Clear encryption syntax in case it's already defined.
        $EncryptionSyntax = ""

        # Create config syntax for scanstate for generated XML.
        IF (!($SelectedXMLS)) {
            # Create the scan configuration
            Update-Textbox 'Generating configuration file...'
            Set-Config
            $GeneratedConfig = """$Config"""
            $ScanStateConfig = "/i:$GeneratedConfig"
        }

        # Generate parameter for logging
        $Logs = "`"/listfiles:$Destination\FilesMigrated.log`" `"/l:$Destination\scan.log`" `"/progress:$Destination\scan_progress.log`""

        # Set parameter for whether save state is compressed
        $Uncompressed = ''


        # Create a string for all users to exclude by default
        foreach ($ExcludeProfile in $Script:DefaultExcludeProfile) {
            $ExcludeProfile = """$ExcludeProfile"""
            $UsersToExclude += "/ue:$ExcludeProfile "
        }

        # Set the EFS Syntax based on the config.
        if ($EFSHandling) {
            $EFSSyntax = "/efs:$EFSHandling"
        }


        # Overwrite existing save state, use volume shadow copy method, exclude all but the selected profile(s)
        # Get the selected profiles
        $UsersToInclude += $Script:SelectedProfile | ForEach-Object { "`"/ui:$($_.Domain)\$($_.UserName)`"" }
        $Arguments = "`"$Destination`" $ScanstateConfig /o /vsc /ue:* $UsersToExclude $UsersToInclude $EncryptionSyntax $Uncompressed $Logs $EFSSyntax $ContinueCommand "

        # Begin saving user state to new computer
        # Create a value to show in the log in order to obscure the encryption key if one was used.
        $LogArguments = $Arguments -Replace '/key:".*"', '/key:(Hidden)'

        Update-Textbox "Command used:"
        Update-Textbox "$ScanState $LogArguments" -Color 'Cyan'


        # If we're running in debug mode don't actually start the process
        if ($Debug) { return }

        Update-Textbox "Saving state of $OldComputer to $Destination..." -NoNewLine

        $Process = (Start-Process -FilePath $ScanState -ArgumentList $Arguments -WindowStyle Hidden -PassThru)
        #-Verb RunAs

        # Give the process time to start before checking for its existence
        Start-Sleep -Seconds 3

        Get-ProgressBar -Runlog "$Destination\Scan_progress.log" -ProcessID $Process.id -Tracker

        # Wait until the save state is complete
        <#
        try {
            $ScanProcess = Get-Process -Name scanstate -ErrorAction Stop
            while (-not $ScanProcess.HasExited) {
                Get-USMTProgress -Destination $Destination -ActionType 'scan'
                Start-Sleep -Milliseconds 250
            }
            
        }
        catch {
            Update-Textbox $_.Exception.Message -Color 'Red'
        }
        #>
        Update-Textbox "Complete!" -Color 'Green'

        Update-Textbox 'Results:'
        Get-USMTResults -ActionType 'scan'
    }
    ELSE {
        Update-Textbox "Error when trying to access [$Destination] Please verify that the user account running the utility has appropriate permissions to the folder.: $($_.Exception.Message)" -Color 'Yellow'
    }
}

function Restore-UserState {
    param(
        [switch] $Debug
    )

    Get-USMT

    Update-Textbox "`nBeginning migration..."
    
    # Get the location of the save state data
    $Destination = "$($ImportLocation.Text)"

    # Check that the save state data exists
    if (!(Test-Path (Get-Childitem -Path $Destination -include *.MIG -recurse).FullName)) {
        Update-Textbox "No saved state found at [$Destination]. Migration cancelled." -Color 'Red'
        return
    }

    # Set the value to continue on error if it was specified above
    $ContinueCommand = "/c"

    # Set the value for the Config file if one exists.
    $ConfigXML = (Get-Childitem -Path $Destination -include Config.xml -recurse).FullName
    if (Test-Path $ConfigXML) {
        $LoadStateConfigFile = """$ConfigXML"""
        $LoadStateConfig = "/i:$LoadStateConfigFile"
    }

    # Generate arguments for load state process
    $Logs = "`"/l:$Destination\load.log`" `"/progress:$Destination\load_progress.log`""

    # Options for creating local accounts that don't already exist on new computer
    $LocalAccountOptions = '/all'

    # Check if user to be migrated is coming from a different domain and do a cross-domain migration if so
    if ($CrossDomainMigrationGroupBox.Enabled) {
        $OldUser = "$($OldDomainTextBox.Text)\$($OldUserNameTextBox.Text)"
        $NewUser = "$($NewDomainTextBox.Text)\$($NewUserNameTextBox.Text)"

        # Make sure the user entered a new user's user name before continuing
        if ($NewUserNameTextBox.Text -eq '') {
            Update-Textbox "New user's user name must not be empty." -Color 'Red'
            return
        }

        Update-Textbox "$OldUser will be migrated as $NewUser."
        $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions `"/mu:$($OldUser):$NewUser`" $Logs $ContinueCommand /v:0"
    }
    else {
        $Arguments = "`"$Destination`" $LoadStateConfig $LocalAccountOptions $Logs $ContinueCommand /v:0"
    }

    # Begin loading user state to this computer
    # Create a value in order to obscure the encryption key if one was specified.
    $LogArguments = $Arguments -Replace '/key:".*"', '/key:(Hidden)'
    Update-Textbox "Command used:"
    Update-Textbox "$LoadState $LogArguments" -Color 'Cyan'


    # If we're running in debug mode don't actually start the process
    if ($Debug) { return }

    Update-Textbox "Loading state of $OldComputer..." -NoNewLine

    $Process = (Start-Process -FilePath $LoadState -ArgumentList $Arguments -WindowStyle Hidden -PassThru)
    #-Verb RunAs

    # Give the process time to start before checking for its existence
    Start-Sleep -Seconds 3

    Get-ProgressBar -Runlog "$Destination\load_progress.log" -ProcessID $Process.id -Tracker
    <#
    # Wait until the load state is complete
    try {
        $LoadProcess = Get-Process -Name loadstate -ErrorAction Stop
        while (-not $LoadProcess.HasExited) {
            Get-USMTProgress
            Start-Sleep -Seconds 1
        }
    }
    catch {
        Update-Log $_.Exception.Message -Color 'Red'
    }
    #>
    Update-Textbox 'Results:'
    Get-USMTResults -ActionType 'load'

    # Sometimes loadstate will kill the explorer task and it needs to be start again manually
    if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
        Update-Textbox 'Restarting Explorer process.'
        Start-Process explorer
    }

    if ($USMTLoadState.ExitCode -eq 0) {
        Update-Textbox "Complete!" -Color 'Green'

        <#
        # Delete the save state data
        try {
            #Get-ChildItem $MigrationStorePath | Remove-Item -Recurse
            Update-Textbox 'Successfully removed old save state data.'
        }
        catch {
            Update-Textbox 'There was an issue when trying to remove old save state data.'
        }
        #>
    }
    else {
        Update-Textbox 'There was an issue during the loadstate process, please review the results. The state data was not deleted.'
    }
}

function Invoke-USMT {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceComputer,
        [pscredential]$Credential
    )
    
    begin {
        #Test source and destination computers are online
        if (!(Test-Connection -ComputerName $SourceComputer -Count 2)) {
            Update-TextBox "Count not ping $SourceComputer" -color 'Red'
            Return
        }
    }
    
    process {
        #Copy USMT files to remote computers
        Try {
            Get-USMT
            if (!(Test-Path "USMT:\usmtfiles")) {
                New-Item -ItemType Directory -Path "USMT:\usmtfiles"# | Out-Null
            }
            Copy-Item -Path $USMTPath -Destination "USMT:\usmtfiles\" -ErrorAction Stop -Recurse -force
        }
        Catch {
            Update-Textbox "Failed to copy $USMTPath to $SourceComputer" -color 'Red'
            Return
        }

        #Enable CredSSP
        if (!((get-service -name WinRM).status -eq 'Running')) {
            start-service -name WinRM
        }
        Enable-WSManCredSSP -Role client -DelegateComputer $SourceComputer -Force
        
        try {
            Invoke-Command -ComputerName $SourceComputer -ErrorAction stop -Credential $Credential -ScriptBlock { Enable-WSManCredSSP -Role server -Force }
        }
        catch {
            if ((get-item wsman:\localhost\client\trustedhosts).value -eq '') {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Value $SourceComputer -force
            }
            else {
                Set-Item WSMan:\localhost\Client\TrustedHosts -Concatenate -Value $SourceComputer -force
            }
            Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBlock { Enable-WSManCredSSP -Role server -Force } 
        }
        
        #Start scanstate on source
        if (!(Test-Path "USMT:\usmtfiles\$SourceComputer")) {
            New-Item -ItemType Directory -Path "USMT:\usmtfiles\$SourceComputer" | Out-Null
        }
        Invoke-Command -ComputerName $SourceComputer -Authentication Credssp -Credential $Credential -Scriptblock {
            &C:\usmtfiles\$using:bit\scanstate.exe "C:\usmtfiles\$using:SourceComputer" /i:c:\usmtfiles\$using:bit\migdocs.xml /i:c:\usmtfiles\$using:bit\migapp.xml /v:13 /uel:90 /c /localonly /listfiles:c:\usmtfiles\$using:SourceComputer\listfiles.txt /l:c:\usmtfiles\$using:SourceComputer\scan.txt /progress:c:\usmtfiles\$using:SourceComputer\scan_progress.txt
        } -asjob

        # Give the process time to start before checking for its existence
        Start-Sleep -Seconds 3
        Get-USMTProgress -ActionType "NetworkScan"

        #Copy Backup to local machine
        $Destination = "$ScriptPath\$SourceComputer"
        if (!(Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination | Out-Null
        }
        Copy-Item -Path "USMT:\usmtfiles\$SourceComputer" -Destination $Destination -ErrorAction Stop -Recurse -force

        #Start loadscan on destination
        # Get the location of the save state data
        $LocalAccountOptions = '/all'
        $Logs = "`"/l:$Destination\load.txt`" `"/progress:$Destination\load_progress.txt`""
        $ContinueCommand = "/c"
        $Arguments = "`"$Destination`" i:c:\usmtfiles\migdocs.xml /i:c:\usmtfiles\migapp.xml $LocalAccountOptions $Logs $ContinueCommand /v:13"
        $Process = (Start-Process -FilePath $LoadState -ArgumentList $Arguments -WindowStyle Hidden -PassThru)

        Get-USMTProgress -Runlog "$Destination\load_progress.txt" -processID $Process.ID -ActionType "LoadState"
        #
        <#
        
        Invoke-Command -ComputerName $DestinationComputer -Authentication Credssp -Credential $Credential -Scriptblock {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Using:SecureKey)
            $Key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            c:\USMTFiles\loadstate.exe "$Using:SharePath\$Using:Username" /i:c:\usmtfiles\printers.xml /i:c:\usmtfiles\custom.xml /i:c:\usmtfiles\migdocs.xml /i:c:\usmtfiles\migapp.xml /v:13 /ui:$Using:Domain\$Using:username /c /decrypt /key:$Key
        } -ArgumentList { $UserName, $SharePath, $SecureKey, $DestinationComputer, $Domain }
#>
        #Remove USMT files on remote computers
        #Remove-Item \\$SourceComputer\C$\USMTFiles -Force -Recurse
        #Remove-Item \\$DestinationComputer\C$\USMTFiles -Force -Recurse

        #Disable CredSSP on remote computers
        Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBlock { Disable-WSManCredSSP -Role server }
        Disable-WSManCredSSP -Role client        
    }
}

function Test-ComputerConnection {
    param(
        [System.Windows.Forms.TextBox] $ComputerNameTextBox,

        [System.Windows.Forms.TextBox] $ComputerIPTextBox,

        [System.Windows.Forms.CheckBox] $ConnectionCheckBox
    )

    $ConnectionCheckBox.Checked = $false
    $UNCVerified.Checked = $false

    # Try and use the IP if the user filled that out, otherwise use the name
    if ($ComputerIPTextBox.Text -ne '') {
        $Computer = $ComputerIPTextBox.Text
        # Try to update the computer's name with its IP address
        if ($ComputerNameTextBox.Text -eq '') {
            try {
                Update-Textbox 'Computer name is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
                $HostName = ([System.Net.Dns]::GetHostEntry($Computer)).HostName
                $ComputerNameTextBox.Text = $HostName
                Update-Textbox "Computer name set to $HostName."
            }
            catch {
                Update-Textbox "Unable to resolve host name from IP address, you'll need to manually set this." -Color 'Red'
                return
            }
        }
    }
    elseif ($ComputerNameTextBox.Text -ne '') {
        $Computer = $ComputerNameTextBox.Text
        # Try to update the computer's IP address using its DNS name
        try {
            Update-Textbox 'Computer IP address is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
            # Get the first IP address found, which is usually the primary adapter
            $IPAddress = ([System.Net.Dns]::GetHostEntry($Computer)).AddressList.IPAddressToString.Split('.', 1)[0]

            # Set IP address in text box
            $ComputerIPTextBox.Text = $IPAddress
            Update-Textbox "Computer IP address set to $IPAddress."
        }
        catch {
            Update-Textbox "Unable to resolve IP address from host name, you'll need to manually set this." -Color 'Red'
            return
        }
    }
    else {
        $Computer = $null
    }

    # Don't even try if both fields are empty
    if ($Computer) {
        <#
        # If the computer doesn't appear to have a valid office IP, such as if it's on VPN, don't allow the user to continue
        if ($ComputerIPTextBox.Text -notlike $ValidIPAddress) {
            Update-Textbox "$IPAddress does not appear to be a valid IP address. The Migration Tool requires an IP address matching $ValidIPAddress." -Color 'Red'
            return
        }
        #>
        Update-Textbox "Testing connection to $Computer..." -NoNewLine

        if (Test-Connection $Computer -Quiet) {
            $ConnectionCheckBox.Checked = $true
            Update-Textbox "Connection established." -Color 'Green'
        }
        else {
            Update-Textbox "Unable to reach $Computer." -Color 'Red'
            if ($ComputerIPTextBox.Text -eq '') {
                Update-Textbox "Try entering $Computer's IP address." -Color 'Yellow'
            }
        }
    }
    else {
        Update-Textbox "Enter the computer's name or IP address."  -Color 'Red'
    }

    if ($ConnectionCheckBox.Checked) {
        Update-Textbox "Testing UNC path to $Computer..." -NoNewLine
        $Script:Creds = Get-Credential
        new-psdrive -name "USMT" -PSProvider "FileSystem" -Root "\\$Computer\C$" -Credential $Creds -scope global
        if (Test-Path -Path "USMT:") {
            $UNCVerified.Checked = $true
            Update-Textbox "Connection established." -Color 'Green'
        }
        else {
            Update-Textbox "Unable to reach $Computer." -Color 'Red'
        }
    }
}

function Get-USMT {
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        $Script:bit = "amd64"
    }
    else {
        $Script:bit = "x86"
    }
    # Test that USMT binaries are reachable
    $Script:USMTPath = "$ScriptPath\User State Migration Tool\$bit"
    if ((Test-Path $USMTPath\scanstate.exe) -and (Test-Path $USMTPath\loadstate.exe)) {
        $Script:ScanState = "$USMTPath\scanstate.exe"
        $Script:LoadState = "$USMTPath\loadstate.exe"
        update-Textbox "Using [$USMTPath] as path to USMT binaries."
    }
    else {
        Update-Textbox "USMT not on local machine. Downloading binaries."
        Get-Files -Source "$DownloadHost/AutoMate/Tools/User_State_Migration_Tool.zip" -Destination "$ScriptPath\User_State_migration_Tool.zip" -NumberOfFiles 1 -Software "User State Migration Tool"
        Start-Extract -File "$ScriptPath\User_State_migration_Tool.zip" -ExtractTo $ScriptPath
        Remove-Item -Path "$ScriptPath\User_State_migration_Tool.zip" -Recurse
        $Script:ScanState = "$USMTPath\scanstate.exe"
        $Script:LoadState = "$USMTPath\loadstate.exe"
    }
}

function Get-USMTProgress {
    param(
        [String] $Runlog,
        [String] $ProcessID,
        [string] $ActionType
    )

    if ($Lastline) {
        Clear-Variable -name LastLine
    }
    if ($Promptcheck) {
        Clear-Variable -name Promptcheck
    }
    if ($CurrentFile.visible -eq $false) {
        $CurrentFile.Value = 0
        $CurrentFile.Visible = $true
    }
    if ($ActionType = 'NetworkScan') {
        while (Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBLock { Get-process scanstate -ErrorAction SilentlyContinue }) {
        
            if (!($Promptcheck)) {
                foreach ($line in ($lines = (Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBLock { get-content "C:\usmtfiles\$using:SourceComputer\scan_progress.txt" -ErrorAction SilentlyContinue }))) {
                    if (!($promptcheck -contains $line)) {
                        if ($line -match '\d{2}\s[a-zA-Z]+\s\d{4}\,\s\d{2}\:\d{2}\:\d{2}') {
                            $line = ($Line.Split(',', 4)[3]).TrimStart()
                        }
                        Update-USMTTextBox -Text $Line
                    }
                }
                $Promptcheck = $Lines
            } 
            start-sleep -Milliseconds 50
        }
    }
    if ($ActionType = 'LoadState') {
        while (get-process -id $ProcessID -ErrorAction SilentlyContinue) {
            if (!($Promptcheck)) {
                foreach ($line in ($lines = get-content $RunLog)){
                    if (!($promptcheck -contains $line)) {
                        if ($line -match '\d{2}\s[a-zA-Z]+\s\d{4}\,\s\d{2}\:\d{2}\:\d{2}') {
                            $line = ($Line.Split(',', 4)[3]).TrimStart()
                        }
                        Update-USMTTextBox -Text $Line
                    }
                }
                $Promptcheck = $Lines
            } 
            start-sleep -Milliseconds 50
        }
    }
    
    if ($CurrentFile.Visible -eq $true) {
        $CurrentFile.Visible = $false
    }
    if ($TotalProgress.Visible -eq $true) {
        $TotalProgress.Visible = $false
    }
}
function Update-USMTTextBox {
    Param (
        [string] $Text
    )
    if (!($null -eq $Text) -and $Text.TrimEnd() -ne '.') {
        if ($Text.TrimEnd() -match '([\d]+)\.\d\%') {
            $CurrentFile.Value = $matches[1]
        }
        elseif ($Text.TrimEnd() -match 'totalPercentageCompleted. ([\d]+)') {
            $CurrentFile.Value = $matches[1]
        }
        elseif ($Text.TrimEnd() -match 'Progress.+\s([\d]+)\%') {
            $CurrentFile.Value = $matches[1]
        }
        elseif ($Text.TrimEnd() -match 'UnableToOpen') {
            Update-Textbox $Text.TrimEnd() -color 'Orange'
            Update-Textbox ''
        }
        elseif ($Text.TrimEnd() -match 'successful' -or $Text.TrimEnd() -match 'completed' -or $Text.TrimEnd() -match 'installed') {
            Update-Textbox $Text.TrimEnd() -color 'Green'
        }
        elseif ($Text.TrimEnd() -match 'ERROR' -or $Text.TrimEnd() -match 'not successful') {
            Update-Textbox $Text.TrimEnd() -Color 'Red'
        }
        elseif ($Text.TrimEnd() -match 'WARNING') {
            Update-Textbox $Text.TrimEnd() -Color 'Yellow'
        }
        elseif ($Text.TrimEnd() -match 'Waiting') {
            if (!($wait)) {
                $Wait = $true
                update-Textbox $Text.TrimEnd()
            }
        }
        else {
            $Wait = $false
            Update-Textbox $Text.TrimEnd()
        }
    }
}

function Get-USMTResults {
    param([string] $ActionType)

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        # Print back the entire log
        $Results = Get-Content "$Destination\$ActionType.log" | Out-String
    }
    else {
        # Get the last 4 lines from the log so we can see the results
        $Results = Get-Content "$Destination\$ActionType.log" -Tail 4 | ForEach-Object {
            ($_.Split(']', 2)[1]).TrimStart()
        } | Out-String
    }

    Update-Textbox $Results -Color 'Cyan'

    if ($ActionType -eq 'load') {
        Update-Textbox 'A reboot is recommended.' -Color 'Yellow'
    }
}

function Get-UserProfiles {
    # Get all user profiles on this PC and let the user select which ones to migrate
    $RegKey = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    # Return each profile on this computer
    Get-ItemProperty -Path $RegKey | ForEach-Object {
        try {
            $SID = New-object System.Security.Principal.SecurityIdentifier($_.PSChildName)
            try {

                $User = $SID.Translate([System.Security.Principal.NTAccount]).Value

                # Don't show NT Authority accounts
                if ($User -notlike 'NT Authority\*') {
                    $Domain = $User.Split('\')[0]
                    $UserName = $User.Split('\')[1]
                    if ($Script:QueryLastLogon) {
                        $LastLogin = Get-UserProfileLastLogin -Domain $Domain -UserName $UserName
                    }
                    else {
                        $LastLogin = 'N/A'
                    }
                    $ProfilePath = Get-UserProfilePath -Domain $Domain -UserName $UserName

                    # Create and return a custom object for each user found
                    $UserObject = New-Object psobject
                    $UserObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain
                    $UserObject | Add-Member -MemberType NoteProperty -Name UserName -Value $UserName
                    $UserObject | Add-Member -MemberType NoteProperty -Name LastLogin -Value $LastLogin
                    $UserObject | Add-Member -MemberType NoteProperty -Name ProfilePath -Value $ProfilePath
                    $UserObject
                }
            }
            catch {
                #$Script:UpdateText = "Error while translating $SID to a user name."
                #update-Textbox "Error while translating $SID to a user name." -color 'Yellow'
            }
        }
        catch {
            #$Script:UpdateText = "Error while translating $($_.PSChildName) to SID."
            #update-Textbox "Error while translating $($_.PSChildName) to SID." -color 'Yellow'
        }
    }
}

function Get-UserProfilePath {
    param(
        [string]$Domain,
        [string]$UserName
    )

    $UserObject = New-Object System.Security.Principal.NTAccount($Domain, $UserName)
    $SID = $UserObject.Translate([System.Security.Principal.SecurityIdentifier])
    $User = Get-ItemProperty -Path "Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\$($SID.Value)"
    $User.ProfileImagePath
}

function Add-ExtraDirectory {
    # Bring up file explorer so user can select a directory to add
    $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
    $OpenDirectoryDialog.RootFolder = 'Desktop'
    $OpenDirectoryDialog.SelectedPath = 'C:\'
    $Result = $OpenDirectoryDialog.ShowDialog()
    $Script:SelectedDirectory = $OpenDirectoryDialog.SelectedPath
    try {
        # If user hits cancel don't add the path
        if ($Result -eq 'OK') {
            #$Script:UpdateText = "Adding to extra directories: $SelectedDirectory."
            update-Textbox "Adding to extra directories: $SelectedDirectory."
            $ExtraDataGridView.Rows.Add($SelectedDirectory)
        }
        else {
            #$Script:UpdateText = "Add directory action cancelled by user."
            update-Textbox "Add directory action cancelled by user."
        }
    }
    catch {
        #$Script:UpdateText = "There was a problem with the directory you chose: $($_.Exception.Message)"
        update-Textbox "There was a problem with the directory you chose: $($_.Exception.Message)"
    }
}

function Remove-ExtraDirectory {
    # Remove selected cell from Extra Directories data grid view
    $CurrentCell = $ExtraDataGridView.CurrentCell
    #$Script:UpdateText = "Removed [$($CurrentCell.Value)] from extra directories."
    update-Textbox "Removed [$($CurrentCell.Value)] from extra directories."
    $CurrentRow = $ExtraDataGridView.Rows[$CurrentCell.RowIndex]
    $ExtraDataGridView.Rows.Remove($CurrentRow)
}

function Set-SaveDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Destination', 'Source')]
        [string] $Type
    )

    # Bring up file explorer so user can select a directory to add
    $OpenDirectoryDialog = New-Object Windows.Forms.FolderBrowserDialog
    $OpenDirectoryDialog.RootFolder = 'Desktop'
    $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
    if ($Type -eq 'Destination') {
        $OpenDirectoryDialog.SelectedPath = $SaveDestinationTextBox.Text
    }
    else {
        $OpenDirectoryDialog.SelectedPath = $SaveSourceTextBox.Text
    }
    $OpenDirectoryDialog.ShowDialog() | Out-Null
    $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
    try {
        # If user hits cancel it could cause attempt to add null path, so check that there's something there
        if ($SelectedDirectory) {
            update-Textbox "Changed save directory to [$SelectedDirectory]."
            if ($Type -eq 'Destination') {
                $ExportLocation.Text = $SelectedDirectory
            }
            else {
                $ImportLocation.Text = $SelectedDirectory
            }
        }
    }
    catch {
        update-Textbox "There was a problem with the directory you chose: $($_.Exception.Message)" -Color Red
    }
}

function Set-Config {
    $ExtraDirectoryCount = $ExtraDataGridView.RowCount

    if ($ExtraDirectoryCount) {
        update-Textbox "Including $ExtraDirectoryCount extra directories."

        $ExtraDirectoryXML = @"
<!-- This component includes the additional directories selected by the user -->
<component type="Documents" context="System">
    <displayName>Additional Folders</displayName>
    <role role="Data">
        <rules>
            <include>
                <objectSet>

"@
        # Include each directory user has added to the Extra Directories data grid view
        $ExtraDataGridView.Rows | ForEach-Object {
            $CurrentRowIndex = $_.Index
            $Path = $ExtraDataGridView.Item(0, $CurrentRowIndex).Value

            $ExtraDirectoryXML += @"
                    <pattern type=`"File`">$Path\* [*]</pattern>"

"@
        }

        $ExtraDirectoryXML += @"
                </objectSet>
            </include>
        </rules>
    </role>
</component>
"@
    }
    else {
        update-Textbox 'No extra directories will be included.'
    }

    update-Textbox 'Data to be included:'
    $Include = @()
    $Exclude = @()
    foreach ($Control in $USMTCheckList.Items) {
        if ($USMTCheckList.checkeditems.Contains(($Control))) {
            $Include += $control
            update-Textbox $Control
        }
        else {
            $Exclude += $Control
        }
    }
    Update-Textbox "Include array $Include"
    Update-Textbox "Exclude array $Exclude"

    $ExcludedDataXML = @"
        $(
            if ($Exclude -Contains 'Printers') { "<pattern type=`"File`">%CSIDL_PRINTERS%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'Recycle Bin') { "<pattern type=`"File`">%CSIDL_BITBUCKET%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Documents') {
                "<pattern type=`"File`">%CSIDL_MYDOCUMENTS%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_PERSONAL%\* [*]</pattern>`n"
            }
            if ($Exclude -Contains 'Desktop') {
                "<pattern type=`"File`">%CSIDL_DESKTOP%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_DESKTOPDIRECTORY%\* [*]</pattern>`n"
            }
            if ($Exclude -Contains 'Downloads') { "<pattern type=`"File`">%CSIDL_DOWNLOADS%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'Favorites') { "<pattern type=`"File`">%CSIDL_FAVORITES%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Music') { "<pattern type=`"File`">%CSIDL_MYMUSIC%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Pictures') { "<pattern type=`"File`">%CSIDL_MYPICTURES%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Video') { "<pattern type=`"File`">%CSIDL_MYVIDEO%\* [*]</pattern>`n" }
        )
"@

    $AppDataXML = if ($Include -Contains 'AppData') {
        @"
        <!-- This component migrates all user app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>App Data</displayName>
            <paths>
                <path type="File">%CSIDL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $LocalAppDataXML = if ($Include -Contains 'Local AppData') {
        @"
        <!-- This component migrates all user local app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>Local App Data</displayName>
            <paths>
                <path type="File">%CSIDL_LOCAL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_LOCAL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $WallpapersXML = if ($Include -Contains 'Wallpapers') {
        @"
        <!-- This component migrates wallpaper settings -->
        <component type="System" context="User">
            <displayName>Wallpapers</displayName>
            <role role="Settings">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [Pattern]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [PatternUpgrade]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallpaperStyle]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Windows\CurrentVersion\Themes [SetupVersion]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperLocalFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperStyle]</pattern>
                            <content filter="MigXmlHelper.ExtractSingleFile(NULL, NULL)">
                                <objectSet>
                                    <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                                </objectSet>
                            </content>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>

        <!-- This component migrates wallpaper files -->
        <component type="Documents" context="System">
            <displayName>Move JPG and BMP</displayName>
            <role role="Data">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="File"> %windir% [*.bmp]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.jpg]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.bmp]</pattern>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>
"@
    }

    $ConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<migration urlid="http://www.microsoft.com/migration/1.0/migxmlext/config">
<_locDefinition>
    <_locDefault _loc="locNone"/>
    <_locTag _loc="locData">displayName</_locTag>
</_locDefinition>

$ExtraDirectoryXML

<!-- This component migrates all user data except specified exclusions -->
<component type="Documents" context="User">
    <displayName>Documents</displayName>
    <role role="Data">
        <rules>
            <include filter="MigXmlHelper.IgnoreIrrelevantLinks()">
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","TRUE","FALSE")</script>
                </objectSet>
            </include>
            <exclude filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","FALSE","FALSE")</script>
                </objectSet>
            </exclude>
            <exclude>
                <objectSet>
$ExcludedDataXML
                </objectSet>
            </exclude>
            <contentModify script="MigXmlHelper.MergeShellLibraries('TRUE','TRUE')">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </contentModify>
            <merge script="MigXmlHelper.SourcePriority()">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </merge>
        </rules>
    </role>
</component>

$AppDataXML

$LocalAppDataXML

$WallpapersXML

</migration>
"@

    $Script:Config = "$Destination\Config.xml"
    try {
        New-Item $Config -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        update-Textbox "Error creating config file [$Config]: $($_.Exception.Message)" -Color 'Red'
        return
    }
    try {
        Set-Content $Config $ConfigContent -ErrorAction Stop
    }
    catch {
        update-Textbox "Error while setting config file content: $($_.Exception.Message)" -Color 'Red'
        return
    }

    # Return the path to the config
    #$Config
}
function Set-NetworkConfig {
    $ExtraDirectoryCount = $ExtraDataGridView.RowCount

    if ($ExtraDirectoryCount) {
        update-Textbox "Including $ExtraDirectoryCount extra directories."

        $ExtraDirectoryXML = @"
<!-- This component includes the additional directories selected by the user -->
<component type="Documents" context="System">
    <displayName>Additional Folders</displayName>
    <role role="Data">
        <rules>
            <include>
                <objectSet>

"@
        # Include each directory user has added to the Extra Directories data grid view
        $ExtraDataGridView.Rows | ForEach-Object {
            $CurrentRowIndex = $_.Index
            $Path = $ExtraDataGridView.Item(0, $CurrentRowIndex).Value

            $ExtraDirectoryXML += @"
                    <pattern type=`"File`">$Path\* [*]</pattern>"

"@
        }

        $ExtraDirectoryXML += @"
                </objectSet>
            </include>
        </rules>
    </role>
</component>
"@
    }
    else {
        update-Textbox 'No extra directories will be included.'
    }

    update-Textbox 'Data to be included:'
    $Include = @()
    $Exclude = @()
    foreach ($Control in $USMTCheckList.Items) {
        if ($USMTCheckList.checkeditems.Contains(($Control))) {
            $Include += $control
            update-Textbox $Control
        }
        else {
            $Exclude += $Control
        }
    }
    Update-Textbox "Include array $Include"
    Update-Textbox "Exclude array $Exclude"

    $ExcludedDataXML = @"
        $(
            if ($Exclude -Contains 'Printers') { "<pattern type=`"File`">%CSIDL_PRINTERS%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'Recycle Bin') { "<pattern type=`"File`">%CSIDL_BITBUCKET%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Documents') {
                "<pattern type=`"File`">%CSIDL_MYDOCUMENTS%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_PERSONAL%\* [*]</pattern>`n"
            }
            if ($Exclude -Contains 'Desktop') {
                "<pattern type=`"File`">%CSIDL_DESKTOP%\* [*]</pattern>`n"
                "<pattern type=`"File`">%CSIDL_DESKTOPDIRECTORY%\* [*]</pattern>`n"
            }
            if ($Exclude -Contains 'Downloads') { "<pattern type=`"File`">%CSIDL_DOWNLOADS%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'Favorites') { "<pattern type=`"File`">%CSIDL_FAVORITES%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Music') { "<pattern type=`"File`">%CSIDL_MYMUSIC%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Pictures') { "<pattern type=`"File`">%CSIDL_MYPICTURES%\* [*]</pattern>`n" }
            if ($Exclude -Contains 'My Video') { "<pattern type=`"File`">%CSIDL_MYVIDEO%\* [*]</pattern>`n" }
        )
"@

    $AppDataXML = if ($Include -Contains 'AppData') {
        @"
        <!-- This component migrates all user app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>App Data</displayName>
            <paths>
                <path type="File">%CSIDL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $LocalAppDataXML = if ($Include -Contains 'Local AppData') {
        @"
        <!-- This component migrates all user local app data -->
        <component type=`"Documents`" context=`"User`">
            <displayName>Local App Data</displayName>
            <paths>
                <path type="File">%CSIDL_LOCAL_APPDATA%</path>
            </paths>
            <role role="Data">
                <detects>
                    <detect>
                        <condition>MigXmlHelper.DoesObjectExist("File","%CSIDL_LOCAL_APPDATA%")</condition>
                    </detect>
                </detects>
                <rules>
                    <include filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </include>
                    <merge script='MigXmlHelper.DestinationPriority()'>
                        <objectSet>
                            <pattern type="File">%CSIDL_LOCAL_APPDATA%\* [*]</pattern>
                        </objectSet>
                    </merge>
                </rules>
            </role>
        </component>
"@
    }

    $WallpapersXML = if ($Include -Contains 'Wallpapers') {
        @"
        <!-- This component migrates wallpaper settings -->
        <component type="System" context="User">
            <displayName>Wallpapers</displayName>
            <role role="Settings">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [Pattern]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [PatternUpgrade]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                            <pattern type="Registry">HKCU\Control Panel\Desktop [WallpaperStyle]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Windows\CurrentVersion\Themes [SetupVersion]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [TileWallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperLocalFileTime]</pattern>
                            <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [WallpaperStyle]</pattern>
                            <content filter="MigXmlHelper.ExtractSingleFile(NULL, NULL)">
                                <objectSet>
                                    <pattern type="Registry">HKCU\Control Panel\Desktop [WallPaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [BackupWallpaper]</pattern>
                                    <pattern type="Registry">HKCU\Software\Microsoft\Internet Explorer\Desktop\General [Wallpaper]</pattern>
                                </objectSet>
                            </content>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>

        <!-- This component migrates wallpaper files -->
        <component type="Documents" context="System">
            <displayName>Move JPG and BMP</displayName>
            <role role="Data">
                <rules>
                    <include>
                        <objectSet>
                            <pattern type="File"> %windir% [*.bmp]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.jpg]</pattern>
                            <pattern type="File"> %windir%\web\wallpaper [*.bmp]</pattern>
                        </objectSet>
                    </include>
                </rules>
            </role>
        </component>
"@
    }

    $ConfigContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<migration urlid="http://www.microsoft.com/migration/1.0/migxmlext/config">
<_locDefinition>
    <_locDefault _loc="locNone"/>
    <_locTag _loc="locData">displayName</_locTag>
</_locDefinition>

$ExtraDirectoryXML

<!-- This component migrates all user data except specified exclusions -->
<component type="Documents" context="User">
    <displayName>Documents</displayName>
    <role role="Data">
        <rules>
            <include filter="MigXmlHelper.IgnoreIrrelevantLinks()">
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","TRUE","FALSE")</script>
                </objectSet>
            </include>
            <exclude filter='MigXmlHelper.IgnoreIrrelevantLinks()'>
                <objectSet>
                    <script>MigXmlHelper.GenerateDocPatterns ("FALSE","FALSE","FALSE")</script>
                </objectSet>
            </exclude>
            <exclude>
                <objectSet>
$ExcludedDataXML
                </objectSet>
            </exclude>
            <contentModify script="MigXmlHelper.MergeShellLibraries('TRUE','TRUE')">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </contentModify>
            <merge script="MigXmlHelper.SourcePriority()">
                <objectSet>
                    <pattern type="File">*[*.library-ms]</pattern>
                </objectSet>
            </merge>
        </rules>
    </role>
</component>

$AppDataXML

$LocalAppDataXML

$WallpapersXML

</migration>
"@

    $Script:Config = "$Destination\Config.xml"
    try {
        New-Item $Config -ItemType File -Force -ErrorAction Stop | Out-Null
    }
    catch {
        update-Textbox "Error creating config file [$Config]: $($_.Exception.Message)" -Color 'Red'
        return
    }
    try {
        Set-Content $Config $ConfigContent -ErrorAction Stop
    }
    catch {
        update-Textbox "Error while setting config file content: $($_.Exception.Message)" -Color 'Red'
        return
    }

    # Return the path to the config
    #$Config
}