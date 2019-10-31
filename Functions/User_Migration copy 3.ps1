#USMT Functions

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

        $FullUserName = "$($SelectedProfile.Domain)\$($SelectedProfile.UserName)"
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
            $Config = Set-Config
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

        Update-Log "Saving state of $OldComputer to $Destination..." -NoNewLine
        $RunLog = "$ScriptPath\logs\USMT_ScanState.txt"
        $Process = (Start-Process -FilePath $ScanState -ArgumentList $Arguments -WindowStyle Hidden -PassThru)
        start-sleep -Seconds 1
        Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID
        


        <#
        # Give the process time to start before checking for its existence
        Start-Sleep -Seconds 3

        # Wait until the save state is complete
        try {
            $ScanProcess = Get-Process -Name scanstate -ErrorAction Stop
            while (-not $ScanProcess.HasExited) {
                Get-USMTProgress
                Start-Sleep -Seconds 3
            }
            Update-Log "Complete!" -Color 'Green'

            Update-Log 'Results:'
            Get-USMTResults -ActionType 'scan'
        }
        catch {
            Update-Log $_.Exception.Message -Color 'Red'
        }
        #>
    }
    ELSE {
        Update-Textbox "Error when trying to access [$Destination] Please verify that the user account running the utility has appropriate permissions to the folder.: $($_.Exception.Message)" -Color 'Yellow'
    }
}

function Get-USMT {
    if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
        $bit = "amd64"
    }
    else {
        $bit = "x86"
    }
    # Test that USMT binaries are reachable
    $USMTPath = "$ScriptPath\User State Migration Tool\$bit"
    if ((Test-Path $USMTPath\scanstate.exe) -and (Test-Path $USMTPath\loadstate.exe)) {
        $Script:ScanState = "$USMTPath\scanstate.exe"
        $Script:LoadState = "$USMTPath\loadstate.exe"
        update-Textbox "Using [$USMTPath] as path to USMT binaries."
    }
    else {
        Update-Textbox "USMT not on local machine. Downloading binaries."
        Get-Files -Source "$DownloadHost/AutoMate/Tools/User_State_Migration_Tool.zip" -Destination "$ScriptPath\User_State_migration_Tool.zip" -NumberOfFiles 1 -Software "USMT"

        Start-Extract -file "$ScriptPath\User_State_migration_Tool.zip" -ExtractTo $ScriptPath

        Start-CleanUp -File "$ScriptPath\User_State_migration_Tool.zip"

        $Script:ScanState = "$USMTPath\scanstate.exe"
        $Script:LoadState = "$USMTPath\loadstate.exe"
        update-Textbox "Using [$USMTPath] as path to USMT binaries."
    }
}

function Get-USMTProgress {
    param(
        [string] $Destination,

        [string] $ActionType
    )

    try {
        # Get the most recent entry in the progress log
        $LastLine = Get-Content "$Destination\$($ActionType)_progress.log" -Tail 1 -ErrorAction SilentlyContinue | Out-String
        if ((($LastLine.Split(',', 4)[3]).TrimStart()) -ne $Promptcheck) {
            Update-Textbox ($LastLine.Split(',', 4)[3]).TrimStart()
            $Script:Promptcheck = ($LastLine.Split(',', 4)[3]).TrimStart()
        }
    }
    catch { Update-Textbox '.' -NoNewLine }
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

function Select-Profiles {
    $Script:SelectedProfile = Get-UserProfiles | Out-GridView -Title 'Profile Selection' -OutputMode Multiple
    update-Textbox "Profile(s) selected for migration:"
    $SelectedProfile | ForEach-Object { 
        update-Textbox "$($_.UserName)"
    }
}

function Get-UserProfiles {
    # Get all user profiles on this PC and let the user select which ones to migrate
    $RegKey = 'Registry::HKey_Local_Machine\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*'

    # Return each profile on this computer
    Get-ItemProperty -Path $RegKey | ForEach-Object {
        try {
            $SID = New-object System.Security.Principal.SecurityIdentifier($_.PSChildName) -ErrorAction stop
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
                #update-Textbox "Error while translating $SID to a user name." -color 'Yellow'
            }
        }
        catch {
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
    $SelectedDirectory = $OpenDirectoryDialog.SelectedPath
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
                $SaveSourceTextBox.Text = $SelectedDirectory
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

    $Config = "$Destination\Config.xml"
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
    $Config
}