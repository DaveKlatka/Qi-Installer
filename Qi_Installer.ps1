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
            Install-Chocolatey
            #$process = (start-process powershell -ArgumentList "Invoke-Expression Install-Chocolatey" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            #Start-Sleep -Seconds 1
            #Get-ProgressBar -RunLog $RunLog -ProcessID $Process.ID
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
                foreach ($line in ($lines = ([xml](get-content $RunLog)).logentries.logentry.message)) {
                    if (!($promptcheck -contains $line)) {
                        Update-ProgressTextBox -Text $line
                    }
                }
                $Promptcheck = $lines
                start-sleep -Milliseconds 500 
            }
            else {
                foreach ($line in ($lines = get-content $RunLog)) {
                    if (!($promptcheck -contains $line)) {
                        Update-ProgressTextBox -Text $line
                    }
                } 
                $Promptcheck = $lines
                start-sleep -Milliseconds 500
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
                foreach ($line in ($lines = ([xml](get-content $RunLog -ErrorAction SilentlyContinue)).logentries.logentry.message)) {
                    if (!($promptcheck -contains $line)) {
                        Update-ProgressTextBox -Text $line -Tracker
                    }
                }
                $Promptcheck = $lines
                start-sleep -Milliseconds 500
            }
            else {
                foreach ($line in ($lines = get-content $RunLog -ErrorAction SilentlyContinue)) {
                    if ($line -match 'password is incorrect') {
                        return
                    }
                    if (!($promptcheck -contains $line)) {
                        Update-ProgressTextBox -Text $line -Tracker
                    }
                }
                $Promptcheck = $lines
                start-sleep -Milliseconds 500
            }
        }
        if ($CurrentFile.Visible -eq $true) {
            $CurrentFile.Visible = $false
        }
        if ($TotalProgress.Visible -eq $true) {
            $TotalProgress.Visible = $false
        }
    }  
}
function Update-ProgressTextBox {
    Param (
        [string] $Text,
        [switch] $Tracker
    )
    if (-not $Tracker) {
        if (!($null -eq $Text) -and $Text.TrimEnd() -ne '.') {
            if ($Text.TrimEnd() -match 'ERROR' -or $Text.TrimEnd() -match 'not successful') {
                Update-Textbox $Text.TrimEnd() -Color 'Red'
            }
            elseif ($Text.TrimEnd() -match 'WARNING') {
                Update-Textbox $Text.TrimEnd() -Color 'Yellow'
            }
            elseif ($Text.TrimEnd() -match 'successful' -or $Text.TrimEnd() -match 'completed' -or $Text.TrimEnd() -match 'installed') {
                Update-Textbox $Text.TrimEnd() -color 'Green'
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
    else {
        if (!($null -eq $Text) -and $Text.TrimEnd() -ne '.') {
            if ($Text.TrimEnd() -match '([\d]+)\.\d\%') {
                $CurrentFile.Value = $matches[1]
            }
            elseif ($Text.TrimEnd() -match '([\d]+)%') {
                $CurrentFile.Value = $matches[1]
            }
            elseif ($Text.TrimEnd() -match 'totalPercentageCompleted. ([\d]+)') {
                $CurrentFile.Value = $matches[1]
            }
            elseif ($Text.TrimEnd() -match 'Progress.+\s([\d]+)\%') {
                $CurrentFile.Value = $matches[1]
            }
            elseif ($Text.TrimEnd() -match 'ERROR' -or $Text.TrimEnd() -match 'not successful') {
                Update-Textbox $Text.TrimEnd() -Color 'Red'
            }
            elseif ($Text.TrimEnd() -match 'WARNING') {
                Update-Textbox $Text.TrimEnd() -Color 'Yellow'
            }
            elseif ($Text.TrimEnd() -match 'successful' -or $Text.TrimEnd() -match 'completed' -or $Text.TrimEnd() -match 'installed') {
                Update-Textbox $Text.TrimEnd() -color 'Green'
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
        $RestorePoint = Get-ComputerRestorePoint -ErrorAction stop | Where-Object { $_.creationtime -like "$date*" -and $_.__CLASS -eq "SystemRestore" -and $_.RestorePointType -eq "12" }
        if ($null -ne $RestorePoint) {
            update-Textbox "Restore Point '$($RestorePoint.Description)' has been created" -Color 'Green'
        }
    }
}

function Connect-AutomateAPI {
    <#
    .SYNOPSIS
    Connect to the Automate API.
    .DESCRIPTION
    Connects to the Automate API and returns a bearer token which when passed with each requests grants up to an hours worth of access.
    .PARAMETER Server
    The address to your Automate Server. Example 'rancor.hostedrmm.com'
    .PARAMETER Credentials
    Takes a standard powershell credential object, this can be built with $CredentialsToPass = Get-Credential, then pass $CredentialsToPass
    .PARAMETER TwoFactorToken
    Takes a string that represents the 2FA number
    .PARAMETER AuthorizationToken
    Used internally when quietly refreshing the Token
    .PARAMETER SkipCheck
    Used internally when quietly refreshing the Token
    .PARAMETER Verify
    Specifies to test the current token, and if it is not valid attempt to obtain a new one using the current credentials. Does not refresh (re-issue) the current token.
    .PARAMETER Force
    Will not attempt to refresh a current session
    .PARAMETER Quiet
    Will not output any standard messages. Returns $True if connection was successful.
    .OUTPUTS
    Three strings into Script variables, $CWAServer containing the server address, $CWACredentials containing the bearer token and $CWACredentialsExpirationDate containing the date the credentials expire
    .NOTES
    Version:        1.1
    Author:         Gavin Stone
    Creation Date:  2019-01-20
    Purpose/Change: Initial script development
    
    Update Date:    2019-02-12
    Author:         Darren White
    Purpose/Change: Credential and 2FA prompting is only if needed. Supports Token Refresh.
    
    .EXAMPLE
    Connect-AutomateAPI -Server "rancor.hostedrmm.com" -Credentials $CredentialObject -TwoFactorToken "999999"
    
    .EXAMPLE
    Connect-AutomateAPI -Quiet
    #>
    [CmdletBinding(DefaultParameterSetName = 'refresh')]
    param (
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [System.Management.Automation.PSCredential]$Credential,
    
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [Parameter(ParameterSetName = 'refresh', Mandatory = $False)]
        [Parameter(ParameterSetName = 'verify', Mandatory = $False)]
        [String]$Server = $Script:CWAServer,
    
        [Parameter(ParameterSetName = 'refresh', Mandatory = $False)]
        [Parameter(ParameterSetName = 'verify', Mandatory = $False)]
        [String]$AuthorizationToken = ($Script:CWAToken.Authorization -replace 'Bearer ', ''),
    
        [Parameter(ParameterSetName = 'refresh', Mandatory = $False)]
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [Switch]$SkipCheck,
    
        [Parameter(ParameterSetName = 'verify', Mandatory = $False)]
        [Switch]$Verify,
    
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [String]$TwoFactorToken,
    
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [Switch]$Force,
    
        [Parameter(ParameterSetName = 'credential', Mandatory = $False)]
        [Parameter(ParameterSetName = 'refresh', Mandatory = $False)]
        [Parameter(ParameterSetName = 'verify', Mandatory = $False)]
        [Switch]$Quiet
    )
    
    Begin {
        # Check for locally stored credentials
        #        [string]$CredentialDirectory = "$($env:USERPROFILE)\AutomateAPI\"
        #        $LocalCredentialsExist = Test-Path "$($CredentialDirectory)Automate - Credentials.txt"
        If ($TwoFactorToken -match '.+') { $Force = $True }
        $TwoFactorNeeded = $False
    
        If (!$Quiet) {
            While (!($Server -match '.+')) {
                $Server = Read-Host -Prompt "Please enter your Automate Server address, IE: rancor.hostedrmm.com" 
            }
        }
        $Server = $Server -replace '^https?://', '' -replace '/[^\/]*$', ''
        $AuthorizationToken = $AuthorizationToken -replace 'Bearer ', ''
    } #End Begin
        
    Process {
        If (!($Server -match '^[a-z0-9][a-z0-9\.\-\/]*$')) { Throw "Server address ($Server) is missing or in invalid format."; Return }
        If ($SkipCheck) {
            $Script:CWAServer = ("https://" + $Server)
            If ($Credential) {
                Write-Debug "Setting Credentials to $($Credential.UserName)"
                $Script:CWAToken = $AutomateToken
            }
            If ($AuthorizationToken) {
                #Build the token
                $AutomateToken = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $Null = $AutomateToken.Add("Authorization", "Bearer $AuthorizationToken")
                Write-Debug "Setting Authorization Token to $($AutomateToken.Authorization)"
                $Script:CWAToken = $AutomateToken
            }
            Return
        }
        If (!$AuthorizationToken -and $PSCmdlet.ParameterSetName -eq 'verify') {
            Throw "Attempt to verify token failed. No token was provided or was cached."
            Return
        }
        Do {
            $AutomateAPIURI = ('https://' + $Server + '/cwa/api/v1')
            $testCredentials = $Credential
            If (!$Quiet) {
                If ($Credential) {
                    $testCredentials = $Credential
                }
                If (!$Credential -and ($Force -or !$AuthorizationToken)) {
                    If (!$Force -and $Script:CWACredentials) {
                        $testCredentials = $Script:CWACredentials
                    }
                    Else {
                        $Username = Read-Host -Prompt "Please enter your Automate Username"
                        $Password = Read-Host -Prompt "Please enter your Automate Password" -AsSecureString
                        $Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
                        $testCredentials = $Credential
                    }
                }
                If ($TwoFactorNeeded -eq $True -and $TwoFactorToken -match '') {
                    $TwoFactorToken = Read-Host -Prompt "Please enter your 2FA Token"
                }
            }
    
            If ($testCredentials) {
                #Build the headers for the Authentication
                $PostBody = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $PostBody.Add("username", $testCredentials.UserName)
                $PostBody.Add("password", $testCredentials.GetNetworkCredential().Password)
                If (!([string]::IsNullOrEmpty($TwoFactorToken))) {
                    #Remove any spaces that were added
                    $TwoFactorToken = $TwoFactorToken -replace '\s', ''
                    $PostBody.Add("TwoFactorPasscode", $TwoFactorToken)
                }
                $RESTRequest = @{
                    'URI'         = ($AutomateAPIURI + '/apitoken')
                    'Method'      = 'POST'
                    'ContentType' = 'application/json'
                    'Body'        = $($PostBody | ConvertTo-Json -Compress)
                }
            }
            ElseIf ($PSCmdlet.ParameterSetName -eq 'refresh') {
                $PostBody = $AuthorizationToken -replace 'Bearer ', ''
                $RESTRequest = @{
                    'URI'         = ($AutomateAPIURI + '/apitoken/refresh')
                    'Method'      = 'POST'
                    'ContentType' = 'application/json'
                    'Body'        = $PostBody | ConvertTo-Json -Compress
                }
            }
            ElseIf ($PSCmdlet.ParameterSetName -eq 'verify') {
                $PostBody = $AuthorizationToken -replace 'Bearer ', ''
                $RESTRequest = @{
                    'URI'         = ($AutomateAPIURI + '/DatabaseServerTime')
                    'Method'      = 'GET'
                    'ContentType' = 'application/json'
                    'Headers'     = @{'Authorization' = "Bearer $PostBody" }
                }
            }
    
            #Invoke the REST Method
            Write-Debug "Submitting Request to $($RESTRequest.URI)`nHeaders:`n$($RESTRequest.Headers|ConvertTo-JSON -Depth 5)`nBody:`n$($RESTRequest.Body|ConvertTo-JSON -Depth 5)"
            Try {
                $AutomateAPITokenResult = Invoke-RestMethod @RESTRequest
            }
            Catch {
                Remove-Variable CWAToken, CWATokenKey -Scope Script -ErrorAction 0
                If ($testCredentials) {
                    Remove-Variable CWACredentials -Scope Script -ErrorAction 0
                }
                If ($Credential) {
                    Throw "Attempt to authenticate to the Automate API has failed with error $_.Exception.Message"
                    Return
                }
            }
                
            $AuthorizationToken = $AutomateAPITokenResult.Accesstoken
            If ($PSCmdlet.ParameterSetName -eq 'verify' -and !$AuthorizationToken -and $AutomateAPITokenResult) {
                $AuthorizationToken = $Script:CWAToken.Authorization -replace 'Bearer ', ''
            }
            $TwoFactorNeeded = $AutomateAPITokenResult.IsTwoFactorRequired
        } Until ($Quiet -or ![string]::IsNullOrEmpty($AuthorizationToken) -or 
            ($TwoFactorNeeded -ne $True -and $Credential) -or 
            ($TwoFactorNeeded -eq $True -and $TwoFactorToken -ne '')
        )
    } #End Process
    
    End {
        If ($SkipCheck) {
            If ($Quiet) {
                Return $False
            }
            Else {
                Return
            }
        }
        ElseIf ([string]::IsNullOrEmpty($AuthorizationToken)) {
            Remove-Variable CWAToken -Scope Script -ErrorAction 0
            Throw "Unable to get Access Token. Either the credentials you entered are incorrect or you did not pass a valid two factor token" 
            If ($Quiet) {
                Return $False
            }
            Else {
                Return
            }
        }
        Else {
            #Build the returned token
            $AutomateToken = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
            $AutomateToken.Add("Authorization", "Bearer $AuthorizationToken")
            #Create Script Variables for this session in order to use the token
            $Script:CWATokenKey = ConvertTo-SecureString $AuthorizationToken -AsPlainText -Force
            $Script:CWAServer = ("https://" + $Server)
            $Script:CWAToken = $AutomateToken
            If ($Credential) {
                $Script:CWACredentials = $Credential
            }
            If ($PSCmdlet.ParameterSetName -ne 'verify') {
                $AutomateAPITokenResult.PSObject.properties.remove('AccessToken')
                $Script:CWATokenInfo = $AutomateAPITokenResult
            }
            Write-Verbose "Token retrieved: $AuthorizationToken, expiration is $($Script:CWATokenInfo.ExpirationDate)"
    
            If (!$Quiet) {
                Write-Host -BackgroundColor Green -ForegroundColor Black "Successfully tested and connected to the Automate REST API. Token will expire at $($Script:CWATokenInfo.ExpirationDate)"
            }
            Else {
                Return $True
            }
        }
    }
}

function Get-AutomateAPIGeneric {
    <#
      .SYNOPSIS
        Internal function used to make generic API calls
      .DESCRIPTION
        Internal function used to make generic API calls
      .PARAMETER PageSize
        The page size of the results that come back from the API - limit this when needed
      .PARAMETER Page
        Brings back a particular page as defined
      .PARAMETER AllResults
        Will bring back all results for a particular query with no concern for result set size
      .PARAMETER Endpoint
        The individial URI to post to for results, IE computers?
      .PARAMETER OrderBy
        Order by - Used to sort the results by a field. Can be sorted in ascending or descending order.
        Example - fieldname asc
        Example - fieldname desc
      .PARAMETER Condition
        Condition - the searches that can be used to search for specific things. Supported operators are '=', 'eq', '>', '>=', '<', '<=', 'and', 'or', '()', 'like', 'contains', 'in', 'not'.
        The 'not' operator is only used with 'in', 'like', or 'contains'. The '=' and 'eq' operator are the same. String values can be surrounded with either single or double quotes.
        Boolean values are specified as 'true' or 'false'. Parenthesis can be used to control the order of operations and group conditions.
        The 'like' operator translates to the MySQL 'like' operator.
      .PARAMETER IncludeFields
        A comma delimited list of fields, when specified only these fields will be included in the result set
      .PARAMETER ExcludeFields
        A comma delimited list of fields, when specified these fields will be excluded from the final result set
      .PARAMETER IDs
        A comma delimited list of fields, when specified only these IDs will be returned
      .OUTPUTS
        The returned results from the API call
      .NOTES
        Version:        1.0
        Author:         Gavin Stone
        Creation Date:  20/01/2019
        Purpose/Change: Initial script development
      .EXAMPLE
        Get-AutomateAPIGeneric -Page 1 -Condition "RemoteAgentLastContact <= 2019-12-18T00:50:19.575Z" -Endpoint "computers?"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = "Page")]
        [ValidateRange(1, 1000)]
        [int]
        $PageSize = 1000,

        [Parameter(Mandatory = $true, ParameterSetName = "Page")]
        [ValidateRange(1, 65535)]
        [int]
        $Page,

        [Parameter(Mandatory = $false, ParameterSetName = "AllResults")]
        [switch]
        $AllResults,

        [Parameter(Mandatory = $true)]
        [string]
        $Endpoint,

        [Parameter(Mandatory = $false)]
        [string]
        $OrderBy,

        [Parameter(Mandatory = $false)]
        [string]
        $Condition,

        [Parameter(Mandatory = $false)]
        [string]
        $IncludeFields,

        [Parameter(Mandatory = $false)]
        [string]
        $ExcludeFields,

        [Parameter(Mandatory = $false)]
        [string]
        $IDs,

        [Parameter(Mandatory = $false)]
        [string]
        $Expand
    )
    
    begin {
        #Build the URL to hit
        $url = ($Script:CWAServer + '/cwa/api/v1/' + $EndPoint)

        #Build the Body Up
        $Body = @{ }

        #Put the page size in
        $Body.Add("pagesize", "$PageSize")

        if ($page) {
            
        }

        #Put the condition in
        if ($Condition) {
            $Body.Add("condition", "$condition")
        }

        #Put the orderby in
        if ($OrderBy) {
            $Body.Add("orderby", "$orderby")
        }

        #Include only these fields
        if ($IncludeFields) {
            $Body.Add("includefields", "$IncludeFields")
        }

        #Exclude only these fields
        if ($ExcludeFields) {
            $Body.Add("excludefields", "$ExcludeFields")
        }

        #Include only these IDs
        if ($IDs) {
            $Body.Add("ids", "$IDs")
        }

        #Expands in the returned object
        if ($Expand) {
            $Body.Add("expand", "$Expand")
        }
    }
    
    process {
        if ($AllResults) {
            $ReturnedResults = @()
            [System.Collections.ArrayList]$ReturnedResults
            $i = 0
            DO {
                [int]$i += 1
                $URLNew = "$($url)?page=$($i)"
                try {
                    $return = Invoke-RestMethod -Uri $URLNew -Headers $script:CWAToken -ContentType "application/json" -Body $Body
                }
                catch {
                    Write-Error "Failed to perform Invoke-RestMethod to Automate API with error $_.Exception.Message"
                }

                $ReturnedResults += ($return)
            }
            WHILE ($return.count -gt 0)
        }

        if ($Page) {
            $ReturnedResults = @()
            [System.Collections.ArrayList]$ReturnedResults
            $URLNew = "$($url)?page=$($Page)"
            try {
                $return = Invoke-RestMethod -Uri $URLNew -Headers $script:CWAToken -ContentType "application/json" -Body $Body
            }
            catch {
                Write-Error "Failed to perform Invoke-RestMethod to Automate API with error $_.Exception.Message"
            }

            $ReturnedResults += ($return)
        }

    }
    
    end {
        return $ReturnedResults
    }
}

function Get-ConditionsStacked {
    param (
        [Parameter()]
        [string[]]$ArrayOfConditions
    )

    $FinalString = ($ArrayOfConditions) -join " And "
    Return $FinalString
  
}

Function Invoke-Install_Automate {
    #Install Command
    $RunLog = "$ScriptPath\logs\Automate_Install.txt"
    if (!((Get-WMIObject win32_operatingsystem).name -like 'Server')) {
        if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
            $dotnet35.performclick()
        }

        if ($DotNetInstalled -eq $true) {
            if ((Get-Host).Version.Major -gt 3) {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID)" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            } 
            else {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID)" -RedirectStandardOutput $RunLog -PassThru)
            }
        }
        else {
            if ((Get-Host).Version.Major -gt 3) {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
            } 
            else {
                $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
            }
        }
    }
    else {
        if ((Get-Host).Version.Major -gt 3) {
            $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
        } 
        else {
            $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; Install-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
        }
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID

    if (Test-Path $env:windir\LTSVC) {
        $ReInstall_Automate.Enabled = $true
        $UnInstall_Automate.Enabled = $true
        $Install_Automate.Enabled = $false
    }
}

Function Invoke-ReInstall_Automate {
    #Re-Install Command
    $RunLog = "$ScriptPath\logs\Automate_Re-Install.txt"
    if ((Get-Host).Version.Major -gt 3) {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; ReInstall-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -WindowStyle hidden -PassThru)
    } 
    else {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; ReInstall-LTService -Server $AutomateServer -Password $AutomatePass -LocationID $($Location.ID) -SkipDotNet" -RedirectStandardOutput $RunLog -PassThru)
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID
}

Function Invoke-UnInstall_Automate {
    #Un-Install Command
    $RunLog = "$ScriptPath\logs\Automate_Un-Install.txt"
    if ((Get-Host).Version.Major -gt 3) {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; UnInstall-LTService -Server $AutomateServer" -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
    } 
    else {
        $Process = (start-process powershell -ArgumentList "-executionpolicy bypass -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/LTPoSh') | Invoke-Expression; UnInstall-LTService -Server $AutomateServer" -RedirectStandardOutput $RunLog -PassThru)
    }
    start-sleep -Seconds 1
    Get-ProgressBar -Runlog $RunLog -ProcessID $Process.ID

    if (!(Test-Path $env:windir\LTSVC)) {
        $ReInstall_Automate.Enabled = $false
        $UnInstall_Automate.Enabled = $false
        $install_Automate.Enabled = $true
    }
}

# PowerShell v2/3 caches the output stream. Then it throws errors due
# to the FileStream not being what is expected. Fixes "The OS handle's
# position is not what FileStream expected. Do not use a handle
# simultaneously in one FileStream and in Win32 code or another
# FileStream."
function Repair-PowerShellOutputRedirectionBug {
    $poshMajorVerion = $PSVersionTable.PSVersion.Major
  
    if ($poshMajorVerion -lt 4) {
        try {
            # http://www.leeholmes.com/blog/2008/07/30/workaround-the-os-handles-position-is-not-what-filestream-expected/ plus comments
            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
            $objectRef = $host.GetType().GetField("externalHostRef", $bindingFlags).GetValue($host)
            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetProperty"
            $consoleHost = $objectRef.GetType().GetProperty("Value", $bindingFlags).GetValue($objectRef, @())
            [void] $consoleHost.GetType().GetProperty("IsStandardOutputRedirected", $bindingFlags).GetValue($consoleHost, @())
            $bindingFlags = [Reflection.BindingFlags] "Instance,NonPublic,GetField"
            $field = $consoleHost.GetType().GetField("standardOutputWriter", $bindingFlags)
            $field.SetValue($consoleHost, [Console]::Out)
            [void] $consoleHost.GetType().GetProperty("IsStandardErrorRedirected", $bindingFlags).GetValue($consoleHost, @())
            $field2 = $consoleHost.GetType().GetField("standardErrorWriter", $bindingFlags)
            $field2.SetValue($consoleHost, [Console]::Error)
        }
        catch {
            Update-Textbox "Unable to apply redirection fix." -Color 'red'
        }
    }
}

function Get-ChocoString {
    param (
        [string]$url
    )
    $downloader = Get-ChocoDownloader $url
  
    return $downloader.DownloadString($url)
}

function Get-ChocoFile {
    param (
        [string]$url,
        [string]$file
    )
    #Write-Output "Downloading $url to $file"
    $downloader = Get-ChocoDownloader $url
  
    $downloader.DownloadFile($url, $file)
}

function Get-ChocoDownloader {
    param (
        [string]$url
    )
  
    $downloader = new-object System.Net.WebClient
  
    $defaultCreds = [System.Net.CredentialCache]::DefaultCredentials
    if ($null -ne $defaultCreds) {
        $downloader.Credentials = $defaultCreds
    }
  
    $ignoreProxy = $env:chocolateyIgnoreProxy
    if ($null -ne $ignoreProxy -and $ignoreProxy -eq 'true') {
        Update-Textbox "Explicitly bypassing proxy due to user environment variable"
        $downloader.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    }
    else {
        # check if a proxy is required
        $explicitProxy = $env:chocolateyProxyLocation
        $explicitProxyUser = $env:chocolateyProxyUser
        $explicitProxyPassword = $env:chocolateyProxyPassword
        if ($null -ne $explicitProxy -and $explicitProxy -ne '') {
            # explicit proxy
            $proxy = New-Object System.Net.WebProxy($explicitProxy, $true)
            if ($null -ne $explicitProxyPassword -and $explicitProxyPassword -ne '') {
                $passwd = ConvertTo-SecureString $explicitProxyPassword -AsPlainText -Force
                $proxy.Credentials = New-Object System.Management.Automation.PSCredential ($explicitProxyUser, $passwd)
            }
  
            Update-Textbox "Using explicit proxy server '$explicitProxy'."
            $downloader.Proxy = $proxy
  
        }
        elseif (!$downloader.Proxy.IsBypassed($url)) {
            # system proxy (pass through)
            $creds = $defaultCreds
            if ($null -eq $creds) {
                Update-Textbox "Default credentials were null. Attempting backup method"
                $cred = get-credential
                $creds = $cred.GetNetworkCredential();
            }
  
            $proxyaddress = $downloader.Proxy.GetProxy($url).Authority
            Update-Textbox "Using system proxy server '$proxyaddress'."
            $proxy = New-Object System.Net.WebProxy($proxyaddress)
            $proxy.Credentials = $creds
            $downloader.Proxy = $proxy
        }
    }
  
    return $downloader
}
function Install-Chocolatey {
    $url = ''

    $chocolateyVersion = $env:chocolateyVersion
    if (![string]::IsNullOrEmpty($chocolateyVersion)) {
        Update-Textbox "Downloading specific version of Chocolatey: $chocolateyVersion"
        $url = "https://chocolatey.org/api/v2/package/chocolatey/$chocolateyVersion"
    }
    
    $chocolateyDownloadUrl = $env:chocolateyDownloadUrl
    if (![string]::IsNullOrEmpty($chocolateyDownloadUrl)) {
        Update-Textbox "Downloading Chocolatey from : $chocolateyDownloadUrl"
        $url = "$chocolateyDownloadUrl"
    }
    
    if ($null -eq $env:TEMP) {
        $env:TEMP = Join-Path $env:SystemDrive 'temp'
    }
    $chocTempDir = Join-Path $env:TEMP "chocolatey"
    $tempDir = Join-Path $chocTempDir "chocInstall"
    if (![System.IO.Directory]::Exists($tempDir)) { [void][System.IO.Directory]::CreateDirectory($tempDir) }
    $file = Join-Path $tempDir "chocolatey.zip"
    
    Repair-PowerShellOutputRedirectionBug
    
    # Attempt to set highest encryption available for SecurityProtocol.
    # PowerShell will not set this by default (until maybe .NET 4.6.x). This
    # will typically produce a message for PowerShell v2 (just an info
    # message though)
    try {
        # Set TLS 1.2 (3072), then TLS 1.1 (768), then TLS 1.0 (192), finally SSL 3.0 (48)
        # Use integers because the enumeration values for TLS 1.2 and TLS 1.1 won't
        # exist in .NET 4.0, even though they are addressable if .NET 4.5+ is
        # installed (.NET 4.5 is an in-place upgrade).
        [System.Net.ServicePointManager]::SecurityProtocol = 3072 -bor 768 -bor 192 -bor 48
    }
    catch {
        Update-Textbox 'Unable to set PowerShell to use TLS 1.2 and TLS 1.1 due to old .NET Framework installed. If you see underlying connection closed or trust errors, you may need to do one or more of the following: (1) upgrade to .NET Framework 4.5+ and PowerShell v3, (2) specify internal Chocolatey package location (set $env:chocolateyDownloadUrl prior to install or host the package internally), (3) use the Download + PowerShell method of install. See https://chocolatey.org/install for all install options.' -Color 'red'
    }
    
    if ($null -eq $url -or $url -eq '') {
        Update-Textbox "Getting latest version of the Chocolatey package for download."
        $url = 'https://chocolatey.org/api/v2/Packages()?$filter=((Id%20eq%20%27chocolatey%27)%20and%20(not%20IsPrerelease))%20and%20IsLatestVersion'
        [xml]$result = Get-ChocoString $url
        $url = $result.feed.entry.content.src
    }
    
    # Download the Chocolatey package
    Update-Textbox "Getting Chocolatey from $url."
    Get-ChocoFile $url $file
    
    # Determine unzipping method
    # 7zip is the most compatible so use it by default
    $7zaExe = Join-Path $tempDir '7za.exe'
    $unzipMethod = '7zip'
    $useWindowsCompression = $env:chocolateyUseWindowsCompression
    if ($null -ne $useWindowsCompression -and $useWindowsCompression -eq 'true') {
        Update-Textbox 'Using built-in compression to unzip'
        $unzipMethod = 'builtin'
    }
    elseif (-Not (Test-Path ($7zaExe))) {
        Update-Textbox "Downloading 7-Zip commandline tool prior to extraction."
        # download 7zip
        Get-ChocoFile 'https://chocolatey.org/7za.exe' "$7zaExe"
    }
    
    # unzip the package
    Update-Textbox "Extracting $file to $tempDir..."
    if ($unzipMethod -eq '7zip') {
        $params = "x -o`"$tempDir`" -bd -y `"$file`""
        # use more robust Process as compared to Start-Process -Wait (which doesn't
        # wait for the process to finish in PowerShell v3)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo($7zaExe, $params)
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $process.Dispose()
    
        $errorMessage = "Unable to unzip package using 7zip. Perhaps try setting `$env:chocolateyUseWindowsCompression = 'true' and call install again. Error:"
        switch ($exitCode) {
            0 { break }
            1 { throw "$errorMessage Some files could not be extracted" }
            2 { throw "$errorMessage 7-Zip encountered a fatal error while extracting the files" }
            7 { throw "$errorMessage 7-Zip command line error" }
            8 { throw "$errorMessage 7-Zip out of memory" }
            255 { throw "$errorMessage Extraction cancelled by the user" }
            default { throw "$errorMessage 7-Zip signalled an unknown error (code $exitCode)" }
        }
    }
    else {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            try {
                $shellApplication = new-object -com shell.application
                $zipPackage = $shellApplication.NameSpace($file)
                $destinationFolder = $shellApplication.NameSpace($tempDir)
                $destinationFolder.CopyHere($zipPackage.Items(), 0x10)
            }
            catch {
                throw "Unable to unzip package using built-in compression. Set `$env:chocolateyUseWindowsCompression = 'false' and call install again to use 7zip to unzip. Error: `n $_"
            }
        }
        else {
            Expand-Archive -Path "$file" -DestinationPath "$tempDir" -Force
        }
    }
    
    # Call chocolatey install
    Update-Textbox "Installing chocolatey on this machine"
    $toolsFolder = Join-Path $tempDir "tools"
    $chocInstallPS1 = Join-Path $toolsFolder "chocolateyInstall.ps1"
    
    & $chocInstallPS1
    
    Update-Textbox 'Ensuring chocolatey commands are on the path'
    $chocInstallVariableName = "ChocolateyInstall"
    $chocoPath = [Environment]::GetEnvironmentVariable($chocInstallVariableName)
    if ($null -eq $chocoPath -or $chocoPath -eq '') {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }
    
    if (!(Test-Path ($chocoPath))) {
        $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
    }
    
    $chocoExePath = Join-Path $chocoPath 'bin'
    
    if ($($env:Path).ToLower().Contains($($chocoExePath).ToLower()) -eq $false) {
        $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);
    }
    
    Update-Textbox 'Ensuring chocolatey.nupkg is in the lib folder'
    $chocoPkgDir = Join-Path $chocoPath 'lib\chocolatey'
    $nupkg = Join-Path $chocoPkgDir 'chocolatey.nupkg'
    if (![System.IO.Directory]::Exists($chocoPkgDir)) { [System.IO.Directory]::CreateDirectory($chocoPkgDir); }
    Copy-Item "$file" "$nupkg" -Force -ErrorAction SilentlyContinue
}

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

function Install-DotNet {
    if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
        update-Textbox ".NET 3.5 installation needed."
        #Install-WindowsFeature Net-Framework-Core
    
        if ([version][System.Environment]::OSVersion.Version -gt [version]'6.2') {
            try {
                
                $output = $ScriptPath + '\dotnet3_5'
                if (!(Test-Path $output)) {
                    New-Item -ItemType Directory -Path $output | Out-Null
                }
                
                Get-Files -Source "$DownloadHost/AutoMate/Microsoft/Windows/DotNet/Win10_sxs.zip" -Destination "$output\Win10_sxs.zip" -NumberOfFiles 1 -Software '.NET 3.5'
                Start-Extract -File "$output\Win10_sxs.zip" -ExtractTo $output
    
                #Install Command
                $RunLog = "$ScriptPath\logs\DotNet3_5_Install.txt"
                $arguments = '/online /enable-feature /featurename:NetFX3 /All /source:' + $output + '\sxs'
                $Process = (Start-Process -filepath $env:windir\system32\dism.exe -ArgumentList $arguments -RedirectStandardOutput $RunLog -WindowStyle Hidden -PassThru)
                start-sleep 1
                Get-ProgressBar -Runlog $RunLog -ProcessID $Process.id -Tracker
                
            }
            catch {
                if (!((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.')) {
                    update-Textbox "ERROR: .NET 3.5 install failed." -Color 'Red'
                }
            }
        }
        Else {
    
            Try { $Result = (Start-Process -FilePath "$env:windir\system32\Dism.exe" -ArgumentList '/online Enable /get-featureinfo /featurename:NetFx3') } 
            Catch { update-Textbox "Error calling Dism.exe." -Color 'Red'; $Result = $Null }
            If ($Result -contains "State : Enabled") {
                update-Textbox ".Net Framework 3.5 has been installed and enabled." -Color 'Green'
            }
            Else { 
                update-Textbox "ERROR: .NET 3.5 install failed." -Color 'Red'
            }#End If
            
        }#End If
    
        if ((Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse | Get-ItemProperty -name Version -EA 0 | Where-Object { $_.PSChildName -match '^(?!S)\p{L}' } | Select-Object -ExpandProperty Version) -match '(3\.5.+)\.') {
            update-Textbox ".net 3.5 installed succesfully" -Color 'Green'
            if ($dotnet35.Enabled -eq $true) {
                $dotnet35.Enabled = $false
            } 
            $Script:DotNetInstalled = $true
        }
        else {
            update-Textbox ".net 3.5 failed to install" -color 'Red'
        }
    }
    else {
        update-Textbox ".Net 3.5 already installed" -color 'Yellow'
        if ($dotnet35.Enabled -eq $true) {
            $dotnet35.Enabled = $false
        } 
        $DotNetInstalled = $true
    }
}

function Install-Office {
    if ($365ComboBox.Text -eq '--Select--') {
        update-Textbox "Please select an office product"
    }
    else {
        if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq '64-bit') {
            Switch ($365ComboBox.Text) {
                "Office 365 Business" {
                    $Source = "$DownloadHost/AutoMate/Microsoft/Office/365_Business_x64/Office_365_Business_x64.zip"
                    $Destination = "$ScriptPath\O365\Business x64\Office_365_Business_x64.zip"
                    $ArgumentList = "/Configure $env:systemDrive\office365\configuration-Office365-x64.xml"
                    $NumberOfFiles = 24
                }
                "Office 365 ProPlus" {
                    $Source = "$DownloadHost/AutoMate/Microsoft/Office/365_ProPlus_x64/Office_365_ProPlus_x64.zip"
                    $Destination = "$ScriptPath\O365\ProPlus x64\Office_365_ProPlus_x64.zip"
                    $ArgumentList = "/Configure $env:systemDrive\office365\configuration-Office365-x64.xml"
                    $NumberOfFiles = 23
                }
                "Office 2019 Standard" {
                    $Source = "$DownloadHost/AutoMate/Microsoft/Office/2019_Standard/Office_2019_Standard.zip"
                    $Destination = "$ScriptPath\Office_2019\Standard\Office_2019_Standard.zip"
                    $ArgumentList = "/Configure $env:systemDrive\office365\configuration-Office2019.xml"
                    $NumberOfFiles = 20
                }
            }
    
        }
        else {
            Switch ($365ComboBox.Text) {
                "Office 365 Business" {
                    $Source = "$DownloadHost/AutoMate/Microsoft/Office/365_Business_x86/Office_365_Business_x86.zip"         
                    $Destination = "$ScriptPath\O365\Business x86\Office_365_Business_x86.zip"
                    $ArgumentList = "/Configure $env:systemDrive\office365\configuration-Office365-x86.xml"
                    $NumberOfFiles = 18
                }
                "Office 365 ProPlus" {
                    $Source = "$DownloadHost/AutoMate/Microsoft/Office/365_ProPlus_x86/Office_365_ProPlus_x86.zip"
                    $Destination = "$ScriptPath\O365\ProPlus x86\Office_365_ProPlus_x86.zip"
                    $ArgumentList = "/Configure $env:systemDrive\office365\configuration-Office365-x86.xml"
                    $NumberOfFiles = 18
                }
                "Office 2019 Standard" {
                    update-Textbox "No Installer for 32 bit Office 2019 Standard"
                    $NumberOfFiles = 0
                }
            }
        }
        if ((Get-ChildItem -path (Split-Path -path $Destination) -ErrorAction SilentlyContinue).count -lt $NumberOfFiles) {
            Get-Files -Source $Source -Destination $Destination -NumberOfFiles $NumberOfFiles -Software $365ComboBox.Text
        }
        if ($NumberOfFiles -gt 0) {
            if (!(Test-Path "$env:systemDrive\office365")) { New-Item -ItemType Directory -Path "$env:systemDrive\office365" }
            Start-Extract -File "$($Destination).001" -ExtractTo "$env:systemDrive\office365"
            Start-Sleep -seconds 1
            update-Textbox "Installing $($365ComboBox.Text)"
            Start-Process -filepath "$env:systemDrive\office365\setup.exe" -ArgumentList $ArgumentList
        }
        
        $365Checkbox.Checked = $false
        $365ComboBox.enabled = $false
    }
}

function Set-PowerPolicy {
    Try {
        $hardwaretype = (Get-WmiObject -Class Win32_ComputerSystem).PCSystemType
        If ($hardwaretype -ne 2) {
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
            get-files -source "$DownloadHost/Standalone_Installer/Tech_Installer/PowerPolicy/Qi%20-%20Power%20Policy.zip" -Destination "$Output\Qi - Power Policy.zip" -NumberOfFiles 1 -Software "PowerPolicy"
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
}

function Test-Compatibility {
    $Script:ReturnValue = $true

    $BuildVersion = [System.Environment]::OSVersion.Version

    if ($BuildVersion.Major -ge '10') {
        update-Textbox 'WMF 5.1 is not supported for Windows 10 and above.' -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## OS is below Windows Vista
    if ($BuildVersion.Major -lt '6') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## OS is Windows Vista
    if ($BuildVersion.Major -eq '6' -and $BuildVersion.Minor -le '0') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }
    ## OS 7 is missing Service Pack 1
    if ($BuildVersion.Major -eq '6' -and $BuildVersion.Build -eq '7600') {
        update-Textbox "WMF 5.1 is not supported on BuildVersion: $($BuildVersion.ToString())" -color "Yellow"
        $Script:ReturnValue = $false
    }

    ## Check if WMF 3 is installed
    $wmf3 = Get-WmiObject -Query "select * from Win32_QuickFixEngineering where HotFixID = 'KB2506143'"

    if ($wmf3) {
        update-Textbox "WMF 5.1 is not supported when WMF 3.0 is installed." -color "Yellow"
        Add-Type -AssemblyName PresentationFramework
        $wmf3msgBoxInput = [System.Windows.MessageBox]::Show('Powershell 3 detected. PS 4 Must be installed prior to 5 Would you like to install Powershell 4 now?', 'WMF 4.0', 'YesNo', 'Warning')

        switch ($wmf3msgBoxInput) {
            'Yes' {
                Install-Software -Application "powershell4"
                Request-Reboot
            }
            'No' {
                update-Textbox "Powershell Upgrade Canceled" -color "Yellow"
            }
        }
        $Script:ReturnValue = $false
    }

    # Check if .Net 4.5 or above is installed

    $release = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Release -ErrorAction SilentlyContinue -ErrorVariable evRelease).release
    $installed = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Install -ErrorAction SilentlyContinue -ErrorVariable evInstalled).install

    if ($evRelease -or $evInstalled) {
        Update-Textbox "WMF 5.1 requires .Net 4.5" -color 'Yellow'
        $Script:ReturnValue = $false
    }
    elseif (($installed -ne 1) -or ($release -lt 378389)) {
        Update-Textbox "WMF 5.1 requires .Net 4.5" -color 'Yellow'
        $Script:ReturnValue = $false
    }
}

function Read-InputBoxDialog([string]$Message, [string]$WindowTitle, [string]$DefaultText) {
    Add-Type -AssemblyName Microsoft.VisualBasic
    return [Microsoft.VisualBasic.Interaction]::InputBox($Message, $WindowTitle, $DefaultText)
}
Function Request-Reboot {
    Add-Type -AssemblyName PresentationFramework
    $rebootrequest = [System.Windows.MessageBox]::Show('A reboot is required to finish settings changes. Would you like to reboot now?', 'Reboot Required', 'YesNo', 'Question')

    switch ($rebootrequest) {
        'Yes' {
            shutdown.exe -r -t 10
            update-Textbox "Computer rebooting"
        }
        'No' {
            update-Textbox "Please reboot at your earliest convenience." -Color "Yellow"
        }
    }
}
<#
function Test-Cred {
           
    [CmdletBinding()]
    [OutputType([String])] 
       
    Param ( 
        [Parameter( 
            Mandatory = $false, 
            ValueFromPipeLine = $true, 
            ValueFromPipelineByPropertyName = $true
        )] 
        [Alias( 
            'PSCredential'
        )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
    $Domain = $null
    $Username = $null
    $Password = $null
      
    If ($null -eq $Credentials) {
        Try {
            $Credentials = Get-Credential "domain\$env:username" -ErrorAction Stop
        }
        Catch {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Domain = $NewDomain
    }
    Catch {
        $_.Exception.Message
        Continue
    }
  
    If (!$domain) {
        Write-Warning "Something went wrong"
    }
    Else {
        If ($null -ne $domain.name) {
            return "Authenticated"
        }
        Else {
            return "Not authenticated"
        }
    }
}
#>
function Update-Win10 {
    if (((Get-Host).version).major -gt 2) {
        $version = "1909"
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
                $ArgumentList = "/auto upgrade /Compat IgnoreWarning /DynamicUpdate disable /copylogs $env:SystemDrive\wti\Windows10UpgradeLogs /migratedrivers alll /noreboot"
                update-Textbox "$((Split-Path -path $Destination) + "\setup.exe") $ArgumentList"
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
    }
    else {
        update-Textbox "Please upgrade powershell before updating windows" -Color "Yellow"
    }
}

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
        Get-USMT
        Try {
            if (!(Test-Path "A:\usmtfiles")) {
                New-Item -ItemType Directory -Path "A:\usmtfiles"# | Out-Null
            }
            Copy-Item -Path $USMTPath -Destination "A:\usmtfiles\" -ErrorAction Stop -Recurse -force
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
        if (!(Test-Path "\\$SourceComputer\C$\usmtfiles\$SourceComputer")) {
            New-Item -ItemType Directory -Path "$SourceComputer\C$\usmtfiles\$SourceComputer" | Out-Null
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
        Get-Files -Source (Get-Childitem -Path "A:\usmtfiles\$SourceComputer" -include *.MIG -recurse).FullName -Destination "$Destination\USMT\USMT.MIG" -NumberOfFiles 1 -Software "USMT.MIG"

        #Start loadscan on destination
        # Get the location of the save state data
        $LocalAccountOptions = '/all'
        $Logs = "`"/l:$Destination\load.txt`" `"/progress:$Destination\load_progress.txt`""
        $ContinueCommand = "/c"
        $Arguments = "`"$Destination`" $LocalAccountOptions $Logs $ContinueCommand /v:13"
        $Process = (Start-Process -FilePath $LoadState -ArgumentList $Arguments -WindowStyle Hidden -PassThru)
        
        Get-USMTProgress -Runlog "$Destination\load_progress.txt" -processID $Process.ID -ActionType "LoadState"
 
        #Remove USMT files on remote computers
        #Remove-Item \\$SourceComputer\C$\USMTFiles -Force -Recurse
        #Remove-Item \\$DestinationComputer\C$\USMTFiles -Force -Recurse

        #Disable CredSSP on remote computers
        Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBlock { Disable-WSManCredSSP -Role server }
        Disable-WSManCredSSP -Role client        
    }
}

function Test-ComputerConnection {
    $ConnectionCheckBox.Checked = $false
    $UNCVerified.Checked = $false

    # Try and use the IP if the user filled that out, otherwise use the name
    if ($SourceIPAddressText.Text -ne '') {
        $Computer = $SourceIPAddressText.Text
        # Try to update the computer's name with its IP address
        if ($SourceComputerText.Text -eq '') {
            try {
                Update-Textbox 'Computer name is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
                $HostName = ([System.Net.Dns]::GetHostEntry($Computer)).HostName
                $SourceComputerText.Text = $HostName
                Update-Textbox "Computer name set to $HostName."
            }
            catch {
                Update-Textbox "Unable to resolve host name from IP address, you'll need to manually set this." -Color 'Red'
                return
            }
        }
    }
    elseif ($SourceComputerText.Text -ne '') {
        $Computer = $SourceComputerText.Text
        # Try to update the computer's IP address using its DNS name
        try {
            Update-Textbox 'Computer IP address is blank, attempting to resolve...' -Color 'Yellow' -NoNewLine
            # Get the first IP address found, which is usually the primary adapter
            $IPAddress = ([System.Net.Dns]::GetHostEntry($Computer)).AddressList.IPAddressToString.Split('.', 1)[0]

            # Set IP address in text box
            $SourceIPAddressText.Text = $IPAddress
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
            if ($SourceIPAddressText.Text -eq '') {
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
        new-psdrive -name "A" -PSProvider "FileSystem" -Root "\\$Computer\C$" -Credential $Creds -scope global
        if (Test-Path -Path "A:") {
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
    Switch ($ActionType) {
        "NetworkScan" {
            while (Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBLock { Get-process scanstate -ErrorAction SilentlyContinue }) {
                foreach ($line in ($lines = (Invoke-Command -ComputerName $SourceComputer -Credential $Credential -ScriptBLock { get-content "C:\usmtfiles\$using:SourceComputer\scan_progress.txt" -ErrorAction SilentlyContinue }))) {
                    if (!($promptcheck -contains $line)) {
                        if ($line -match '\d{2}\s[a-zA-Z]+\s\d{4}\,\s\d{2}\:\d{2}\:\d{2}') {
                            $line = ($Line.Split(',', 4)[3]).TrimStart()
                        }
                        Update-USMTTextBox -Text $Line
                    }
                }
                $Promptcheck = $Lines
                
                start-sleep -Milliseconds 50
            }
        }
        "LoadState" {
            while (get-process -id $ProcessID -ErrorAction SilentlyContinue) {
                foreach ($line in ($lines = get-content $RunLog -ErrorAction SilentlyContinue)) {
                    if (!($promptcheck -contains $line)) {
                        if ($line -match '\d{2}\s[a-zA-Z]+\s\d{4}\,\s\d{2}\:\d{2}\:\d{2}') {
                            $line = ($Line.Split(',', 4)[3]).TrimStart()
                        }
                        Update-USMTTextBox -Text $Line
                    }
                }
                $Promptcheck = $Lines
                
                start-sleep -Milliseconds 50
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
function Update-USMTTextBox {
    Param (
        [string] $Text
    )
    if (!($null -eq $Text) -and $Text.TrimEnd() -ne '.' -and $Text.TrimEnd() -notmatch 'detectedComponent' -and $Text.TrimEnd() -notmatch 'estimatePercentageCompleted') {
        if ($Text.TrimEnd() -match '([\d]+)\.\d\%') {
            $CurrentFile.Value = $matches[1]
        }
        elseif ($Text.TrimEnd() -match 'totalPercentageCompleted. ([\d]+)') {
            $CurrentFile.Value = $matches[1]
        }
        elseif ($Text.TrimEnd() -match 'UnableToOpen') {
            Update-Textbox $Text.TrimEnd() -color 'Orange'
            Update-Textbox ''
        }
        elseif ($Text.TrimEnd() -match 'successful' -or $Text.TrimEnd() -match 'completed') {
            Update-Textbox $Text.TrimEnd() -color 'Green'
        }
        elseif ($Text.TrimEnd() -match 'ERROR' -or $Text.TrimEnd() -match 'not successful') {
            Update-Textbox $Text.TrimEnd() -Color 'Red'
        }
        elseif ($Text.TrimEnd() -match 'WARNING') {
            Update-Textbox $Text.TrimEnd() -Color 'Yellow'
        }
        else {
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




function Start-QiInstaller {
    param(
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $AutomateServer,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $AutomatePass,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $DownloadHost,
        [Parameter(ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
        [string] $ScriptPath,
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
    elseif ($ScriptPath -match 'QiInstaller') {
        if ($ScriptPath -match '\\\\') {
            $ScriptPath = $ScriptPath.replace('\\', '\')
        }
        write-host $ScriptPath
    }
    else {
        $ScriptPath = "$ScriptPath\QiInstaller"
    }

    #Create local files folder
    if (!(Test-Path $ScriptPath)) {
        New-Item -ItemType Directory -Path $ScriptPath | Out-Null
    }
    if (!(Test-Path $ScriptPath\logs)) {
        New-Item -ItemType Directory -Path $ScriptPath\logs | Out-Null
    }

    #Debug Options
    $AuthDebugButton_Click = {
        if ($AuthPanel.Visible) {
            $AuthPanel.Visible = $false
        }
    }
    $DebugConsole_Click = {
        $DebugCommandButton.Visible = -not $DebugCommandButton.Visible
        $DebugCommand.Visible = -not $DebugCommand.Visible
    }
    $DebugCommandButton_Click = {
        $test = @{value = $DebugCommand.Text }
        invoke-expression $test.value | out-file "$Scriptpath\logs\debugger.txt"
        foreach ($line in (Get-content -Path "$Scriptpath\logs\debugger.txt")) {
            Update-Textbox $line
        }
        
        Remove-Item -path "$Scriptpath\logs\debugger.txt" -force
        $DebugCommand.Text = ''
    }

    #Authenticator
    $AuthSubmit_Click = {
        if ($AuthUser.Text -eq 'Debug' -and $2FAAuth.Text -eq '136590') {
            #Debug Options
            $DebugConsole.Visible = $true
            $AuthDebugButton.Visible = $true
            $AuthUser.Text = ''
            $2FAAuth.Text = ''
        }
        elseif ($AuthUser.Text -eq 'Console') {
            if ($QiDebug) {
                start-process powershell.exe -argumentlist "-executionpolicy bypass -noprofile -command (New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/DaveKlatka/Qi-Installer/Development/Qi_Installer.ps1') | Invoke-Expression; Start-QiInstaller -ScriptPath $ScriptPath -AutomateServer 'Automate.QualityIP.com' -AutomatePass 'BndOZpmJrChvdODpKIbdiA==' -DownloadHost 'https://qi-host.nyc3.digitaloceanspaces.com' -QiDebug"
            }
            else {
                start-process powershell.exe -argumentlist "-executionpolicy bypass -noprofile -command (New-Object System.Net.WebClient).DownloadString('http://bit.ly/34uSuCU') | Invoke-Expression; Start-QiInstaller -ScriptPath $ScriptPath -AutomateServer 'Automate.QualityIP.com' -AutomatePass 'BndOZpmJrChvdODpKIbdiA==' -DownloadHost 'https://qi-host.nyc3.digitaloceanspaces.com'"
            }
            $TechInstaller.Close()
        }
        else {
            #https://github.com/gavsto/AutomateAPI
            Try {
                $secpasswd = ConvertTo-SecureString $AuthPass.Text -AsPlainText -Force
                $Credential = New-Object System.Management.Automation.PSCredential ($AuthUser.Text, $secpasswd)
                Connect-AutomateAPI -credential $Credential -Server $AutomateServer -TwoFactorToken $2FAAuth.Text -ErrorAction stop
                if ($AuthUser.text -eq 'dklatkaadm') {
                    $Script:Location = (Get-AutomateAPIGeneric -page 1 -Condition "client.name eq 'QualityIP' and ScriptExtra1 eq '$($AuthUser.text)'" -Endpoint "locations")
                }
                else {
                    $Script:Location = (Get-AutomateAPIGeneric -page 1 -Condition "client.name eq '1_Technician Catchall' and ScriptExtra1 eq '$($AuthUser.text)'" -Endpoint "locations")
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
        Invoke-ReInstall_Automate  
    }
    $UnInstall_Automate_Click = {
        Invoke-UnInstall_Automate
    }
    $Install_Automate_Click = {
        Invoke-Install_Automate
    }
    
    $dotnet35_Click = {
        Install-DotNet
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
                    Test-Compatibility
                    if ($ReturnValue) {
                        if (((Get-WmiObject win32_OperatingSystem).Caption) -match 'Windows 7') {
                            Install-Software -Application 'Powershell'
                            switch ($msgBoxInput) {
                                'Yes' {
                                    shutdown.exe -r -t 30
                                    update-Textbox "System Rebooting" -color "Yellow"
                                }
                                'No' {
                                    update-Textbox "Please reboot at your earliest convenience" -color "Yellow"
                                }
                            }
                        }
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
            Install-Office
        }
    }
    
    #Qi Power Policy
    $PowerPolicy_Click = {
        Set-PowerPolicy
    }
    
    #Dell Command Update
    $DellUpdate_Click = {
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
            if (!((([xml](get-content $RunLog)).logentries.logentry.message | Where-Object { $_.message -like "*Install*" }).data | Where-Object { $_.type -eq "install" })) {
                Update-Textbox "No Updates Availaible" -Color "Green"
            }
        }
        else {
            update-Textbox "Dell Hardware Not Detected"
        }
    }
    
    #Powershell 5
    $Powershell5_Click = {
        Test-Compatibility
        if ($ReturnValue) {
            if (((Get-WmiObject win32_OperatingSystem).Caption) -match 'Windows 7') {
                Install-Software -Application 'Powershell'
                switch ($msgBoxInput) {
                    'Yes' {
                        shutdown.exe -r -t 30
                        update-Textbox "System Rebooting" -color "Yellow"
                    }
                    'No' {
                        update-Textbox "Please reboot at your earliest convenience" -color "Yellow"
                    }
                }
            }
        }
    }
    
    #Win10 Upgrade
    $Win10Upgrade_Click = {
        Add-Type -AssemblyName PresentationFramework
        $msgBoxInput = [System.Windows.MessageBox]::Show('Options selected will reboot your computer. Would you like to continue?', 'Reboot Required', 'YesNo', 'Warning')
        switch ($msgBoxInput) {
            'Yes' {
                Update-Win10
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
        $NewComputerName = (Read-InputBoxDialog -Message "Enter New Computer Name.`n `nFormat: (ComputerName-DT) `n `nLeave Blank if no change." -WindowTitle "New Computer Name")
        $NewDomain = (Read-InputBoxDialog -Message "Enter New Domain.`n `nFormat: (Domain.local) `n `nLeave Blank if no change." -WindowTitle "New Domain")
        
        #Name and Domain
        if ([bool]($NewComputerName) -and [bool]($NewDomain)) {
            $message = "Please enter credentials for $($NewDomain)."
            $Credential = Get-Credential -Message $message
            if ($NewDomain -like '*.*') {
                Add-Computer -Domain $NewDomain -NewName $NewComputerName -Credential $Credential -Force
            }
            else {
                Remove-Computer -UnjoinDomainCredential $Credential -WorkgroupName $NewDomain -Force
                Rename-Computer -NewName $NewComputerName -Force
            }
            Request-Reboot
        }
        #Name
        elseif ([bool]($NewComputerName) -and ![bool]($NewDomain)) {
            update-Textbox "Renaming computer to $($NewComputerName)"
            if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
                if ([string](nltest.exe /query) -match '(Connection Status = 0 0x0 NERR_Success)') {
                    $credential = Get-Credential -Message 'Please enter the domain admin credentials.'
                    Rename-Computer -NewName $NewComputerName -DomainCredential $credential
                }
            }
            else {
                Rename-Computer -NewName $NewComputerName
            }
            Request-Reboot
        }
        #Domain
        elseif (![bool]($NewComputerName) -and [bool]($NewDomain)) {
            $message = "Please enter credentials for $($NewDomain)."
            $Credential = Get-Credential -Message $message
                
            if ($NewDomain -like '*.*') {
                if (Test-Connection -TargetName $Newdomain) {
                    try {
                        $ArgumentList = "Add-Computer -Domain $NewDomain -Credential $Credential"
                        $process = (start-process powershell -ArgumentList "-executionpolicy bypass -command $ArgumentList" -WindowStyle Hidden -passthru)
                        if ($Process -match "failed") {
                            update-Textbox $error -color "Red"
                        }
                        Request-Reboot
                    }
                    catch {
                        update-Textbox $error -color "Red"
                    }
                }
                else {
                    update-Textbox "Unable to reach Domain controller" -Color "Red"
                }
            }
            else {
                Remove-Computer -UnjoinDomainCredential $Credential -WorkgroupName $NewDomain -Force
                Request-Reboot
            }
        }
        else {
            update-Textbox "Rename Canceled"
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
        Test-ComputerConnection
    }
    $RunNetMig_Click = {
        if ($ConnectionCheckBox.Checked -and $UNCVerified.Checked) {
            Invoke-USMT -SourceComputer $SourceComputerText.Text -Credential $Creds
        }
        else {
            Update-Textbox "Connection not Verified. Please Test Connection first" -color 'Orange'
        }
    }

    $Logout_Click = {
        if ($AuthError.Visible -eq $True) {
            $AuthError.Visible = $false
        }
        $AuthUser.Text = ''
        $AuthPass.Text = ''
        $2FAAuth.Text = ''
        $TechInstaller.Text = [System.String]"Tech Installer"
        $AuthPanel.Visible = $true
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

    #USMT Variables
    $DestComputerText.Text = $env:COMPUTERNAME
    $DestIpAddressText.Text = (Test-Connection -ComputerName (hostname) -Count 1).IPV4Address.IPAddressToString
    $ExportLocation.Text = $ScriptPath

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

    $AdditionalLocations.ColumnCount = 1
    $TechInstaller.icon = $ico
    $picturebox1.imageLocation = $png
    
    $365ComboBox.Enabled = -not $365ComboBox.Enabled
    
    $TechInstaller.ShowDialog()
}
