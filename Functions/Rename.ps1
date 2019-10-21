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
      
    If($Credentials -eq $null)
    {
        Try
        {
            $Credentials = Get-Credential "domain\$env:username" -ErrorAction Stop
        }
        Catch
        {
            $ErrorMsg = $_.Exception.Message
            Write-Warning "Failed to validate credentials: $ErrorMsg "
            Pause
            Break
        }
    }
      
    # Checking module
    Try
    {
        # Split username and password
        $Username = $credentials.username
        $Password = $credentials.GetNetworkCredential().password
  
        # Get Domain
        $Domain = $NewDomain
    }
    Catch
    {
        $_.Exception.Message
        Continue
    }
  
    If(!$domain)
    {
        Write-Warning "Something went wrong"
    }
    Else
    {
        If ($domain.name -ne $null)
        {
            return "Authenticated"
        }
        Else
        {
            return "Not authenticated"
        }
    }
}

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

