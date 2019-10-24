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

            }
        }
    }
    if ((Get-ChildItem -path (Split-Path -path $Destination) -ErrorAction SilentlyContinue).count -lt $NumberOfFiles) {
        Get-Files -Source $Source -Destination $Destination -NumberOfFiles $NumberOfFiles -Software $365ComboBox.Text
    }
    if (!(Test-Path "$env:systemDrive\office365")) { New-Item -ItemType Directory -Path "$env:systemDrive\office365" }
    Start-Extract -File "$($Destination).001" -ExtractTo "$env:systemDrive\office365"
    Start-Sleep -seconds 1
    update-Textbox "Installing $($365ComboBox.Text)"
    Start-Process -filepath "$env:systemDrive\office365\setup.exe" -ArgumentList $ArgumentList
            
    $365Checkbox.Checked = $false
    $365ComboBox.enabled = $false
}