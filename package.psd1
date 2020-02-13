@{
        Root = 'c:\Users\dklatka\source\repos\Powershell\Network\NetUse.ps1'
        OutputPath = 'c:\Users\dklatka\source\repos\Qi-Installer\out'
        Package = @{
            Enabled = $true
            Obfuscate = $false
            HideConsoleWindow = $false
            DotNetVersion = 'v4.6.2'
            FileVersion = '1.0.0'
            FileDescription = ''
            ProductName = ''
            ProductVersion = ''
            Copyright = ''
            RequireElevation = $false
            ApplicationIconPath = ''
            PackageType = 'Console'
        }
        Bundle = @{
            Enabled = $true
            Modules = $true
            # IgnoredModules = @()
        }
    }
    