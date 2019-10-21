@{
        Root = 'C:\Users\dklatka\source\repos\Qi-Installer\qi-installer\Qi-Installer\Qi-Installer.ps1'
        OutputPath = 'C:\Users\dklatka\source\repos\Qi-Installer\qi-installer\Qi-Installer\out'
        Package = @{
            Enabled = $true
            Obfuscate = $false
            HideConsoleWindow = $false
            DotNetVersion = 'v4.7'
            FileVersion = '1.0.0'
            FileDescription = 'QiInstaller is a technician installer to be useed by Qi Technicians'
            ProductName = 'Qi-Installer'
            ProductVersion = '1.0.0'
            Copyright = 'Quality IP'
            RequireElevation = $true
            ApplicationIconPath = 'C:\QiInstaller\Qi_ico.ico'
            PackageType = 'Console'
            #PowerShellCore = $true
            HighDPISupport = $true
            PowerShellArguments = '-ExecutionPolicy Bypass -noprofile'
        }
        <#
        Bundle = @{
            Enabled = $true
            Modules = $true
            # IgnoredModules = @()
        }
        #>
    }
    