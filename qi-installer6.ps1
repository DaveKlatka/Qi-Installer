$authserver = 'Autoamte.QualityIP.com'
#Set Default Path
if (!($PSScriptRoot -match $env:SystemDrive)) {
    $ScriptPath = $PSScriptRoot
} else {
    $ScriptPath = "$env:systemDrive\QiInstaller"
}
if (!(Test-Path $ScriptPath\logs)) {
    New-Item -ItemType Directory -Path $ScriptPath\logs | Out-Null
}
$command = @"
    '$authserver = Autoamte.QualityIP.com'
    (New-Object System.Net.WebClient).DownloadString('https://gitlab.com/api/v4/projects/14874591/repository/files/Qi_Installer%2Eps1/raw?ref=master') | Invoke-Expression
"@
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

start-process C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -argumentlist $encodedCommand

<#
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
function fixuri($uri){
    $type = $uri.GetType();
    $fieldInfo = $type.GetField('m_Syntax', ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic));
    $uriParser = $fieldInfo.GetValue($uri);
    $typeUriParser = $uriParser.GetType().BaseType;$fieldInfo = $typeUriParser.GetField('m_Flags', ([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::FlattenHierarchy));
    $uriSyntaxFlags = $fieldInfo.GetValue($uriParser);
    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot 0x2000000);
    $uriSyntaxFlags = $uriSyntaxFlags -band (-bnot 0x20000);
    $fieldInfo.SetValue($uriParser, $uriSyntaxFlags);
};
$uri = New-Object System.Uri -ArgumentList ('https://gitlab.com/api/v4/projects/14874591/repository/files/Qi_Installer%2Eps1/raw?ref=master');
fixuri $uri;
$PrivateToken = 'iZukjgy--jToWBo5Xe1t';
$Header = @{'PRIVATE-TOKEN' = $PrivateToken};
Invoke-restmethod -Headers $Header -Method Get -Uri $URI | Invoke-Expression;
#>