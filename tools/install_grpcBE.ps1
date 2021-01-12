param (
    [Parameter(Mandatory=$true)] [bool] $RDPOnly,
    [Parameter(Mandatory=$true)] [string] $serverAddress,
    [Parameter(Mandatory=$true)] [string] $serverApikey,
    [Parameter(Mandatory=$false)] [string] $defaultDomain
)

$SelfDir = $PSScriptRoot
& "$SelfDir\uninstall.ps1"

$DLLName = Join-Path $SelfDir -ChildPath "OTPCredentialProvider.dll"
$DLLPluginName = Join-Path $SelfDir -ChildPath "grpcBE.dll"

$clsid='{1aebb89c-B0A1-4C4D-8B2B-4FF4E0A3D978}'

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction SilentlyContinue | out-null

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$clsid" -Value 'OTPCredentialProvider' | out-null
New-Item -Path "HKCR:\CLSID\$clsid" -Value 'OTPCredentialProvider'  | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'Plugin' -Value $DLLPluginName | out-null

if ($RDPOnly) {
    New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'RDPOnly' -Value 1 | out-null
} else {
    New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'RDPOnly' -Value 0 | out-null
}

New-Item -Path "HKCR:\CLSID\$clsid\InprocServer32" -Value $DLLName | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid\InprocServer32" -PropertyType 'string' -Name 'ThreadingModel' -Value 'Apartment' | out-null

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\$clsid" -Value 'OTPCredentialProvider' | out-null

########################################## plugin config ##########################################
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'grpc.endpoint' -Value $serverAddress | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'grpc.apikey' -Value $serverApikey | out-null

if ("$defaultDomain" -ne "") {
    New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'Defaultdomain' -Value $defaultDomain | out-null
}
