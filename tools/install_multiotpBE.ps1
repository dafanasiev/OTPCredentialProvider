param (
    [Parameter(Mandatory=$true)] [bool] $RDPOnly,
    [Parameter(Mandatory=$true)] [string] $multiOTPPath,
    [Parameter(Mandatory=$true)] [int] $multiOTPTimeout
    [Parameter(Mandatory=$false)] [bool] $multiOTPDebug
)

$SelfDir = $PSScriptRoot
& "$SelfDir\uninstall.ps1"

$DLLName = Join-Path $SelfDir -ChildPath "OTPCredentialProvider.dll"
$DLLPluginName = Join-Path $SelfDir -ChildPath "multiotpBE.dll"

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
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'string' -Name 'multiotp.path' -Value $multiOTPPath | out-null
New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiotp.timeout' -Value $multiOTPTimeout | out-null
if($multiOTPDebug) {
	New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiotp.debug' -Value 1 | out-null
} else {
	New-ItemProperty -Path "HKCR:\CLSID\$clsid" -PropertyType 'dword' -Name 'multiotp.debug' -Value 0 | out-null
}