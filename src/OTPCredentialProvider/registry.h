#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

DWORD readRegistryConfValueString(
	_In_ PCWSTR confValueName,
	_Outptr_result_nullonfailure_ PWSTR *data, _In_ PWSTR defaultValue);

DWORD readRegistryConfValueInteger(
	_In_ PCWSTR confKeyName,
	_In_ DWORD defaultValue);


DWORD readRegistryValueString(
	_In_ HKEY rootKeyValue,
	_In_ PCWSTR confKeyName,
	_In_ PCWSTR confValueName,
	_Outptr_result_nullonfailure_ PWSTR *data, _In_ PWSTR defaultValue);

DWORD readRegistryValueInteger(_In_ HKEY rootKeyValue,
	_In_ PCWSTR confKeyName,
	_In_ PCWSTR confValueName,
	_In_ DWORD defaultValue);
