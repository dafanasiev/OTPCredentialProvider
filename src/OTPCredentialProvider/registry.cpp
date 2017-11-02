#include "registry.h"
#include "guid.h"
#include "helpers.h"
#include "Logger.h"

DWORD readRegistryValueString(
	_In_ HKEY rootKeyValue,
	_In_ PCWSTR confKeyName,
	_In_ PCWSTR confValueName,
	_Outptr_result_nullonfailure_ PWSTR *data, 
	_In_ PWSTR defaultValue) {

	DWORD dwSize = 0;
	*data = nullptr;

	PrintLn(L"Reading REGISTRY Key: ", confKeyName, L"\\", confValueName);

	DWORD keyType = 0;
	DWORD dataSize = 0;
	const DWORD flags = RRF_RT_REG_SZ; // Only read strings (REG_SZ)
	LONG result = ::RegGetValue(
		rootKeyValue,
		confKeyName,
		confValueName,
		flags,
		&keyType,
		nullptr,    // pvData == nullptr --> Request buffer size for string
		&dataSize);
	if ((result == ERROR_SUCCESS) && (keyType == REG_SZ)) {
		//reserve read return
		*data = (PWSTR)CoTaskMemAlloc(dataSize);
		result = ::RegGetValue(
			rootKeyValue,
			confKeyName,
			confValueName,
			flags,
			nullptr,
			*data, // Write string in this destination buffer
			&dataSize);
		if (result == ERROR_SUCCESS) {
			dwSize = dataSize / sizeof(WCHAR);
			PrintLn("Len %d", dataSize);
			return dwSize;
		}
		else {
			CoTaskMemFree(*data);
			*data = nullptr;
			dwSize = 0;
		}
	}

	dwSize = (DWORD)wcslen(defaultValue);
	*data = (PWSTR)CoTaskMemAlloc(sizeof(wchar_t) * (dwSize + 1));
	wcscpy_s(*data, 1024, defaultValue);
	return dwSize;
}

DWORD readRegistryValueInteger(_In_ HKEY rootKeyValue,
	_In_ PCWSTR confKeyName,
	_In_ PCWSTR confValueName,
	_In_ DWORD defaultValue) {
	DWORD DWdata;
	DWORD dataSize;


	PrintLn(L"Reading REGISTRY Key:", confKeyName, L"\\", confValueName);

	dataSize = sizeof(DWORD);

	LONG result = ::RegGetValue(
		rootKeyValue,
		confKeyName,
		confValueName,
		RRF_RT_REG_DWORD,
		NULL,
		&DWdata,
		&dataSize);

	if (result == ERROR_SUCCESS) {
		return DWdata;
	}
	else {
		PrintLn("ReadRegistryValue: System Error Code ( %d )", result);
		PrintLn("default value: %d", defaultValue);
		return defaultValue;
	}
}


DWORD readRegistryConfValueString(
	_In_ PCWSTR confValueName,
	_Outptr_result_nullonfailure_ PWSTR *data, _In_ PWSTR defaultValue) {

	return readRegistryValueString(HKEY_CLASSES_ROOT, L"CLSID\\" CLSID_COTPCredentialProviderAsString, confValueName, data, defaultValue);
}

DWORD readRegistryConfValueInteger(
	_In_ PCWSTR confValueName,
	_In_ DWORD defaultValue) {

	return readRegistryValueInteger(HKEY_CLASSES_ROOT, L"CLSID\\" CLSID_COTPCredentialProviderAsString, confValueName, defaultValue);
}