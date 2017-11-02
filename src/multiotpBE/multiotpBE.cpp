// multiotpBE.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "./../OTPCredentialProvider/BEApi.h"
#include "./../OTPCredentialProvider/Logger.h"
#include "./../OTPCredentialProvider/registry.h"

HRESULT call_multiotp(_In_ PCWSTR username, _In_ PCWSTR PREV_PIN, _In_ PCWSTR PIN);

struct MULTIOTP_RESPONSE
{
	HRESULT ErrorNum;
	PWSTR MessageText;
};

static const PWSTR const DEFAULT_UNKNOWN_ERROR_TEXT = L"ERROR : Operation failed(and other possible unknown errors)";

static const MULTIOTP_RESPONSE s_rgmultiOTPResponse[] =
{
	{ 0,  L"SUCCES: Token resynchronization complete" },
	{ 10, L"INFO: Access Challenge returned back to the client" },
	{ 11, L"INFO : User successfully created or updated" },
	{ 12, L"INFO : User successfully deleted" },
	{ 13, L"INFO : User PIN code successfully changed" },
	{ 14, L"INFO : Token has been resynchronized successfully" },
	{ 15, L"INFO : Tokens definition file successfully imported" },
	{ 16, L"INFO : QRcode successfully created" },
	{ 17, L"INFO : UrlLink successfully created" },
	{ 18, L"INFO : SMS code request received" },
	{ 19, L"INFO : Requested operation successfully done" },
	{ 21, L"ERROR : User doesn't exist" },
	{ 22, L"ERROR : User already exists" },
	{ 23, L"ERROR : Invalid algorithm" },
	{ 24, L"ERROR : User locked(too many tries)" },
	{ 25, L"ERROR : User delayed(too many tries, but still a hope in a few minutes)" },
	{ 26, L"ERROR : The token has already been used" },
	{ 27, L"ERROR : Resynchronization of the token has failed" },
	{ 28, L"ERROR : Unable to write the changes in the file" },
	{ 29, L"ERROR : Token doesn't exist" },
	{ 30, L"ERROR : At least one parameter is missing" },
	{ 31, L"ERROR : Tokens definition file doesn't exist" },
	{ 32, L"ERROR : Tokens definition file not successfully imported" },
	{ 33, L"ERROR : Encryption hash error, encryption key is not matching" },
	{ 34, L"ERROR : Linked user doesn't exist" },
	{ 35, L"ERROR : User not created" },
	{ 37, L"ERROR : Token already attributed" },
	{ 38, L"ERROR : User is desactivated" },
	{ 39, L"ERROR : Requested operation aborted" },
	{ 41, L"ERROR : SQL error" },
	{ 50, L"ERROR : QRcode not created" },
	{ 51, L"ERROR : UrlLink not created(no provisionable client for this protocol)" },
	{ 60, L"ERROR : No information on where to send SMS code" },
	{ 61, L"ERROR : SMS code request received, but an error occurred during transmission" },
	{ 62, L"ERROR : SMS provider not supported" },
	{ 70, L"ERROR : Server authentication error" },
	{ 71, L"ERROR : Server request is not correctly formatted" },
	{ 72, L"ERROR : Server answer is not correctly formatted" },
	{ 80, L"ERROR : Server cache error" },
	{ 81, L"ERROR : Cache too old for this user, account autolocked" },
	{ 98, L"ERROR : Authentication failed(wrong token length)" },
	{ 99,  DEFAULT_UNKNOWN_ERROR_TEXT },
};

BE_API int __stdcall Load(void) {
	return 0;
}

BE_API int __stdcall Unload(void) {
	return 0;
}

BE_API int __stdcall CheckTOTP(wchar_t* login, wchar_t* prevCode, wchar_t* code, wchar_t** reason) {
	*reason = NULL;
	HRESULT hr = call_multiotp(login, prevCode, code);
	for (DWORD i = 0; i < ARRAYSIZE(s_rgmultiOTPResponse); i++) {
		if (s_rgmultiOTPResponse[i].ErrorNum - hr == 0) {
			*reason = s_rgmultiOTPResponse[i].MessageText;
			break;
		}
	}
	if (*reason == NULL) {
		*reason = DEFAULT_UNKNOWN_ERROR_TEXT;
	}
	return hr;
}



HRESULT call_multiotp(_In_ PCWSTR username, _In_ PCWSTR PREV_PIN, _In_ PCWSTR PIN)
{
	PrintLn("call_multiotp");
	HRESULT hr = E_NOTIMPL;
	wchar_t cmd[1024];
	size_t len;
	
	len = wcslen(username);
	if (wcslen(PREV_PIN) > 0) {
		len += 1;//space char
		len += wcslen(PREV_PIN);
	}
	len += 1;//space char
	len += wcslen(PIN);

	DWORD multiotpDebug = readRegistryConfValueInteger(L"multiotp.debug", 0);
	if (multiotpDebug!=0) {
		wcscpy_s(cmd, 1024, L"-debug ");
	}

	if (wcslen(PREV_PIN) > 0) {
		wcscpy_s(cmd, 1024, L"-resync ");
	}

	//cmd = StrDup(cmd);
	wcscat_s(cmd, 1024, username);
	wcscat_s(cmd, 1024, L" ");

	if (wcslen(PREV_PIN) > 0) {
		wcscat_s(cmd, 1024, PREV_PIN);
		wcscat_s(cmd, 1024, L" ");
	}
	wcscat_s(cmd, 1024, PIN);

	len = wcslen(cmd);
	PrintLn("command len:%d", len);
	PrintLn(cmd);

	PWSTR path;
	if (readRegistryConfValueString(L"multiotp.path", &path, L"c:\\multiotp\\")) {
		DWORD timeout = readRegistryConfValueInteger(L"multiotp.timeout", 60);

		wchar_t appname[1024];
		wcscpy_s(appname, 1024, path);
		size_t npath = wcslen(appname);
		if (appname[npath - 1] != '\\' && appname[npath - 1] != '/') {
			appname[npath] = '\\';
			appname[npath + 1] = '\0';
		}
		wcscat_s(appname, 1024, L"multiotp.exe");

		PrintLn(L"Calling ", appname);

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));
		si.cb = sizeof(si);
		if (::CreateProcessW(appname, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, path, &si, &pi)) {

			DWORD result = WaitForSingleObject(pi.hProcess, (timeout * 1000));

			/*
			Return values:
			WAIT_ABANDONED
			WAIT_OBJECT_0
			WAIT_TIMEOUT
			WAIT_FAILED
			*/
			/*
			switch (result)
			{
			case WAIT_ABANDONED:
			//hr = ENDPOINT_ERROR_WAIT_ABANDONED;
			break;
			case WAIT_OBJECT_0:
			//hr = ENDPOINT_SUCCESS_WAIT_OBJECT_0;
			break;
			case WAIT_TIMEOUT:
			//hr = ENDPOINT_ERROR_WAIT_TIMEOUT;
			break;
			case WAIT_FAILED:
			//hr = ENDPOINT_ERROR_WAIT_FAILED;
			break;
			default:
			//hr = E_FAIL;
			break;
			}
			*/

			PrintLn("WaitForSingleObject result: %d", result);

			if (result == WAIT_OBJECT_0) {
				DWORD exitCode;
				GetExitCodeProcess(pi.hProcess, &exitCode);

				PrintLn("multiOTP.exe Exit Code: %d", exitCode);

				hr = exitCode;
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
			}
		}
		CoTaskMemFree(path);
	}
	return hr;
}