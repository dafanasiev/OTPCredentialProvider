#include "BEManager.h"
#include "helpers.h"
#include "Logger.h"

BEManager *BEManager::s_instance = NULL;

BEManager::BEManager() {
	_hBE = NULL;
	InitializeCriticalSection(&_lock);
}

BEManager::~BEManager() {
	DeleteCriticalSection(&_lock);
}

HRESULT BEManager::UnLoad() {
	EnterCriticalSection(&_lock);
	if (_hBE != NULL) {
		PrintLn(L"Try unload BE");
		int rv = pUnload();
		PrintLn(L"BE unloaded; rv:%d", rv);
		FreeLibrary(_hBE);
		_hBE = NULL;
	}
	
	pUnload = NULL;
	pCheckTOTP = NULL;

	LeaveCriticalSection(&_lock);
	return S_OK;
}


HRESULT BEManager::Load(const wchar_t* dllName) {
	EnterCriticalSection(&_lock);
	PrintLn(L"Try load BE from ", dllName);
	_hBE = LoadLibrary(dllName);
	if (_hBE == NULL) {
		DWORD rv = GetLastError();
		PrintLn(L"Load BE dll failed with error: %#010x", rv);

		LeaveCriticalSection(&_lock);
		return rv;
	}

	PrintLn(L"BE load success");

	pBEApiLoad lpadFn = (pBEApiLoad)GetProcAddress(_hBE, "Load");
	if (lpadFn == NULL) {
		DWORD rv = GetLastError();
		PrintLn(L"GetProcAddress(Load) from BE dll failed with error: %#010x", rv);
	}
	pUnload = (pBEApiLoad)GetProcAddress(_hBE, "Unload");
	if (pUnload == NULL) {
		DWORD rv = GetLastError();
		PrintLn(L"GetProcAddress(Unload) from BE dll failed with error: %#010x", rv);
	}
	pCheckTOTP = (pBEApiCheckTOTP)GetProcAddress(_hBE, "CheckTOTP");
	if (pCheckTOTP == NULL) {
		DWORD rv = GetLastError();
		PrintLn(L"GetProcAddress(CheckTOTP) from BE dll failed with error: %#010x", rv);
	}

	if (lpadFn != NULL) {
		PrintLn(L"Call Load from BE");
		int loadRet = lpadFn();
		if (loadRet != 0) {
			PrintLn(L"BE Load() result is error; code:%d", loadRet);
			pCheckTOTP = NULL;
		}
	}
	else {
		PrintLn(L"Call Load from BE disabled, because GetProcAddress(Load) return NULL");
	}

	LeaveCriticalSection(&_lock);
	return S_OK;
}

HRESULT BEManager::CheckTOTP(const wchar_t* login, const wchar_t* prevCode, const wchar_t* code, wchar_t** reason) {
	if (pCheckTOTP) {
		HRESULT rv = pCheckTOTP(login, prevCode, code, reason);
		PrintLn(L"CheckTOTP from BE dll result code: %#010x", rv);
		return rv;
	}

	PrintLn(L"CheckTOTP from BE cant be called : see Load BE errors");
	*reason = L"BE Init FAILED";
	return E_FAIL;
}