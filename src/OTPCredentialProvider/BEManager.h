#pragma once


#include <windows.h>

typedef int (__stdcall *pBEApiLoad)(void);
typedef int (__stdcall *pBEApiUnload)(void);
typedef int (__stdcall *pBEApiCheckTOTP)(const wchar_t* login, const wchar_t* prevCode, const wchar_t* code, wchar_t** reason);

class BEManager {
private:
	BEManager();
	~BEManager();
	static BEManager *s_instance;
public:
	static BEManager *Instance() {
		if (!s_instance) {
			s_instance = new BEManager();
		}
		return s_instance;
	}
	HRESULT UnLoad();
	HRESULT Load(const wchar_t* dllName);
	HRESULT CheckTOTP(const wchar_t* login, const wchar_t* prevCode, const wchar_t* code, wchar_t** reason);
private:
	CRITICAL_SECTION _lock;
	HMODULE _hBE;
	pBEApiUnload pUnload;
	pBEApiCheckTOTP pCheckTOTP;
};