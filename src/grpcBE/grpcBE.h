#include "stdafx.h"
#include "./../OTPCredentialProvider/BEApi.h"

BE_API int __stdcall Load(void);
BE_API int __stdcall Unload(void);
BE_API int __stdcall CheckTOTP(wchar_t* login, wchar_t* prevCode, wchar_t* code, wchar_t** reason);