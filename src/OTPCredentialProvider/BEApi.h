#pragma once


#ifdef BE_EXPORTS
#define BE_API EXTERN_C __declspec(dllexport)
#else
#define BE_API EXTERN_C __declspec(dllimport) 
#endif

BE_API int __stdcall Load(void);
BE_API int __stdcall Unload(void);
BE_API int __stdcall CheckTOTP(wchar_t* login, wchar_t* prevCode, wchar_t* code, wchar_t** reason);

