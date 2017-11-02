// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <Objbase.h>


// TODO: reference additional headers your program requires here
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Shlwapi.lib")
#define BE_EXPORTS
