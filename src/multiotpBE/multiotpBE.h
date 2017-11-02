// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MULTIOTPBE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MULTIOTPBE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MULTIOTPBE_EXPORTS
#define MULTIOTPBE_API __declspec(dllexport)
#else
#define MULTIOTPBE_API __declspec(dllimport)
#endif

// This class is exported from the multiotpBE.dll
class MULTIOTPBE_API CmultiotpBE {
public:
	CmultiotpBE(void);
	// TODO: add your methods here.
};

extern MULTIOTPBE_API int nmultiotpBE;

MULTIOTPBE_API int fnmultiotpBE(void);
