//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// Standard dll required functions and class factory implementation.

#include <windows.h>
#include <unknwn.h>
#include "Dll.h"
#include "helpers.h"
#include "Logger.h"
#include "BEManager.h"
#include "registry.h"

static long g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = NULL; // global dll hinstance

extern HRESULT COTPCredentialProvider_CreateInstance(__in REFIID riid, __deref_out void** ppv);
extern HRESULT CLMSFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_COTPCredentialProvider;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1)
    {
    }

    // IUnknown
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            //hr = COTPCredentialProvider_CreateInstance(riid, ppv);
			if (IID_ICredentialProvider == riid) {
				PrintLn("invoke IID_ICredentialProvider");
				hr = COTPCredentialProvider_CreateInstance(riid, ppv);
			}
			else if (IID_ICredentialProviderFilter == riid) {
				PrintLn("invoke IID_ICredentialProviderFilter");
				hr = CLMSFilter_CreateInstance(riid, ppv);
			}
			else {
				*ppv = NULL;
				hr = CLASS_E_NOAGGREGATION;
				PrintLn("invoke unknown object");
			}

        }
        else
        {
            *ppv = NULL;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CClassFactory()
    {
    }
    long _cRef;
};

HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void **ppv)
{
    *ppv = NULL;

    HRESULT hr;

    if (CLSID_COTPCredentialProvider == rclsid) 
    {
        CClassFactory* pcf = new CClassFactory();
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

void DllAddRef()
{
	PrintLn("DllAddRef");
    long newVal = InterlockedIncrement(&g_cRef);
	if (newVal == 1) {
		PWSTR pluginDllName;
		if (readRegistryConfValueString(L"Plugin", &pluginDllName, L"")) {
			BEManager::Instance()->Load(pluginDllName);
			CoTaskMemFree(pluginDllName);
		}
		else {
			PrintLn("Plugin not set in configuration?");
		}
	}
}

void DllRelease()
{
	PrintLn("DllRelease");
    long newVal = InterlockedDecrement(&g_cRef);
	if (newVal == 0) {
		BEManager::Instance()->UnLoad();
	}
}

STDAPI DllCanUnloadNow()
{
	PrintLn("DllCanUnloadNow?");
	HRESULT rv = (g_cRef > 0) ? S_FALSE : S_OK;
	return rv;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void *)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;
}

