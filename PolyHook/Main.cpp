// PolyHook.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include "PolyHook.h"
#define PLH_SHOW_DEBUG_MESSAGES 1 //To print messages even in release

typedef int(__stdcall* tMessageBoxA)(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType);
tMessageBoxA oMessageBoxA;

typedef void(__stdcall* tVirtNoParams)(DWORD_PTR pThis);
tVirtNoParams oVirtNoParams;

typedef void(__stdcall* tGetCurrentThreadId)();
tGetCurrentThreadId oGetCurrentThreadID;

typedef int(__stdcall* tVEH)(int intparam);
tVEH oVEHTest;

std::shared_ptr<PLH::VEHHook> VEHHook_Ex;

DWORD __stdcall hkGetCurrentThreadId()
{
	printf("Called hkGetCurrentThreadID\n");
	return 1337;
}

int __stdcall hkMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	printf("In Hook\n");
	return oMessageBoxA(hWnd, lpText, lpCaption, uType);
}

void __stdcall hkVirtNoParams(DWORD_PTR pThis)
{
	printf("hk Virt Called\n");
	return oVirtNoParams(pThis);
}

__declspec(noinline) int __stdcall VEHTest(int param)
{
	printf("VEHFunc %d\n",param);
	return 3;
}

__declspec(noinline) int __stdcall hkVEHTest(int param)
{
	printf("hkVEH %d\n",param);
	auto ProtectionObject = VEHHook_Ex->GetProtectionObject();

	return oVEHTest(param);
}

class VirtualTest
{
public:
	virtual void NoParamVirt()
	{
		volatile int x = 0;
		printf("Called Virt\n");
	}
	virtual void BS()
	{
		volatile int y = 0;
	}
};

int _tmain(int argc, _TCHAR* argv[])
{
	std::vector<std::shared_ptr<PLH::IHook>> Hooks;

	///X86/x64 Detour Example
	std::shared_ptr<PLH::Detour> Detour_Ex(new PLH::Detour);
	Detour_Ex->SetupHook((BYTE*)&MessageBoxA,(BYTE*) &hkMessageBoxA); //can cast to byte* to
	Detour_Ex->Hook();
	oMessageBoxA = Detour_Ex->GetOriginal<tMessageBoxA>();
	MessageBoxA(NULL, "Message", "Sample", MB_OK);
	Detour_Ex->UnHook();
	MessageBoxA(NULL, "Message", "Sample", MB_OK);
	Hooks.push_back(Detour_Ex);

	///x86/x64 IAT Hook Example
	//std::shared_ptr<PLH::IATHook> IATHook_Ex(new PLH::IATHook);
	//IATHook_Ex->SetupHook("kernel32.dll", "GetCurrentThreadId", (BYTE*)&hkGetCurrentThreadId);
	//IATHook_Ex->Hook();
	//oGetCurrentThreadID = IATHook_Ex->GetOriginal<tGetCurrentThreadId>();
	//printf("Thread ID:%d \n", GetCurrentThreadId());
	//IATHook_Ex->UnHook();
	//printf("Real Thread ID:%d\n", GetCurrentThreadId());
	//Hooks.push_back(IATHook_Ex);

	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);
	///x86/x64 VFuncDetour Example
	/*std::shared_ptr<PLH::VFuncDetour> VFuncDetour_Ex(new PLH::VFuncDetour);
	VFuncDetour_Ex->SetupHook(*(BYTE***)ClassToHook.get(), 0, (BYTE*)&hkVirtNoParams);
	VFuncDetour_Ex->Hook();
	oVirtNoParams = VFuncDetour_Ex->GetOriginal<tVirtNoParams>();
	ClassToHook->NoParamVirt();
	VFuncDetour_Ex->UnHook();
	ClassToHook->NoParamVirt();
	Hooks.push_back(VFuncDetour_Ex);*/

	///x86/x64 VFuncSwap Example
	//std::shared_ptr<PLH::VFuncSwap> VFuncSwap_Ex(new PLH::VFuncSwap);
	//VFuncSwap_Ex->SetupHook(*(BYTE***)ClassToHook.get(), 0, (BYTE*)&hkVirtNoParams);
	//VFuncSwap_Ex->Hook();
	//oVirtNoParams = VFuncSwap_Ex->GetOriginal<tVirtNoParams>();
	//ClassToHook->NoParamVirt();
	//VFuncSwap_Ex->UnHook();
	//ClassToHook->NoParamVirt();
	//Hooks.push_back(VFuncSwap_Ex);

	///x86/x64 VTableSwap Example
	/*std::shared_ptr<PLH::VTableSwap> VTableSwap_Ex(new PLH::VTableSwap);
	VTableSwap_Ex->SetupHook((BYTE*)ClassToHook.get(), 0, (BYTE*)&hkVirtNoParams);
	VTableSwap_Ex->Hook();
	oVirtNoParams = VTableSwap_Ex->GetOriginal<tVirtNoParams>();
	ClassToHook->NoParamVirt();
	VTableSwap_Ex->UnHook();
	ClassToHook->NoParamVirt();
	Hooks.push_back(VTableSwap_Ex);*/

	/*!!!!IMPORTANT!!!!!: Since this demo is small it's possible for internal methods to be on the same memory page
	as the VEHTest function. If that happens the GUARD_PAGE type method will fail with an unexpected exception. 
	If this method is used in larger applications this risk is incredibly small, to the point where it should not
	be worried about. You CANNOT run this demo under a debugger when using VEH type
	*/
	///x86/x64 VEH Example (GUARD_PAGE and INT3_BP)
	/*VEHHook_Ex = std::make_shared<PLH::VEHHook>();
	VEHHook_Ex->SetupHook((BYTE*)&VEHTest, (BYTE*)&hkVEHTest, PLH::VEHHook::VEHMethod::INT3_BP);
	VEHHook_Ex->Hook();
	oVEHTest = VEHHook_Ex->GetOriginal<tVEH>();
	VEHTest(3);
	VEHHook_Ex->UnHook();
	VEHTest(1);
	Hooks.push_back(VEHHook_Ex);*/


	for (auto&& HookInstance : Hooks)
	{
		HookInstance->PrintError(HookInstance->GetLastError());
	}
	Sleep(100000);
	return 0;
}
