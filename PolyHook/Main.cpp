// PolyHook.cpp : Defines the entry point for the console application.
//
#include <tchar.h>
#include "PolyHook.h"

typedef int(__stdcall* tNoParams)(int intparam);
tNoParams oNoParams;

typedef void(__stdcall* tVirtNoParams)(DWORD_PTR pThis);
tVirtNoParams oVirtNoParams;

typedef void(__stdcall* tGetCurrentThreadId)();
tGetCurrentThreadId oGetCurrentThreadID;

typedef int(__stdcall* tVEH)();
tVEH oVEHTest;

PLH::VEHHook* VEHHook;

DWORD __stdcall hkGetCurrentThreadId()
{
	printf("Called hkGetCurrentThreadID\n");
	return 1337;
}

__declspec(noinline) int __stdcall NoParams(int intparam)
{
	printf("Hello\n");
	volatile int x = 0;
	x += 1;
	x /= 2;

	return intparam + 1;
}

int __stdcall hkNoParams(int intparam)
{
	printf("In Hook\n");
	return oNoParams(intparam);
}

void __stdcall hkVirtNoParams(DWORD_PTR pThis)
{
	printf("hk Virt Called\n");
	return oVirtNoParams(pThis);
}

__declspec(noinline) int __stdcall VEHTest()
{
	printf("VEH\n");
	return 3;
}

int __stdcall hkVEHTest()
{
	printf("hkVEH\n");
	auto ProtectionObject = VEHHook->GetProtectionObject();

	return oVEHTest();
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
	///X86/x64 Detour Example
	//PLH::Detour* Hook = new PLH::Detour();
	//Hook->SetupHook(&NoParams, &hkNoParams); //can cast to byte* to
	//Hook->Hook();
	//oNoParams = Hook->GetOriginal<tNoParams>();
	//NoParams(98);
	//Hook->UnHook();
	//NoParams(99);

	///x86/x64 IAT Hook Example
	/*PLH::IATHook* Hook = new PLH::IATHook();
	Hook->SetupHook("kernel32.dll", "GetCurrentThreadId", (BYTE*)&hkGetCurrentThreadId);
	Hook->Hook();
	oGetCurrentThreadID = Hook->GetOriginal<tGetCurrentThreadId>();
	printf("Thread ID:%d \n", GetCurrentThreadId());
	Hook->UnHook();
	printf("Real Thread ID:%d\n", GetCurrentThreadId());*/

	///x86/x64 VFuncDetour Example
	VirtualTest* ClassToHook = new VirtualTest();
	//PLH::VFuncDetour* VirtHook = new PLH::VFuncDetour();
	//VirtHook->SetupHook(*(BYTE***)ClassToHook, 0, (BYTE*)&hkVirtNoParams);
	//VirtHook->Hook();
	//oVirtNoParams = VirtHook->GetOriginal<tVirtNoParams>();
	//ClassToHook->NoParamVirt();
	//VirtHook->UnHook();
	//ClassToHook->NoParamVirt();

	///x86/x64 VFuncSwap Example
	/*PLH::VFuncSwap* VirtHook = new PLH::VFuncSwap();
	VirtHook->SetupHook(*(BYTE***)ClassToHook, 0, (BYTE*)&hkVirtNoParams);
	VirtHook->Hook();
	oVirtNoParams = VirtHook->GetOriginal<tVirtNoParams>();
	ClassToHook->NoParamVirt();
	VirtHook->UnHook();
	ClassToHook->NoParamVirt();*/

	///x86/x64 VTableSwap Example
	//PLH::VTableSwap* VTableHook = new PLH::VTableSwap();
	//VTableHook->SetupHook((BYTE*)ClassToHook, 0, (BYTE*)&hkVirtNoParams);
	//VTableHook->Hook();
	//oVirtNoParams = VTableHook->GetOriginal<tVirtNoParams>();
	//ClassToHook->NoParamVirt();
	//VTableHook->UnHook();
	//ClassToHook->NoParamVirt();

	VEHHook = new PLH::VEHHook();
	VEHHook->SetupHook((BYTE*)&VEHTest,(BYTE*)&hkVEHTest,PLH::VEHHook::VEHMethod::INT3_BP);
	VEHHook->Hook();
	oVEHTest = VEHHook->GetOriginal<tVEH>();
	VEHTest();
	VEHHook->UnHook();
	VEHTest();

	Sleep(100000);
	return 0;
}
