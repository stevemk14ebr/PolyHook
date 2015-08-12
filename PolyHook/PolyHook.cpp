// PolyHook.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "PolyHook.h"

typedef int(__stdcall* tNoParams)(int intparam);
tNoParams oNoParams;

typedef void(__stdcall* tVirtNoParams)(DWORD_PTR pThis);
tVirtNoParams oVirtNoParams;

typedef void(__stdcall* tSleep)(DWORD dwTime);
tSleep oSleep;
void __stdcall hkSleep(DWORD dwTime)
{
	printf("Called hk Sleep:%d\n",dwTime);
	oSleep(dwTime);
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

void hkVirtNoParams(DWORD_PTR pThis)
{
	printf("hk Virt Called\n");
	return oVirtNoParams(pThis);
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
	PLH::Detour* Hook = new PLH::Detour();
	Hook->SetupHook(&NoParams, &hkNoParams); //can cast to byte* to
	Hook->Hook();
	oNoParams = Hook->GetOriginal<tNoParams>();
	NoParams(98);
	Hook->UnHook();
	NoParams(99);

	/*PLH::IATHook* Hook = new PLH::IATHook();
	Hook->SetupHook("kernel32.dll", "sleep", (BYTE*)&hkSleep);
	Hook->Hook();
	oSleep = Hook->GetOriginal<tSleep>();
	Sleep(100);
	Hook->UnHook();*/

	///x86/x64 VFuncDetour Example
	VirtualTest* ClassToHook = new VirtualTest();
	/*PLH::VFuncDetour* VirtHook = new PLH::VFuncDetour();
	VirtHook->SetupHook(*(BYTE***)ClassToHook, 0,(BYTE*)&hkVirtNoParams);
	VirtHook->Hook();
	oVirtNoParams = VirtHook->GetOriginal<tVirtNoParams>();
	ClassToHook->NoParamVirt();
	VirtHook->UnHook();
	ClassToHook->NoParamVirt();*/

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

	Sleep(100000);
	return 0;
}
