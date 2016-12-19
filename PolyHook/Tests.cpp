// PolyHook.cpp : Defines the entry point for the console application.
//
#include "PolyHook.hpp"
#define CATCH_CONFIG_MAIN
#include "CatchUnitTest.h"

decltype(&MessageBoxA) oMessageBoxA;
int WINAPI hkMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	int Result = oMessageBoxA(hWnd, "Hooked", lpCaption, uType);
	REQUIRE(strcmp("Message",lpText) == 0);
	return -10;
}

TEST_CASE("Hooks MessageBox", "[Detours]")
{
	std::shared_ptr<PLH::Detour> Detour_Ex(new PLH::Detour);
	REQUIRE(Detour_Ex->GetType() == PLH::HookType::Detour);

	Detour_Ex->SetupHook((BYTE*)&MessageBoxA,(BYTE*) &hkMessageBoxA); //can cast to byte* to
	REQUIRE( Detour_Ex->Hook() );
	oMessageBoxA = Detour_Ex->GetOriginal<decltype(&MessageBoxA)>();

	REQUIRE(MessageBoxA(NULL, "Message", "Sample", MB_OK) == -10); //The return value set by our handler
	Detour_Ex->UnHook();
	REQUIRE(MessageBoxA(NULL, "Message", "Sample", MB_OK) == IDOK);

	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
}

decltype(&WriteProcessMemory) oWriteProcessMemory;
BYTE DummyBuffer2[] = { 0x13,0x24,0x36,0x38 };
BOOL WINAPI hkWriteProcessMemory(HANDLE  hProcess,LPVOID  lpBaseAddress,LPCVOID lpBuffer,SIZE_T  nSize,SIZE_T  *lpNumberOfBytesWritten)
{
	lpBuffer = &DummyBuffer2;
	nSize = sizeof(DummyBuffer2);
	return oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

TEST_CASE("Hooks WriteProcessMemory", "[Detours]")
{
	std::shared_ptr<PLH::Detour> Detour_Ex(new PLH::Detour);
	REQUIRE(Detour_Ex->GetType() == PLH::HookType::Detour);

	Detour_Ex->SetupHook((BYTE*)&WriteProcessMemory, (BYTE*)&hkWriteProcessMemory); //can cast to byte* to
	REQUIRE(Detour_Ex->Hook());
	oWriteProcessMemory = Detour_Ex->GetOriginal<decltype(&WriteProcessMemory)>();

	BYTE Buffer[] = { 0x00,0x12,0x44,0x91 };
	BYTE Buffer2[] = { 0x11,0x21,0x56,0x78};

	REQUIRE(Buffer[0] == 0x00);
	SIZE_T Written = 0;
	WriteProcessMemory(GetCurrentProcess(), &Buffer, &Buffer2, sizeof(Buffer2), &Written);
	REQUIRE(Buffer[0] == 0x13); //Make sure our hook changed the data written to the data in the dummy buffer
	Detour_Ex->UnHook();
	
	Written = 0;
	WriteProcessMemory(GetCurrentProcess(), &Buffer, &Buffer2, sizeof(Buffer2), &Written);
	REQUIRE(Buffer[0] == 0x11);
	
	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
}

decltype(&GetCommandLineA) oGetCommandLine;
int CommandLineVerifier = 0;
LPSTR WINAPI hkGetCommandLineA()
{
	CommandLineVerifier = 1294;
	LPSTR ReturnVal = oGetCommandLine();
	return ReturnVal;
}

TEST_CASE("Hooks GetCommandLine", "[Detours]")
{
	std::shared_ptr<PLH::Detour> Detour_Ex(new PLH::Detour);
	REQUIRE(Detour_Ex->GetType() == PLH::HookType::Detour);

	Detour_Ex->SetupHook((BYTE*)&GetCommandLineA, (BYTE*)&hkGetCommandLineA); //can cast to byte* to
	REQUIRE(Detour_Ex->Hook());
	oGetCommandLine = Detour_Ex->GetOriginal<decltype(&GetCommandLineA)>();

	REQUIRE(CommandLineVerifier == 0);
	GetCommandLineA();
	REQUIRE(CommandLineVerifier == 1294);
	Detour_Ex->UnHook();
	REQUIRE(CommandLineVerifier == 1294);

	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
	REQUIRE(Detour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
}
/////////////////////////////////////////////////////////////////////////////////////////////////

typedef DWORD(__stdcall* tGetCurrentThreadId)();
tGetCurrentThreadId oGetCurrentThreadID;

DWORD __stdcall hkGetCurrentThreadId()
{
	return oGetCurrentThreadID() + 1;
}

typedef BOOL(__stdcall* tBitBlt)(HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
	HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop);
tBitBlt oBitBlt;

//Just an int that gets incremented to verify handler got called for unit tests

int BitBltHookVerifier = 0; 
BOOL __stdcall hkBitBlt(HDC hdcDest, int nXDest, int nYDest, int nWidth, int nHeight,
	HDC hdcSrc, int nXSrc, int nYSrc, DWORD dwRop)
{
	BitBltHookVerifier += 1337;
	return oBitBlt(hdcDest, nXDest, nYDest, nWidth, nHeight, hdcSrc, nXSrc, nYSrc, dwRop);
}

TEST_CASE("Hooks Using IAT", "[IATHOOK]")
{
	std::shared_ptr<PLH::IATHook> IATHook_Ex(new PLH::IATHook);
	DWORD RealThreadId = GetCurrentThreadId();

	REQUIRE(IATHook_Ex->GetType() == PLH::HookType::IAT);

	SECTION("GetCurrentThread Hook")
	{
		IATHook_Ex->SetupHook("kernel32.dll", "GetCurrentThreadId", (BYTE*)&hkGetCurrentThreadId);
		REQUIRE(IATHook_Ex->Hook());
		oGetCurrentThreadID = IATHook_Ex->GetOriginal<tGetCurrentThreadId>();
		REQUIRE(GetCurrentThreadId() == RealThreadId + 1);
		IATHook_Ex->UnHook();
		REQUIRE(GetCurrentThreadId() == RealThreadId);

		REQUIRE(IATHook_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
		REQUIRE(IATHook_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
	}
	SECTION("BitBlt Hook")
	{
		REQUIRE(BitBltHookVerifier == 0);
		IATHook_Ex->SetupHook("Gdi32.dll", "BitBlt", (BYTE*)&hkBitBlt);
		REQUIRE(IATHook_Ex->Hook());
		oBitBlt = IATHook_Ex->GetOriginal<tBitBlt>();
		BitBlt(NULL, 0, 0, 0, 0, NULL, 0, 0, 0);
		REQUIRE(BitBltHookVerifier == 1337);
		IATHook_Ex->UnHook();
		BitBlt(NULL, 0, 0, 0, 0, NULL, 0, 0, 0);
		REQUIRE(BitBltHookVerifier == 1337);

		REQUIRE(IATHook_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
		REQUIRE(IATHook_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////

class VirtualTest
{
public:
	virtual int NoParamVirt()
	{
		return 4;
	}
	virtual int NoParamVirt2()
	{
		return 7;
	}
};

typedef int(__thiscall* tVirtNoParams)(DWORD_PTR pThis);
tVirtNoParams oVirtNoParams;
tVirtNoParams oVirtNoParams2;

int __fastcall hkVirtNoParams(DWORD_PTR pThis)
{
	return oVirtNoParams(pThis) + 1;
}

TEST_CASE("Detours a function pointed to in a virtual table", "[VFuncDetour]")
{
	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);
	std::shared_ptr<PLH::VFuncDetour> VFuncDetour_Ex(new PLH::VFuncDetour);

	int OriginalRetVal = ClassToHook->NoParamVirt();
	REQUIRE(VFuncDetour_Ex->GetType() == PLH::HookType::VFuncDetour);

	VFuncDetour_Ex->SetupHook(*(BYTE***)ClassToHook.get(), 0, (BYTE*)&hkVirtNoParams);
	REQUIRE(VFuncDetour_Ex->Hook());
	oVirtNoParams = VFuncDetour_Ex->GetOriginal<tVirtNoParams>();
	REQUIRE(ClassToHook->NoParamVirt() == OriginalRetVal + 1);
	VFuncDetour_Ex->UnHook();
	REQUIRE(ClassToHook->NoParamVirt() == OriginalRetVal);

	REQUIRE(VFuncDetour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
	REQUIRE(VFuncDetour_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
}

////////////////////////////////////////////////////////////////////////////////////////////////

int __fastcall hkVirtNoParams2(DWORD_PTR pThis)
{
	return oVirtNoParams2(pThis) + 1;
}

TEST_CASE("Replaces the vtable pointer to hook a function", "[VTableSwap]")
{
	std::shared_ptr<VirtualTest> ClassToHook(new VirtualTest);
	std::shared_ptr<PLH::VTableSwap> VTableSwap_Ex(new PLH::VTableSwap);

	REQUIRE(VTableSwap_Ex->GetType() == PLH::HookType::VTableSwap);
	int OriginalRetVal = ClassToHook->NoParamVirt();
	int OriginalRetVal2 = ClassToHook->NoParamVirt2();

	VTableSwap_Ex->SetupHook((BYTE*)ClassToHook.get(), 0, (BYTE*)&hkVirtNoParams);
	REQUIRE(VTableSwap_Ex->Hook());
	oVirtNoParams = VTableSwap_Ex->GetOriginal<tVirtNoParams>();

	REQUIRE(ClassToHook->NoParamVirt() == OriginalRetVal + 1);
	oVirtNoParams2 = VTableSwap_Ex->HookAdditional<tVirtNoParams>(1, (BYTE*)&hkVirtNoParams2);
	REQUIRE(ClassToHook->NoParamVirt2() == OriginalRetVal2 + 1);

	VTableSwap_Ex->UnHook();
	REQUIRE(ClassToHook->NoParamVirt() == OriginalRetVal);
	REQUIRE(ClassToHook->NoParamVirt2() == OriginalRetVal2);


	REQUIRE(VTableSwap_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::UnRecoverable);
	REQUIRE(VTableSwap_Ex->GetLastError().GetSeverity() != PLH::RuntimeError::Severity::Critical);
}

////////////////////////////////////////////////////////////////////////////////////////////////
typedef int(__stdcall* tVEH)(int intparam);
tVEH oVEHTest;
__declspec(noinline) int __stdcall VEHTest(int param)
{
	return 3;
}

std::shared_ptr<PLH::VEHHook> VEHHook_Ex;
__declspec(noinline) int __stdcall hkVEHTest(int param)
{
	auto ProtectionObject = VEHHook_Ex->GetProtectionObject();
	return oVEHTest(param) + 1;
}

TEST_CASE("Hooks a function using vectored exception handler", "[VEHHook]")
{
	////THESE TESTS CANNOT BE RUN IN A DEBUGGER
	//VEHHook_Ex = std::make_shared<PLH::VEHHook>();

	//REQUIRE(VEHHook_Ex->GetType() == PLH::HookType::VEH);
	//int OriginalRetVal = VEHTest(1);

	//SECTION("INT3 Type Breakpoint")
	//{
	//	VEHHook_Ex->SetupHook((BYTE*)&VEHTest, (BYTE*)&hkVEHTest, PLH::VEHHook::VEHMethod::INT3_BP);
	//	REQUIRE(VEHHook_Ex->Hook());
	//	oVEHTest = VEHHook_Ex->GetOriginal<tVEH>();
	//	REQUIRE(VEHTest(3) == OriginalRetVal + 1);
	//	VEHHook_Ex->UnHook();
	//	REQUIRE(VEHTest(3) == OriginalRetVal);
	//}
	//SECTION("Hardware Type Breakpoint")
	//{
	//	VEHHook_Ex->SetupHook((BYTE*)&VEHTest, (BYTE*)&hkVEHTest, PLH::VEHHook::VEHMethod::HARDWARE_BP);
	//	REQUIRE(VEHHook_Ex->Hook());
	//	oVEHTest = VEHHook_Ex->GetOriginal<tVEH>();
	//	REQUIRE(VEHTest(3) == OriginalRetVal + 1);
	//	VEHHook_Ex->UnHook();
	//	REQUIRE(VEHTest(3) == OriginalRetVal);
	//}
	//SECTION("Guard Page Type Hook")
	//{
	//	INFO("This Type may fail, due to the small demo size");
	//	/*!!!!IMPORTANT!!!!!: Since this demo is small it's possible for internal methods to be on the same memory page
	//	as the VEHTest function. If that happens the GUARD_PAGE type method will fail with an unexpected exception.
	//	If this method is used in larger applications this risk is incredibly small, to the point where it should not
	//	be worried about. You CANNOT run this demo under a debugger when using VEH type
	//	*/

	//	VEHHook_Ex->SetupHook((BYTE*)&VEHTest, (BYTE*)&hkVEHTest, PLH::VEHHook::VEHMethod::GUARD_PAGE);
	//	REQUIRE(VEHHook_Ex->Hook());
	//	oVEHTest = VEHHook_Ex->GetOriginal<tVEH>();
	//	REQUIRE(VEHTest(3) == OriginalRetVal + 1);
	//	VEHHook_Ex->UnHook();
	//	REQUIRE(VEHTest(3) == OriginalRetVal);
	//}
}

