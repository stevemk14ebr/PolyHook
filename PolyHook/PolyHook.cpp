#include "PolyHook.h"
PLH::IDetour::IDetour() :IHook(), m_NeedFree(false)
{
#ifdef _WIN64
	Initialize(CS_MODE_64);
#else
	Initialize(CS_MODE_32);
#endif // _WIN64
}

PLH::IDetour::~IDetour()
{
	cs_close(&m_CapstoneHandle);
}

void PLH::IDetour::SetupHook(BYTE* Src, BYTE* Dest)
{
	m_hkSrc = Src;
	m_hkDest = Dest;
}

void PLH::IDetour::UnHook()
{
	DWORD OldProtection;
	VirtualProtect(m_hkSrc, m_hkLength, PAGE_EXECUTE_READWRITE, &OldProtection);

	memcpy(m_hkSrc, m_Trampoline, m_hkLength); //Copy original from trampoline back to src
	RelocateASM(m_hkSrc, m_hkLength, (DWORD_PTR)m_Trampoline, (DWORD_PTR)m_hkSrc); //Un-Relocate

	VirtualProtect(m_hkSrc, m_hkLength, PAGE_EXECUTE_READWRITE, &OldProtection);
	FlushSrcInsCache();

	FreeTrampoline();
}

DWORD PLH::IDetour::CalculateLength(BYTE* Src, DWORD NeededLength)
{
	//Grab First 100 bytes of function, disasm until invalid instruction
	cs_insn* InstructionInfo;
	size_t InstructionCount = cs_disasm(m_CapstoneHandle, Src, 0x100, (uint64_t)Src, 0, &InstructionInfo);

	//Loop over instructions until we have at least NeededLength's Size
	printf("\nORIGINAL:\n");
	DWORD InstructionSize = 0;
	bool BigEnough = false;
	for (int i = 0; i < InstructionCount && !BigEnough; i++)
	{
		cs_insn* CurIns = (cs_insn*)&InstructionInfo[i];
		InstructionSize += CurIns->size;
		if (InstructionSize >= NeededLength)
			BigEnough = true;

		printf("%I64X [%d]: ", CurIns->address, CurIns->size);
		for (int j = 0; j < CurIns->size; j++)
			printf("%02X ", CurIns->bytes[j]);
		printf("%s %s\n", CurIns->mnemonic, CurIns->op_str);
	}
	if (!BigEnough)
		InstructionSize = 0;

	cs_free(InstructionInfo, InstructionCount);
	return InstructionSize;
}

void PLH::IDetour::RelocateASM(BYTE* Code, DWORD64 CodeSize, DWORD64 From, DWORD64 To)
{
	cs_insn* InstructionInfo;
	size_t InstructionCount = cs_disasm(m_CapstoneHandle, Code, CodeSize, (uint64_t)Code, 0, &InstructionInfo);

	printf("\nTrampoline:\n");
	for (int i = 0; i < InstructionCount; i++)
	{
		cs_insn* CurIns = (cs_insn*)&InstructionInfo[i];
		cs_x86* x86 = &(CurIns->detail->x86);

		printf("%I64X: ", CurIns->address);
		for (int j = 0; j < CurIns->size; j++)
			printf("%02X ", CurIns->bytes[j]);
		printf("%s %s\n", CurIns->mnemonic, CurIns->op_str);

		for (int j = 0; j < x86->op_count; j++)
		{
			cs_x86_op* op = &(x86->operands[j]);
			if (op->type == X86_OP_MEM)
			{
				//MEM are types like lea rcx,[rip+0xdead]
				if (op->mem.base == X86_REG_INVALID)
					continue;

				//Are we relative to instruction pointer?
				if (op->mem.base != GetIpReg())
					continue;

				_Relocate(CurIns, From, To, x86->offsets.displacement_size, x86->offsets.displacement_offset);
			}else if (op->type == X86_OP_IMM) {
				//IMM types are like call 0xdeadbeef
				if (x86->op_count > 1) //exclude types like sub rsp,0x20
					continue;

				//types like push 0x20 slip through, check mnemonic
				char* mnemonic = CurIns->mnemonic;
				if (strcmp(mnemonic, "call") != 0 && strcmp(mnemonic, "jmp") != 0) //probably more types than just these, update list as they're found
					continue;

				_Relocate(CurIns, From, To, x86->offsets.imm_size, x86->offsets.imm_offset);
			}
		}
	}

	printf("\nFixed Trampoline\n");
	InstructionCount = cs_disasm(m_CapstoneHandle, Code, CodeSize, (uint64_t)Code, 0, &InstructionInfo);
	for (int i = 0; i < InstructionCount; i++)
	{
		cs_insn* CurIns = (cs_insn*)&InstructionInfo[i];
		cs_x86* x86 = &(CurIns->detail->x86);

		printf("%I64X: ", CurIns->address);
		for (int j = 0; j < CurIns->size; j++)
			printf("%02X ", CurIns->bytes[j]);
		printf("%s %s\n", CurIns->mnemonic, CurIns->op_str);
	}
	cs_free(InstructionInfo, InstructionCount);
}

void PLH::IDetour::_Relocate(cs_insn* CurIns, DWORD64 From, DWORD64 To, const uint8_t DispSize, const uint8_t DispOffset)
{
	printf("Relocating...\n");
	ASMHelper::DISP DispType = m_ASMInfo.GetDisplacementType(DispSize);
	if (DispType == ASMHelper::DISP::D_BYTE)
	{
		int8_t Disp = m_ASMInfo.GetDisplacement<int8_t>(CurIns->bytes, DispOffset);
		Disp -= (To - From);
		*(int8_t*)(CurIns->address + DispOffset) = Disp;
	}else if (DispType == ASMHelper::DISP::D_WORD) {
		int16_t Disp = Disp = m_ASMInfo.GetDisplacement<int16_t>(CurIns->bytes, DispOffset);
		Disp -= (To - From);
		*(short*)(CurIns->address + DispOffset) = Disp;
	}else if (DispType == ASMHelper::DISP::D_DWORD) {
		int32_t Disp = Disp = m_ASMInfo.GetDisplacement<int32_t>(CurIns->bytes, DispOffset);
		Disp -= (To - From);
		*(long*)(CurIns->address + DispOffset) = Disp;
	}
}

void PLH::IDetour::FlushSrcInsCache()
{
	FlushInstructionCache(GetCurrentProcess(), m_hkSrc, m_hkLength);
}

void PLH::IDetour::Initialize(cs_mode Mode)
{
	if (cs_open(CS_ARCH_X86, Mode, &m_CapstoneHandle) != CS_ERR_OK)
		printf("Error Initializing Capstone x86\n");

	cs_option(m_CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}

/*----------------------------------------------*/
#ifndef _WIN64
PLH::X86Detour::X86Detour() : IDetour()
{

}

PLH::X86Detour::~X86Detour()
{
	if (m_NeedFree)
		delete[] m_Trampoline;
}

void PLH::X86Detour::Hook()
{
	DWORD OldProtection;

	m_hkLength = CalculateLength(m_hkSrc, 5);
	if (m_hkLength == 0)
	{
		printf("Function to small to hook\n");
		return;
	}

	m_Trampoline = new BYTE[m_hkLength + 5];   //Allocate Space for original plus 5 to jump back
	VirtualProtect(m_Trampoline, m_hkLength + 5, PAGE_EXECUTE_READWRITE, &OldProtection); //Allow Execution
	m_NeedFree = true;

	memcpy(m_Trampoline, m_hkSrc, m_hkLength); //Copy original into allocated space
	RelocateASM(m_Trampoline, m_hkLength, (DWORD)m_hkSrc, (DWORD)m_Trampoline);
	m_Trampoline[m_hkLength] = 0xE9;       //Write jump opcode to jump back to non overwritten code
	*(long*)(m_Trampoline + m_hkLength + 1) = CalculateRelativeDisplacement<long>((DWORD)&m_Trampoline[m_hkLength], (DWORD)m_hkSrc + m_hkLength, 5); //Encode the jump back to original code

	//Change protection to allow write on original function
	VirtualProtect(m_hkSrc, m_hkLength, PAGE_EXECUTE_READWRITE, &OldProtection);

	//Encode Jump from Hooked Function to the Destination function
	m_hkSrc[0] = 0xE9;
	*(long*)(m_hkSrc + 1) = CalculateRelativeDisplacement<long>((DWORD)m_hkSrc, (DWORD)m_hkDest, 5);

	//Write nops over bytes of overwritten instructions
	for (int i = 5; i < m_hkLength; i++)
		m_hkSrc[i] = 0x90;
	FlushSrcInsCache();
	//Revert to old protection on original function
	VirtualProtect(m_hkSrc, m_hkLength, OldProtection, &OldProtection);
	/*Original
	-JMP Destination
	-NOP (extends to length of overwritten opcode)
	-Rest of function

	Destination
	-Do your shit
	-Return Trampoline (goes to trampoline)

	Trampoline
	-Execute Overwritten Opcodes
	-JMP Rest of function (in original)
	*/
}

x86_reg PLH::X86Detour::GetIpReg()
{
	return X86_REG_EIP;
}

void PLH::X86Detour::FreeTrampoline()
{
	if (m_NeedFree)
	{
		delete[] m_Trampoline;
		m_NeedFree = false;
	}
}
#else
PLH::X64Detour::X64Detour() :IDetour()
{

}

PLH::X64Detour::~X64Detour()
{
	FreeTrampoline();
}

void PLH::X64Detour::Hook()
{
	//Allocate Memory as close as possible to src, to minimize chance 32bit displacements will be out of range (if out of range relocation will fail)
	MEMORY_BASIC_INFORMATION mbi;
	for (size_t Addr = (size_t)m_hkSrc; Addr > (size_t)m_hkSrc - 0x80000000; Addr = (size_t)mbi.BaseAddress - 1)
	{
		if (!VirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
			break;

		if (mbi.State != MEM_FREE)
			continue;

		if (m_Trampoline = (BYTE*)VirtualAlloc(mbi.BaseAddress, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
			break;
	}

	if (!m_Trampoline)
		return;
	m_NeedFree = true;

	/*push rax
	mov rax ...   //Address to original
	xchg qword ptr ss:[rsp], rax
	ret*/
	BYTE detour[] = { 0x50, 0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x87, 0x04, 0x24, 0xC3 };
	m_hkLength = CalculateLength(m_hkSrc, 16);
	if (m_hkLength == 0)
	{
		printf("Function to small to hook\n");
		return;
	}
	memcpy(m_Trampoline, m_hkSrc, m_hkLength);
	RelocateASM(m_Trampoline, m_hkLength, (DWORD64)m_hkSrc, (DWORD64)m_Trampoline);
	memcpy(&m_Trampoline[m_hkLength], detour, sizeof(detour));
	*(DWORD64*)&m_Trampoline[m_hkLength + 3] = (DWORD64)m_hkSrc + m_hkLength;

	// Build a far jump to the Destination function. (jmps not to address pointed at but to the value in the address)
	MemoryProtect Protector = MemoryProtect(m_hkSrc, 6, PAGE_EXECUTE_READWRITE);
	m_hkSrc[0] = 0xFF;
	m_hkSrc[1] = 0x25;
	//Write 32Bit Displacement from rip
	*(long*)(m_hkSrc + 2) = CalculateRelativeDisplacement<long>((DWORD64)m_hkSrc, (DWORD64)&m_Trampoline[m_hkLength + 16], 6);
	*(DWORD64*)&m_Trampoline[m_hkLength + 16] = (DWORD64)m_hkDest; //Write the address into memory at [RIP+Displacement]

	//Nop Extra bytes from overwritten opcode
	for (int i = 6; i < m_hkLength; i++)
		m_hkSrc[i] = 0x90;

	FlushInstructionCache(GetCurrentProcess(), m_hkSrc, m_hkLength);
}

x86_reg PLH::X64Detour::GetIpReg()
{
	return X86_REG_RIP;
}

void PLH::X64Detour::FreeTrampoline()
{
	if (m_NeedFree)
	{
		VirtualFree(m_Trampoline, 0, MEM_RELEASE);
		m_NeedFree = false;
	}
}
#endif

/*----------------------------------------------*/
void PLH::VFuncSwap::Hook()
{
	MemoryProtect Protector = MemoryProtect(&m_hkVtable[m_hkIndex], sizeof(void*), PAGE_READWRITE);
	m_OrigVFunc = m_hkVtable[m_hkIndex];
	m_hkVtable[m_hkIndex] = m_hkDest;
}

void PLH::VFuncSwap::UnHook()
{
	MemoryProtect Protector = MemoryProtect(&m_hkVtable[m_hkIndex], sizeof(void*), PAGE_READWRITE);
	m_hkVtable[m_hkIndex] = m_OrigVFunc;
}

void PLH::VFuncSwap::SetupHook(BYTE** Vtable, const int Index, BYTE* Dest)
{
	m_hkVtable = Vtable;
	m_hkDest = Dest;
	m_hkIndex = Index;
}

/*----------------------------------------------*/
PLH::VFuncDetour::VFuncDetour() :IHook()
{
	m_Detour = new Detour();
}

PLH::VFuncDetour::~VFuncDetour()
{
	delete m_Detour;
}

void PLH::VFuncDetour::Hook()
{
	m_Detour->Hook();
}

void PLH::VFuncDetour::UnHook()
{
	m_Detour->UnHook();
}

void PLH::VFuncDetour::SetupHook(BYTE** Vtable, const int Index, BYTE* Dest)
{
	m_Detour->SetupHook(Vtable[Index], Dest);
}

/*----------------------------------------------*/
PLH::VTableSwap::VTableSwap() :IHook()
{
	m_NeedFree = false;
}

PLH::VTableSwap::~VTableSwap()
{
	FreeNewVtable();
}

void PLH::VTableSwap::Hook()
{
	MemoryProtect Protector = MemoryProtect(m_phkClass, sizeof(void*), PAGE_READWRITE);
	m_OrigVtable = *m_phkClass;
	m_hkOriginal = m_OrigVtable[m_hkIndex];
	m_VFuncCount = GetVFuncCount(m_OrigVtable);
	m_NewVtable = (BYTE**) new DWORD_PTR[m_VFuncCount];
	m_NeedFree = true;
	memcpy(m_NewVtable, m_OrigVtable, sizeof(void*)*m_VFuncCount);
	*m_phkClass = m_NewVtable;
	m_NewVtable[m_hkIndex] = m_hkDest;
}

void PLH::VTableSwap::UnHook()
{
	MemoryProtect Protector = MemoryProtect(m_phkClass, sizeof(void*), PAGE_READWRITE);
	*m_phkClass = m_OrigVtable;
	FreeNewVtable();
}

void PLH::VTableSwap::SetupHook(BYTE* pClass, const int Index, BYTE* Dest)
{
	m_phkClass = (BYTE***)pClass; //ppp is just convenient to work with
	m_hkDest = Dest;
	m_hkIndex = Index;
}

int PLH::VTableSwap::GetVFuncCount(BYTE** pVtable)
{
	int FuncCount = 0;
	for (; ; FuncCount++)
	{
		if (!IsValidPtr(pVtable[FuncCount]))
			break;
	}
	return FuncCount;
}

void PLH::VTableSwap::FreeNewVtable()
{
	if (m_NeedFree)
	{
		delete[] m_NewVtable;
		m_NeedFree = false;
	}
}

/*----------------------------------------------*/
void PLH::IATHook::Hook()
{
	PIMAGE_THUNK_DATA Thunk;
	if (!FindIATFunc(m_hkLibraryName.c_str(), m_hkSrcFunc.c_str(), &Thunk,m_hkModuleName.c_str()))
		return;

	MemoryProtect Protector = MemoryProtect(Thunk, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE);
	m_pIATFuncOrig = (void*)Thunk->u1.Function;
	Thunk->u1.Function = (ULONG_PTR)m_hkDest;
}

void PLH::IATHook::UnHook()
{
	PIMAGE_THUNK_DATA Thunk;
	if (!FindIATFunc(m_hkLibraryName.c_str(), m_hkSrcFunc.c_str(), &Thunk))
		return;

	MemoryProtect Protector = MemoryProtect(Thunk, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE);
	Thunk->u1.Function = (ULONG_PTR)m_pIATFuncOrig;
}

void PLH::IATHook::SetupHook(const char* LibraryName,const char* SrcFunc, BYTE* Dest,const char* Module)
{
	m_hkLibraryName = LibraryName;
	m_hkSrcFunc = SrcFunc;
	m_hkModuleName = Module;
	m_hkDest = Dest;
}

bool PLH::IATHook::FindIATFunc(const char* LibraryName,const char* FuncName, PIMAGE_THUNK_DATA* pFuncThunkOut,const char* Module)
{
	bool UseModuleName = true;
	if (Module == NULL || Module[0] == '\0')
		UseModuleName = false;

	HINSTANCE hInst = GetModuleHandleA(UseModuleName ? Module:NULL);
	ULONG Sz;
	PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)
		ImageDirectoryEntryToDataEx(hInst, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Sz, nullptr);

	for (int i = 0; pImports[i].Characteristics != 0; i++)
	{
		char* _ModuleName = (char*)ResolveRVA(hInst, pImports[i].Name);
		if (_stricmp(_ModuleName, LibraryName) != 0)
			continue;

		//Original holds the API Names
		PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)
			ResolveRVA(hInst, pImports->OriginalFirstThunk);

		//FirstThunk is overwritten by PE with API addresses, we change this
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			ResolveRVA(hInst, pImports->FirstThunk);
		
		//Table is null terminated, increment both tables
		for (; pOriginalThunk->u1.Function != NULL; pOriginalThunk++,pThunk++)
		{
			if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;

			PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)
				ResolveRVA(hInst, pOriginalThunk->u1.AddressOfData);

			//Check the name of API given by OriginalFirthThunk
			if (_stricmp(FuncName, pImport->Name) != 0)
				continue;

			/*Name matched in OriginalFirthThunk, return FirstThunk
			so we can changed it's address*/
			*pFuncThunkOut = pThunk;
			return true;
		}
	}
	return false;
}

/*----------------------------------------------*/
std::vector<PLH::VEHHook::HookCtx> PLH::VEHHook::m_HookTargets;
std::vector<PLH::VEHHook::HookCtx> PLH::VEHHook::m_PendingTargets;
PLH::VEHHook::VEHHook()
{
	m_HookTargets = std::vector<PLH::VEHHook::HookCtx>();
	m_PendingTargets = std::vector<PLH::VEHHook::HookCtx>();
	void* pVEH = AddVectoredExceptionHandler(1, &PLH::VEHHook::VEHHandler);
	if (pVEH == nullptr)
		printf("Failed to add VEH\n");
}

void PLH::VEHHook::SetupHook(BYTE* Src, BYTE* Dest)
{
	HookCtx Ctx(Src, Dest);
	m_PendingTargets.push_back(Ctx);
	m_ThisInstance = Ctx;
}

void PLH::VEHHook::Hook()
{
	for (HookCtx& Ctx : m_PendingTargets)
	{
		//Write INT3 BreakPoint
		MemoryProtect Protector(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE);
		Ctx.m_OriginalByte = *Ctx.m_Src;
		*Ctx.m_Src = 0xCC;

		m_HookTargets.push_back(Ctx);
	}
	m_PendingTargets.clear();
}

LONG CALLBACK PLH::VEHHook::VEHHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
#ifdef _WIN64
	#define XIP Rip
#else
	#define XIP Eip
#endif // _WIN64

	DWORD ExceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
	if (ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		for (HookCtx& Ctx : m_HookTargets)
		{
			if (ExceptionInfo->ContextRecord->XIP != (DWORD_PTR)Ctx.m_Src)
				continue;

			//Remove Int3 Breakpoint
			MemoryProtect Protector(Ctx.m_Src, 1, PAGE_EXECUTE_READWRITE);
			*Ctx.m_Src = Ctx.m_OriginalByte;
			
			ExceptionInfo->ContextRecord->XIP = (DWORD_PTR) Ctx.m_Dest;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

/*----------------------------------------------*/
PLH::MemoryProtectDelay::MemoryProtectDelay(void* Address, size_t Size)
{
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(Address, &mbi, Size);
	m_OriginalProtection = mbi.Protect;
	m_Address = Address;
	m_Size = Size;
}

void PLH::MemoryProtectDelay::SetProtection(DWORD ProtectionFlags)
{
	m_DesiredProtection = ProtectionFlags;
}

void PLH::MemoryProtectDelay::ApplyProtection()
{
	VirtualProtect(m_Address, m_Size, m_DesiredProtection, &m_PreviousProtection);
}

void PLH::MemoryProtectDelay::RestoreOriginal()
{
	VirtualProtect(m_Address, m_Size, m_OriginalProtection, &m_PreviousProtection);
}

/*----------------------------------------------*/
PLH::MemoryProtect::MemoryProtect(void* Address, size_t Size, DWORD ProtectionFlags)
{
	m_Address = Address;
	m_Size = Size;
	m_Flags = ProtectionFlags;
	Protect(m_Address, m_Size, m_Flags);
}

bool PLH::MemoryProtect::Protect(void* Address, size_t Size, DWORD ProtectionFlags)
{
	return VirtualProtect(Address, Size, ProtectionFlags, &m_OldProtection);
}

PLH::MemoryProtect::~MemoryProtect()
{
	Protect(m_Address,m_Size, m_OldProtection);
}