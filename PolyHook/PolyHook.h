#ifndef POLYHOOK_H
#define POLYHOOK_H
#include <capstone.h>
#include <DbgHelp.h>
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"capstone.lib")

namespace PLH {
	class ASMHelper
	{
	public:
		enum DISP
		{
			D_QWORD = 8,
			D_DWORD = 4,
			D_WORD = 2,
			D_BYTE = 1,
			D_INVALID = -1
		};
		DISP GetDisplacementType(const uint8_t DispVal)
		{
			switch (DispVal)
			{
			case 1:
				return DISP::D_BYTE;
			case 2:
				return DISP::D_WORD;
			case 4:
				return DISP::D_DWORD;
			case 8:
				return DISP::D_QWORD;
			default:
				return DISP::D_INVALID;
			}
		}
		template<typename T>
		T GetDisplacement(BYTE* Instruction, const uint32_t Offset)
		{
			T Disp;
			memset(&Disp, 0x00, sizeof(T));
			memcpy(&Disp, &Instruction[Offset], sizeof(T));
			return Disp;
		}
	};

	class IHook
	{
	public:
		IHook() = default;
		virtual void Hook() = 0;
		virtual void UnHook() = 0;
		virtual ~IHook() = default;
	};

	class IDetour :public IHook
	{
	public:
		IDetour():IHook(),m_NeedFree(false){
#ifdef _WIN64
			Initialize(CS_MODE_64);
#else
			Initialize(CS_MODE_32);
#endif // _WIN64
		}
		virtual ~IDetour() {
			cs_close(&m_CapstoneHandle);
		}
		template<typename T>
		void SetupHook(T* Src, T* Dest)
		{
			SetupHook((BYTE*)Src, (BYTE*)Dest);
		}
		void SetupHook(BYTE* Src, BYTE* Dest)
		{
			m_hkSrc = Src;
			m_hkDest = Dest;
		}

		virtual void UnHook() override
		{
			DWORD OldProtection;
			VirtualProtect(m_hkSrc, m_hkLength, PAGE_EXECUTE_READWRITE, &OldProtection);

			memcpy(m_hkSrc, m_Trampoline, m_hkLength); //Copy original from trampoline back to src
			RelocateASM(m_hkSrc, m_hkLength, (DWORD_PTR)m_Trampoline, (DWORD_PTR)m_hkSrc); //Un-Relocate

			VirtualProtect(m_hkSrc, m_hkLength, PAGE_EXECUTE_READWRITE, &OldProtection);
			FlushSrcInsCache();

			FreeTrampoline();
		}

		template<typename T>
		T GetOriginal()
		{
			return (T)m_Trampoline;
		}
	protected:
		template<typename T>
		T CalculateRelativeDisplacement(DWORD64 From, DWORD64 To, DWORD InsSize)
		{
			if (To < From)
				return 0 - (From - To) - InsSize;
			return To - (From + InsSize);
		}
		DWORD CalculateLength(BYTE* Src, DWORD NeededLength)
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
		void RelocateASM(BYTE* Code, DWORD64 CodeSize, DWORD64 From, DWORD64 To)
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
		void _Relocate(cs_insn* CurIns, DWORD64 From, DWORD64 To, const uint8_t DispSize, const uint8_t DispOffset)
		{
			printf("Relocating...\n");
			ASMHelper::DISP DispType = m_ASMInfo.GetDisplacementType(DispSize);
			if (DispType == ASMHelper::DISP::D_BYTE)
			{
				int8_t Disp = m_ASMInfo.GetDisplacement<int8_t>(CurIns->bytes, DispOffset);
				Disp -= (To - From);
				*(int8_t*)(CurIns->address + DispOffset) = Disp;
			}else if (DispType == ASMHelper::DISP::D_WORD) {
				short Disp = Disp = m_ASMInfo.GetDisplacement<short>(CurIns->bytes, DispOffset);
				Disp -= (To - From);
				*(short*)(CurIns->address + DispOffset) = Disp;
			}else if (DispType == ASMHelper::DISP::D_DWORD) {
				long Disp = Disp = m_ASMInfo.GetDisplacement<long>(CurIns->bytes, DispOffset);
				Disp -= (To - From);
				*(long*)(CurIns->address + DispOffset) = Disp;
			}
		}
		virtual x86_reg GetIpReg() = 0;
		virtual void FreeTrampoline() = 0;
		void FlushSrcInsCache()
		{
			FlushInstructionCache(GetCurrentProcess(), m_hkSrc, m_hkLength);
		}
		void Initialize(cs_mode Mode)
		{
			if (cs_open(CS_ARCH_X86, Mode, &m_CapstoneHandle) != CS_ERR_OK)
				printf("Error Initializing Capstone x86\n");

			cs_option(m_CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
		}
		csh m_CapstoneHandle;
		ASMHelper m_ASMInfo;

		BYTE* m_Trampoline;
		bool m_NeedFree;
		BYTE* m_hkSrc;
		BYTE* m_hkDest;
		DWORD m_hkLength;
		cs_mode m_CapMode;
	};

#ifndef _WIN64
#define Detour X86Detour
	//x86 5 Byte Detour
	class X86Detour :public IDetour
	{
	public:
		X86Detour() : IDetour() {}
		~X86Detour() {
			if (m_NeedFree)
				delete[] m_Trampoline;
		}

		virtual void Hook() override
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
	protected:
		virtual x86_reg GetIpReg() override
		{
			return X86_REG_EIP;
		}
		virtual void FreeTrampoline()
		{
			if (m_NeedFree)
			{
				delete[] m_Trampoline;
				m_NeedFree = false;
			}
		}
	};
#else
#define Detour X64Detour
	//X64 6 Byte Detour
	class X64Detour :public IDetour
	{
	public:
		//Credits DarthTon, evolution536
		X64Detour() :IDetour() {}
		~X64Detour()
		{
			FreeTrampoline();
		}

		virtual void Hook() override
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
			DWORD flOld = 0;
			VirtualProtect(m_hkSrc, 6, PAGE_EXECUTE_READWRITE, &flOld);
			m_hkSrc[0] = 0xFF;
			m_hkSrc[1] = 0x25;
			//Write 32Bit Displacement from rip
			*(long*)(m_hkSrc + 2) = CalculateRelativeDisplacement<long>((DWORD64)m_hkSrc, (DWORD64)&m_Trampoline[m_hkLength + 16], 6);
			*(DWORD64*)&m_Trampoline[m_hkLength + 16] = (DWORD64)m_hkDest; //Write the address into memory at [RIP+Displacement]

			//Nop Extra bytes from overwritten opcode
			for (int i = 6; i < m_hkLength; i++)
				m_hkSrc[i] = 0x90;

			FlushInstructionCache(GetCurrentProcess(), m_hkSrc, m_hkLength);
			VirtualProtect(m_hkSrc, 6, flOld, &flOld);
		}
	protected:
		virtual x86_reg GetIpReg() override
		{
			return X86_REG_RIP;
		}
		virtual void FreeTrampoline() override
		{
			if (m_NeedFree)
			{
				VirtualFree(m_Trampoline, 0, MEM_RELEASE);
				m_NeedFree = false;
			}
		}
	};
#endif //END _WIN64 IFDEF

	//Swap Virtual Function Pointer to Destination
	class VFuncSwap : public IHook
	{
	public:
		VFuncSwap() : IHook() {}
		~VFuncSwap() = default;
		virtual void Hook() override
		{
			DWORD OldProtection;
			VirtualProtect(&m_hkVtable[m_hkIndex], sizeof(void*), PAGE_READWRITE, &OldProtection);
			m_OrigVFunc = m_hkVtable[m_hkIndex];
			m_hkVtable[m_hkIndex] = m_hkDest;
			VirtualProtect(&m_hkVtable[m_hkIndex], sizeof(void*), OldProtection, &OldProtection);
		}
		virtual void UnHook() override
		{
			DWORD OldProtection;
			VirtualProtect(&m_hkVtable[m_hkIndex], sizeof(void*), PAGE_READWRITE, &OldProtection);
			m_hkVtable[m_hkIndex] = m_OrigVFunc;
			VirtualProtect(&m_hkVtable[m_hkIndex], sizeof(void*), OldProtection, &OldProtection);
		}
		void SetupHook(BYTE** Vtable, const int Index, BYTE* Dest)
		{
			m_hkVtable = Vtable;
			m_hkDest = Dest;
			m_hkIndex = Index;
		}
		template<typename T>
		T GetOriginal()
		{
			return (T)m_OrigVFunc;
		}
	private:
		BYTE** m_hkVtable;
		BYTE* m_hkDest;
		BYTE* m_OrigVFunc;
		int m_hkIndex;
	};

	//Detour the Function the VTable Points to
	class VFuncDetour :public IHook
	{
	public:
		VFuncDetour() :IHook()
		{
			m_Detour = new Detour();
		}
		~VFuncDetour() {
			delete m_Detour;
		}
		virtual void Hook() override
		{
			m_Detour->Hook();
		}
		virtual void UnHook() override
		{
			m_Detour->UnHook();
		}
		void SetupHook(BYTE** Vtable, const int Index, BYTE* Dest)
		{
			m_Detour->SetupHook(Vtable[Index], Dest);
		}
		template<typename T>
		T GetOriginal()
		{
			return m_Detour->GetOriginal<T>();
		}
	private:
		Detour* m_Detour;
	};

	//Credit to Dogmatt for IsValidPtr
#ifdef _WIN64
#define _PTR_MAX_VALUE ((PVOID)0x000F000000000000)
#else
#define _PTR_MAX_VALUE ((PVOID)0xFFF00000)
#endif
	__forceinline bool IsValidPtr(PVOID p) { return (p >= (PVOID)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr; }

	class VTableSwap : public IHook
	{
	public:
		VTableSwap() :IHook() {
			m_NeedFree = false;
		}
		~VTableSwap()
		{
			FreeNewVtable();
		}
		virtual void Hook() override
		{
			DWORD OldProtection;
			VirtualProtect(m_phkClass, sizeof(void*), PAGE_READWRITE, &OldProtection);
			m_VFuncCount = GetVFuncCount(*m_phkClass);
			m_hkOriginal = *m_phkClass[m_hkIndex];
			m_OrigVtable = *m_phkClass;
			m_NewVtable = (BYTE**) new DWORD_PTR[m_VFuncCount];
			m_NeedFree = true;
			memcpy(m_NewVtable, m_phkClass, sizeof(void*)*m_VFuncCount);
			*m_phkClass = m_NewVtable;
			m_NewVtable[m_hkIndex] = m_hkDest;
			VirtualProtect(m_phkClass, sizeof(void*), OldProtection, &OldProtection);
		}
		virtual void UnHook() override
		{
			DWORD OldProtection;
			VirtualProtect(m_phkClass, sizeof(void*), PAGE_READWRITE, &OldProtection);
			*m_phkClass = m_OrigVtable;
			VirtualProtect(m_phkClass, sizeof(void*), OldProtection, &OldProtection);
			FreeNewVtable();
		}
		void SetupHook(BYTE* pClass, const int Index, BYTE* Dest)
		{
			m_phkClass = (BYTE***)pClass; //ppp is just convenient to work with
			m_hkDest = Dest;
			m_hkIndex = Index;
		}
		template<typename T>
		T GetOriginal()
		{
			return (T)m_hkOriginal;
		}
	private:
		int GetVFuncCount(BYTE** pVtable)
		{
			int FuncCount = 0;
			for (int i = 0; IsValidPtr(m_phkClass[FuncCount]); FuncCount++)
			{
				if (!IsValidPtr(m_phkClass[FuncCount]))
					break;
			}
			return FuncCount;
		}
		void FreeNewVtable()
		{
			if (m_NeedFree)
			{
				delete[] m_NewVtable;
				m_NeedFree = false;
			}
		}
		BYTE** m_NewVtable;
		BYTE** m_OrigVtable;
		BYTE*** m_phkClass;
		BYTE*  m_hkDest;
		BYTE*  m_hkOriginal;
		int    m_hkIndex;
		int    m_VFuncCount;
		bool m_NeedFree;
	};

#define ResolveRVA(base,rva) (( (BYTE*)base) +rva)
	class IATHook:public IHook
	{
	public:
		IATHook() :IHook() {}
		~IATHook() {}
		virtual void Hook() override
		{
			PIMAGE_THUNK_DATA Thunk;
			if (!FindIATFunc(m_hkModule, m_hkSrcFunc, &Thunk))
				return;

			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(Thunk, &mbi, sizeof(mbi));
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
			m_pIATFuncOrig =(void*)Thunk->u1.Function;
#ifdef _WIN64
			Thunk->u1.Function =(ULONGLONG) m_hkDest;
#else
			Thunk->u1.Function =(DWORD) m_hkDest;
#endif // _WIN64
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);
		}
		virtual void UnHook() override
		{
			PIMAGE_THUNK_DATA Thunk;
			if (!FindIATFunc(m_hkModule, m_hkSrcFunc, &Thunk))
				return;

			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(Thunk, &mbi, sizeof(mbi));
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);
#ifdef _WIN64
			Thunk->u1.Function = (ULONGLONG)m_pIATFuncOrig;
#else
			Thunk->u1.Function = (DWORD)m_pIATFuncOrig;
#endif // _WIN64
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);
		}
		template<typename T>
		T GetOriginal()
		{
			return (T)m_pIATFuncOrig;
		}
		void SetupHook(char* Module,char* SrcFunc, BYTE* Dest)
		{
			strcpy_s(m_hkModule,32, Module);
			strcpy_s(m_hkSrcFunc,32, SrcFunc);
			m_hkDest = Dest;
		}
	private:
		bool FindIATFunc(char* ModuleName, char* FuncName,PIMAGE_THUNK_DATA* pFuncThunkOut)
		{
			HINSTANCE hInst = GetModuleHandle(NULL);
			ULONG Sz;
			PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)
				ImageDirectoryEntryToDataEx(hInst, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Sz, nullptr);

			for (int i = 0; pImports[i].Characteristics != 0; i++)
			{
				char* ModuleName = (char*)ResolveRVA(hInst, pImports[i].Name);
				if (_stricmp(ModuleName, ModuleName) != 0)
					continue;

				PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)
					ResolveRVA(hInst, pImports->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
					ResolveRVA(hInst, pImports->FirstThunk);
				for (; pOriginalThunk->u1.Function != NULL; pOriginalThunk++)
				{
					if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
						continue;

					PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)
						ResolveRVA(hInst, pOriginalThunk->u1.AddressOfData);

					if (_stricmp(FuncName, pImport->Name) != 0)
						continue;

					*pFuncThunkOut =pThunk;
					return true;
				}
			}
			return false;
		}
		char m_hkSrcFunc[32];
		char m_hkModule[32];
		BYTE* m_hkDest;
		void* m_pIATFuncOrig;
	};
}//end PLH namespace
#endif//end include guard