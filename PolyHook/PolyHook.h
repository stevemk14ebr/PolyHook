#ifndef POLYHOOK_H
#define POLYHOOK_H
#include <windows.h>
#include "../Capstone/include/capstone.h"
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
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
		IDetour();
		virtual ~IDetour();
		template<typename T>
		void SetupHook(T* Src, T* Dest)
		{
			SetupHook((BYTE*)Src, (BYTE*)Dest);
		}
		void SetupHook(BYTE* Src, BYTE* Dest);

		virtual void UnHook() override;

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
		DWORD CalculateLength(BYTE* Src, DWORD NeededLength);
		void RelocateASM(BYTE* Code, DWORD64 CodeSize, DWORD64 From, DWORD64 To);
		void _Relocate(cs_insn* CurIns, DWORD64 From, DWORD64 To, const uint8_t DispSize, const uint8_t DispOffset);
		virtual x86_reg GetIpReg() = 0;
		virtual void FreeTrampoline() = 0;
		void FlushSrcInsCache();
		void Initialize(cs_mode Mode);
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
		X86Detour();
		~X86Detour();

		virtual void Hook() override;
	protected:
		virtual x86_reg GetIpReg() override;
		virtual void FreeTrampoline();
	};
#else
#define Detour X64Detour
	//X64 6 Byte Detour
	class X64Detour :public IDetour
	{
	public:
		//Credits DarthTon, evolution536
		X64Detour();
		~X64Detour();

		virtual void Hook() override;
	protected:
		virtual x86_reg GetIpReg() override;
		virtual void FreeTrampoline() override;
	};
#endif //END _WIN64 IFDEF

	//Swap Virtual Function Pointer to Destination
	class VFuncSwap : public IHook
	{
	public:
		VFuncSwap() = default;
		~VFuncSwap() = default;
		virtual void Hook() override;
		virtual void UnHook() override;
		void SetupHook(BYTE** Vtable, const int Index, BYTE* Dest);
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
		VFuncDetour();
		~VFuncDetour();
		virtual void Hook() override;
		virtual void UnHook() override;
		void SetupHook(BYTE** Vtable, const int Index, BYTE* Dest);
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
		VTableSwap();
		~VTableSwap();
		virtual void Hook() override;
		template<typename T>
		T HookAdditional(const int Index, BYTE* Dest)
		{
			//The makes sure we called Hook first
			if (!m_NeedFree)
				return nullptr;

			m_NewVtable[Index] = Dest;
			return (T)m_OrigVtable[Index];
		}
		virtual void UnHook() override;
		void SetupHook(BYTE* pClass, const int Index, BYTE* Dest);
		template<typename T>
		T GetOriginal()
		{
			return (T)m_hkOriginal;
		}
	private:
		int GetVFuncCount(BYTE** pVtable);
		void FreeNewVtable();
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
		IATHook() = default;
		~IATHook() = default;
		virtual void Hook() override;
		virtual void UnHook() override;
		template<typename T>
		T GetOriginal()
		{
			return (T)m_pIATFuncOrig;
		}
		void SetupHook(const char* LibraryName,const char* SrcFunc, BYTE* Dest,const char* Module = "");
	private:
		bool FindIATFunc(const char* LibraryName,const char* FuncName,PIMAGE_THUNK_DATA* pFuncThunkOut,const char* Module = "");
		std::string m_hkSrcFunc;
		std::string m_hkLibraryName;
		std::string m_hkModuleName;
		BYTE* m_hkDest;
		void* m_pIATFuncOrig;
	};

	class MemoryProtectDelay
	{
	public:
		void RestoreOriginal();
		void SetProtection(DWORD ProtectionFlags);
		void ApplyProtection();
		MemoryProtectDelay(void* Address, size_t Size);
	private:
		DWORD m_OriginalProtection;
		DWORD m_PreviousProtection;
		DWORD m_DesiredProtection;
		size_t m_Size;
		void* m_Address;
	};

	template<typename Func>
	class FinalAction {
	public:
		FinalAction(Func f) :FinalActionFunc(std::move(f)) {}
		~FinalAction()
		{
			FinalActionFunc();
		}
	private:
		Func FinalActionFunc;

		/*Uses RAII to call a final function on destruction
		C++ 11 version of java's finally (kindof)*/
	};

	template <typename F>
	FinalAction<F> finally(F f) {
		return FinalAction<F>(f);
	}

	class MemoryProtect
	{
	public:
		MemoryProtect(void* Address, size_t Size, DWORD ProtectionFlags);
		~MemoryProtect();
	private:
		bool Protect(void* Address, size_t Size, DWORD ProtectionFlags);
		void* m_Address;
		size_t m_Size;
		DWORD m_Flags;
		DWORD m_OldProtection;
	};

	class VEHHook : public IHook
	{
	public:
		VEHHook();
		~VEHHook() = default;
		virtual void Hook() override;
		virtual void UnHook() override;
		template<typename T>
		T GetOriginal()
		{
			return (T)m_ThisInstance.m_Src;
		}

		void SetupHook(BYTE* Src, BYTE* Dest);

		auto GetProtectionObject()
		{
			//Return an object to restore INT3 BP after return
			return finally([&]() {
				MemoryProtect Protector(m_ThisInstance.m_Src, 1, PAGE_EXECUTE_READWRITE);
				*m_ThisInstance.m_Src = 0xCC;
			});
		}
	protected:
		struct HookCtx {
			BYTE* m_Src;
			BYTE* m_Dest;
			BYTE m_OriginalByte;

			HookCtx(BYTE* Src, BYTE* Dest)
			{
				m_Dest = Dest;
				m_Src = Src;
			}
			HookCtx()
			{

			}
			friend bool operator==(const HookCtx& Ctx1, const HookCtx& Ctx2)
			{
				if (Ctx1.m_Dest == Ctx2.m_Dest && Ctx1.m_Src == Ctx2.m_Src)
					return true;
				return false;
			}
		};
		
	private:
		static LONG CALLBACK VEHHandler(EXCEPTION_POINTERS* ExceptionInfo);
		static std::vector<HookCtx> m_HookTargets;
		static std::mutex m_TargetMutex;
		HookCtx m_ThisInstance;
	};
}//end PLH namespace
#endif//end include guard