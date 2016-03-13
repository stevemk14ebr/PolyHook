#ifndef POLYHOOK_H
#define POLYHOOK_H
#include <windows.h>
#include "../Capstone/include/capstone.h"
#include <DbgHelp.h>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <utility>
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"capstone.lib")

namespace PLH {
	class ASMHelper
	{
	public:
		enum DISP
		{
			D_INT64 = 8,
			D_INT32 = 4,
			D_INT16 = 2,
			D_INT8 = 1,
			D_INVALID = -1
		};
		DISP GetDisplacementType(const uint8_t DispVal)
		{
			switch (DispVal)
			{
			case 1:
				return DISP::D_INT8;
			case 2:
				return DISP::D_INT16;
			case 4:
				return DISP::D_INT32;
			case 8:
				return DISP::D_INT64;
			default:
				return DISP::D_INVALID;
			}
		}
		bool IsConditionalJump(const BYTE* bytes,const uint16_t Size)
		{
			//http://unixwiz.net/techtips/x86-jumps.html
			if (Size < 1)
				return false;

			if (bytes[0] == 0x0F && Size > 1)
			{
				if (bytes[1] >= 0x80 && bytes[1] <= 0x8F)
					return true;
			}

			if (bytes[0] >= 0x70 && bytes[0] <= 0x7F)
				return true;

			if (bytes[0] == 0xE3)
				return true;

			return false;
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

	class RuntimeError
	{
	public:
		enum class Severity
		{
			Warning, //Might have an issue
			Critical, //Definitely have an issue, but it's not serious
			UnRecoverable, //Definitely have an issue, it's serious
			NoError //Default
		};
		RuntimeError();
		RuntimeError(Severity Sev, const std::string& Msg);
		virtual ~RuntimeError() = default;
		const Severity GetSeverity() const;
		const std::string GetString() const;
	private:
		Severity m_Severity;
		std::string m_Message;
	};

	enum class HookType
	{
		X86Detour,
		X64Detour,
		VFuncSwap,
		VFuncDetour,
		VTableSwap,
		IAT,
		VEH,
		UNKNOWN
	};
	class IHook
	{
	public:
		IHook() = default;
		IHook(IHook&& other) = default; //move
		IHook& operator=(IHook&& other) = default;//move assignment
		IHook(const IHook& other) = delete; //copy
		IHook& operator=(const IHook& other) = delete; //copy assignment
		virtual ~IHook() = default;

		virtual bool Hook() = 0;
		virtual void UnHook() = 0;
		virtual HookType GetType() = 0;

		virtual RuntimeError GetLastError() const;
		virtual void PrintError(const RuntimeError& Err) const;
		
	protected:
		virtual void PostError(const RuntimeError& Err);
		RuntimeError m_LastError;
	};

	class AbstractDetour :public IHook
	{
	public:
		AbstractDetour();
		AbstractDetour(const AbstractDetour& other) = delete;
		AbstractDetour& operator=(const AbstractDetour& other) = delete;
		virtual ~AbstractDetour();

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
		void RelocateASM(BYTE* Code, DWORD& CodeSize, DWORD64 From, DWORD64 To);
		void _Relocate(cs_insn* CurIns, DWORD64 From, DWORD64 To, const uint8_t DispSize, const uint8_t DispOffset);
		void RelocateConditionalJMP(cs_insn* CurIns, DWORD& CodeSize, DWORD64 From, DWORD64 To, const uint8_t DispSize, const uint8_t DispOffset);
		virtual x86_reg GetIpReg() = 0;
		virtual void FreeTrampoline() = 0;
		virtual void WriteJMP(DWORD_PTR From, DWORD_PTR To) = 0;
		virtual int GetJMPSize() = 0;
		void FlushSrcInsCache();
		void Initialize(cs_mode Mode);
		csh m_CapstoneHandle;
		ASMHelper m_ASMInfo;

		BYTE m_OriginalCode[64];
		DWORD m_OriginalLength;
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
	class X86Detour :public AbstractDetour
	{
	public:
		friend class VFuncDetour;
		X86Detour();
		X86Detour(X86Detour&& other) = default; //move
		X86Detour& operator=(X86Detour&& other) = default;//move assignment
		X86Detour(const X86Detour& other) = delete; //copy
		X86Detour& operator=(const X86Detour& other) = delete; //copy assignment
		virtual ~X86Detour();

		virtual bool Hook() override;
		virtual HookType GetType() override;
	protected:
		virtual x86_reg GetIpReg() override;
		virtual void FreeTrampoline();
		virtual void WriteJMP(DWORD_PTR From, DWORD_PTR To);
		virtual int GetJMPSize();
	private:
		void WriteRelativeJMP(DWORD Destination, DWORD JMPDestination);
	};
#else
#define Detour X64Detour
	//X64 6 Byte Detour
	class X64Detour :public AbstractDetour
	{
	public:
		friend class VFuncDetour;
		//Credits DarthTon, evolution536
		X64Detour();
		X64Detour(X64Detour&& other) = default; //move
		X64Detour& operator=(X64Detour&& other) = default;//move assignment
		X64Detour(const X64Detour& other) = delete; //copy
		X64Detour& operator=(const X64Detour& other) = delete; //copy assignment
		virtual ~X64Detour();

		virtual bool Hook() override;
		virtual HookType GetType() override;
	protected:
		virtual x86_reg GetIpReg() override;
		virtual void FreeTrampoline() override;
		virtual void WriteJMP(DWORD_PTR From, DWORD_PTR To) override;
		virtual int GetJMPSize() override;
	private:
		void WriteAbsoluteJMP(DWORD64 Destination, DWORD64 JMPDestination);
	};
#endif //END _WIN64 IFDEF

	//Swap Virtual Function Pointer to Destination
	class VFuncSwap : public IHook
	{
	public:
		VFuncSwap() = default;
		VFuncSwap(VFuncSwap&& other) = default;
		VFuncSwap& operator=(VFuncSwap&& other) = default;
		VFuncSwap(const VFuncSwap& other) = delete;
		VFuncSwap& operator=(const VFuncSwap& other) = delete;
		virtual ~VFuncSwap() = default;

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

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
		VFuncDetour(VFuncDetour&& other) = default; //move
		VFuncDetour& operator=(VFuncDetour&& other) = default;//move assignment
		VFuncDetour(const VFuncDetour& other) = delete; //copy
		VFuncDetour& operator=(const VFuncDetour& other) = delete; //copy assignment
		virtual ~VFuncDetour();

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

		void SetupHook(BYTE** Vtable, const int Index, BYTE* Dest);
		template<typename T>
		T GetOriginal()
		{
			return m_Detour->GetOriginal<T>();
		}
		virtual RuntimeError GetLastError() const override;
	protected:
		virtual void PostError(const RuntimeError& Err) override;
	private:
		std::unique_ptr<Detour> m_Detour;
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
		VTableSwap(VTableSwap&& other) = default; //move
		VTableSwap& operator=(VTableSwap&& other) = default;//move assignment
		VTableSwap(const VTableSwap& other) = delete; //copy
		VTableSwap& operator=(const VTableSwap& other) = delete; //copy assignment
		virtual ~VTableSwap();

		virtual bool Hook() override;
		virtual HookType GetType() override;

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
		IATHook(IATHook&& other) = default; //move
		IATHook& operator=(IATHook&& other) = default;//move assignment
		IATHook(const IATHook& other) = delete; //copy
		IATHook& operator=(const IATHook& other) = delete; //copy assignment
		virtual ~IATHook() = default;

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

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
		enum class VEHMethod
		{
			INT3_BP,
			HARDWARE_BP,
			GUARD_PAGE,
			ERROR_TYPE
		};
		VEHHook();
		VEHHook(VEHHook&& other) = default; //move
		VEHHook& operator=(VEHHook&& other) = default;//move assignment
		VEHHook(const VEHHook& other) = delete; //copy
		VEHHook& operator=(const VEHHook& other) = delete; //copy assignment
		virtual ~VEHHook() = default;

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

		template<typename T>
		T GetOriginal()
		{
			return (T)m_ThisCtx.m_Src;
		}
		void SetupHook(BYTE* Src, BYTE* Dest,VEHMethod Method);

		auto GetProtectionObject()
		{
				//Return an object to restore INT3_BP after callback is done
			return finally([&]() {
				if (m_ThisCtx.m_Type == VEHMethod::INT3_BP)
				{
					MemoryProtect Protector(m_ThisCtx.m_Src, 1, PAGE_EXECUTE_READWRITE);
					*m_ThisCtx.m_Src = 0xCC;
				}else if (m_ThisCtx.m_Type == VEHMethod::GUARD_PAGE) {
					DWORD OldProtection;
					VirtualProtect(m_ThisCtx.m_Src, 1, PAGE_EXECUTE_READWRITE | PAGE_GUARD, &OldProtection);
				}
			});
		}
	protected:
		struct HookCtx {
			VEHMethod m_Type;
			BYTE* m_Src;
			BYTE* m_Dest;
			BYTE m_StorageByte; 
			/*Different methods store different things in this byte,
			INT3_BP = hold the byte overwritten
			HARDWARE_BP = the index of the debug register we used
			GUARD_PAGE = unused*/

			HookCtx(BYTE* Src, BYTE* Dest,VEHMethod Method)
			{
				m_Dest = Dest;
				m_Src = Src;
				m_Type = Method;
			}
			HookCtx()
			{
				m_Type = VEHMethod::ERROR_TYPE;
			}
			friend bool operator==(const HookCtx& Ctx1, const HookCtx& Ctx2)
			{
				if (Ctx1.m_Dest == Ctx2.m_Dest && Ctx1.m_Src == Ctx2.m_Src && Ctx1.m_Type == Ctx2.m_Type)
					return true;
				return false;
			}
		};
	private:
		static bool AreInSamePage(BYTE* Addr1, BYTE* Addr2);
		static LONG CALLBACK VEHHandler(EXCEPTION_POINTERS* ExceptionInfo);
		static std::vector<HookCtx> m_HookTargets;
		static std::mutex m_TargetMutex;
		HookCtx m_ThisCtx;
		DWORD m_PageSize;
	};
}//end PLH namespace
#endif//end include guard