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
#include <TlHelp32.h>
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"capstone.lib")
#define PLH_SHOW_DEBUG_MESSAGES 1 //To print messages even in release

namespace PLH {
	namespace Tools
	{
		inline void XTrace(char* fmt, ...)
		{
			va_list args;
			va_start(args, fmt);
#if defined(_DEBUG) || defined(PLH_SHOW_DEBUG_MESSAGES)
			vfprintf_s(stdout, fmt, args);
#endif
			va_end(args);
		}

		class ThreadHandle
		{
		public:
			//Thread ID, OpenThread's AccessFlag 
			ThreadHandle(DWORD ThreadId, DWORD  DesiredAccessFlags) : m_ThreadId(ThreadId), m_IsSuspended(false)
			{
				m_hThread = OpenThread(DesiredAccessFlags, FALSE, ThreadId);
				if(m_hThread == NULL)
					throw "PolyHook: Failed to open thread in class ThreadHandle";
			}

			//Only allow once instance to control a handle
			ThreadHandle(const ThreadHandle& other) = delete; //copy
			ThreadHandle& operator=(const ThreadHandle& other) = delete; //copy assignment

			//Move
			ThreadHandle(ThreadHandle &&other) noexcept
				: m_IsSuspended(other.m_IsSuspended)
				, m_hThread(other.m_hThread)
				, m_ThreadId(other.m_ThreadId)
			{
				other.m_hThread = nullptr;
				other.m_IsSuspended = false;
			}

			//Move assignment
			ThreadHandle& operator=(ThreadHandle &&other) noexcept
			{
				if (this != &other)
				{
					m_IsSuspended = other.m_IsSuspended;
					m_hThread = other.m_hThread;
					m_ThreadId = other.m_ThreadId;

					other.m_hThread = nullptr;
					other.m_IsSuspended = false;
				}
				return *this;
			}


			//false resumes, true suspends
			void ToggleSuspend(bool Suspend)
			{
				if (Suspend && !m_IsSuspended)
				{
					if(SuspendThread(m_hThread) != -1)
						m_IsSuspended = true;
				}else if (!Suspend && m_IsSuspended){
					if(ResumeThread(m_hThread) != -1)
						m_IsSuspended = false;
				}
			}

			~ThreadHandle()
			{
				if (m_IsSuspended)
					ToggleSuspend(false);

				if (m_hThread)
					CloseHandle(m_hThread);
			}
		private:
			bool m_IsSuspended;
			HANDLE m_hThread;
			DWORD m_ThreadId;
		};

		class ThreadManager
		{
		public:
			void SuspendThreads()
			{
				UpdateThreadList(GetCurrentThreadId());
				for (ThreadHandle& ThreadInstance : m_SuspendedThreads)
				{
					ThreadInstance.ToggleSuspend(true);
				}
			}

			void ResumeThreads()
			{
				for (ThreadHandle& ThreadInstance : m_SuspendedThreads)
				{
					ThreadInstance.ToggleSuspend(false);
				}
			}
		private:
			void UpdateThreadList(DWORD CallingThreadId)
			{
				m_SuspendedThreads.clear();
				HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
				if (h == INVALID_HANDLE_VALUE)
					return;

				THREADENTRY32 te;
				te.dwSize = sizeof(te);
				BOOL Result = FALSE;
				//Loop threads
				for (Result = Thread32First(h, &te), te.dwSize = sizeof(te); Result == TRUE && Thread32Next(h, &te); )
				{
					//Verify size field was set properly
					if (te.dwSize < RTL_SIZEOF_THROUGH_FIELD(THREADENTRY32, th32OwnerProcessID))
						continue;
					
					if (te.th32ThreadID != CallingThreadId && te.th32OwnerProcessID == GetCurrentProcessId())
						m_SuspendedThreads.emplace_back(te.th32ThreadID, THREAD_SUSPEND_RESUME);
				}
				CloseHandle(h);
			}
			std::vector<Tools::ThreadHandle> m_SuspendedThreads;
		};

		inline void* Allocate_2GB_IMPL(uint8_t* pStart,size_t Size,int_fast64_t Delta)
		{
			/*These lambda's let us use a single for loop for both the forward and backward loop conditions.
			I passed delta variable as a parameter instead of capturing it because it is faster, it allows
			the compiler to optimize the lambda into a function pointer rather than constructing
			an anonymous class and incur the extra overhead that involves (negligible overhead but why not optimize)*/
			auto Incrementor = [](int_fast64_t Delta,MEMORY_BASIC_INFORMATION mbi) -> uintptr_t{
				if (Delta > 0)
					return (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
				else
					return (uintptr_t)mbi.BaseAddress - 1; //TO-DO can likely jump much more than 1 byte, figure out what the max is
			};

			auto Comparator = [](long long int Delta,uintptr_t Addr, uintptr_t End)->bool {
				if (Delta > 0)
					return Addr < End;
				else
					return Addr > End;
			};

			//Start at pStart, search 2GB around it (up/down depending on Delta)
			MEMORY_BASIC_INFORMATION mbi;
			for (uintptr_t Addr = (uintptr_t)pStart; Comparator(Delta,Addr, (uintptr_t)pStart + Delta); Addr = Incrementor(Delta,mbi))
			{
				if (!VirtualQuery((LPCVOID)Addr, &mbi, sizeof(mbi)))
					break;

				if (mbi.State != MEM_FREE)
					continue;

				//VirtualAlloc requires 64k aligned addresses
				void* PageBase = (uint8_t*)mbi.BaseAddress - (PtrToUlong(mbi.BaseAddress) & 0xffff);
				if (void* Allocated = (uint8_t*)VirtualAlloc(PageBase, Size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
					return Allocated;
			}
			return nullptr;
		}

		inline void* AllocateWithin2GB(uint8_t* pStart, size_t Size, size_t& AllocationDelta)
		{
			//Attempt to allocate +-2GB from pStart
			AllocationDelta = 0;
			void* Allocated = nullptr;
			Allocated = Tools::Allocate_2GB_IMPL(pStart, Size, 0xFFFFFFFF80000000); //Search down first (-2GB) (~0x80000000+1)

			//If search down found nothing
			if (Allocated == nullptr)
				Allocated = Tools::Allocate_2GB_IMPL(pStart, Size,0x80000000); //Search up (+2GB)

			//Sanity check the delta is less than 2GB
			if (Allocated != nullptr)
			{
				AllocationDelta = std::abs(pStart - Allocated);
				if (AllocationDelta > 0x80000000)
				{
					//Out of range, free then return
					VirtualFree(Allocated, 0, MEM_RELEASE);
					return nullptr;
				}
			}
			return Allocated;
		}
	}

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
		bool IsConditionalJump(const uint8_t* bytes,const uint16_t Size)
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
		T GetDisplacement(uint8_t* Instruction, const uint32_t Offset)
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
			SetupHook((uint8_t*)Src, (uint8_t*)Dest);
		}
		void SetupHook(uint8_t* Src, uint8_t* Dest);

		virtual void UnHook() override;

		template<typename T>
		T GetOriginal()
		{
			return (T)m_Trampoline;
		}
	protected:
		template<typename T>
		T CalculateRelativeDisplacement(uintptr_t From,uintptr_t To, uint_fast32_t InsSize)
		{
			if (To < From)
				return 0 - (From - To) - InsSize;
			return To - (From + InsSize);
		}
		uint_fast32_t CalculateLength(uint8_t* Src, uint_fast32_t NeededLength);
		void RelocateASM(uint8_t* Code, uint_fast32_t* CodeSize, const uintptr_t From, const uintptr_t To);
		void _Relocate(cs_insn* CurIns, const uintptr_t From, const uintptr_t To, const uint8_t DispSize, const uint8_t DispOffset);
		void RelocateConditionalJMP(cs_insn* CurIns, uint_fast32_t* CodeSize, const uintptr_t From, const uintptr_t To, const uint8_t DispSize, const uint8_t DispOffset);
		virtual x86_reg GetIpReg() = 0;
		virtual void FreeTrampoline() = 0;
		virtual void WriteJMP(uintptr_t From, uintptr_t To) = 0;
		virtual int GetJMPSize() = 0;
		void FlushSrcInsCache();
		void Initialize(cs_mode Mode);
		csh m_CapstoneHandle;
		ASMHelper m_ASMInfo;

		uint8_t m_OriginalCode[64];
		uint_fast32_t m_OriginalLength;
		uint8_t* m_Trampoline;
		bool m_NeedFree;
		bool m_Hooked;
		uint8_t* m_hkSrc;
		uint8_t* m_hkDest;
		uint_fast32_t m_hkLength;
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
		virtual void WriteJMP(uintptr_t From, uintptr_t To);
		virtual int GetJMPSize();
	private:
		void WriteRelativeJMP(uintptr_t Destination, uintptr_t JMPDestination);
		void WriteAbsoluteJMP(uintptr_t Destination, uintptr_t JMPDestination);
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
		virtual void WriteJMP(const uintptr_t From,const uintptr_t To) override;
		virtual int GetJMPSize() override;
	private:
		void WriteAbsoluteJMP(const uintptr_t Destination,const uintptr_t JMPDestination);
	};
#endif //END _WIN64 IFDEF

	//Swap Virtual Function Pointer to Destination
	class VFuncSwap : public IHook
	{
	public:
		VFuncSwap();
		VFuncSwap(VFuncSwap&& other) = default;
		VFuncSwap& operator=(VFuncSwap&& other) = default;
		VFuncSwap(const VFuncSwap& other) = delete;
		VFuncSwap& operator=(const VFuncSwap& other) = delete;
		virtual ~VFuncSwap();

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

		void SetupHook(uint8_t** Vtable, const uint_fast16_t Index, uint8_t* Dest);
		template<typename T>
		T GetOriginal()
		{
			return (T)m_OrigVFunc;
		}
	private:
		uint8_t** m_hkVtable;
		uint8_t* m_hkDest;
		uint8_t* m_OrigVFunc;
		uint_fast16_t m_hkIndex;
		bool m_Hooked;
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

		void SetupHook(uint8_t** Vtable, const uint_fast16_t Index, uint8_t* Dest);
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
		/*We don't need an m_Hooked bool because this 
		detour object above handles the unhook on destruction by itself*/
	};

	//Credit to Dogmatt on unknowncheats.me for IsValidPtr
#ifdef _WIN64
#define _PTR_MAX_VALUE ((void*)0x000F000000000000)
#else
#define _PTR_MAX_VALUE ((void*)0xFFF00000)
#endif
	__forceinline bool IsValidPtr(void* p) { return (p >= (void*)0x10000) && (p < _PTR_MAX_VALUE) && p != nullptr; }

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
		T HookAdditional(const uint_fast16_t Index, uint8_t* Dest)
		{
			//The makes sure we called Hook first
			if (!m_NeedFree)
				return nullptr;

			m_NewVtable[Index] = Dest;
			return (T)m_OrigVtable[Index];
		}
		virtual void UnHook() override;
		void SetupHook(uint8_t* pClass, const uint_fast16_t Index, uint8_t* Dest);
		template<typename T>
		T GetOriginal()
		{
			return (T)m_hkOriginal;
		}
	private:
		uint_fast16_t GetVFuncCount(uint8_t** pVtable);
		void FreeNewVtable();
		uint8_t** m_NewVtable;
		uint8_t** m_OrigVtable;
		uint8_t*** m_phkClass;
		uint8_t*  m_hkDest;
		uint8_t*  m_hkOriginal;
		uint_fast16_t    m_hkIndex;
		uint_fast16_t    m_VFuncCount;
		bool m_NeedFree;
		bool m_Hooked;
	};

#define ResolveRVA(base,rva) (( (uint8_t*)base) +rva)
	class IATHook:public IHook
	{
	public:
		IATHook();
		IATHook(IATHook&& other) = default; //move
		IATHook& operator=(IATHook&& other) = default;//move assignment
		IATHook(const IATHook& other) = delete; //copy
		IATHook& operator=(const IATHook& other) = delete; //copy assignment
		virtual ~IATHook();

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

		template<typename T>
		T GetOriginal()
		{
			return (T)m_pIATFuncOrig;
		}
		void SetupHook(const char* LibraryName,const char* SrcFunc, uint8_t* Dest,const char* Module = "");
	private:
		bool FindIATFunc(const char* LibraryName,const char* FuncName,PIMAGE_THUNK_DATA* pFuncThunkOut,const char* Module = "");
		std::string m_hkSrcFunc;
		std::string m_hkLibraryName;
		std::string m_hkModuleName;
		uint8_t* m_hkDest;
		void* m_pIATFuncOrig;
		bool m_Hooked;
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
		virtual ~VEHHook();

		virtual bool Hook() override;
		virtual void UnHook() override;
		virtual HookType GetType() override;

		template<typename T>
		T GetOriginal()
		{
			return (T)m_ThisCtx.m_Src;
		}
		void SetupHook(uint8_t* Src, uint8_t* Dest, VEHMethod Method);

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
			uint8_t* m_Src;
			uint8_t* m_Dest;
			uint8_t m_StorageByte;
			/*Different methods store different things in this byte,
			INT3_BP = hold the byte overwritten
			HARDWARE_BP = the index of the debug register we used
			GUARD_PAGE = unused*/

			HookCtx(uint8_t* Src, uint8_t* Dest, VEHMethod Method)
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
		static bool AreInSamePage(const uint8_t* Addr1,const uint8_t* Addr2);
		static LONG CALLBACK VEHHandler(EXCEPTION_POINTERS* ExceptionInfo);
		static std::vector<HookCtx> m_HookTargets;
		static std::mutex m_TargetMutex;
		HookCtx m_ThisCtx;
		DWORD m_PageSize;
		bool m_Hooked;
	};
}//end PLH namespace
#endif//end include guard