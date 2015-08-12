# PolyHook - x86/x64 Hooking Library
**Provides abstract C++ interface  for various hooking methods**

#Hooking Methods*:

1. **_Detour_**
  * Description: Modifies opcode to jmp to hook and allocates a trampoline for jmp back
  * Length Disassembler Support (Capstone)
  * Supports Basic Code Relocation

2. **_Virtual Function Detour_** : 
  * Description: Detours the function pointed to by the Vtable

3. **_Virtual Function Pointer Swap_** 
  * Description: Swaps the pointer in the Vtable to your hook
  
4. **_Virtual Table Pointer Swap_**
  * Description: Swaps the Vtable pointer after copying pointers in source Vtable, 
  then swaps virtual function pointer in the new copy

5. **Import Address Table**
  * Description: Swaps pointer in the input address table to the hook

*All methods support x86 and x64

**RELIES ON MODIFIED CAPSTONE BRANCH, THIS BRANCH CAN BE FOUND HERE:https://github.com/stevemk14ebr/capstone**

Credits to DarthTon, evolution536, Dogmatt

#LICENSE:
BSD 2-Clause (Simplified BSD)
