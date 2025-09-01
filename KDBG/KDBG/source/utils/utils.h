#pragma once
#include "../include.h"

#define to_rva(address, offset) address + (int32_t)((*(int32_t*)(address + offset) + offset) + sizeof(int32_t))
#define kdbg_log(fmt, ...) \
    DbgPrintEx(0, 0, "[kdbg] " fmt, __VA_ARGS__)

namespace util
{
	inline PVOID g_ProcessInfoBuffer = nullptr;
	inline ULONG g_BufferSize = 0;

    uintptr_t find_pattern(uintptr_t Base, CHAR* Pattern, CHAR* Mask);
	uintptr_t retrieve_ntos();
	uintptr_t resolve_address(std::uintptr_t Instruction, ULONG OffsetOffset, ULONG InstructionSize);

	HANDLE retrieve_pid(PCWSTR target_name);
	void terminate_process(HANDLE pid);
}

namespace kernel_funcs
{
	inline INT kmemcmp(const void* s1, const void* s2, size_t n)
	{
		const unsigned char* p1 = (const unsigned char*)s1;
		const unsigned char* end1 = p1 + n;
		const unsigned char* p2 = (const unsigned char*)s2;
		int                   d = 0;
		for (;;) {
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
		}
		return d;
	}

	inline SIZE_T kstrlen(const char* str)
	{
		const char* s;
		for (s = str; *s; ++s);
		return (s - str);
	}
}