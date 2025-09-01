#pragma once
#include "../utils/utils.h"

namespace kdbg
{
	inline PEPROCESS process{ };
	inline HANDLE processId{ };
	inline uintptr_t ntosbase{ };

	bool DebugPort();
	bool BeingDebugged();
	bool NtGlobalFlag();
	bool DebugObjectHandle();
	bool DebugFlags();
	void ExeCheck();
}