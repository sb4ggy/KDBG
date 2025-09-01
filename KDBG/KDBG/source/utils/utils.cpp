#include "utils.h"

auto get_pattern(uintptr_t base, size_t range, const char* pattern, const char* mask) -> uintptr_t
{
	const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool
		{
			for (; *mask; ++base, ++pattern, ++mask)
			{
				if (*mask == 'x' && *base != *pattern)
				{
					return false;
				}
			}

			return true;
		};

	range = range - kernel_funcs::kstrlen(mask);

	for (size_t i = 0; i < range; ++i)
	{
		if (check_mask((const char*)base + i, pattern, mask))
		{
			return base + i;
		}
	}

	return NULL;
}

auto util::find_pattern(uintptr_t Base, CHAR* Pattern, CHAR* Mask) -> uintptr_t
{
	IMAGE_NT_HEADERS* Headers{ (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew) };
	IMAGE_SECTION_HEADER* Sections{ IMAGE_FIRST_SECTION(Headers) };

	for (auto i = 0; i < Headers->FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER* Section{ &Sections[i] };

		if (!kernel_funcs::kmemcmp(Section->Name, (".text"), 5) || !kernel_funcs::kmemcmp(Section->Name, ("PAGE"), 4))
		{
			const auto match = get_pattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);

			if (match) {
				return (match);
			}
		}
	}

	return 0;
}

uintptr_t util::resolve_address(std::uintptr_t Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	LONG RipOffset = *(PLONG)(Instruction + OffsetOffset);
	auto ResolvedAddr = (
		Instruction +
		InstructionSize +
		RipOffset);

	return ResolvedAddr;
}

uintptr_t util::retrieve_ntos()
{
	typedef unsigned char uint8_t;
	auto Idt_base = reinterpret_cast<uintptr_t>(KeGetPcr()->IdtBase);
	auto align_page = *reinterpret_cast<uintptr_t*>(Idt_base + 4) >> 0xc << 0xc;

	for (; align_page; align_page -= PAGE_SIZE)
	{
		for (int index = 0; index < PAGE_SIZE - 0x7; index++)
		{
			auto current_address = static_cast<intptr_t>(align_page) + index;

			if (*reinterpret_cast<uint8_t*>(current_address) == 0x48
				&& *reinterpret_cast<uint8_t*>(current_address + 1) == 0x8D
				&& *reinterpret_cast<uint8_t*>(current_address + 2) == 0x1D
				&& *reinterpret_cast<uint8_t*>(current_address + 6) == 0xFF) 
			{
				auto Ntosbase = resolve_address(current_address, 3, 7);
				if (!((UINT64)Ntosbase & 0xfff))
				{
					return Ntosbase;
				}
			}
		}
	}
	return 0;
}

HANDLE util::retrieve_pid(PCWSTR target_name)
{
	NTSTATUS status;
	ULONG requiredSize = 0;

	status = ZwQuerySystemInformation(SystemProcessInformation, nullptr, 0, &requiredSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	if (requiredSize > g_BufferSize) {
		if (g_ProcessInfoBuffer) {
			ExFreePoolWithTag(g_ProcessInfoBuffer, 'enoN');
			g_ProcessInfoBuffer = nullptr;
		}
		g_ProcessInfoBuffer = ExAllocatePoolWithTag(PagedPool, requiredSize, 'enoN');
		g_BufferSize = requiredSize;
	}

	if (!g_ProcessInfoBuffer)
		return nullptr;

	status = ZwQuerySystemInformation(SystemProcessInformation, g_ProcessInfoBuffer, g_BufferSize, &requiredSize);
	if (!NT_SUCCESS(status))
		return nullptr;

	PSYSTEM_PROCESSES processEntry = (PSYSTEM_PROCESSES)g_ProcessInfoBuffer;
	UNICODE_STRING target;
	RtlInitUnicodeString(&target, target_name);

	do {
		if (processEntry->ProcessName.Length) {
			if (RtlEqualUnicodeString(&processEntry->ProcessName, &target, TRUE)) {
				return (HANDLE)processEntry->ProcessId;
			}
		}
		if (!processEntry->NextEntryDelta) break;
		processEntry = (PSYSTEM_PROCESSES)((BYTE*)processEntry + processEntry->NextEntryDelta);
	} while (true);

	return nullptr;
}

void util::terminate_process(HANDLE pid)
{
	if (!pid) return;

	HANDLE hProcess;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID clientId;

	InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	clientId.UniqueProcess = pid;
	clientId.UniqueThread = 0;

	NTSTATUS status = ZwOpenProcess(&hProcess, 0x0001, &objAttr, &clientId);
	if (NT_SUCCESS(status)) {
		ZwTerminateProcess(hProcess, STATUS_SUCCESS);
		ZwClose(hProcess);
	}
}

