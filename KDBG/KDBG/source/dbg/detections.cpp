#include "detections.h"
#define NT_GLOBAL_FLAG_DEBUGGED (0x10 | 0x20 | 0x40)

/*
* Here we check if DebugPort is valid. If DebugPort is valid, it means that a debugger is attached.
* DebugPort is located inside the EPROCESS structure.
* VOID* DebugPort; 0x578 -> https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_EPROCESS
* Here we can also use the undocumented function PsGetProcessDebugPort:
* __int64 __fastcall PsGetProcessDebugPort(__int64 a1)
* {
*   return *(_QWORD *)(a1 + 0x578);
* }
*/
bool kdbg::DebugPort()
{
	VOID* DebugPortAddress = *reinterpret_cast<VOID**>((PUCHAR)process + 0x578);
	if (DebugPortAddress)
		return true;

	return false;
}

/*
* Here we check if BeingDebugged is valid. If BeingDebugged is valid, it means that a debugger is attached.
* BeingDebugged is located inside the _PEB structure.
* UCHAR BeingDebugged; 0x2 -> https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_PEB
*/
bool kdbg::BeingDebugged()
{
	UCHAR BeingDebugged{ };
	SIZE_T BytesRead{ };

	NTSTATUS status = MmCopyVirtualMemory(process, (PVOID)((PUCHAR)pebAddress + 0x2), PsGetCurrentProcess(), &BeingDebugged, sizeof(UCHAR), KernelMode, &BytesRead);
	if (NT_SUCCESS(status) && BeingDebugged)
		return true;

	return false;
}

/*
* Here we check the NtGlobalFlag flags to see if the process is created by a debugger.
* NtGlobalFlag is located inside the _PEB structure.
* ULONG NtGlobalFlag; 0xbc -> https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_PEB
* 0xbc for 64-bit windows, 0x68 for 32-bit windows
*/
bool kdbg::NtGlobalFlag()
{
	UCHAR NtGlobalFlag{ };
	SIZE_T BytesRead{ };

	NTSTATUS status = MmCopyVirtualMemory(process, (PVOID)((PUCHAR)pebAddress + 0xbc), PsGetCurrentProcess(), &NtGlobalFlag, sizeof(UCHAR), KernelMode, &BytesRead);
	if (NT_SUCCESS(status) && NtGlobalFlag && NT_GLOBAL_FLAG_DEBUGGED)
		return true;

	return false;
}

/*
* Here we check the DebugObjectHandle. If DebugObjectHandle is valid, it means that a debugger is attached.
* DebugObjectHandle is located inside the EPROCESS structure ( undocumented ).
* Here we access DebugObjectHandle via ZwQueryInformationProcess. -> 0x1e
*/
bool kdbg::DebugObjectHandle()
{
	HANDLE hProcess{ };
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid = { kdbg::processId, nullptr };
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	
	if (!NT_SUCCESS(ZwOpenProcess(&hProcess, STANDARD_RIGHTS_ALL, &oa, &cid)))
		return false;

	HANDLE hDebugObject{ };
	NTSTATUS status = ZwQueryInformationProcess(hProcess, ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), nullptr);

	ZwClose(hProcess);

	if (NT_SUCCESS(status) && hDebugObject != nullptr)
		return true;

	return false;
}


/*
* Here we check the DebugFlags. If DebugFlags is 0, it means that a debugger is attached.
* DebugFlags is located inside the EPROCESS structure ( undocumented ).
* Here we access DebugFlags via ZwQueryInformationProcess. -> 0x1f
*/
bool kdbg::DebugFlags()
{
	HANDLE hProcess{ };
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid = { kdbg::processId, nullptr };
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenProcess(&hProcess, 0x0400, &oa, &cid)))
		return false;

	ULONG hDebugFlags = 0;
	NTSTATUS status = ZwQueryInformationProcess(hProcess, ProcessDebugFlags, &hDebugFlags, sizeof(hDebugFlags), nullptr);
	
	ZwClose(hProcess);

	if (NT_SUCCESS(status) && hDebugFlags == 0)
		return true;

	return false;
}

/*
* Here we check if there are any open debuggers so we can close them, you can add anything you want to the blacklist
*/
void kdbg::ExeCheck()
{
	const PCWSTR blacklisted[] = {
	L"ida.exe",
	L"idaq.exe",
	L"idaq64.exe",
	L"ida64.exe",
	L"x64dbg.exe",
	L"cheatengine-x86_64.exe",
	L"Ghidra.exe",
	L"ollydbg.exe",
	L"HTTPDebuggerUI.exe",
	L"FolderChangesView.exe",
	L"HxD.exe",
	L"Scylla_x64.exe",
	L"Scylla_x86.exe",
	L"ProcessHacker.exe",
	L"x64dbg-unsigned.exe",
	};

	for (int i = 0; i < ARRAYSIZE(blacklisted); i++) {
		HANDLE pid = util::retrieve_pid(blacklisted[i]);
		if (pid) {
			util::terminate_process(pid);
		}
	}
}