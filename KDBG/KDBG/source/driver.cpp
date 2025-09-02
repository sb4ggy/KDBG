#include "dbg/detections.h"

void thread_check()
{
	LARGE_INTEGER interval_short, interval_long;
	interval_short.QuadPart = -5000000; 
	interval_long.QuadPart = -9000000;

	while (true) 
	{
		HANDLE processId = util::retrieve_pid(L"test_program.exe");
		if (!processId)
		{
			if (kdbg::process) {
				ObDereferenceObject(kdbg::process);
				kdbg::process = NULL;
				kdbg::pebAddress = NULL;
			}
			kdbg::processId = NULL;

			kdbg_log("failed to find the target process\n");
			KeDelayExecutionThread(KernelMode, FALSE, &interval_long);
			continue;
		}

		if (processId != kdbg::processId || !kdbg::process)
		{
			PEPROCESS tempProc{};
			NTSTATUS status = PsLookupProcessByProcessId(processId, &tempProc);
			if (!NT_SUCCESS(status))
			{
				KeDelayExecutionThread(KernelMode, FALSE, &interval_long);
				continue;
			}
			if (kdbg::process)
				ObDereferenceObject(kdbg::process);

			kdbg::process = tempProc;
			kdbg::processId = processId;
			kdbg::pebAddress = *reinterpret_cast<PPEB*>((PUCHAR)kdbg::process + 0x550);
		}

		kdbg::ExeCheck();

		if (kdbg::BeingDebugged()) 
			kdbg_log("BeingDebugged: found debugger\n");

		if (kdbg::DebugPort())
			kdbg_log("DebugPort: found debugger\n");

		if (kdbg::NtGlobalFlag()) 
			kdbg_log("NtGlobalFlag: found debugger\n");

		if (kdbg::DebugObjectHandle())
			kdbg_log("DebugObjectHandle: found debugger\n");

		/*
		* Once the debugger is attached the flag will remain there, so if they unplug the debugger it will still detect the DebugFlag!
		*/
		if (kdbg::DebugFlags())
			kdbg_log("DebugFlags: found debugger\n");

		KeDelayExecutionThread(KernelMode, FALSE, &interval_short);
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	kdbg_log("succesfully loaded the driver!\n");

	HANDLE thread{};
	NTSTATUS status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)thread_check, NULL);
	if (status == STATUS_UNSUCCESSFUL) 
	{
		kdbg_log("failed to create the thread!\n");
		return status;
	}

	return STATUS_SUCCESS;
}