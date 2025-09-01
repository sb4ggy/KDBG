#pragma once
#include <ntifs.h>
#include <cstdint>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <wdf.h>
#include <ntddk.h>
#include <ntimage.h>
#pragma comment(lib, "ntoskrnl.lib")

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern "C" NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
extern "C" NTSYSCALLAPI NTSTATUS ZwQueryInformationProcess(_In_ HANDLE ProcessHandle,_In_ PROCESSINFOCLASS ProcessInformationClass,_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation, _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
extern "C" PLIST_ENTRY NTKERNELAPI PsLoadedModuleList;
extern "C" PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ProcessName;
	KPRIORITY        BasePriority;
	SIZE_T           ProcessId;
	SIZE_T           InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;
	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	/* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
	/* 0x0010 */ void* ExceptionTable;
	/* 0x0018 */ unsigned long ExceptionTableSize;
	/* 0x001c */ long Padding_687;
	/* 0x0020 */ void* GpValue;
	/* 0x0028 */ struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	/* 0x0030 */ void* DllBase;
	/* 0x0038 */ void* EntryPoint;
	/* 0x0040 */ unsigned long SizeOfImage;
	/* 0x0044 */ long Padding_688;
	/* 0x0048 */ struct _UNICODE_STRING FullDllName;
	/* 0x0058 */ struct _UNICODE_STRING BaseDllName;
	/* 0x0068 */ unsigned long Flags;
	/* 0x006c */ unsigned short LoadCount;
	union
	{
		union
		{
			struct /* bitfield */
			{
				/* 0x006e */ unsigned short SignatureLevel : 4; /* bit position: 0 */
				/* 0x006e */ unsigned short SignatureType : 3; /* bit position: 4 */
				/* 0x006e */ unsigned short Unused : 9; /* bit position: 7 */
			}; /* bitfield */
			/* 0x006e */ unsigned short EntireField;
		}; /* size: 0x0002 */
	} /* size: 0x0002 */ u1;
	/* 0x0070 */ void* SectionPointer;
	/* 0x0078 */ unsigned long CheckSum;
	/* 0x007c */ unsigned long CoverageSectionSize;
	/* 0x0080 */ void* CoverageSection;
	/* 0x0088 */ void* LoadedImports;
	/* 0x0090 */ void* Spare;
	/* 0x0098 */ unsigned long SizeOfImageNotRounded;
	/* 0x009c */ unsigned long TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY; /* size: 0x00a0 */

#define SystemProcessInformation 5