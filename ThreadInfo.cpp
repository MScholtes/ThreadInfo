// Markus Scholtes, 2017
// Get process and thread information
// can be compiled as 32bit and 64bit executable

// Compile with:
// cl ThreadInfo.cpp

#define _WIN32_WINNT 0x0600 // Windows Vista and above
#include "stdio.h"
#include <windows.h>

typedef LONG KPRIORITY;

struct CLIENT_ID
{
	DWORD UniqueProcess; // Process ID
#ifdef _WIN64
	ULONG pad1;
#endif
  DWORD UniqueThread;  // Thread ID
#ifdef _WIN64
	ULONG pad2;
#endif
};

typedef struct
{
	FILETIME ProcessorTime;
	FILETIME UserTime;
	FILETIME CreateTime;
	ULONG WaitTime;
#ifdef _WIN64
	ULONG pad1;
#endif
	PVOID StartAddress;
	CLIENT_ID Client_Id;
	KPRIORITY CurrentPriority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchesPerSec;
	ULONG ThreadState;
	ULONG ThreadWaitReason;
	ULONG pad2;
} SYSTEM_THREAD_INFORMATION;


typedef struct
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct
{
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
#ifdef _WIN64
	ULONG pad1;
#endif
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
} VM_COUNTERS;

typedef struct
{
	ULONG NextOffset;
	ULONG ThreadCount;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	FILETIME CreateTime;
	FILETIME UserTime;
	FILETIME KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
#ifdef _WIN64
	ULONG pad1;
#endif
  ULONG ProcessId;
#ifdef _WIN64
	ULONG pad2;
#endif
  ULONG InheritedFromProcessId;
#ifdef _WIN64
	ULONG pad3;
#endif
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // always NULL, use SystemExtendedProcessInformation (57) to get value
  VM_COUNTERS VirtualMemoryCounters;
 	ULONG_PTR PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} SYSTEM_PROCESS_INFORMATION;

SYSTEM_PROCESS_INFORMATION *info;
#define SYSTEMPROCESSINFORMATION 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

typedef NTSTATUS (WINAPI* t_NtQuerySystemInformation)(int, PVOID, ULONG, PULONG);


typedef enum
{
	ThreadStateInitialized,
	ThreadStateReady,
	ThreadStateRunning,
	ThreadStateStandby,
	ThreadStateTerminated,
	ThreadStateWaiting,
	ThreadStateTransition,
	ThreadStateDeferredReady
} THREAD_STATE;

const WCHAR* ThreadStateValueNames[] =
{
  L"Initialized",
  L"Ready",
  L"Running",
  L"Standby",
  L"Terminated",
  L"Waiting",
  L"Transition",
  L"DeferredReady"
};


typedef enum 
{
	ThreadWaitReasonExecutive,
	ThreadWaitReasonFreePage,
	ThreadWaitReasonPageIn,
	ThreadWaitReasonPoolAllocation,
	ThreadWaitReasonDelayExecution,
	ThreadWaitReasonSuspended,
	ThreadWaitReasonUserRequest,
	ThreadWaitReasonWrExecutive ,
	ThreadWaitReasonWrFreePage,
	ThreadWaitReasonWrPageIn,
	ThreadWaitReasonWrPoolAllocation,
	ThreadWaitReasonWrDelayExecution,
	ThreadWaitReasonWrSuspended,
	ThreadWaitReasonWrUserRequest,
	ThreadWaitReasonWrEventPair,
	ThreadWaitReasonWrQueue,
	ThreadWaitReasonWrLpcReceive,
	ThreadWaitReasonWrLpcReply,
	ThreadWaitReasonWrVirtualMemory,
	ThreadWaitReasonWrPageOut,
	ThreadWaitReasonWrRendezvous,
	ThreadWaitReasonWrKeyedEvent,
	ThreadWaitReasonWrTerminated,
	ThreadWaitReasonWrProcessInSwap,
	ThreadWaitReasonWrCpuRateControl,
	ThreadWaitReasonWrCalloutStack,
	ThreadWaitReasonWrKernel,
	ThreadWaitReasonWrResource,
	ThreadWaitReasonWrPushLock,
	ThreadWaitReasonWrMutex,
	ThreadWaitReasonWrQuantumEnd,
	ThreadWaitReasonWrDispatchInt,
	ThreadWaitReasonWrPreempted,
	ThreadWaitReasonWrYieldExecution,
	ThreadWaitReasonWrFastMutex,
	ThreadWaitReasonWrGuardedMutex,
	ThreadWaitReasonWrRundown,
	ThreadWaitReasonMaximumWaitReason
} THREAD_WAIT_REASON;

const WCHAR* ThreadWaitReasonValueNames[] =
{
	L"Executive",
	L"FreePage",
	L"PageIn",
	L"PoolAllocation",
	L"DelayExecution",
	L"Suspended",
	L"UserRequest",
	L"WrExecutive ",
	L"WrFreePage",
	L"WrPageIn",
	L"WrPoolAllocation",
	L"WrDelayExecution",
	L"WrSuspended",
	L"WrUserRequest",
	L"WrEventPair",
	L"WrQueue",
	L"WrLpcReceive",
	L"WrLpcReply",
	L"WrVirtualMemory",
	L"WrPageOut",
	L"WrRendezvous",
	L"WrKeyedEvent",
	L"WrTerminated",
	L"WrProcessInSwap",
	L"WrCpuRateControl",
	L"WrCalloutStack",
	L"WrKernel",
	L"WrResource",
	L"WrPushLock",
	L"WrMutex",
	L"WrQuantumEnd",
	L"WrDispatchInt",
	L"WrPreempted",
	L"WrYieldExecution",
	L"WrFastMutex",
	L"WrGuardedMutex",
	L"WrRundown",
	L"MaximumWaitReason"
};



void main()
{ ULONG buflen = 0;
	BYTE* buffer = NULL;

	// define WINAPI function NtQuerySystemInformation
	t_NtQuerySystemInformation f_NtQuerySystemInformation = (t_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
  if (!f_NtQuerySystemInformation)
  {
  	fprintf(stderr, "Error %d while retrieving adress of NtQuerySystemInformation.\n", GetLastError());
  	return;
  }
	
	// first call just to retrieve the needed buffer size for the information
	NTSTATUS lResult = f_NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, buffer, buflen, &buflen);
	if (lResult == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer = (BYTE*)LocalAlloc(LMEM_FIXED, buflen);
	}
	else
  {
  	fprintf(stderr, "Error %d calling NtQuerySystemInformation.\n", GetLastError());
  	return;
  }

	// buffer is generated, now retireve the information
	if (f_NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, buffer, buflen, &buflen))
  {
  	fprintf(stderr, "Error %d calling NtQuerySystemInformation.\n", GetLastError());
  	return;
  }

	// iterate through processes (array of SYSTEM_PROCESS_INFORMATION struct was returned by NtQuerySystemInformation
	unsigned int i = 0;
	do {
		info = (SYSTEM_PROCESS_INFORMATION *)&buffer[i];

		// print process information
		if (info->ProcessId == 0) info->ImageName.Buffer = L"System Idle Process";
		wprintf(L"%s (PID %d, SID %d) with %d threads and %d handles.\n", info->ImageName.Buffer, info->ProcessId, info->SessionId, info->ThreadCount, info->HandleCount);

		// loop through threads of process (at the end of each SYSTEM_PROCESS_INFORMATION struct
		// there is an array of SYSTEM_THREAD_INFORMATION structs)
		for (unsigned int j = 0; j < info->ThreadCount; j++)
		{ // print thread information
			wprintf(L"Thread %d:\t%d ", j, info->ThreadInfos[j].Client_Id.UniqueThread);
			if (info->ThreadInfos[j].ThreadState < 8)
				wprintf(L"with state %s, ", ThreadStateValueNames[info->ThreadInfos[j].ThreadState]);
			else
				wprintf(L"with state %d, ", info->ThreadInfos[j].ThreadState);
			if (info->ThreadInfos[j].ThreadWaitReason < 38)
				wprintf(L"reason %s\n", ThreadWaitReasonValueNames[info->ThreadInfos[j].ThreadWaitReason]);
			else
				wprintf(L"reason %d\n", info->ThreadInfos[j].ThreadWaitReason);
		}

		wprintf(L"\n");
		// next process
		i += info->NextOffset;
	} while (info->NextOffset != 0);

	// free memory
	LocalFree(buffer);
}
