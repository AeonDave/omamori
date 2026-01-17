#pragma once
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdint>

#ifndef __cplusplus
typedef struct _PEB PEB;
#endif

// Define PEB locally if needed with fields we use
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    ULONG CrossProcessFlags;
    PVOID UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG_PTR HeapSegmentReserve;
    ULONG_PTR HeapSegmentCommit;
    ULONG_PTR HeapDeCommitTotalFreeThreshold;
    ULONG_PTR HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
    // ... we can add more if needed
} MY_PEB, *PMY_PEB;


namespace Omamori {
namespace Windows {
namespace Internal {

// PEB structures for direct access
#ifdef _WIN64
using PEB_PTR = MY_PEB*;
inline MY_PEB* ReadPEB() { return reinterpret_cast<MY_PEB*>(__readgsqword(0x60)); }
#else
using PEB_PTR = MY_PEB*;
inline MY_PEB* ReadPEB() { return reinterpret_cast<MY_PEB*>(__readfsdword(0x30)); }
#endif

// NT API function types
typedef NTSTATUS (NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Helper functions
class NtApi {
public:
    static pNtQueryInformationProcess GetNtQueryInformationProcess();
    static pNtSetInformationThread GetNtSetInformationThread();
    static pNtQuerySystemInformation GetNtQuerySystemInformation();
};

// Memory utilities
void SecureZeroMemory(void* ptr, size_t size);
void* GetModuleBaseAddress(const wchar_t* moduleName = nullptr);

// Timing utilities
uint64_t GetCPUTimestamp();
uint64_t GetPerformanceCounter();

} // namespace Internal
} // namespace Windows
} // namespace Omamori
