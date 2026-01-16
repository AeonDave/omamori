#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

namespace Omamori {
namespace Windows {
namespace Internal {

// PEB structures for direct access
#ifdef _WIN64
using PEB_PTR = PEB*;
#define READ_PEB() reinterpret_cast<PEB*>(__readgsqword(0x60))
#else
using PEB_PTR = PEB*;
#define READ_PEB() reinterpret_cast<PEB*>(__readfsdword(0x30))
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
