#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

namespace Omamori {
namespace Windows {
namespace Syscall {

// Syscall number structure
struct SyscallInfo {
    uint32_t number;
    void* address;
};

class SyscallResolver {
private:
    static bool ResolveSyscallNumber(const char* functionName, SyscallInfo& info);
    static void* FindSyscallInstruction(void* functionAddress);
    
public:
    static SyscallInfo GetSyscallInfo(const char* ntFunction);
    static bool IsSyscallHooked(const char* ntFunction);
};

// Direct syscall execution
class DirectSyscall {
private:
    SyscallInfo info;
    
public:
    explicit DirectSyscall(const char* ntFunction);
    
    template<typename RetType = NTSTATUS, typename... Args>
    RetType Execute(Args... args);
    
    bool IsValid() const { return info.number != 0; }
};

// Common syscalls
namespace Common {
    NTSTATUS NtQueryInformationProcess(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    NTSTATUS NtSetInformationThread(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength
    );
    
    NTSTATUS NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
    
    NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T NumberOfBytesToProtect,
        ULONG NewAccessProtection,
        PULONG OldAccessProtection
    );
}

// Syscall stub manager
class SyscallStubManager {
private:
    static void* AllocateStub();
    static bool WriteStub(void* stub, uint32_t syscallNumber);
    
public:
    static void* CreateStubForSyscall(uint32_t syscallNumber);
    static void FreeStub(void* stub);
};

} // namespace Syscall
} // namespace Windows
} // namespace Omamori
