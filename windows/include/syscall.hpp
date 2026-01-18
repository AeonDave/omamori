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
    void* syscallAddress;  // Address of syscall instruction for indirect syscalls
};

// ============================================================================
// Halo's Gate - SSN Resolution even when hooked
// ============================================================================
class HalosGate {
public:
    // Resolve SSN by looking at neighboring functions when hooked
    static bool ResolveSyscallNumber(const char* functionName, SyscallInfo& info);
    
    // Check if function is hooked
    static bool IsHooked(void* functionAddress);
    
    // Find clean syscall address in ntdll for indirect syscalls
    static void* FindCleanSyscallAddress();
    
private:
    // Look up/down neighboring functions to find unhoooked one
    static bool ResolveFromNeighbor(void* functionAddress, SyscallInfo& info, int direction);
    
    // Get SSN from function bytes
    static bool ExtractSSN(void* address, uint32_t& ssn);
};

class SyscallResolver {
private:
    static bool ResolveSyscallNumber(const char* functionName, SyscallInfo& info);
    static void* FindSyscallInstruction(void* functionAddress);
    
public:
    static SyscallInfo GetSyscallInfo(const char* ntFunction);
    static bool IsSyscallHooked(const char* ntFunction);
    
    // Use Halo's Gate for robust resolution
    static SyscallInfo GetSyscallInfoRobust(const char* ntFunction);
};

// ============================================================================
// Indirect Syscall Execution - Evades EDR call stack analysis
// ============================================================================
class IndirectSyscall {
private:
    SyscallInfo info_;
    void* cleanSyscallAddr_;  // Address to jump to for syscall
    
public:
    explicit IndirectSyscall(const char* ntFunction);
    
    bool IsValid() const { return info_.number != 0 && cleanSyscallAddr_ != nullptr; }
    uint32_t GetSSN() const { return info_.number; }
    void* GetSyscallAddress() const { return cleanSyscallAddr_; }
};

// Direct syscall execution (original)
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
    
    // New: Write to process memory via indirect syscall
    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );
    
    // New: Read process memory via indirect syscall  
    NTSTATUS NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    );
}

// Syscall stub manager
class SyscallStubManager {
private:
    static void* AllocateStub();
    static bool WriteStub(void* stub, uint32_t syscallNumber);
    static bool WriteIndirectStub(void* stub, uint32_t syscallNumber, void* syscallAddr);
    
public:
    static void* CreateStubForSyscall(uint32_t syscallNumber);
    static void* CreateIndirectStub(uint32_t syscallNumber, void* syscallAddr);
    static void FreeStub(void* stub);
};

} // namespace Syscall
} // namespace Windows
} // namespace Omamori
