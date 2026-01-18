#include "../include/syscall.hpp"
#include <cstring>

namespace Omamori {
namespace Windows {
namespace Syscall {

// ============================================================================
// Halo's Gate Implementation - Resolve SSN even when hooked
// ============================================================================

bool HalosGate::IsHooked(void* functionAddress) {
    if (!functionAddress) return true;
    
    BYTE* code = static_cast<BYTE*>(functionAddress);
    
    // Check for JMP (E9), JMP [rip+disp] (FF 25), or other hook patterns
    if (code[0] == 0xE9) return true;                    // JMP rel32
    if (code[0] == 0xFF && code[1] == 0x25) return true; // JMP [rip+disp]
    if (code[0] == 0x68) return true;                    // PUSH (trampoline)
    if (code[0] == 0xEB) return true;                    // JMP short
    
    // Expected pattern for x64: 4C 8B D1 B8 [SSN]
    // If first bytes don't match, likely hooked
#ifdef _WIN64
    if (!(code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)) {
        return true;
    }
#else
    if (code[0] != 0xB8) return true;
#endif
    
    return false;
}

bool HalosGate::ExtractSSN(void* address, uint32_t& ssn) {
    if (!address) return false;
    
    BYTE* code = static_cast<BYTE*>(address);
    
#ifdef _WIN64
    // x64: 4C 8B D1 B8 [SSN as 4 bytes]
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) {
        ssn = *reinterpret_cast<uint32_t*>(&code[4]);
        return true;
    }
#else
    // x86: B8 [SSN as 4 bytes]
    if (code[0] == 0xB8) {
        ssn = *reinterpret_cast<uint32_t*>(&code[1]);
        return true;
    }
#endif
    
    return false;
}

bool HalosGate::ResolveFromNeighbor(void* functionAddress, SyscallInfo& info, int direction) {
    // Syscall stubs are typically 32 bytes apart in ntdll
    const int SYSCALL_STUB_SIZE = 32;
    
    BYTE* neighbor = static_cast<BYTE*>(functionAddress);
    
    // Search up to 20 neighbors
    for (int i = 1; i <= 20; i++) {
        neighbor = static_cast<BYTE*>(functionAddress) + (direction * i * SYSCALL_STUB_SIZE);
        
        // Check if this neighbor is clean (not hooked)
        if (!IsHooked(neighbor)) {
            uint32_t neighborSSN;
            if (ExtractSSN(neighbor, neighborSSN)) {
                // Calculate our SSN based on distance
                // If we went UP (direction=-1), our SSN = neighbor + i
                // If we went DOWN (direction=1), our SSN = neighbor - i
                info.number = neighborSSN - (direction * i);
                info.address = functionAddress;
                return true;
            }
        }
    }
    
    return false;
}

void* HalosGate::FindCleanSyscallAddress() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return nullptr;
    
    // Try to find any clean syscall instruction in ntdll
    // Look for common NT functions
    const char* cleanFunctions[] = {
        "NtClose",
        "NtFlushBuffersFile",
        "NtQueryVolumeInformationFile",
        "NtQueryDirectoryFile",
        "NtCreateFile",
        nullptr
    };
    
    for (int i = 0; cleanFunctions[i] != nullptr; i++) {
        void* funcAddr = reinterpret_cast<void*>(GetProcAddress(ntdll, cleanFunctions[i]));
        if (funcAddr && !IsHooked(funcAddr)) {
            // Find syscall instruction within this function
            BYTE* code = static_cast<BYTE*>(funcAddr);
            for (int j = 0; j < 32; j++) {
#ifdef _WIN64
                if (code[j] == 0x0F && code[j+1] == 0x05) { // syscall
                    return &code[j];
                }
#else
                if (code[j] == 0x0F && code[j+1] == 0x34) { // sysenter
                    return &code[j];
                }
#endif
            }
        }
    }
    
    return nullptr;
}

bool HalosGate::ResolveSyscallNumber(const char* functionName, SyscallInfo& info) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    
    void* funcAddr = reinterpret_cast<void*>(GetProcAddress(ntdll, functionName));
    if (!funcAddr) return false;
    
    info.address = funcAddr;
    info.syscallAddress = nullptr;
    
    // Try direct extraction first
    if (!IsHooked(funcAddr)) {
        if (ExtractSSN(funcAddr, info.number)) {
            // Find syscall address for indirect syscalls
            BYTE* code = static_cast<BYTE*>(funcAddr);
            for (int i = 0; i < 32; i++) {
#ifdef _WIN64
                if (code[i] == 0x0F && code[i+1] == 0x05) {
                    info.syscallAddress = &code[i];
                    break;
                }
#else
                if (code[i] == 0x0F && code[i+1] == 0x34) {
                    info.syscallAddress = &code[i];
                    break;
                }
#endif
            }
            return true;
        }
    }
    
    // Function is hooked - use Halo's Gate
    // Try looking DOWN first (higher SSNs)
    if (ResolveFromNeighbor(funcAddr, info, 1)) {
        info.syscallAddress = FindCleanSyscallAddress();
        return true;
    }
    
    // Try looking UP (lower SSNs)
    if (ResolveFromNeighbor(funcAddr, info, -1)) {
        info.syscallAddress = FindCleanSyscallAddress();
        return true;
    }
    
    return false;
}

// ============================================================================
// SyscallResolver implementation
// ============================================================================
bool SyscallResolver::ResolveSyscallNumber(const char* functionName, SyscallInfo& info) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    
    void* funcAddr = reinterpret_cast<void*>(GetProcAddress(ntdll, functionName));
    if (!funcAddr) return false;
    
    // Parse syscall number from function prologue
    // Typical NT function starts with:
    // mov r10, rcx (x64) or mov eax, <syscall_number>
    // mov eax, <syscall_number> (x64) or ...
    
    BYTE* code = static_cast<BYTE*>(funcAddr);
    
#ifdef _WIN64
    // x64: Look for pattern: 4C 8B D1 B8 [syscall_num]
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8) {
        info.number = *reinterpret_cast<uint32_t*>(&code[4]);
        info.address = funcAddr;
        return true;
    }
#else
    // x86: Look for pattern: B8 [syscall_num]
    if (code[0] == 0xB8) {
        info.number = *reinterpret_cast<uint32_t*>(&code[1]);
        info.address = funcAddr;
        return true;
    }
#endif
    
    return false;
}

void* SyscallResolver::FindSyscallInstruction(void* functionAddress) {
    BYTE* code = static_cast<BYTE*>(functionAddress);
    
    // Search for syscall instruction (0F 05 on x64, various on x86)
    for (int i = 0; i < 32; i++) {
#ifdef _WIN64
        if (code[i] == 0x0F && code[i+1] == 0x05) {
            return &code[i];
        }
#else
        // x86 uses int 2E or sysenter
        if (code[i] == 0x0F && code[i+1] == 0x34) { // sysenter
            return &code[i];
        }
        if (code[i] == 0xCD && code[i+1] == 0x2E) { // int 2E
            return &code[i];
        }
#endif
    }
    
    return nullptr;
}

SyscallInfo SyscallResolver::GetSyscallInfo(const char* ntFunction) {
    SyscallInfo info = {0, nullptr};
    ResolveSyscallNumber(ntFunction, info);
    return info;
}

bool SyscallResolver::IsSyscallHooked(const char* ntFunction) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return true;
    
    void* funcAddr = reinterpret_cast<void*>(GetProcAddress(ntdll, ntFunction));
    if (!funcAddr) return true;
    
    BYTE* code = static_cast<BYTE*>(funcAddr);
    
    // Check for common hook patterns
    // JMP rel32 (E9)
    if (code[0] == 0xE9) return true;
    
    // JMP [rip+disp] (FF 25)
    if (code[0] == 0xFF && code[1] == 0x25) return true;
    
    // PUSH + RET (hook trampolines)
    if (code[0] == 0x68) return true;
    
    return false;
}

SyscallInfo SyscallResolver::GetSyscallInfoRobust(const char* ntFunction) {
    SyscallInfo info = {0, nullptr, nullptr};
    HalosGate::ResolveSyscallNumber(ntFunction, info);
    return info;
}

// ============================================================================
// IndirectSyscall implementation
// ============================================================================

IndirectSyscall::IndirectSyscall(const char* ntFunction) {
    info_ = {0, nullptr, nullptr};
    cleanSyscallAddr_ = nullptr;
    
    if (HalosGate::ResolveSyscallNumber(ntFunction, info_)) {
        cleanSyscallAddr_ = info_.syscallAddress;
        if (!cleanSyscallAddr_) {
            cleanSyscallAddr_ = HalosGate::FindCleanSyscallAddress();
        }
    }
}

// DirectSyscall implementation
DirectSyscall::DirectSyscall(const char* ntFunction) {
    info = SyscallResolver::GetSyscallInfo(ntFunction);
}

// SyscallStubManager implementation
void* SyscallStubManager::AllocateStub() {
    return VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

bool SyscallStubManager::WriteStub(void* stub, uint32_t syscallNumber) {
    if (!stub) return false;
    
    BYTE* code = static_cast<BYTE*>(stub);
    
#ifdef _WIN64
    // x64 syscall stub
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;  // mov r10, rcx
    code[3] = 0xB8;                                     // mov eax, <syscall_number>
    *reinterpret_cast<uint32_t*>(&code[4]) = syscallNumber;
    code[8] = 0x0F; code[9] = 0x05;                    // syscall
    code[10] = 0xC3;                                    // ret
#else
    // x86 syscall stub
    code[0] = 0xB8;                                     // mov eax, <syscall_number>
    *reinterpret_cast<uint32_t*>(&code[1]) = syscallNumber;
    code[5] = 0xBA;                                     // mov edx, <SharedUserData>
    *reinterpret_cast<uint32_t*>(&code[6]) = 0x7FFE0300;
    code[10] = 0xFF; code[11] = 0x12;                  // call dword ptr [edx]
    code[12] = 0xC2; code[13] = 0x14; code[14] = 0x00; // ret 14h
#endif
    
    return true;
}

void* SyscallStubManager::CreateStubForSyscall(uint32_t syscallNumber) {
    void* stub = AllocateStub();
    if (!stub) return nullptr;
    
    if (!WriteStub(stub, syscallNumber)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return nullptr;
    }
    
    return stub;
}

// Create an indirect syscall stub that jumps to ntdll for the actual syscall
void* SyscallStubManager::CreateIndirectStub(uint32_t syscallNumber, void* syscallAddr) {
    if (!syscallAddr) {
        // Fallback to direct syscall
        return CreateStubForSyscall(syscallNumber);
    }
    
    void* stub = AllocateStub();
    if (!stub) return nullptr;
    
    if (!WriteIndirectStub(stub, syscallNumber, syscallAddr)) {
        VirtualFree(stub, 0, MEM_RELEASE);
        return nullptr;
    }
    
    return stub;
}

bool SyscallStubManager::WriteIndirectStub(void* stub, uint32_t syscallNumber, void* syscallAddr) {
    if (!stub || !syscallAddr) return false;
    
    BYTE* code = static_cast<BYTE*>(stub);
    
#ifdef _WIN64
    // x64 indirect syscall stub:
    // mov r10, rcx           ; 4C 8B D1
    // mov eax, <SSN>         ; B8 XX XX XX XX
    // mov r11, <syscallAddr> ; 49 BB XX XX XX XX XX XX XX XX
    // jmp r11                ; 41 FF E3
    
    code[0] = 0x4C; code[1] = 0x8B; code[2] = 0xD1;     // mov r10, rcx
    code[3] = 0xB8;                                       // mov eax, <SSN>
    *reinterpret_cast<uint32_t*>(&code[4]) = syscallNumber;
    code[8] = 0x49; code[9] = 0xBB;                       // mov r11, <addr>
    *reinterpret_cast<uint64_t*>(&code[10]) = reinterpret_cast<uint64_t>(syscallAddr);
    code[18] = 0x41; code[19] = 0xFF; code[20] = 0xE3;   // jmp r11
#else
    // x86 indirect syscall stub:
    // mov eax, <SSN>
    // push <syscallAddr>
    // ret  (effectively jmp to syscallAddr)
    code[0] = 0xB8;
    *reinterpret_cast<uint32_t*>(&code[1]) = syscallNumber;
    code[5] = 0x68;  // push
    *reinterpret_cast<uint32_t*>(&code[6]) = reinterpret_cast<uint32_t>(syscallAddr);
    code[10] = 0xC3; // ret
#endif
    
    return true;
}

void SyscallStubManager::FreeStub(void* stub) {
    if (stub) {
        VirtualFree(stub, 0, MEM_RELEASE);
    }
}

// Common syscalls implementation
namespace Common {

NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    SyscallInfo info = SyscallResolver::GetSyscallInfo("NtQueryInformationProcess");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateStubForSyscall(info.number);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ProcessHandle, ProcessInformationClass, 
                           ProcessInformation, ProcessInformationLength, ReturnLength);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

NTSTATUS NtSetInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
) {
    SyscallInfo info = SyscallResolver::GetSyscallInfo("NtSetInformationThread");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateStubForSyscall(info.number);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, THREADINFOCLASS, PVOID, ULONG);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ThreadHandle, ThreadInformationClass, 
                           ThreadInformation, ThreadInformationLength);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

NTSTATUS NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    SyscallInfo info = SyscallResolver::GetSyscallInfo("NtQuerySystemInformation");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateStubForSyscall(info.number);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(SystemInformationClass, SystemInformation, 
                           SystemInformationLength, ReturnLength);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    // Use Halo's Gate for robust resolution
    SyscallInfo info = SyscallResolver::GetSyscallInfoRobust("NtProtectVirtualMemory");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    // Use indirect syscall if available
    void* stub = SyscallStubManager::CreateIndirectStub(info.number, info.syscallAddress);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ProcessHandle, BaseAddress, NumberOfBytesToProtect,
                           NewAccessProtection, OldAccessProtection);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    SyscallInfo info = SyscallResolver::GetSyscallInfoRobust("NtWriteVirtualMemory");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateIndirectStub(info.number, info.syscallAddress);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ProcessHandle, BaseAddress, Buffer,
                           NumberOfBytesToWrite, NumberOfBytesWritten);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

NTSTATUS NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
) {
    SyscallInfo info = SyscallResolver::GetSyscallInfoRobust("NtReadVirtualMemory");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateIndirectStub(info.number, info.syscallAddress);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ProcessHandle, BaseAddress, Buffer,
                           NumberOfBytesToRead, NumberOfBytesRead);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

} // namespace Common

} // namespace Syscall
} // namespace Windows
} // namespace Omamori
