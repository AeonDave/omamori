#include "../include/syscall.hpp"
#include <cstring>

namespace Omamori {
namespace Windows {
namespace Syscall {

// SyscallResolver implementation
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
    SyscallInfo info = SyscallResolver::GetSyscallInfo("NtProtectVirtualMemory");
    if (info.number == 0) return STATUS_NOT_IMPLEMENTED;
    
    void* stub = SyscallStubManager::CreateStubForSyscall(info.number);
    if (!stub) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (*SyscallFunc)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    SyscallFunc func = reinterpret_cast<SyscallFunc>(stub);
    
    NTSTATUS result = func(ProcessHandle, BaseAddress, NumberOfBytesToProtect,
                           NewAccessProtection, OldAccessProtection);
    
    SyscallStubManager::FreeStub(stub);
    return result;
}

} // namespace Common

} // namespace Syscall
} // namespace Windows
} // namespace Omamori
