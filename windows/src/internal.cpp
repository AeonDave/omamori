#include "../include/internal.hpp"
#include <intrin.h>

namespace Omamori {
namespace Windows {
namespace Internal {

pNtQueryInformationProcess NtApi::GetNtQueryInformationProcess() {
    static pNtQueryInformationProcess func = nullptr;
    if (!func) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            func = reinterpret_cast<pNtQueryInformationProcess>(
                GetProcAddress(ntdll, "NtQueryInformationProcess")
            );
        }
    }
    return func;
}

pNtSetInformationThread NtApi::GetNtSetInformationThread() {
    static pNtSetInformationThread func = nullptr;
    if (!func) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            func = reinterpret_cast<pNtSetInformationThread>(
                GetProcAddress(ntdll, "NtSetInformationThread")
            );
        }
    }
    return func;
}

pNtQuerySystemInformation NtApi::GetNtQuerySystemInformation() {
    static pNtQuerySystemInformation func = nullptr;
    if (!func) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            func = reinterpret_cast<pNtQuerySystemInformation>(
                GetProcAddress(ntdll, "NtQuerySystemInformation")
            );
        }
    }
    return func;
}

void SecureZeroMemory(void* ptr, size_t size) {
    volatile char* p = static_cast<volatile char*>(ptr);
    while (size--) {
        *p++ = 0;
    }
}

void* GetModuleBaseAddress(const wchar_t* moduleName) {
    if (!moduleName) {
        return GetModuleHandleW(nullptr);
    }
    return GetModuleHandleW(moduleName);
}

uint64_t GetCPUTimestamp() {
    return __rdtsc();
}

uint64_t GetPerformanceCounter() {
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    return counter.QuadPart;
}

} // namespace Internal
} // namespace Windows
} // namespace Omamori
