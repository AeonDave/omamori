#include "../include/antidebug.hpp"
#include "../include/internal.hpp"
#include "../include/syscall.hpp"
#include <intrin.h>
#include <tlhelp32.h>

namespace Omamori {
namespace Windows {
namespace AntiDebug {

// =============================================================================
// Advanced Techniques - ETW Patching
// =============================================================================

bool Detector::PatchETW() {
    // Get ntdll.dll base
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    // Get EtwEventWrite address
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return false;
    
    // Patch with RET (0xC3) to disable ETW
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<void*>(pEtwEventWrite), 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Write RET instruction
    *reinterpret_cast<unsigned char*>(pEtwEventWrite) = 0xC3;
    
    // Restore protection
    VirtualProtect(reinterpret_cast<void*>(pEtwEventWrite), 1, oldProtect, &oldProtect);
    
    return true;
}

// =============================================================================
// Advanced Techniques - AMSI Bypass
// =============================================================================

bool Detector::PatchAMSI() {
    // Load amsi.dll if not loaded
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return true; // AMSI not present, nothing to patch
    
    // Get AmsiScanBuffer address
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return false;
    
    // Patch to return AMSI_RESULT_CLEAN (0)
    // mov eax, 0x80070057 (E_INVALIDARG) ; ret
    // This makes AMSI think the scan failed and allows the code
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<void*>(pAmsiScanBuffer), 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
#ifdef _WIN64
    // x64: mov eax, 0x80070057; ret
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#else
    // x86: mov eax, 0x80070057; ret 0x18
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    
    memcpy(reinterpret_cast<void*>(pAmsiScanBuffer), patch, sizeof(patch));
    
    // Restore protection
    VirtualProtect(reinterpret_cast<void*>(pAmsiScanBuffer), 8, oldProtect, &oldProtect);
    
    return true;
}

// =============================================================================
// Advanced Techniques - INT 2D Check
// =============================================================================

bool Detector::CheckInt2D() {
#ifdef _MSC_VER
    __try {
        // INT 2D is a debug break interrupt
        // If a debugger is present, it intercepts this
        // If no debugger, an exception is raised
        __asm {
            xor eax, eax
            int 0x2d
            nop
        }
        // If we reach here without exception, debugger is present
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Exception occurred - no debugger (or debugger passed it)
        return false;
    }
#else
    // MinGW alternative using VEH
    // Use static to communicate with the exception handler
    static volatile bool s_exceptionOccurred = false;
    s_exceptionOccurred = false;
    
    // Use VEH to catch the exception
    PVOID handler = AddVectoredExceptionHandler(1, [](PEXCEPTION_POINTERS ep) -> LONG {
        if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT ||
            ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT) {
            s_exceptionOccurred = true;
#ifdef _WIN64
            ep->ContextRecord->Rip += 2;  // Skip INT 2D (2 bytes)
#else
            ep->ContextRecord->Eip += 2;  // Skip INT 2D (2 bytes)
#endif
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
    
    if (handler) {
        // Try to execute INT 2D
        // Under debugger this won't raise exception
        __asm__ volatile(
            "xor %%eax, %%eax\n"
            ".byte 0xCD, 0x2D\n"  // INT 2D
            "nop\n"
            : : : "eax"
        );
        RemoveVectoredExceptionHandler(handler);
        
        // If no exception occurred, debugger intercepted the INT 2D
        return !s_exceptionOccurred;
    }
    
    return false;
#endif
}

// =============================================================================
// Advanced Techniques - Debug Filter State
// =============================================================================

bool Detector::DisableDebugFilters() {
    // NtSetDebugFilterState can disable debug output
    typedef NTSTATUS(NTAPI* pNtSetDebugFilterState)(ULONG ComponentId, ULONG Level, BOOLEAN State);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    auto NtSetDebugFilterState = reinterpret_cast<pNtSetDebugFilterState>(
        GetProcAddress(hNtdll, "NtSetDebugFilterState")
    );
    
    if (!NtSetDebugFilterState) return false;
    
    // Disable all debug components (0-100)
    for (ULONG i = 0; i < 100; i++) {
        for (ULONG level = 0; level < 4; level++) {
            NtSetDebugFilterState(i, level, FALSE);
        }
    }
    
    return true;
}

bool Detector::CheckDebugFilterState() {
    // NtQueryDebugFilterState returns TRUE if debugging is enabled for a component
    typedef NTSTATUS(NTAPI* pNtQueryDebugFilterState)(ULONG ComponentId, ULONG Level);
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;
    
    auto NtQueryDebugFilterState = reinterpret_cast<pNtQueryDebugFilterState>(
        GetProcAddress(hNtdll, "NtQueryDebugFilterState")
    );
    
    if (!NtQueryDebugFilterState) return false;
    
    // Check if any debug filter is enabled
    for (ULONG i = 0; i < 10; i++) {
        NTSTATUS status = NtQueryDebugFilterState(i, 0);
        if (status == TRUE) {
            return true; // Debug filter enabled - possible debugger
        }
    }
    
    return false;
}

// =============================================================================
// Advanced Techniques - Thread Context Manipulation
// =============================================================================

bool Detector::CheckThreadContextManipulation() {
    // Set DR7 to a specific value and check if it persists
    // Debuggers often clear or modify debug registers
    
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    // Save original values
    DWORD64 originalDr7 = ctx.Dr7;
    
    // Set a specific pattern
    ctx.Dr7 = 0x155; // Enable DR0-DR3 local breakpoints
    
    if (!SetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    // Read back
    ctx.Dr7 = 0;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    // Check if value was modified
    bool debuggerPresent = (ctx.Dr7 != 0x155);
    
    // Restore original
    ctx.Dr7 = originalDr7;
    SetThreadContext(GetCurrentThread(), &ctx);
    
    return debuggerPresent;
}

// =============================================================================
// Advanced Techniques - Memory Breakpoint Detection
// =============================================================================

bool Detector::CheckMemoryBreakpoints() {
    // Scan our own code for INT3 (0xCC) breakpoints
    HMODULE hModule = GetModuleHandleA(nullptr);
    if (!hModule) return false;
    
    // Get DOS header
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    // Get NT headers
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew
    );
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    
    // Get .text section
    auto section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            BYTE* codeStart = reinterpret_cast<BYTE*>(hModule) + section->VirtualAddress;
            SIZE_T codeSize = section->Misc.VirtualSize;

            // Scan for INT3 (0xCC) with padding-aware heuristic
            size_t runLength = 0;
            for (SIZE_T j = 0; j < codeSize; j++) {
                if (codeStart[j] == 0xCC) {
                    runLength++;
                } else {
                    if (runLength > 0 && runLength <= 2) {
                        return true; // Likely breakpoint, not padding
                    }
                    runLength = 0;
                }
            }
            if (runLength > 0 && runLength <= 2) {
                return true;
            }
            break;
        }
    }
    
    return false;
}

// PEB-based checks
bool Detector::CheckPEBBeingDebugged() {
    auto peb = Internal::ReadPEB();
    if (!peb) return false;
    return peb->BeingDebugged != 0;
}

bool Detector::CheckPEBNtGlobalFlag() {
    auto peb = Internal::ReadPEB();
    if (!peb) return false;
#ifdef _WIN64
    DWORD* pNtGlobalFlag = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(peb) + 0xBC);
#else
    DWORD* pNtGlobalFlag = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(peb) + 0x68);
#endif
    return (*pNtGlobalFlag & 0x70) != 0;
}

bool Detector::CheckPEBHeapFlags() {
    auto peb = Internal::ReadPEB();
    if (!peb) return false;
    PVOID heapBase = peb->ProcessHeap;
    
    if (!heapBase) return false;
    
#ifdef _WIN64
    DWORD* flags = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(heapBase) + 0x70);
    DWORD* forceFlags = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(heapBase) + 0x74);
#else
    DWORD* flags = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(heapBase) + 0x0C);
    DWORD* forceFlags = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(heapBase) + 0x10);
#endif
    
    return (*flags & 0x2) != 0 || (*forceFlags != 0);
}

// API-based checks
bool Detector::CheckRemoteDebuggerPresent() {
    BOOL debuggerPresent = FALSE;
    ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent != FALSE;
}

bool Detector::CheckDebugPort() {
    auto pNtQIP = Internal::NtApi::GetNtQueryInformationProcess();
    if (!pNtQIP) return false;
    
    DWORD debugPort = 0;
    NTSTATUS status = pNtQIP(
        GetCurrentProcess(),
        static_cast<PROCESSINFOCLASS>(7), // ProcessDebugPort
        &debugPort,
        sizeof(debugPort),
        nullptr
    );
    
    return NT_SUCCESS(status) && debugPort != 0;
}

bool Detector::CheckDebugFlags() {
    auto pNtQIP = Internal::NtApi::GetNtQueryInformationProcess();
    if (!pNtQIP) return false;
    
    DWORD debugFlags = 0;
    NTSTATUS status = pNtQIP(
        GetCurrentProcess(),
        static_cast<PROCESSINFOCLASS>(31), // ProcessDebugFlags
        &debugFlags,
        sizeof(debugFlags),
        nullptr
    );
    
    return NT_SUCCESS(status) && debugFlags == 0;
}

bool Detector::CheckDebugObjectHandle() {
    auto pNtQIP = Internal::NtApi::GetNtQueryInformationProcess();
    if (!pNtQIP) return false;
    
    HANDLE debugObject = nullptr;
    NTSTATUS status = pNtQIP(
        GetCurrentProcess(),
        static_cast<PROCESSINFOCLASS>(30), // ProcessDebugObjectHandle
        &debugObject,
        sizeof(debugObject),
        nullptr
    );
    
    return NT_SUCCESS(status) && debugObject != nullptr;
}

// Hardware checks
bool Detector::CheckHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &ctx)) {
        return false;
    }
    
    return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
}

void Detector::ClearHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        SetThreadContext(GetCurrentThread(), &ctx);
    }
}

// Timing checks
bool Detector::CheckTimingRDTSC() {
    uint64_t start = Internal::GetCPUTimestamp();
    
    // Simulate some work
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }
    
    uint64_t end = Internal::GetCPUTimestamp();
    uint64_t elapsed = end - start;
    
    // If elapsed > 10000 cycles, likely debugger present
    return elapsed > 10000;
}

bool Detector::CheckTimingQPC() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Simulate work
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy += i;
    }
    
    QueryPerformanceCounter(&end);
    double elapsed = ((end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
    
    // If > 10ms for simple loop, likely debugger
    return elapsed > 10.0;
}

// Exception-based checks
bool Detector::CheckCloseHandleException() {
#ifdef _MSC_VER
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(0xDEADBEEF));
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true; // Debugger catches exception
    }
#else
    return false;
#endif
}

bool Detector::CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("AntiDebug");
    return GetLastError() == 0;
}

// System checks
bool Detector::CheckKernelDebugger() {
    auto pNtQSI = Internal::NtApi::GetNtQuerySystemInformation();
    if (!pNtQSI) return false;
    
    struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
        BOOLEAN KernelDebuggerEnabled;
        BOOLEAN KernelDebuggerNotPresent;
    } info;
    
    NTSTATUS status = pNtQSI(
        static_cast<SYSTEM_INFORMATION_CLASS>(35), // SystemKernelDebuggerInformation
        &info,
        sizeof(info),
        nullptr
    );
    
    return NT_SUCCESS(status) && info.KernelDebuggerEnabled;
}

bool Detector::CheckParentProcess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == currentPid) {
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    
    if (parentPid == 0) return false;
    
    // Check if parent is explorer.exe or common legitimate processes
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    bool suspicious = true;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == parentPid) {
                const wchar_t* exeName = pe.szExeFile;
                if (wcsstr(exeName, L"explorer.exe") || 
                    wcsstr(exeName, L"cmd.exe") ||
                    wcsstr(exeName, L"powershell.exe")) {
                    suspicious = false;
                }
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return suspicious;
}

// Main detection function
bool Detector::IsDebuggerPresent(uint32_t methods) {
    if (methods & PEB_BEING_DEBUGGED && CheckPEBBeingDebugged()) return true;
    if (methods & PEB_NT_GLOBAL_FLAG && CheckPEBNtGlobalFlag()) return true;
    if (methods & PEB_HEAP_FLAGS && CheckPEBHeapFlags()) return true;
    if (methods & REMOTE_DEBUGGER_PRESENT && CheckRemoteDebuggerPresent()) return true;
    if (methods & HARDWARE_BREAKPOINTS && CheckHardwareBreakpoints()) return true;
    if (methods & TIMING_RDTSC && CheckTimingRDTSC()) return true;
    if (methods & TIMING_QPC && CheckTimingQPC()) return true;
    if (methods & CLOSE_HANDLE_EXCEPTION && CheckCloseHandleException()) return true;
    if (methods & OUTPUT_DEBUG_STRING && CheckOutputDebugString()) return true;
    if (methods & PROCESS_DEBUG_PORT && CheckDebugPort()) return true;
    if (methods & PROCESS_DEBUG_FLAGS && CheckDebugFlags()) return true;
    if (methods & DEBUG_OBJECT_HANDLE && CheckDebugObjectHandle()) return true;
    if (methods & SYSTEM_KERNEL_DEBUGGER && CheckKernelDebugger()) return true;
    if (methods & PARENT_PROCESS_CHECK && CheckParentProcess()) return true;
    // New advanced techniques
    if (methods & INT_2D_CHECK && CheckInt2D()) return true;
    if (methods & DEBUG_FILTER_STATE && CheckDebugFilterState()) return true;
    if (methods & THREAD_CONTEXT_CHECK && CheckThreadContextManipulation()) return true;
    if (methods & MEMORY_BREAKPOINT && CheckMemoryBreakpoints()) return true;
    
    return false;
}

// Protection functions
void Detector::HideThreadFromDebugger() {
    auto pNtSIT = Internal::NtApi::GetNtSetInformationThread();
    if (pNtSIT) {
        pNtSIT(GetCurrentThread(), static_cast<THREADINFOCLASS>(0x11), nullptr, 0);
    }
}

void Detector::TerminateIfDebugged() {
    if (IsDebuggerPresent()) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
}

bool Detector::EnableAntiDebug() {
    HideThreadFromDebugger();
    ClearHardwareBreakpoints();
    
    // Advanced evasion techniques
    PatchETW();           // Disable Event Tracing for Windows
    PatchAMSI();          // Bypass AMSI scanning
    DisableDebugFilters(); // Disable debug output filters
    
    return true;
}

// TimingGuard implementation
TimingGuard::TimingGuard(double thresholdMs) 
    : maxThresholdMs(thresholdMs) {
    startTSC = Internal::GetCPUTimestamp();
    startTime = Internal::GetPerformanceCounter();
}

TimingGuard::~TimingGuard() {
    if (IsAnomalous()) {
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
}

bool TimingGuard::IsAnomalous() const {
    return GetElapsedMs() > maxThresholdMs;
}

double TimingGuard::GetElapsedMs() const {
    uint64_t endTime = Internal::GetPerformanceCounter();
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    return ((endTime - startTime) * 1000.0) / freq.QuadPart;
}

// ProtectionThread implementation
HANDLE ProtectionThread::threadHandle = nullptr;
bool ProtectionThread::running = false;

DWORD WINAPI ProtectionThread::ThreadProc(LPVOID param) {
    uint32_t interval = *reinterpret_cast<uint32_t*>(param);
    delete reinterpret_cast<uint32_t*>(param);
    
    while (running) {
        if (Detector::IsDebuggerPresent()) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }
        Sleep(interval);
    }
    
    return 0;
}

bool ProtectionThread::Start(uint32_t checkIntervalMs) {
    if (running) return false;
    
    running = true;
    uint32_t* interval = new uint32_t(checkIntervalMs);
    threadHandle = CreateThread(nullptr, 0, ThreadProc, interval, 0, nullptr);
    
    return threadHandle != nullptr;
}

void ProtectionThread::Stop() {
    running = false;
    if (threadHandle) {
        WaitForSingleObject(threadHandle, INFINITE);
        CloseHandle(threadHandle);
        threadHandle = nullptr;
    }
}

} // namespace AntiDebug
} // namespace Windows
} // namespace Omamori
