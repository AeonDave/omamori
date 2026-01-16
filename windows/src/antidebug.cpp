#include "../include/antidebug.hpp"
#include "../include/internal.hpp"
#include <intrin.h>
#include <tlhelp32.h>

namespace Omamori {
namespace Windows {
namespace AntiDebug {

// PEB-based checks
bool Detector::CheckPEBBeingDebugged() {
    PEB* peb = Internal::READ_PEB();
    return peb->BeingDebugged != 0;
}

bool Detector::CheckPEBNtGlobalFlag() {
    PEB* peb = Internal::READ_PEB();
#ifdef _WIN64
    DWORD* pNtGlobalFlag = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(peb) + 0xBC);
#else
    DWORD* pNtGlobalFlag = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(peb) + 0x68);
#endif
    return (*pNtGlobalFlag & 0x70) != 0;
}

bool Detector::CheckPEBHeapFlags() {
    PEB* peb = Internal::READ_PEB();
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
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
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
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(0xDEADBEEF));
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return true; // Debugger catches exception
    }
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
