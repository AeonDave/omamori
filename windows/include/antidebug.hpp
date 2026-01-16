#pragma once
#include "../common/include/sec_string.hpp"
#include <windows.h>
#include <cstdint>

namespace Omamori {
namespace Windows {
namespace AntiDebug {

enum DetectionMethod : uint32_t {
    PEB_BEING_DEBUGGED       = 0x00000001,
    PEB_NT_GLOBAL_FLAG       = 0x00000002,
    PEB_HEAP_FLAGS           = 0x00000004,
    REMOTE_DEBUGGER_PRESENT  = 0x00000008,
    HARDWARE_BREAKPOINTS     = 0x00000010,
    TIMING_RDTSC             = 0x00000020,
    TIMING_QPC               = 0x00000040,
    EXCEPTION_BASED          = 0x00000080,
    PROCESS_DEBUG_PORT       = 0x00000100,
    PROCESS_DEBUG_FLAGS      = 0x00000200,
    DEBUG_OBJECT_HANDLE      = 0x00000400,
    SYSTEM_KERNEL_DEBUGGER   = 0x00000800,
    CLOSE_HANDLE_EXCEPTION   = 0x00001000,
    OUTPUT_DEBUG_STRING      = 0x00002000,
    PARENT_PROCESS_CHECK     = 0x00004000,
    SEDEBUGRPRIVILEGE        = 0x00008000,
    ALL_CHECKS               = 0xFFFFFFFF
};

class Detector {
private:
    // PEB-based checks
    static bool CheckPEBBeingDebugged();
    static bool CheckPEBNtGlobalFlag();
    static bool CheckPEBHeapFlags();
    
    // API-based checks
    static bool CheckRemoteDebuggerPresent();
    static bool CheckDebugPort();
    static bool CheckDebugFlags();
    static bool CheckDebugObjectHandle();
    
    // Hardware checks
    static bool CheckHardwareBreakpoints();
    static void ClearHardwareBreakpoints();
    
    // Timing checks
    static bool CheckTimingRDTSC();
    static bool CheckTimingQPC();
    
    // Exception-based checks
    static bool CheckCloseHandleException();
    static bool CheckOutputDebugString();
    
    // System checks
    static bool CheckKernelDebugger();
    static bool CheckParentProcess();
    
public:
    // Main detection function
    static bool IsDebuggerPresent(uint32_t methods = ALL_CHECKS);
    
    // Protection functions
    static void HideThreadFromDebugger();
    static void TerminateIfDebugged();
    static bool EnableAntiDebug();
};

// RAII Timing Guard for anti-debug timing checks
class TimingGuard {
private:
    uint64_t startTime;
    uint64_t startTSC;
    double maxThresholdMs;
    
public:
    explicit TimingGuard(double thresholdMs = 10.0);
    ~TimingGuard();
    
    bool IsAnomalous() const;
    double GetElapsedMs() const;
};

// Continuous protection thread
class ProtectionThread {
private:
    static HANDLE threadHandle;
    static bool running;
    static DWORD WINAPI ThreadProc(LPVOID param);
    
public:
    static bool Start(uint32_t checkIntervalMs = 100);
    static void Stop();
};

} // namespace AntiDebug
} // namespace Windows
} // namespace Omamori
