#pragma once
#include "../common/include/sec_string.hpp"
#include <cstdint>
#include <sys/types.h>

namespace Omamori {
namespace Linux {
namespace AntiDebug {

enum DetectionMethod : uint32_t {
    PTRACE_TRACEME           = 0x00000001,
    PROC_STATUS_TRACERPID    = 0x00000002,
    PROC_SELF_STATUS         = 0x00000004,
    LD_PRELOAD_CHECK         = 0x00000008,
    TIMING_BASED             = 0x00000010,
    BREAKPOINT_SCAN          = 0x00000020,
    PARENT_PROCESS_CHECK     = 0x00000040,
    SELINUX_CHECK            = 0x00000080,
    PROC_MAPS_CHECK          = 0x00000100,
    SIGNAL_BASED             = 0x00000200,
    SYSCALL_TRACING          = 0x00000400,
    GDB_SPECIFIC             = 0x00000800,
    FRIDA_DETECTION          = 0x00001000,
    ALL_CHECKS               = 0xFFFFFFFF
};

class Detector {
public:
    // ptrace-based checks
    static bool CheckPtraceTraceme();
    static bool CheckPtraceAttach();
    
    // /proc based checks
    static bool CheckProcStatusTracerPid();
    static bool CheckProcMaps();
    static bool CheckProcSelfStatus();
    
private:
    // Environment checks
    static bool CheckLDPreload();
    static bool CheckDebugEnvironment();
    
    // Timing checks
    static bool CheckTimingAnomaly();
    
    // Process checks
    static bool CheckParentProcess();
    static bool CheckProcessName();
    
    // Debugger-specific checks
    static bool CheckGDB();
    static bool CheckLLDB();
    static bool CheckFrida();
    
    // Signal-based checks
    static bool CheckSignalHandlers();
    
public:
    // Main detection function
    static bool IsDebuggerPresent(uint32_t methods = ALL_CHECKS);
    
    // Protection functions
    static bool EnableAntiDebug();
    static void TerminateIfDebugged();
    static bool BlockPtrace();
    static bool BlockPtraceAdvanced(); // Self-attach to prevent external debuggers
    static bool ObfuscateMemory();
};

// RAII Timing Guard
class TimingGuard {
private:
    uint64_t startTime;
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
    static pthread_t threadHandle;
    static bool running;
    static void* ThreadProc(void* param);
    
public:
    static bool Start(uint32_t checkIntervalMs = 100);
    static void Stop();
};

// Signal handler for anti-debugging
class SignalProtection {
public:
    static bool InstallHandlers();
    static void RemoveHandlers();
    
private:
    static void SigTrapHandler(int sig);
    static void SigSegvHandler(int sig);
};

} // namespace AntiDebug
} // namespace Linux
} // namespace Omamori
