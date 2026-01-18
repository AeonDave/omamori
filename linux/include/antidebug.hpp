#pragma once
#include "../common/include/sec_string.hpp"
#include <cstdint>
#include <sys/types.h>

namespace Omamori {
namespace Linux {
namespace AntiDebug {

enum DetectionMethod : uint32_t {
    // Values aligned with omamori_config.hpp AntiDebugTechniques
    PROC_SELF_STATUS         = 0x00000004,  // = PEB_HEAP_FLAGS alias
    TIMING_BASED             = 0x00000020,  // = TIMING_RDTSC alias
    SIGNAL_BASED             = 0x00000200,  // = DEBUG_OBJECT_HANDLE alias
    GDB_SPECIFIC             = 0x00000400,  // = SYSTEM_KERNEL_DEBUGGER alias
    PARENT_PROCESS_CHECK     = 0x00002000,  // Shared with Windows
    NAMESPACE_DETECTION      = 0x00008000,  // = DEBUG_FILTER_STATE alias
    MEMORY_BREAKPOINT        = 0x00020000,  // Shared with Windows
    // Linux-specific (no Windows equivalent)
    PTRACE_TRACEME           = 0x00040000,
    PROC_STATUS_TRACERPID    = 0x00080000,
    PROC_MAPS_CHECK          = 0x00100000,
    LD_PRELOAD_CHECK         = 0x00200000,
    FRIDA_DETECTION          = 0x00400000,
    SECCOMP_DETECTION        = 0x00800000,
    EBPF_DETECTION           = 0x01000000,
    PERSONALITY_CHECK        = 0x02000000,
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
    
    // Advanced techniques (NEW)
    static bool CheckSeccomp();            // Seccomp sandbox detection
    static bool CheckEBPF();               // eBPF tracing detection
    static bool CheckNamespace();          // Container/namespace detection
    static bool CheckMemoryBreakpoints();  // Software breakpoint (INT3) detection
    static bool CheckPersonality();        // Personality flags check
    static bool CheckSyscallFilter();      // Syscall filtering detection
    
public:
    // Main detection function
    static bool IsDebuggerPresent(uint32_t methods = ALL_CHECKS);
    
    // Protection functions
    static bool EnableAntiDebug();
    static void TerminateIfDebugged();
    static bool BlockPtrace();
    static bool BlockPtraceAdvanced(); // Self-attach to prevent external debuggers
    
    // Advanced evasion functions
    static bool DisableCoreDumps();        // Disable core dumps via prctl
    static bool SetDumpable(bool enable);  // Control PR_SET_DUMPABLE
    static bool SetupAntiTrace();          // Comprehensive anti-trace setup
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
