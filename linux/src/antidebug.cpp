#include "../include/antidebug.hpp"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>

namespace Omamori {
namespace Linux {
namespace AntiDebug {

// =============================================================================
// Advanced Techniques - Seccomp Detection
// =============================================================================

bool Detector::CheckSeccomp() {
    // Check if seccomp is enabled via /proc/self/status
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;
    
    char line[256];
    int seccompMode = 0;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Seccomp:", 8) == 0) {
            sscanf(line, "Seccomp: %d", &seccompMode);
            break;
        }
    }
    
    fclose(f);
    
    // 0 = disabled, 1 = strict, 2 = filter
    // If seccomp is enabled in filter mode, we might be sandboxed
    return (seccompMode != 0);
}

// =============================================================================
// Advanced Techniques - eBPF Tracing Detection
// =============================================================================

bool Detector::CheckEBPF() {
    // Check for eBPF programs attached to our process
    // This is done by checking /sys/kernel/debug/tracing
    
    // Method 1: Check if kprobes are enabled for our process
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fdinfo", getpid());
    
    DIR* dir = opendir(path);
    if (!dir) return false;
    
    struct dirent* entry;
    bool detected = false;
    
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG || entry->d_type == DT_LNK) {
            char fdPath[512];
            snprintf(fdPath, sizeof(fdPath), "%s/%s", path, entry->d_name);
            
            FILE* f = fopen(fdPath, "r");
            if (f) {
                char buf[1024];
                while (fgets(buf, sizeof(buf), f)) {
                    // Look for bpf indicators
                    if (strstr(buf, "bpf") || strstr(buf, "perf")) {
                        detected = true;
                        break;
                    }
                }
                fclose(f);
            }
            if (detected) break;
        }
    }
    
    closedir(dir);
    
    // Method 2: Check /sys/kernel/debug/tracing/events
    if (!detected) {
        FILE* f = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
        if (f) {
            // If we can open trace_pipe, tracing might be active
            // Just check if it's accessible (don't actually read)
            fclose(f);
            // This alone doesn't mean eBPF, just that tracing is possible
        }
    }
    
    return detected;
}

// =============================================================================
// Advanced Techniques - Namespace Detection
// =============================================================================

bool Detector::CheckNamespace() {
    // Check if we're in a non-root namespace (container)
    
    // Method 1: Check /proc/1/ns vs our ns
    char ourNs[256], initNs[256];
    ssize_t ourLen, initLen;
    
    ourLen = readlink("/proc/self/ns/pid", ourNs, sizeof(ourNs) - 1);
    initLen = readlink("/proc/1/ns/pid", initNs, sizeof(initNs) - 1);
    
    if (ourLen > 0 && initLen > 0) {
        ourNs[ourLen] = '\0';
        initNs[initLen] = '\0';
        
        if (strcmp(ourNs, initNs) != 0) {
            return true; // Different PID namespace - likely container
        }
    }
    
    // Method 2: Check cgroup
    FILE* f = fopen("/proc/self/cgroup", "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "docker") || strstr(line, "lxc") || 
                strstr(line, "kubepods") || strstr(line, "containerd")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    
    // Method 3: Check for /.dockerenv
    if (access("/.dockerenv", F_OK) == 0) {
        return true;
    }
    
    return false;
}

// =============================================================================
// Advanced Techniques - Memory Breakpoint Detection
// =============================================================================

bool Detector::CheckMemoryBreakpoints() {
    // Scan our own executable for INT3 (0xCC) breakpoints
    
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    bool detected = false;
    
    while (fgets(line, sizeof(line), f)) {
        // Look for executable sections
        if (strstr(line, "r-xp") || strstr(line, "r-x")) {
            unsigned long start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                // Scan this region for INT3
                unsigned char* ptr = reinterpret_cast<unsigned char*>(start);
                size_t size = end - start;
                
                size_t runLength = 0;
                for (size_t i = 0; i < size; i++) {
                    if (ptr[i] == 0xCC) {
                        runLength++;
                    } else {
                        if (runLength > 0 && runLength <= 2) {
                            detected = true;
                            break;
                        }
                        runLength = 0;
                    }
                }
                if (!detected && runLength > 0 && runLength <= 2) {
                    detected = true;
                }
                
                if (detected) break;
            }
        }
    }
    
    fclose(f);
    return detected;
}

// =============================================================================
// Advanced Techniques - Personality Check
// =============================================================================

bool Detector::CheckPersonality() {
    // Check personality flags for ADDR_NO_RANDOMIZE (disabled ASLR)
    // Debuggers sometimes disable ASLR for easier debugging
    
    int persona = personality(0xffffffff);
    if (persona == -1) return false;
    
    // ADDR_NO_RANDOMIZE = 0x0040000
    if (persona & 0x0040000) {
        return true; // ASLR disabled - suspicious
    }
    
    // READ_IMPLIES_EXEC can also be suspicious
    if (persona & 0x0400000) {
        return true;
    }
    
    return false;
}

// =============================================================================
// Advanced Techniques - Syscall Filter Detection
// =============================================================================

bool Detector::CheckSyscallFilter() {
    // Try to detect if syscalls are being filtered/traced
    
    // Method 1: Check seccomp status via prctl
    int result = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (result > 0) {
        return true; // Seccomp is enabled
    }
    
    // Method 2: Check /proc/self/syscall
    FILE* f = fopen("/proc/self/syscall", "r");
    if (f) {
        char buf[64];
        if (fgets(buf, sizeof(buf), f)) {
            // If we can read this, check for anomalies
            // Normal: "running" or syscall number
        }
        fclose(f);
    }
    
    return false;
}

// =============================================================================
// Advanced Evasion - Disable Core Dumps
// =============================================================================

bool Detector::DisableCoreDumps() {
    // Method 1: setrlimit
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        return false;
    }
    
    // Method 2: prctl PR_SET_DUMPABLE
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return false;
    }
    
    return true;
}

bool Detector::SetDumpable(bool enable) {
    return prctl(PR_SET_DUMPABLE, enable ? 1 : 0, 0, 0, 0) == 0;
}

bool Detector::SetupAntiTrace() {
    // Comprehensive anti-trace setup
    
    // 1. Disable core dumps
    DisableCoreDumps();
    
    // 2. Block ptrace
    BlockPtraceAdvanced();
    
    // 3. Install signal handlers
    SignalProtection::InstallHandlers();
    
    return true;
}

// ptrace-based checks
bool Detector::CheckPtraceTraceme() {
    // If ptrace fails, we're already being traced
    if (ptrace((__ptrace_request)PTRACE_TRACEME, 0, 0, 0) == -1) {
        return true;
    }
    // Detach from ourselves
    ptrace((__ptrace_request)PTRACE_DETACH, 0, 0, 0);
    return false;
}

bool Detector::CheckPtraceAttach() {
    pid_t pid = fork();
    
    if (pid == -1) {
        return false;
    }
    
    if (pid == 0) {
        // Child process
        int status = ptrace(PTRACE_ATTACH, getppid(), 0, 0);
        exit(status == -1 ? 1 : 0);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return WEXITSTATUS(status) != 0;
    }
}

// /proc based checks
bool Detector::CheckProcStatusTracerPid() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;
    
    char line[256];
    bool debugged = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = 0;
            sscanf(line, "TracerPid: %d", &tracerPid);
            debugged = (tracerPid != 0);
            break;
        }
    }
    
    fclose(f);
    return debugged;
}

bool Detector::CheckProcMaps() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    bool suspicious = false;
    
    while (fgets(line, sizeof(line), f)) {
        // Look for debugger-related libraries
        if (strstr(line, "libfrida") || 
            strstr(line, "frida") ||
            strstr(line, "xposed") ||
            strstr(line, "substrate")) {
            suspicious = true;
            break;
        }
    }
    
    fclose(f);
    return suspicious;
}

bool Detector::CheckProcSelfStatus() {
    // Check if /proc/self/status is accessible
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd == -1) return true; // Suspicious
    close(fd);
    return false;
}

// Environment checks
bool Detector::CheckLDPreload() {
    const char* ldPreload = getenv("LD_PRELOAD");
    return (ldPreload != nullptr && strlen(ldPreload) > 0);
}

bool Detector::CheckDebugEnvironment() {
    // Check for common debugger environment variables
    const char* suspicious[] = {
        "LINES", "COLUMNS", "GDB", "LLDB", 
        "_", "TERM", nullptr
    };
    
    for (int i = 0; suspicious[i] != nullptr; i++) {
        const char* val = getenv(suspicious[i]);
        if (val && strstr(val, "gdb")) {
            return true;
        }
    }
    
    return false;
}

// Timing checks
bool Detector::CheckTimingAnomaly() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Simple operation
    volatile int dummy = 0;
    for (int i = 0; i < 1000; i++) {
        dummy += i;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000L + 
                      (end.tv_nsec - start.tv_nsec);
    
    // If > 10ms for simple loop, suspicious
    return elapsed_ns > 10000000;
}

// Process checks
bool Detector::CheckParentProcess() {
    pid_t ppid = getppid();
    if (ppid == 1) return false; // Init is OK
    
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", ppid);
    
    FILE* f = fopen(path, "r");
    if (!f) return true;
    
    char cmdline[512] = {0};
    size_t readBytes = fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);

    if (readBytes == 0) {
        return false;
    }
    cmdline[readBytes] = '\0';
    
    // Check for debuggers
    return (strstr(cmdline, "gdb") || 
            strstr(cmdline, "lldb") || 
            strstr(cmdline, "strace") ||
            strstr(cmdline, "ltrace"));
}

bool Detector::CheckProcessName() {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", getpid());
    
    FILE* f = fopen(path, "r");
    if (!f) return true;
    
    char cmdline[512] = {0};
    size_t readBytes = fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);

    if (readBytes == 0) {
        return false;
    }
    cmdline[readBytes] = '\0';
    
    return false;
}

// Debugger-specific checks
bool Detector::CheckGDB() {
    // Check for GDB-specific artifacts in environment and parent process
    // Also delegate to memory breakpoint check
    return CheckMemoryBreakpoints() || CheckParentProcess();
}

bool Detector::CheckLLDB() {
    // LLDB detection - similar to GDB but check for lldb-specific strings
    return CheckParentProcess(); // Parent process check handles this
}

bool Detector::CheckFrida() {
    // Check for Frida-specific artifacts
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    bool detected = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gum-js-loop")) {
            detected = true;
            break;
        }
    }
    
    fclose(f);
    return detected;
}

// Signal-based checks
bool Detector::CheckSignalHandlers() {
    // Check if SIGTRAP handler is set (debugger might set it)
    struct sigaction sa;
    sigaction(SIGTRAP, nullptr, &sa);
    
    return (sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN);
}

// Main detection function
bool Detector::IsDebuggerPresent(uint32_t methods) {
    if (methods & PTRACE_TRACEME && CheckPtraceTraceme()) return true;
    if (methods & PROC_STATUS_TRACERPID && CheckProcStatusTracerPid()) return true;
    if (methods & PROC_SELF_STATUS && CheckProcSelfStatus()) return true;
    if (methods & LD_PRELOAD_CHECK && CheckLDPreload()) return true;
    if (methods & TIMING_BASED && CheckTimingAnomaly()) return true;
    if (methods & PARENT_PROCESS_CHECK && CheckParentProcess()) return true;
    if (methods & PROC_MAPS_CHECK && CheckProcMaps()) return true;
    if (methods & SIGNAL_BASED && CheckSignalHandlers()) return true;
    if (methods & GDB_SPECIFIC && CheckGDB()) return true;
    if (methods & FRIDA_DETECTION && CheckFrida()) return true;
    // Advanced techniques
    if (methods & SECCOMP_DETECTION && CheckSeccomp()) return true;
    if (methods & EBPF_DETECTION && CheckEBPF()) return true;
    if (methods & NAMESPACE_DETECTION && CheckNamespace()) return true;
    if (methods & MEMORY_BREAKPOINT && CheckMemoryBreakpoints()) return true;
    if (methods & PERSONALITY_CHECK && CheckPersonality()) return true;
    
    return false;
}

// Protection functions
bool Detector::EnableAntiDebug() {
    // Setup comprehensive anti-trace
    SetupAntiTrace();
    
    // Try advanced blocking first, fallback to simple
    if (!BlockPtraceAdvanced()) {
        BlockPtrace();
    }
    return true;
}

void Detector::TerminateIfDebugged() {
    if (IsDebuggerPresent()) {
        _exit(1);
    }
}

bool Detector::BlockPtrace() {
    // Use ptrace on ourselves to prevent others from attaching
    return ptrace((__ptrace_request)PTRACE_TRACEME, 0, 0, 0) != -1;
}

bool Detector::BlockPtraceAdvanced() {
    // Advanced technique: attach to ourselves and keep ptrace occupied
    // This prevents ANY external debugger from attaching (even with -p)
    // Similar to the self-debugging technique but without the heavy tracer
    
    // First, check if we're already being traced
    if (CheckProcStatusTracerPid()) {
        return false; // Already traced, can't do it
    }
    
    // Attempt to trace ourselves
    // This occupies the ptrace slot for our process
    long result = ptrace((__ptrace_request)PTRACE_TRACEME, 0, 0, 0);
    
    if (result == -1) {
        // Failed - either already traced or permission denied
        return false;
    }
    
    // Successfully attached to ourselves
    // Now any external debugger attempting to attach will fail with EPERM
    
    // Note: This is lighter than fork+tracer approach
    // We don't intercept syscalls, just block external attach
    
    return true;
}

// TimingGuard implementation
TimingGuard::TimingGuard(double thresholdMs) 
    : maxThresholdMs(thresholdMs) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    startTime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

TimingGuard::~TimingGuard() {
    if (IsAnomalous()) {
        _exit(1);
    }
}

bool TimingGuard::IsAnomalous() const {
    return GetElapsedMs() > maxThresholdMs;
}

double TimingGuard::GetElapsedMs() const {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t endTime = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    return (endTime - startTime) / 1000000.0;
}

// ProtectionThread implementation
pthread_t ProtectionThread::threadHandle = 0;
bool ProtectionThread::running = false;

void* ProtectionThread::ThreadProc(void* param) {
    uint32_t interval = *reinterpret_cast<uint32_t*>(param);
    delete reinterpret_cast<uint32_t*>(param);
    
    while (running) {
        if (Detector::IsDebuggerPresent()) {
            _exit(1);
        }
        usleep(interval * 1000);
    }
    
    return nullptr;
}

bool ProtectionThread::Start(uint32_t checkIntervalMs) {
    if (running) return false;
    
    running = true;
    uint32_t* interval = new uint32_t(checkIntervalMs);
    
    return pthread_create(&threadHandle, nullptr, ThreadProc, interval) == 0;
}

void ProtectionThread::Stop() {
    running = false;
    if (threadHandle) {
        pthread_join(threadHandle, nullptr);
        threadHandle = 0;
    }
}

// SignalProtection implementation
void SignalProtection::SigTrapHandler(int) {
    _exit(1);
}

void SignalProtection::SigSegvHandler(int) {
    _exit(1);
}

bool SignalProtection::InstallHandlers() {
    struct sigaction sa;
    sa.sa_handler = SigTrapHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGTRAP, &sa, nullptr) == -1) return false;
    
    sa.sa_handler = SigSegvHandler;
    if (sigaction(SIGSEGV, &sa, nullptr) == -1) return false;
    
    return true;
}

void SignalProtection::RemoveHandlers() {
    signal(SIGTRAP, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
}

} // namespace AntiDebug
} // namespace Linux
} // namespace Omamori
