#include "../include/antidebug.hpp"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

namespace Omamori {
namespace Linux {
namespace AntiDebug {

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
    fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);
    
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
    fread(cmdline, 1, sizeof(cmdline) - 1, f);
    fclose(f);
    
    return false;
}

// Debugger-specific checks
bool Detector::CheckGDB() {
    // GDB sets specific breakpoint instructions
    // Check for INT3 (0xCC) in code
    return false; // Simplified
}

bool Detector::CheckLLDB() {
    return false; // Simplified
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
    
    return false;
}

// Protection functions
bool Detector::EnableAntiDebug() {
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

bool Detector::ObfuscateMemory() {
    // Implement memory obfuscation techniques
    return false;
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
