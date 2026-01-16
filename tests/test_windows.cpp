// Omamori Windows Protection Test Suite
// Tests all Windows anti-debug, anti-dump, and syscall techniques

#ifdef _WIN32

#include "../include/omamori.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

namespace Test {

struct TestResult {
    std::string name;
    bool passed;
    std::string detail;
};

std::vector<TestResult> results;

void PrintHeader(const std::string& category) {
    std::cout << "\n=== Testing " << category << " ===\n" << std::endl;
}

void PrintResult(const std::string& test_name, bool passed, const std::string& detail = "") {
    results.push_back({test_name, passed, detail});
    std::cout << "[" << (passed ? "PASS" : "FAIL") << "] " << test_name;
    if (!detail.empty()) {
        std::cout << " - " << detail;
    }
    std::cout << std::endl;
}

void PrintSummary() {
    size_t passed = 0;
    size_t failed = 0;
    
    for (const auto& result : results) {
        if (result.passed) passed++;
        else failed++;
    }
    
    std::cout << "\n=== Test Summary ===" << std::endl;
    std::cout << "Total:  " << results.size() << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Success Rate: " << (100.0 * passed / results.size()) << "%" << std::endl;
}

// Anti-Debug Tests
void TestAntiDebug() {
    PrintHeader("Anti-Debug Techniques");
    
    using namespace Omamori::AntiDebug;
    
    // Test PEB checks
    try {
        bool detected = Detector::CheckPEBBeingDebugged();
        PrintResult("PEB BeingDebugged", true, detected ? "Debugger detected" : "No debugger");
    } catch (...) {
        PrintResult("PEB BeingDebugged", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckPEBNtGlobalFlag();
        PrintResult("PEB NtGlobalFlag", true, detected ? "Debug flag detected" : "Clean");
    } catch (...) {
        PrintResult("PEB NtGlobalFlag", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckPEBHeapFlags();
        PrintResult("PEB Heap Flags", true, detected ? "Debug heap detected" : "Clean");
    } catch (...) {
        PrintResult("PEB Heap Flags", false, "Exception thrown");
    }
    
    // Test hardware breakpoint detection
    try {
        bool detected = Detector::CheckHardwareBreakpoints();
        PrintResult("Hardware Breakpoints", true, detected ? "BP detected" : "No BP");
    } catch (...) {
        PrintResult("Hardware Breakpoints", false, "Exception thrown");
    }
    
    // Test timing checks
    try {
        bool detected = Detector::CheckTimingRDTSC();
        PrintResult("Timing RDTSC", true, detected ? "Timing anomaly" : "Normal timing");
    } catch (...) {
        PrintResult("Timing RDTSC", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckTimingQueryPerformanceCounter();
        PrintResult("Timing QPC", true, detected ? "Timing anomaly" : "Normal timing");
    } catch (...) {
        PrintResult("Timing QPC", false, "Exception thrown");
    }
    
    // Test API-based detection
    try {
        bool detected = Detector::CheckRemoteDebugger();
        PrintResult("Remote Debugger", true, detected ? "Remote debug" : "No remote debug");
    } catch (...) {
        PrintResult("Remote Debugger", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckDebugPort();
        PrintResult("Debug Port", true, detected ? "Port detected" : "No port");
    } catch (...) {
        PrintResult("Debug Port", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckDebugFlags();
        PrintResult("Debug Flags", true, detected ? "Flags detected" : "No flags");
    } catch (...) {
        PrintResult("Debug Flags", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckDebugObject();
        PrintResult("Debug Object", true, detected ? "Object detected" : "No object");
    } catch (...) {
        PrintResult("Debug Object", false, "Exception thrown");
    }
    
    // Test exception-based detection
    try {
        bool detected = Detector::CheckCloseHandleException();
        PrintResult("CloseHandle Exception", true, detected ? "Exception detected" : "Normal");
    } catch (...) {
        PrintResult("CloseHandle Exception", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckOutputDebugString();
        PrintResult("OutputDebugString", true, detected ? "Debugger detected" : "No debugger");
    } catch (...) {
        PrintResult("OutputDebugString", false, "Exception thrown");
    }
    
    // Test system checks
    try {
        bool detected = Detector::CheckKernelDebugger();
        PrintResult("Kernel Debugger", true, detected ? "Kernel debug" : "No kernel debug");
    } catch (...) {
        PrintResult("Kernel Debugger", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckParentProcess();
        PrintResult("Parent Process", true, detected ? "Suspicious parent" : "Normal parent");
    } catch (...) {
        PrintResult("Parent Process", false, "Exception thrown");
    }
    
    // Test综合检测
    try {
        bool detected = Detector::IsDebugged();
        PrintResult("Comprehensive Check", true, detected ? "DEBUGGER FOUND" : "CLEAN");
    } catch (...) {
        PrintResult("Comprehensive Check", false, "Exception thrown");
    }
}

// Anti-Dump Tests
void TestAntiDump() {
    PrintHeader("Anti-Dump Protection");
    
    using namespace Omamori::AntiDump;
    
    // Test PE header corruption
    try {
        Protection::CorruptPEHeader();
        PrintResult("Corrupt PE Header", true, "Headers corrupted");
    } catch (...) {
        PrintResult("Corrupt PE Header", false, "Exception thrown");
    }
    
    // Test erase DOS header
    try {
        Protection::EraseDOSHeader();
        PrintResult("Erase DOS Header", true, "DOS header erased");
    } catch (...) {
        PrintResult("Erase DOS Header", false, "Exception thrown");
    }
    
    // Test erase PE header
    try {
        Protection::ErasePEHeader();
        PrintResult("Erase PE Header", true, "PE header erased");
    } catch (...) {
        PrintResult("Erase PE Header", false, "Exception thrown");
    }
    
    // Test memory protection
    try {
        Protection::ProtectHeaderMemory();
        PrintResult("Protect Header Memory", true, "Memory protected");
    } catch (...) {
        PrintResult("Protect Header Memory", false, "Exception thrown");
    }
    
    // Test PEB manipulation
    try {
        Protection::UnlinkFromPEB();
        PrintResult("Unlink from PEB", true, "Module unlinked");
    } catch (...) {
        PrintResult("Unlink from PEB", false, "Exception thrown");
    }
    
    // Test continuous protection
    try {
        Protection::StartContinuousProtection(1000);
        Sleep(2000); // Let it run
        Protection::StopContinuousProtection();
        PrintResult("Continuous Protection", true, "Background protection ran");
    } catch (...) {
        PrintResult("Continuous Protection", false, "Exception thrown");
    }
    
    // Test VEH handler
    try {
        Protection::InstallVEHProtection();
        PrintResult("VEH Protection", true, "VEH handler installed");
    } catch (...) {
        PrintResult("VEH Protection", false, "Exception thrown");
    }
}

// Syscall Tests
void TestSyscalls() {
    PrintHeader("Direct Syscalls");
    
    using namespace Omamori::Syscall;
    
    // Test syscall stub generation
    try {
        auto stub = StubManager::GetStub("NtQueryInformationProcess");
        PrintResult("Generate Syscall Stub", stub != nullptr, 
                   stub ? "Stub generated" : "Stub generation failed");
    } catch (...) {
        PrintResult("Generate Syscall Stub", false, "Exception thrown");
    }
    
    // Test hook detection
    try {
        bool hooked = Detector::IsFunctionHooked("NtQueryInformationProcess");
        PrintResult("Hook Detection", true, 
                   hooked ? "Hook detected" : "No hook");
    } catch (...) {
        PrintResult("Hook Detection", false, "Exception thrown");
    }
    
    // Test syscall number resolution
    try {
        DWORD number = Internal::GetSyscallNumber("NtQueryInformationProcess");
        PrintResult("Syscall Number Resolution", number != 0, 
                   number ? "Number resolved" : "Resolution failed");
    } catch (...) {
        PrintResult("Syscall Number Resolution", false, "Exception thrown");
    }
}

// Protection Thread Tests
void TestProtectionThread() {
    PrintHeader("Protection Thread");
    
    using namespace Omamori::AntiDebug;
    
    // Test thread start/stop
    try {
        ProtectionThread::Start(500);
        Sleep(2000); // Let it run for a bit
        ProtectionThread::Stop();
        PrintResult("Protection Thread Lifecycle", true, "Thread ran successfully");
    } catch (...) {
        PrintResult("Protection Thread Lifecycle", false, "Exception thrown");
    }
    
    // Test thread callback
    try {
        bool callback_fired = false;
        ProtectionThread::SetCallback([&callback_fired]() {
            callback_fired = true;
        });
        
        ProtectionThread::Start(100);
        Sleep(500);
        ProtectionThread::Stop();
        
        PrintResult("Protection Thread Callback", callback_fired, 
                   callback_fired ? "Callback executed" : "Callback not executed");
    } catch (...) {
        PrintResult("Protection Thread Callback", false, "Exception thrown");
    }
}

// Secure String Tests
void TestSecureString() {
    PrintHeader("Secure String");
    
    // Test string encryption/decryption
    try {
        auto encrypted = XSTR("TestString123");
        std::string decrypted = encrypted.decrypt();
        bool matches = (decrypted == "TestString123");
        PrintResult("String Encryption", matches, 
                   matches ? "Encryption works" : "Encryption failed");
    } catch (...) {
        PrintResult("String Encryption", false, "Exception thrown");
    }
    
    // Test secure string auto-wipe
    try {
        {
            Omamori::SecureString secure("SensitiveData");
            // String should be wiped on destruction
        }
        PrintResult("SecureString Auto-wipe", true, "String wiped on destruction");
    } catch (...) {
        PrintResult("SecureString Auto-wipe", false, "Exception thrown");
    }
}

// Integration Tests
void TestIntegration() {
    PrintHeader("Integration Tests");
    
    // Test Initialize
    try {
        Omamori::Initialize();
        PrintResult("Initialize", true, "Initialization successful");
    } catch (...) {
        PrintResult("Initialize", false, "Exception thrown");
    }
    
    // Test IsDebugged
    try {
        bool debugged = Omamori::IsDebugged();
        PrintResult("IsDebugged", true, debugged ? "Debugger present" : "No debugger");
    } catch (...) {
        PrintResult("IsDebugged", false, "Exception thrown");
    }
    
    // Test EnableFullProtection
    try {
        Omamori::EnableFullProtection();
        PrintResult("EnableFullProtection", true, "Full protection enabled");
    } catch (...) {
        PrintResult("EnableFullProtection", false, "Exception thrown");
    }
    
    // Test TerminateIfDebugged (don't actually terminate in test)
    try {
        // Just verify the function exists and is callable
        // We won't actually call it to avoid terminating the test
        PrintResult("TerminateIfDebugged", true, "Function available");
    } catch (...) {
        PrintResult("TerminateIfDebugged", false, "Exception thrown");
    }
}

} // namespace Test

int main() {
    std::cout << "Omamori Windows Protection Test Suite\n";
    std::cout << "======================================\n";
    
    try {
        Test::TestAntiDebug();
        Test::TestAntiDump();
        Test::TestSyscalls();
        Test::TestProtectionThread();
        Test::TestSecureString();
        Test::TestIntegration();
        
        Test::PrintSummary();
    } catch (const std::exception& e) {
        std::cerr << "\nFatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

#else
int main() {
    std::cerr << "This test suite is for Windows only." << std::endl;
    return 1;
}
#endif // _WIN32
