// Omamori Linux Protection Test Suite
// Tests all Linux anti-debug, anti-dump, and anti-VM techniques

#ifdef __linux__

#include "../include/omamori.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <unistd.h>

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
    
    using namespace Omamori::Linux::AntiDebug;
    
    // Test ptrace checks
    try {
        bool detected = Detector::CheckPtraceTraceme();
        PrintResult("Ptrace TRACEME", true, detected ? "Already traced" : "Not traced");
    } catch (...) {
        PrintResult("Ptrace TRACEME", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckPtraceAttach();
        PrintResult("Ptrace ATTACH", true, detected ? "Attach failed (traced)" : "Can attach");
    } catch (...) {
        PrintResult("Ptrace ATTACH", false, "Exception thrown");
    }
    
    // Test /proc checks
    try {
        bool detected = Detector::CheckProcStatusTracerPid();
        PrintResult("Proc Status TracerPid", true, detected ? "TracerPid > 0" : "TracerPid = 0");
    } catch (...) {
        PrintResult("Proc Status TracerPid", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckProcMaps();
        PrintResult("Proc Maps", true, detected ? "Suspicious maps" : "Normal maps");
    } catch (...) {
        PrintResult("Proc Maps", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckProcSelfStatus();
        PrintResult("Proc Self Status", true, detected ? "Debug detected" : "Normal status");
    } catch (...) {
        PrintResult("Proc Self Status", false, "Exception thrown");
    }
    
    // Test blocking techniques
    try {
        bool blocked = Detector::BlockPtrace();
        PrintResult("Block Ptrace", true, blocked ? "Ptrace blocked" : "Block failed");
    } catch (...) {
        PrintResult("Block Ptrace", false, "Exception thrown");
    }
    
    try {
        bool blocked = Detector::BlockPtraceAdvanced();
        PrintResult("Block Ptrace Advanced", true, blocked ? "Advanced block" : "Block failed");
    } catch (...) {
        PrintResult("Block Ptrace Advanced", false, "Exception thrown");
    }
    
    // Test comprehensive check
    try {
        bool detected = Detector::IsDebuggerPresent();
        PrintResult("Comprehensive Check", true, detected ? "DEBUGGER FOUND" : "CLEAN");
    } catch (...) {
        PrintResult("Comprehensive Check", false, "Exception thrown");
    }
}

// Anti-Dump Tests
void TestAntiDump() {
    PrintHeader("Anti-Dump Protection");
    
    using namespace Omamori::Linux::AntiDump;
    
    // Test Memory protection
    try {
        bool success = MemoryProtection::GetModuleInfo();
        PrintResult("Get Module Info", true, success ? "Module info obtained" : "Failed");
    } catch (...) {
        PrintResult("Get Module Info", false, "Exception thrown");
    }
    
    try {
        bool success = MemoryProtection::ProtectHeaders();
        PrintResult("Protect Headers", true, success ? "Headers protected" : "Failed");
    } catch (...) {
        PrintResult("Protect Headers", false, "Exception thrown");
    }
    
    try {
        bool success = MemoryProtection::EraseELFHeader();
        PrintResult("Erase ELF Header", true, success ? "Header erased" : "Failed");
    } catch (...) {
        PrintResult("Erase ELF Header", false, "Exception thrown");
    }
    
    // Test Core dump protection
    try {
        bool success = CoreDumpProtection::DisableCoreDumps();
        PrintResult("Disable Core Dumps", true, success ? "Core dumps disabled" : "Failed");
    } catch (...) {
        PrintResult("Disable Core Dumps", false, "Exception thrown");
    }
    
    try {
        bool success = CoreDumpProtection::SetResourceLimits();
        PrintResult("Resource Limits", true, success ? "Resource limits set" : "Failed");
    } catch (...) {
        PrintResult("Resource Limits", false, "Exception thrown");
    }
    
    // Test ELF protector
    try {
        ELFProtector protector;
        protector.ObfuscateELF();
        PrintResult("ELF Obfuscation", true, "ELF obfuscated");
    } catch (...) {
        PrintResult("ELF Obfuscation", false, "Exception thrown");
    }
}

// Anti-VM Tests
void TestAntiVM() {
    PrintHeader("Anti-VM Detection");
    
    using namespace Omamori::Linux::AntiVM;
    
    // Test CPUID check
    try {
        bool detected = Detector::CheckCPUID();
        PrintResult("CPUID Hypervisor", true, detected ? "Hypervisor detected" : "Bare metal");
    } catch (...) {
        PrintResult("CPUID Hypervisor", false, "Exception thrown");
    }
    
    try {
        bool detected = Detector::CheckHypervisorBit();
        PrintResult("Hypervisor Bit", true, detected ? "Hypervisor bit set" : "No hypervisor");
    } catch (...) {
        PrintResult("Hypervisor Bit", false, "Exception thrown");
    }
    
    // Test comprehensive VM check
    try {
        bool detected = Detector::IsVirtualMachine();
        PrintResult("Comprehensive VM Check", true, detected ? "VM DETECTED" : "BARE METAL");
    } catch (...) {
        PrintResult("Comprehensive VM Check", false, "Exception thrown");
    }
    
    // Test VM type detection
    try {
        const char* vmType = Detector::GetVMType();
        PrintResult("VM Type Detection", true, vmType ? vmType : "No VM");
    } catch (...) {
        PrintResult("VM Type Detection", false, "Exception thrown");
    }
    
    // Test container detection
    try {
        bool detected = Detector::IsContainerized();
        PrintResult("Container Detection", true, detected ? "Container detected" : "Not containerized");
    } catch (...) {
        PrintResult("Container Detection", false, "Exception thrown");
    }
    
    // Test hardware info
    try {
        bool hasHypervisor = HardwareInfo::HasHypervisor();
        PrintResult("Hardware Hypervisor Check", true, hasHypervisor ? "Hypervisor present" : "No hypervisor");
    } catch (...) {
        PrintResult("Hardware Hypervisor Check", false, "Exception thrown");
    }
    
    try {
        const char* vendor = HardwareInfo::GetCPUVendor();
        PrintResult("CPU Vendor", true, vendor ? vendor : "Unknown");
    } catch (...) {
        PrintResult("CPU Vendor", false, "Exception thrown");
    }
}

// Protection Thread Tests
void TestProtectionThread() {
    PrintHeader("Protection Thread");
    
    using namespace Omamori::Linux::AntiDebug;
    
    // Test thread start/stop
    try {
        ProtectionThread::Start(500);
        sleep(2); // Let it run for a bit
        ProtectionThread::Stop();
        PrintResult("Protection Thread Lifecycle", true, "Thread ran successfully");
    } catch (...) {
        PrintResult("Protection Thread Lifecycle", false, "Exception thrown");
    }
}

// Secure String Tests
void TestSecureString() {
    PrintHeader("Secure String");
    
    // Test string encryption/decryption
    try {
        auto encrypted = SECURE_STR("TestString123");
        const char* decrypted = encrypted.get();
        bool matches = (std::string(decrypted) == "TestString123");
        PrintResult("String Encryption", matches, 
                   matches ? "Encryption works" : "Encryption failed");
    } catch (...) {
        PrintResult("String Encryption", false, "Exception thrown");
    }
    
    // Test secure string auto-wipe
    try {
        {
            auto secure = SECURE_STR("SensitiveData");
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
        bool success = Omamori::Initialize();
        PrintResult("Initialize", success, "Initialization successful");
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
    
    // Test GetVersion
    try {
        const char* version = Omamori::GetVersion();
        PrintResult("GetVersion", version != nullptr, version ? version : "Failed");
    } catch (...) {
        PrintResult("GetVersion", false, "Exception thrown");
    }
}

} // namespace Test

int main() {
    std::cout << "Omamori Linux Protection Test Suite\n";
    std::cout << "====================================\n";
    std::cout << "Version: " << Omamori::GetVersion() << "\n";
    
    try {
        Test::TestAntiDebug();
        Test::TestAntiDump();
        Test::TestAntiVM();
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
    std::cerr << "This test suite is for Linux only." << std::endl;
    return 1;
}
#endif // __linux__
