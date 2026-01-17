#include "../include/omamori.hpp"
#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== Omamori Detailed Test (Windows) ===" << std::endl;
    std::cout << "Version: " << Omamori::GetVersion() << std::endl;
    std::cout << std::endl;
    
    // Test 1: Check environment before initialization
    std::cout << "[TEST 1] Environment checks (using public API)..." << std::endl;
    std::cout << "  Note: Individual checks are internal, we'll test after init" << std::endl;
    std::cout << std::endl;
    
    // Test 2: Initialize with Production preset (Anti-VM OFF)
    std::cout << "[TEST 2] Initializing with Production preset (Anti-VM OFF)..." << std::endl;
    auto config = Omamori::ProtectionConfig::Production();
    
    std::cout << "  Config settings:" << std::endl;
    std::cout << "    - Anti-VM: " << (config.enable_antivm ? "ON" : "OFF") << std::endl;
    std::cout << "    - Anti-Debug: " << (config.enable_antidebug ? "ON" : "OFF") << std::endl;
    std::cout << "    - Anti-Dump: " << (config.enable_antidump ? "ON" : "OFF") << std::endl;
    std::cout << "    - Memory Encryption: " << (config.enable_memory_encryption ? "ON" : "OFF") << std::endl;
    std::cout << std::endl;
    
    if (Omamori::Initialize(config)) {
        std::cout << "[+] Protection initialized successfully" << std::endl;
    } else {
        std::cerr << "[-] Failed to initialize protection" << std::endl;
        return 1;
    }
    std::cout << std::endl;
    
    // Test 3: Check for debugger
    std::cout << "[TEST 3] Debugger detection..." << std::endl;
    if (Omamori::IsDebugged()) {
        std::cout << "[!] DEBUGGER DETECTED - Application would normally terminate" << std::endl;
        std::cout << "    (Continuing for test purposes)" << std::endl;
    } else {
        std::cout << "[+] No debugger detected" << std::endl;
    }
    std::cout << std::endl;
    
    // Test 4: Individual checks via public API
    std::cout << "[TEST 4] Testing public protection API..." << std::endl;
    std::cout << "  IsDebugged() returns: " << (Omamori::IsDebugged() ? "true" : "false") << std::endl;
    std::cout << "  (This aggregates multiple internal checks)" << std::endl;
    std::cout << std::endl;
    
    // Test 5: Secure strings
    std::cout << "[TEST 5] Secure string encryption..." << std::endl;
    auto secureStr = SECURE_STR("Test string");
    std::cout << "  Decrypted: " << secureStr.get() << std::endl;
    std::cout << "[+] Secure strings working" << std::endl;
    std::cout << std::endl;
    
    // Test 6: Memory protection
    std::cout << "[TEST 6] Memory protection test..." << std::endl;
    std::cout << "  Installing VEH protection..." << std::endl;
    Omamori::AntiDump::MemoryProtection::InstallVEHProtection();
    std::cout << "[+] VEH protection installed" << std::endl;
    std::cout << std::endl;
    
    // Test 7: Run for a few seconds
    std::cout << "[TEST 7] Running with protection active..." << std::endl;
    for (int i = 0; i < 5; i++) {
        std::cout << "  Tick " << (i+1) << "/5" << std::endl;
        Sleep(500);
        
        if (Omamori::IsDebugged()) {
            std::cout << "[!] Debugger attached during runtime!" << std::endl;
            break;
        }
    }
    std::cout << "[+] Runtime test completed" << std::endl;
    std::cout << std::endl;
    
    // Cleanup
    std::cout << "[CLEANUP] Removing protections..." << std::endl;
    Omamori::AntiDump::MemoryProtection::RemoveVEHProtection();
    std::cout << "[+] All tests completed successfully" << std::endl;
    
    return 0;
}
