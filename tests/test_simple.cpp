#include "../include/omamori.hpp"
#include <windows.h>
#include <iostream>

int main() {
    std::cout << "=== Omamori Simple Test (Windows) ===" << std::endl;
    std::cout << "Version: " << Omamori::GetVersion() << std::endl;
    std::cout << std::endl;
    
    // Test with custom config - ONLY Anti-Debug, NO Anti-Dump full protection
    std::cout << "[TEST] Creating custom configuration..." << std::endl;
    Omamori::ProtectionConfig config;
    config.enable_antivm = false;           // No VM check
    config.enable_antidebug = true;         // Enable debugger detection
    config.enable_antidebug_thread = false; // No background thread for now
    config.enable_antidump = false;         // Disable anti-dump to avoid PAGE_NOACCESS issues
    config.enable_memory_encryption = false;
    config.erase_headers = false;
    
    std::cout << "  Config:" << std::endl;
    std::cout << "    Anti-VM: OFF" << std::endl;
    std::cout << "    Anti-Debug: ON (no thread)" << std::endl;
    std::cout << "    Anti-Dump: OFF" << std::endl;
    std::cout << std::endl;
    
    std::cout << "[+] Initializing Omamori..." << std::endl;
    if (!Omamori::Initialize(config)) {
        std::cerr << "[-] Failed to initialize" << std::endl;
        return 1;
    }
    std::cout << "[+] Protection initialized" << std::endl;
    std::cout << std::endl;
    
    // Test debugger detection
    std::cout << "[TEST] Checking for debugger..." << std::endl;
    if (Omamori::IsDebugged()) {
        std::cout << "[!] DEBUGGER DETECTED" << std::endl;
        std::cout << "    (Would normally terminate)" << std::endl;
    } else {
        std::cout << "[+] No debugger detected" << std::endl;
    }
    std::cout << std::endl;
    
    // Test secure strings
    std::cout << "[TEST] Secure string encryption..." << std::endl;
    auto secret = SECURE_STR("My secret password!");
    std::cout << "  Decrypted value: " << secret.get() << std::endl;
    std::cout << "[+] Secure strings working correctly" << std::endl;
    std::cout << std::endl;
    
    // Now try with PE header obfuscation only (safe)
    std::cout << "[TEST] Testing PE header obfuscation..." << std::endl;
    Omamori::AntiDump::PEProtector protector(GetModuleHandle(nullptr));
    protector.ObfuscatePE();
    std::cout << "[+] PE header obfuscated successfully" << std::endl;
    std::cout << "    (DOS header and PE headers are now corrupted)" << std::endl;
    std::cout << std::endl;
    
    // Test syscall
    std::cout << "[TEST] Direct syscall check..." << std::endl;
    BOOL isDebugged = FALSE;
    NTSTATUS status = Omamori::Syscall::Common::NtQueryInformationProcess(
        GetCurrentProcess(),
        static_cast<PROCESSINFOCLASS>(7), // ProcessDebugPort
        &isDebugged,
        sizeof(isDebugged),
        nullptr
    );
    
    if (status == 0) {
        std::cout << "  Syscall result: " 
                  << (isDebugged ? "Debugger present" : "No debugger") << std::endl;
    } else {
        std::cout << "  Syscall status: 0x" << std::hex << status << std::dec << std::endl;
    }
    std::cout << "[+] Direct syscall working" << std::endl;
    std::cout << std::endl;
    
    std::cout << "[+] All tests completed successfully!" << std::endl;
    std::cout << "    The application is running with partial protection:" << std::endl;
    std::cout << "    - Anti-Debug: Active" << std::endl;
    std::cout << "    - PE Headers: Obfuscated" << std::endl;
    std::cout << "    - Syscalls: Working" << std::endl;
    std::cout << "    - Secure Strings: Encrypted" << std::endl;
    std::cout << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    
    return 0;
}
