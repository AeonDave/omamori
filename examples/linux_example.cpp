#include "../include/omamori.hpp"
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== Omamori Protection Demo (Linux) ===" << std::endl;
    std::cout << "Version: " << Omamori::GetVersion() << std::endl;
    std::cout << std::endl;
    
    // Initialize protection
    std::cout << "[+] Initializing Omamori..." << std::endl;
    if (Omamori::Initialize()) {
        std::cout << "[+] Protection initialized successfully" << std::endl;
    } else {
        std::cerr << "[-] Failed to initialize protection" << std::endl;
        return 1;
    }
    
    // Check for debugger
    std::cout << "[+] Checking for debugger..." << std::endl;
    if (Omamori::IsDebugged()) {
        std::cout << "[!] DEBUGGER DETECTED!" << std::endl;
        std::cout << "[!] Terminating..." << std::endl;
        Omamori::TerminateIfDebugged();
    } else {
        std::cout << "[+] No debugger detected" << std::endl;
    }
    
    // Check for VM
    std::cout << "[+] Checking for virtual machine..." << std::endl;
    if (Omamori::AntiVM::Detector::IsVirtualMachine()) {
        std::cout << "[!] VM DETECTED: " << Omamori::AntiVM::Detector::GetVMType() << std::endl;
        if (Omamori::AntiVM::Detector::IsContainerized()) {
            std::cout << "[!] Running in container (Docker/LXC)" << std::endl;
        }
    } else {
        std::cout << "[+] Running on bare metal" << std::endl;
    }
    
    // Enable full protection
    std::cout << "[+] Enabling full protection (anti-debug, anti-dump)..." << std::endl;
    
    // Anti-debug protection thread
    Omamori::AntiDebug::ProtectionThread::Start(500);
    std::cout << "[+] Anti-debug protection thread started" << std::endl;
    
    // Anti-dump protection
    Omamori::AntiDump::CoreDumpProtection::DisableCoreDumps();
    Omamori::AntiDump::CoreDumpProtection::InstallPrctlProtection();
    std::cout << "[+] Core dump protection enabled" << std::endl;
    
    // ELF protection
    Omamori::AntiDump::ELFProtector protector;
    protector.EnableFullProtection();
    std::cout << "[+] ELF header protection enabled" << std::endl;
    
    // Test secure strings
    std::cout << std::endl;
    std::cout << "[+] Testing secure string encryption..." << std::endl;
    auto secureStr = SECURE_STR("This is a protected string!");
    std::cout << "[+] Decrypted: " << secureStr.get() << std::endl;
    
    // Simulate protected application work
    std::cout << std::endl;
    std::cout << "[+] Application is now running with full protection" << std::endl;
    std::cout << "[+] Try attaching gdb, strace, or creating a core dump!" << std::endl;
    std::cout << std::endl;
    
    // Use timing guard for sensitive operations
    {
        Omamori::AntiDebug::TimingGuard guard(100.0); // 100ms threshold
        
        std::cout << "[+] Performing sensitive operation..." << std::endl;
        // Simulate some work
        for (int i = 0; i < 5; i++) {
            std::cout << "    Working... " << (i + 1) << "/5" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            
            // Check for debugger periodically
            if (Omamori::IsDebugged()) {
                std::cout << "[!] Debugger detected during execution!" << std::endl;
                return 1;
            }
        }
        
        std::cout << "[+] Sensitive operation completed" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "[+] Press Ctrl+C to exit..." << std::endl;
    
    // Keep running and monitoring
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Periodic checks
        if (Omamori::IsDebugged()) {
            std::cout << "[!] DEBUGGER DETECTED - TERMINATING!" << std::endl;
            break;
        }
    }
    
    // Cleanup
    Omamori::AntiDebug::ProtectionThread::Stop();
    std::cout << "[+] Protection thread stopped" << std::endl;
    std::cout << "[+] Exiting safely" << std::endl;
    
    return 0;
}
