#include "../include/omamori.hpp"
#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== Omamori Protection Demo (Windows) ===" << std::endl;
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
    
    // Hide thread from debugger
    Omamori::AntiDebug::Detector::HideThreadFromDebugger();
    std::cout << "[+] Thread hidden from debugger" << std::endl;
    
    // Check for debugger with multiple methods
    std::cout << "[+] Checking for debugger..." << std::endl;
    if (Omamori::IsDebugged()) {
        std::cout << "[!] DEBUGGER DETECTED!" << std::endl;
        
        MessageBoxA(nullptr,
                   "Debugger detected! Application will terminate.",
                   "Omamori Protection", MB_ICONERROR);

        Omamori::TerminateIfDebugged();
    } else {
        std::cout << "[+] No debugger detected" << std::endl;
    }
    
    // Enable PE protection
    std::cout << "[+] Enabling PE protection..." << std::endl;
    Omamori::AntiDump::PEProtector protector(GetModuleHandle(nullptr));
    protector.ObfuscatePE();
    std::cout << "[+] PE header obfuscated" << std::endl;
    
    // Start protection thread
    std::cout << "[+] Starting anti-debug protection thread..." << std::endl;
    Omamori::AntiDebug::ProtectionThread::Start(500);
    std::cout << "[+] Protection thread started (checking every 500ms)" << std::endl;
    
    // Install VEH protection
    std::cout << "[+] Installing VEH memory protection..." << std::endl;
    Omamori::AntiDump::MemoryProtection::InstallVEHProtection();
    std::cout << "[+] VEH protection installed" << std::endl;
    
    // Test secure strings
    std::cout << std::endl;
    std::cout << "[+] Testing secure string encryption..." << std::endl;
    auto secureStr = SECURE_STR("This is a protected string!");
    auto secureWStr = SECURE_WSTR(L"Unicode protected string!");
    
    std::cout << "[+] Decrypted: " << secureStr.get() << std::endl;
    std::wcout << L"[+] Decrypted (wide): " << secureWStr.get() << std::endl;
    
    // Test syscall protection
    std::cout << std::endl;
    std::cout << "[+] Testing direct syscall execution..." << std::endl;
    
    BOOL isDebugged = FALSE;
    Omamori::Syscall::Common::NtQueryInformationProcess(
        GetCurrentProcess(),
        static_cast<PROCESSINFOCLASS>(7), // ProcessDebugPort
        &isDebugged,
        sizeof(isDebugged),
        nullptr
    );
    
    std::cout << "[+] Direct syscall check: " 
              << (isDebugged ? "Debugger present" : "No debugger") << std::endl;
    
    // Show message box
    std::cout << std::endl;
    std::cout << "[+] Application is now running with full protection" << std::endl;
    
    MessageBoxA(nullptr,
               "Omamori Protection is active!\n\n"
               "Try attaching a debugger, dumping memory, or using Process Hacker.\n"
               "The application will detect and terminate.",
               "Omamori Demo", MB_ICONINFORMATION);

    // Use timing guard for sensitive operations
    {
        Omamori::AntiDebug::TimingGuard guard(100.0); // 100ms threshold
        
        std::cout << "[+] Performing sensitive operation..." << std::endl;
        
        for (int i = 0; i < 5; i++) {
            std::cout << "    Working... " << (i + 1) << "/5" << std::endl;
            Sleep(200);
            
            // Check for debugger periodically
            if (Omamori::IsDebugged()) {
                std::cout << "[!] Debugger detected during execution!" << std::endl;
                MessageBoxA(nullptr, "Debugger detected!", "Omamori", MB_ICONERROR);
                return 1;
            }
        }
        
        std::cout << "[+] Sensitive operation completed" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "[+] Press any key to perform cleanup and exit..." << std::endl;
    std::cin.get();
    
    // Cleanup
    Omamori::AntiDebug::ProtectionThread::Stop();
    Omamori::AntiDump::MemoryProtection::RemoveVEHProtection();
    
    std::cout << "[+] Protection thread stopped" << std::endl;
    std::cout << "[+] Exiting safely" << std::endl;
    
    return 0;
}
