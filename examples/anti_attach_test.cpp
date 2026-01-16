/**
 * Anti-Attach Test
 * 
 * Demonstrates self-attach anti-debugging technique
 * Try to attach gdb to this process - it will fail!
 */

#include "../include/omamori.hpp"
#include <iostream>
#include <unistd.h>
#include <thread>
#include <chrono>

int main() {
    std::cout << "=== Anti-Attach Protection Test ===" << std::endl;
    std::cout << "PID: " << getpid() << std::endl;
    std::cout << std::endl;
    
    // Enable advanced anti-attach protection
    std::cout << "[+] Enabling BlockPtraceAdvanced()..." << std::endl;
    
    if (Omamori::AntiDebug::Detector::BlockPtraceAdvanced()) {
        std::cout << "[+] ✅ Self-attach successful!" << std::endl;
        std::cout << "[+] Process is now protected from external debugger attach" << std::endl;
    } else {
        std::cout << "[-] ❌ Self-attach failed (already being traced?)" << std::endl;
        
        // Check why
        if (Omamori::AntiDebug::Detector::CheckProcStatusTracerPid()) {
            std::cout << "[-] Reason: Process is already being traced" << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "=== Test Instructions ===" << std::endl;
    std::cout << "1. Open another terminal" << std::endl;
    std::cout << "2. Try: gdb -p " << getpid() << std::endl;
    std::cout << "3. GDB should fail with: 'Operation not permitted'" << std::endl;
    std::cout << std::endl;
    std::cout << "[*] Process will run for 60 seconds..." << std::endl;
    std::cout << std::endl;
    
    // Run for 60 seconds to give time for testing
    for (int i = 0; i < 60; i++) {
        std::cout << "[" << (i + 1) << "/60] Running... "
                  << "(Try to attach now!)" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    std::cout << std::endl;
    std::cout << "[+] Test completed. If you couldn't attach, protection works! ✅" << std::endl;
    
    return 0;
}
