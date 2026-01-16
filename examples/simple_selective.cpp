// Simple test of selective protection - Layer 2 and 4 only
#include "../include/omamori.hpp"
#include <iostream>

int main() {
    std::cout << "=== Layer 2 + 4 Only (Anti-Debug + Memory Encryption) ===" << std::endl;
    
    // Configure: Only Layer 2 and 4
    Omamori::ProtectionConfig config;
    config.enable_antivm = false;              // Layer 1: OFF
    config.enable_antidebug = true;            // Layer 2: ON
    config.enable_antidebug_thread = false;    // No background thread
    config.enable_antidump = false;            // Layer 3: OFF
    config.enable_memory_encryption = false;   // Layer 4: Available but not auto-init
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Layer 1 (Anti-VM):       " << (config.enable_antivm ? "ON" : "OFF") << std::endl;
    std::cout << "  Layer 2 (Anti-Debug):    " << (config.enable_antidebug ? "ON" : "OFF") << std::endl;
    std::cout << "  Layer 3 (Anti-Dump):     " << (config.enable_antidump ? "ON" : "OFF") << std::endl;
    std::cout << "  Layer 4 (Mem Encrypt):   " << (config.enable_memory_encryption ? "ON" : "OFF") << std::endl;
    
    std::cout << "\nInitializing..." << std::endl;
    bool init_ok = Omamori::Initialize(config);
    
    std::cout << "Initialize returned: " << (init_ok ? "true" : "false") << std::endl;
    
    // Check if debugger is present
    if (Omamori::IsDebugged()) {
        std::cout << "⚠ DEBUGGER DETECTED" << std::endl;
    } else {
        std::cout << "✓ No debugger detected" << std::endl;
    }
    
    std::cout << "\n✓ Application running with Layer 2 protection" << std::endl;
    std::cout << "  Try attaching gdb to see anti-debug in action!" << std::endl;
    
    return 0;
}
