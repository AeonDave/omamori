// Omamori Selective Protection Example
// Demonstrates how to enable only specific protection layers

#include "../include/omamori.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>

void example_production_config() {
    std::cout << "\n=== Example 1: Production Configuration ===" << std::endl;
    std::cout << "Layers: Anti-Debug + Anti-Dump (NO Anti-VM)" << std::endl;
    
    // Production preset: Disables anti-VM by default
    // Use MINIMAL techniques to avoid aggressive header corruption
    auto config = Omamori::ProtectionConfig::Production();
    config.antidump_techniques = Omamori::AntiDumpTechniques::MINIMAL;
    
    std::cout << "  Layer 1 (Anti-VM):       " << (config.enable_antivm ? "ON" : "OFF") << std::endl;
    std::cout << "  Layer 2 (Anti-Debug):    " << (config.enable_antidebug ? "ON" : "OFF") << std::endl;
    std::cout << "  Layer 3 (Anti-Dump):     " << (config.enable_antidump ? "ON (minimal)" : "OFF") << std::endl;
    std::cout << "  Layer 4 (Mem Encrypt):   " << (config.enable_memory_encryption ? "ON" : "OFF") << std::endl;
    
    Omamori::Initialize(config);
    std::cout << "✓ Production protection initialized" << std::endl;
}

void example_layer_2_and_4_only() {
    std::cout << "\n=== Example 2: Only Layer 2 (Anti-Debug) + Layer 4 (Memory Encryption) ===" << std::endl;
    
    // Custom configuration: Only Anti-Debug + Memory Encryption
    Omamori::ProtectionConfig config;
    config.enable_antivm = false;              // Layer 1: OFF
    config.enable_antidebug = true;            // Layer 2: ON
    config.enable_antidebug_thread = false;    // No background thread
    config.enable_antidump = false;            // Layer 3: OFF
    config.enable_memory_encryption = true;    // Layer 4: ON (manual use)
    
    std::cout << "  Layer 1 (Anti-VM):       OFF" << std::endl;
    std::cout << "  Layer 2 (Anti-Debug):    ON (no thread)" << std::endl;
    std::cout << "  Layer 3 (Anti-Dump):     OFF" << std::endl;
    std::cout << "  Layer 4 (Mem Encrypt):   ON (manual)" << std::endl;
    
    Omamori::Initialize(config);
    
    // Note: Memory encryption layer is enabled but buffers
    // must be allocated manually using EncryptionManager
    std::cout << "✓ Selective protection initialized" << std::endl;
    std::cout << "✓ Memory encryption available for manual use" << std::endl;
}

void example_debug_only() {
    std::cout << "\n=== Example 3: Debug-Only Protection (Layer 2) ===" << std::endl;
    
    auto config = Omamori::ProtectionConfig::DebugOnly();
    
    std::cout << "  Layer 1 (Anti-VM):       OFF" << std::endl;
    std::cout << "  Layer 2 (Anti-Debug):    ON" << std::endl;
    std::cout << "  Layer 3 (Anti-Dump):     OFF" << std::endl;
    std::cout << "  Layer 4 (Mem Encrypt):   OFF" << std::endl;
    
    Omamori::Initialize(config);
    
    // Check for debugger
    if (Omamori::IsDebugged()) {
        std::cout << "⚠ DEBUGGER DETECTED!" << std::endl;
    } else {
        std::cout << "✓ No debugger detected" << std::endl;
    }
}

void example_custom_granular() {
    std::cout << "\n=== Example 4: Granular Custom Configuration ===" << std::endl;
    std::cout << "Layers: Anti-Debug (no thread) + Anti-Dump (minimal)" << std::endl;
    
    Omamori::ProtectionConfig config;
    
    // Layer 1: Disabled
    config.enable_antivm = false;
    
    // Layer 2: Enabled but without background thread
    config.enable_antidebug = true;
    config.enable_antidebug_thread = false;
    
    // Layer 3: Partial - use MINIMAL techniques (no aggressive header corruption)
    config.enable_antidump = true;
    config.antidump_techniques = Omamori::AntiDumpTechniques::MINIMAL;
    
    // Layer 4: Disabled
    config.enable_memory_encryption = false;
    
    std::cout << "  Anti-Debug: ON (one-time check)" << std::endl;
    std::cout << "  Anti-Dump:  Partial (minimal techniques)" << std::endl;
    
    Omamori::Initialize(config);
    std::cout << "✓ Custom protection initialized" << std::endl;
}

void example_maximum_protection() {
    std::cout << "\n=== Example 5: Maximum Protection (All 4 Layers) ===" << std::endl;
    
    auto config = Omamori::ProtectionConfig::MaximumProtection();
    
    std::cout << "  Layer 1 (Anti-VM):       ON" << std::endl;
    std::cout << "  Layer 2 (Anti-Debug):    ON (with thread)" << std::endl;
    std::cout << "  Layer 3 (Anti-Dump):     ON (full)" << std::endl;
    std::cout << "  Layer 4 (Mem Encrypt):   ON (manual)" << std::endl;
    
    Omamori::Initialize(config);
    std::cout << "✓ Maximum protection initialized" << std::endl;
}

void example_antivm_with_selective_methods() {
    std::cout << "\n=== Example 6: Anti-VM with Selective Methods ===" << std::endl;
    std::cout << "Only CPUID + MAC Address checks" << std::endl;
    
    Omamori::ProtectionConfig config;
    config.enable_antivm = true;
    
    // Use central config flags - these work on both platforms
    config.antivm_techniques = 
        Omamori::AntiVMTechniques::CPUID_CHECK | 
        Omamori::AntiVMTechniques::MAC_ADDRESS;  // Only 2 methods
    
    config.enable_antidebug = false;
    config.enable_antidump = false;
    
    std::cout << "  Detection methods: CPUID + MAC only" << std::endl;
    
    Omamori::Initialize(config);
    std::cout << "✓ Selective anti-VM initialized" << std::endl;
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   OMAMORI SELECTIVE PROTECTION EXAMPLES            ║" << std::endl;
    std::cout << "║   Demonstrating Layer-by-Layer Control             ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n⚠ Note: Only ONE example can run per execution" << std::endl;
    std::cout << "         (Multiple Initialize() calls not supported)" << std::endl;
    
    // Choose which example to run (uncomment one):
    
    // Example 1: Production (typical use case - DEFAULT)
    example_production_config();
    
    // Example 2: Only Layer 2 + 4 (as requested)
    // example_layer_2_and_4_only();
    
    // Example 3: Debug protection only
    // example_debug_only();
    
    // Example 4: Granular control
    // example_custom_granular();
    
    // Example 5: Maximum protection
    // example_maximum_protection();  // Would terminate if VM detected
    
    // Example 6: Anti-VM with selective methods
    // example_antivm_with_selective_methods();
    
    std::cout << "\n╔════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║              EXAMPLE COMPLETED                     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n📌 Key Takeaways:" << std::endl;
    std::cout << "  • Each layer can be enabled/disabled independently" << std::endl;
    std::cout << "  • Anti-VM is DISABLED by default in Production preset" << std::endl;
    std::cout << "  • Use ProtectionConfig for fine-grained control" << std::endl;
    std::cout << "  • Memory encryption requires manual buffer creation" << std::endl;
    std::cout << "\n💡 To run other examples, uncomment them in main()" << std::endl;
    
    return 0;
}
