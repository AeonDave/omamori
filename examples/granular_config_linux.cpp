/**
 * @file granular_config_linux.cpp
 * @brief Demonstrates granular technique selection on Linux
 * 
 * This example shows how to:
 * - Select specific anti-debug techniques using bitmasks
 * - Select specific anti-VM techniques using bitmasks
 * - Select specific anti-dump techniques using bitmasks
 * - Use the builder pattern (With* methods) for configuration
 * - Use preset configurations as starting points
 */

#include "../include/omamori.hpp"
#include <iostream>
#include <iomanip>

// Helper to print binary representation
void printBitmask(const char* name, uint32_t value) {
    std::cout << "  " << std::setw(25) << std::left << name << ": 0x" 
              << std::hex << std::setw(8) << std::setfill('0') << value 
              << std::dec << std::setfill(' ') << std::endl;
}

void example_granular_antidebug() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 1: Granular Anti-Debug Technique Selection        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    // Import technique flags
    using namespace Omamori::AntiDebugTechniques;
    
    std::cout << "\nAvailable Anti-Debug Techniques (Linux):" << std::endl;
    std::cout << "  PROC_STATUS_TRACERPID    - /proc/self/status TracerPid" << std::endl;
    std::cout << "  PTRACE_TRACEME           - PTRACE_TRACEME test" << std::endl;
    std::cout << "  TIMING_RDTSC             - RDTSC instruction timing" << std::endl;
    std::cout << "  PROC_MAPS_CHECK          - /proc/self/maps analysis" << std::endl;
    std::cout << "  PARENT_PROCESS_CHECK     - Parent process inspection" << std::endl;
    std::cout << "  LD_PRELOAD_CHECK         - LD_PRELOAD environment" << std::endl;
    std::cout << "  FRIDA_DETECTION          - Frida detection" << std::endl;
    std::cout << "  SECCOMP_DETECTION        - seccomp detection" << std::endl;
    std::cout << "  EBPF_DETECTION           - eBPF tracing detection" << std::endl;
    
    // === Method 1: Select specific techniques with bitmask ===
    std::cout << "\n--- Method 1: Direct Bitmask ---" << std::endl;
    
    Omamori::ProtectionConfig config1;
    config1.enable_antidebug = true;
    config1.enable_antivm = false;
    config1.enable_antidump = false;
    config1.enable_antidebug_thread = false;
    
    // Select only fast, reliable checks (no timing-based)
    config1.antidebug_techniques = 
        PROC_STATUS_TRACERPID |  // Fast /proc check
        PTRACE_TRACEME |         // Reliable ptrace test
        LD_PRELOAD_CHECK |       // Environment check
        PARENT_PROCESS_CHECK;    // Process hierarchy check
        // NOT: TIMING_RDTSC (can cause false positives)
    
    printBitmask("antidebug_techniques", config1.antidebug_techniques);
    
    // === Method 2: Use builder pattern (With* methods) ===
    std::cout << "\n--- Method 2: Builder Pattern (With* methods) ---" << std::endl;
    
    auto config2 = Omamori::ProtectionConfig()
        .WithAntiDebug(true,
            PROC_STATUS_TRACERPID |
            PTRACE_TRACEME |
            PROC_MAPS_CHECK |
            FRIDA_DETECTION
        )
        .WithAntiVM(false)
        .WithAntiDump(false)
        .WithAntiDebugThread(false);
    
    printBitmask("antidebug_techniques", config2.antidebug_techniques);
    
    // === Method 3: Start from preset and customize ===
    std::cout << "\n--- Method 3: Preset + Customization ---" << std::endl;
    
    auto config3 = Omamori::ProtectionConfig::Stealth();  // Start with stealth preset
    config3.antidebug_techniques &= ~TIMING_RDTSC;        // Remove timing (can cause FPs)
    config3.antidebug_techniques |= FRIDA_DETECTION;      // Add Frida detection
    
    printBitmask("antidebug_techniques", config3.antidebug_techniques);
    
    // === Method 4: Use preset technique groups ===
    std::cout << "\n--- Method 4: Preset Technique Groups ---" << std::endl;
    
    Omamori::ProtectionConfig config4;
    config4.enable_antidebug = true;
    config4.enable_antidebug_thread = false;
    config4.enable_antivm = false;
    config4.enable_antidump = false;
    
    // ALL: Every technique
    std::cout << "  ALL (all techniques):" << std::endl;
    printBitmask("    ALL", ALL);
    
    // FAST: Quick checks only
    std::cout << "  FAST (quick checks):" << std::endl;
    config4.antidebug_techniques = FAST;
    printBitmask("    FAST", FAST);
    
    // STEALTH: Less detectable
    std::cout << "  STEALTH (hard to detect):" << std::endl;
    printBitmask("    STEALTH", STEALTH);
    
    std::cout << "\n✓ Using FAST preset for initialization..." << std::endl;
    Omamori::Initialize(config4);
    
    // Test if debugger detected
    if (Omamori::IsDebugged()) {
        std::cout << "⚠ DEBUGGER DETECTED!" << std::endl;
    } else {
        std::cout << "✓ No debugger detected" << std::endl;
    }
}

void example_granular_antivm() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 2: Granular Anti-VM Technique Selection           ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori::AntiVMTechniques;
    
    std::cout << "\nAvailable Anti-VM Techniques (Linux):" << std::endl;
    std::cout << "  CPUID_CHECK              - CPUID hypervisor bit" << std::endl;
    std::cout << "  MAC_ADDRESS              - VM MAC address prefixes" << std::endl;
    std::cout << "  DRIVER_CHECK             - VM kernel modules" << std::endl;
    std::cout << "  DEVICE_CHECK             - /sys/devices/virtual" << std::endl;
    std::cout << "  FILE_CHECK               - VM-related files" << std::endl;
    std::cout << "  PROCESS_CHECK            - VM-related processes" << std::endl;
    std::cout << "  TIMING_ATTACK            - RDTSC timing analysis" << std::endl;
    std::cout << "  ACPI_TABLES              - ACPI/DMI strings" << std::endl;
    std::cout << "  DISK_MODEL               - Virtual disk names" << std::endl;
    std::cout << "  HYPERVISOR_VENDOR        - Hypervisor vendor string" << std::endl;
    std::cout << "  VMWARE_CHECK             - VMware-specific" << std::endl;
    std::cout << "  VIRTUALBOX_CHECK         - VirtualBox-specific" << std::endl;
    std::cout << "  QEMU_CHECK               - QEMU-specific" << std::endl;
    
    // Production: Only non-intrusive checks (no timing)
    std::cout << "\n--- Production-Safe VM Detection ---" << std::endl;
    
    auto config = Omamori::ProtectionConfig()
        .WithAntiVM(true,
            CPUID_CHECK |        // Reliable
            MAC_ADDRESS |        // Non-intrusive
            ACPI_TABLES |        // System info check
            REGISTRY_CHECK       // Linux maps to DMI/SMBIOS
            // NOT: TIMING_ATTACK (can cause false positives)
        )
        .WithAntiDebug(false)
        .WithAntiDump(false);
    
    printBitmask("antivm_techniques", config.antivm_techniques);
    
    // Thorough check: All methods
    std::cout << "\n--- Thorough VM Detection (All Methods) ---" << std::endl;
    printBitmask("ALL", ALL);
    
    // SAFE preset
    std::cout << "\n--- SAFE Preset (Low false positive) ---" << std::endl;
    printBitmask("SAFE", SAFE);
    
    std::cout << "\n✓ VM detection configured (not initializing - would terminate in VM)" << std::endl;
}

void example_granular_antidump() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 3: Granular Anti-Dump Technique Selection         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori::AntiDumpTechniques;
    
    std::cout << "\nAvailable Anti-Dump Techniques (Linux):" << std::endl;
    std::cout << "  WIPE_ELF_HEADER          - Corrupt ELF magic/header" << std::endl;
    std::cout << "  OBFUSCATE_PHDR           - Corrupt program headers" << std::endl;
    std::cout << "  DISABLE_CORE_DUMPS       - setrlimit(RLIMIT_CORE, 0)" << std::endl;
    std::cout << "  PRCTL_DUMPABLE           - prctl(PR_SET_DUMPABLE, 0)" << std::endl;
    std::cout << "  MADVISE_DONTDUMP         - madvise(MADV_DONTDUMP)" << std::endl;
    
    // Minimal: Just core dump protection (non-destructive)
    std::cout << "\n--- Minimal Anti-Dump (Core Dump Only) ---" << std::endl;
    
    auto minimal = Omamori::ProtectionConfig()
        .WithAntiDump(true,
            PRCTL_DUMPABLE |     // Disable dumpable flag
            DISABLE_CORE_DUMPS   // Zero core file size
            // NOT header corruption (preserves ELF)
        )
        .WithAntiDebug(false)
        .WithAntiVM(false);
    
    printBitmask("antidump_techniques", minimal.antidump_techniques);
    
    // Aggressive: Headers + core dumps
    std::cout << "\n--- Aggressive Anti-Dump (Headers + Core) ---" << std::endl;
    
    Omamori::ProtectionConfig aggressive;
    aggressive.enable_antidump = true;
    aggressive.antidump_techniques = 
        WIPE_ELF_HEADER |
        OBFUSCATE_PHDR |
        PRCTL_DUMPABLE |
        DISABLE_CORE_DUMPS;
    aggressive.enable_antidebug = false;
    aggressive.enable_antivm = false;
    
    printBitmask("aggressive", aggressive.antidump_techniques);
    
    // Presets
    std::cout << "\n--- Preset: MINIMAL ---" << std::endl;
    printBitmask("MINIMAL", MINIMAL);
    
    std::cout << "\n--- Preset: STANDARD ---" << std::endl;
    printBitmask("STANDARD", STANDARD);
    
    std::cout << "\n--- Full Anti-Dump (ALL) ---" << std::endl;
    printBitmask("ALL", ALL);
    
    std::cout << "\n✓ Anti-dump configured (not initializing to preserve example headers)" << std::endl;
}

void example_combined_granular() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 4: Combined Granular Configuration                ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori;
    
    std::cout << "\nCreating production-ready config with selective techniques..." << std::endl;
    
    auto config = ProtectionConfig()
        // Layer 1: Anti-VM (disabled for container/VM compatibility)
        .WithAntiVM(false)
        
        // Layer 2: Anti-Debug (fast, reliable checks)
        .WithAntiDebug(true,
            AntiDebugTechniques::PROC_STATUS_TRACERPID |  // Fast /proc check
            AntiDebugTechniques::PTRACE_TRACEME |         // Reliable ptrace
            AntiDebugTechniques::LD_PRELOAD_CHECK |       // Env check
            AntiDebugTechniques::FRIDA_DETECTION          // Frida detection
            // NOT: TIMING_RDTSC (false positives)
        )
        .WithAntiDebugThread(true, 1000)  // Check every 1 second
        
        // Layer 3: Anti-Dump (core protection only, preserve ELF)
        .WithAntiDump(true,
            AntiDumpTechniques::PRCTL_DUMPABLE |   // Disable dumpable
            AntiDumpTechniques::DISABLE_CORE_DUMPS // Zero core size
            // NOT: header erasure (preserves ELF for debugging)
        )
        
        // Layer 4: Memory Encryption (available for manual use)
        .WithMemoryEncryption(true);
    
    std::cout << "\nConfiguration Summary:" << std::endl;
    std::cout << "  Anti-VM:           " << (config.enable_antivm ? "ON" : "OFF") << std::endl;
    std::cout << "  Anti-Debug:        " << (config.enable_antidebug ? "ON" : "OFF") << std::endl;
    std::cout << "  Anti-Debug Thread: " << (config.enable_antidebug_thread ? "ON" : "OFF") << std::endl;
    std::cout << "  Anti-Dump:         " << (config.enable_antidump ? "ON" : "OFF") << std::endl;
    std::cout << "  Memory Encrypt:    " << (config.enable_memory_encryption ? "ON" : "OFF") << std::endl;
    
    std::cout << "\nTechnique Bitmasks:" << std::endl;
    printBitmask("antidebug_techniques", config.antidebug_techniques);
    printBitmask("antivm_techniques", config.antivm_techniques);
    printBitmask("antidump_techniques", config.antidump_techniques);
    
    // Initialize with this config
    std::cout << "\nInitializing protection..." << std::endl;
    bool success = Omamori::Initialize(config);
    
    if (success) {
        std::cout << "✓ Protection initialized successfully!" << std::endl;
    } else {
        std::cout << "✗ Protection initialization failed" << std::endl;
    }
}

void example_server_config() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 5: Server/Daemon Configuration                    ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori;
    
    std::cout << "\nServer config: No VM detection, minimal anti-dump" << std::endl;
    
    // Servers often run in VMs/containers - disable anti-VM
    // Use only core dump protection (don't corrupt headers for debugging)
    auto server_config = ProtectionConfig()
        .WithAntiVM(false)
        .WithAntiDebug(true,
            AntiDebugTechniques::PROC_STATUS_TRACERPID |
            AntiDebugTechniques::PTRACE_TRACEME
        )
        .WithAntiDebugThread(false)  // Don't waste CPU cycles
        .WithAntiDump(true,
            AntiDumpTechniques::PRCTL_DUMPABLE |
            AntiDumpTechniques::DISABLE_CORE_DUMPS
        )
        .WithMemoryEncryption(false);  // Disable for performance
    
    std::cout << "\nServer Configuration:" << std::endl;
    printBitmask("antidebug_techniques", server_config.antidebug_techniques);
    printBitmask("antidump_techniques", server_config.antidump_techniques);
    
    std::cout << "\n✓ Server-optimized configuration ready" << std::endl;
}

void example_single_technique() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 6: Single Technique Mode                          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori;
    
    std::cout << "\nUsing SingleTechnique() factory method..." << std::endl;
    
    // Enable only CPUID check for VM detection (Layer 1, single technique)
    auto vm_cpuid_only = ProtectionConfig::SingleTechnique(1, AntiVMTechniques::CPUID_CHECK);
    std::cout << "  Layer 1 (CPUID only):" << std::endl;
    printBitmask("    antivm_techniques", vm_cpuid_only.antivm_techniques);
    
    // Enable only ptrace check for debug detection (Layer 2, single technique)
    auto debug_ptrace_only = ProtectionConfig::SingleTechnique(2, AntiDebugTechniques::PTRACE_TRACEME);
    std::cout << "  Layer 2 (PTRACE only):" << std::endl;
    printBitmask("    antidebug_techniques", debug_ptrace_only.antidebug_techniques);
    
    // Enable only core dump protection (Layer 3, single technique)
    auto dump_prctl_only = ProtectionConfig::SingleTechnique(3, AntiDumpTechniques::PRCTL_DUMPABLE);
    std::cout << "  Layer 3 (PRCTL only):" << std::endl;
    printBitmask("    antidump_techniques", dump_prctl_only.antidump_techniques);
    
    std::cout << "\n✓ Single technique configurations ready" << std::endl;
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   OMAMORI GRANULAR CONFIGURATION EXAMPLES (Linux)              ║" << std::endl;
    std::cout << "║   Demonstrating Technique-Level Bitmask Selection              ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n📖 This example demonstrates how to select SPECIFIC TECHNIQUES" << std::endl;
    std::cout << "   within each protection layer using bitmasks." << std::endl;
    
    // Show all examples (only last one that calls Initialize() will take effect)
    // example_granular_antidebug();  // Uncomment to run (will initialize)
    example_granular_antivm();
    example_granular_antidump();
    example_server_config();
    example_single_technique();
    example_combined_granular();  // This one initializes
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                      EXAMPLES COMPLETED                         ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n📌 Key Takeaways:" << std::endl;
    std::cout << "  • Use bitmasks to enable/disable specific techniques" << std::endl;
    std::cout << "  • With*() methods provide fluent builder API" << std::endl;
    std::cout << "  • Presets (ALL, FAST, STEALTH, SAFE) simplify configuration" << std::endl;
    std::cout << "  • Combine presets with customization: preset & ~TECHNIQUE" << std::endl;
    std::cout << "  • SingleTechnique() enables just one technique" << std::endl;
    std::cout << "  • Server/daemon: disable anti-VM, minimize anti-dump" << std::endl;
    
    return 0;
}
