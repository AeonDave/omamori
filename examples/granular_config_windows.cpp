/**
 * @file granular_config_windows.cpp
 * @brief Demonstrates granular technique selection on Windows
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
    std::cout << "  " << std::setw(20) << std::left << name << ": 0x" 
              << std::hex << std::setw(8) << std::setfill('0') << value 
              << std::dec << std::setfill(' ') << std::endl;
}

void example_granular_antidebug() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 1: Granular Anti-Debug Technique Selection        ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    // Import technique flags
    using namespace Omamori::AntiDebugTechniques;
    
    std::cout << "\nAvailable Anti-Debug Techniques (Windows):" << std::endl;
    std::cout << "  PEB_BEING_DEBUGGED       - Win32 API check (IsDebuggerPresent)" << std::endl;
    std::cout << "  PEB_NT_GLOBAL_FLAG       - PEB NtGlobalFlag check" << std::endl;
    std::cout << "  PEB_HEAP_FLAGS           - Process heap flags" << std::endl;
    std::cout << "  REMOTE_DEBUGGER_PRESENT  - CheckRemoteDebuggerPresent" << std::endl;
    std::cout << "  PROCESS_DEBUG_PORT       - NtQueryInformationProcess" << std::endl;
    std::cout << "  PROCESS_DEBUG_FLAGS      - ProcessDebugFlags" << std::endl;
    std::cout << "  DEBUG_OBJECT_HANDLE      - Debug object handle" << std::endl;
    std::cout << "  HARDWARE_BREAKPOINTS     - DR0-DR7 registers" << std::endl;
    std::cout << "  OUTPUT_DEBUG_STRING      - OutputDebugString trick" << std::endl;
    std::cout << "  CLOSE_HANDLE_EXCEPTION   - Exception-based detection" << std::endl;
    std::cout << "  TIMING_RDTSC             - RDTSC timing" << std::endl;
    std::cout << "  TIMING_QPC               - QueryPerformanceCounter" << std::endl;
    std::cout << "  PARENT_PROCESS_CHECK     - Parent process check" << std::endl;
    std::cout << "  THREAD_CONTEXT_CHECK     - Thread context analysis" << std::endl;
    std::cout << "  MEMORY_BREAKPOINT        - Memory breakpoint detection" << std::endl;
    
    // === Method 1: Select specific techniques with bitmask ===
    std::cout << "\n--- Method 1: Direct Bitmask ---" << std::endl;
    
    Omamori::ProtectionConfig config1;
    config1.enable_antidebug = true;
    config1.enable_antivm = false;
    config1.enable_antidump = false;
    config1.enable_antidebug_thread = false;
    
    // Select only fast, reliable checks (no timing-based)
    config1.antidebug_techniques = 
        PEB_BEING_DEBUGGED |       // Fast Win32 API
        PEB_NT_GLOBAL_FLAG |       // PEB check
        PROCESS_DEBUG_PORT |       // Reliable NT query
        PROCESS_DEBUG_FLAGS |      // Fast flag check
        HARDWARE_BREAKPOINTS;      // DR register check
    
    printBitmask("antidebug_techniques", config1.antidebug_techniques);
    
    // === Method 2: Use builder pattern (With* methods) ===
    std::cout << "\n--- Method 2: Builder Pattern (With* methods) ---" << std::endl;
    
    auto config2 = Omamori::ProtectionConfig()
        .WithAntiDebug(true, 
            PEB_BEING_DEBUGGED |
            PEB_NT_GLOBAL_FLAG |
            PROCESS_DEBUG_PORT |
            HARDWARE_BREAKPOINTS
        )
        .WithAntiVM(false)
        .WithAntiDump(false)
        .WithAntiDebugThread(false);
    
    printBitmask("antidebug_techniques", config2.antidebug_techniques);
    
    // === Method 3: Start from preset and customize ===
    std::cout << "\n--- Method 3: Preset + Customization ---" << std::endl;
    
    auto config3 = Omamori::ProtectionConfig::Stealth();  // Start with stealth preset
    config3.antidebug_techniques &= ~TIMING_RDTSC;        // Remove timing (can cause FPs)
    config3.antidebug_techniques |= MEMORY_BREAKPOINT;    // Add breakpoint detection
    
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
    
    std::cout << "\nAvailable Anti-VM Techniques (Windows):" << std::endl;
    std::cout << "  CPUID_CHECK              - CPUID hypervisor bit" << std::endl;
    std::cout << "  REGISTRY_CHECK           - VM registry keys" << std::endl;
    std::cout << "  MAC_ADDRESS              - VM MAC address prefixes" << std::endl;
    std::cout << "  PROCESS_CHECK            - VM-related processes" << std::endl;
    std::cout << "  DRIVER_CHECK             - VM drivers" << std::endl;
    std::cout << "  DEVICE_CHECK             - Virtual devices" << std::endl;
    std::cout << "  SERVICE_CHECK            - VM services" << std::endl;
    std::cout << "  FILE_CHECK               - VM-related files" << std::endl;
    std::cout << "  WMI_CHECK                - WMI queries" << std::endl;
    std::cout << "  TIMING_ATTACK            - RDTSC timing" << std::endl;
    std::cout << "  ACPI_TABLES              - ACPI table check" << std::endl;
    std::cout << "  DISK_MODEL               - Virtual disk names" << std::endl;
    std::cout << "  DISPLAY_ADAPTER          - Virtual display" << std::endl;
    std::cout << "  FIRMWARE_TABLES          - BIOS/firmware strings" << std::endl;
    std::cout << "  HYPERVISOR_VENDOR        - Hypervisor vendor ID" << std::endl;
    
    // VM-specific checks
    std::cout << "  VMWARE_CHECK             - VMware-specific" << std::endl;
    std::cout << "  VIRTUALBOX_CHECK         - VirtualBox-specific" << std::endl;
    std::cout << "  HYPERV_CHECK             - Hyper-V specific" << std::endl;
    std::cout << "  QEMU_CHECK               - QEMU-specific" << std::endl;
    std::cout << "  PARALLELS_CHECK          - Parallels-specific" << std::endl;
    
    // Production: Only non-intrusive checks (no timing)
    std::cout << "\n--- Production-Safe VM Detection ---" << std::endl;
    
    auto config = Omamori::ProtectionConfig()
        .WithAntiVM(true,
            CPUID_CHECK |        // Reliable
            MAC_ADDRESS |        // Non-intrusive
            REGISTRY_CHECK |     // Fast
            DRIVER_CHECK         // Reliable
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
    
    std::cout << "\nAvailable Anti-Dump Techniques (Windows):" << std::endl;
    std::cout << "  ERASE_PE_HEADER          - Wipe DOS/PE headers" << std::endl;
    std::cout << "  CORRUPT_PE_HEADER        - Corrupt PE header fields" << std::endl;
    std::cout << "  RANDOMIZE_PE_FIELDS      - Randomize PE fields" << std::endl;
    std::cout << "  WIPE_DEBUG_DIRECTORY     - Remove debug info" << std::endl;
    std::cout << "  WIPE_EXPORT_DIRECTORY    - Clear exports" << std::endl;
    std::cout << "  CORRUPT_IMPORT_DIRECTORY - Corrupt imports" << std::endl;
    std::cout << "  WIPE_IAT                 - Clear Import Address Table" << std::endl;
    std::cout << "  ENCRYPT_SECTION_HEADERS  - Encrypt section headers" << std::endl;
    std::cout << "  MANIPULATE_PEB           - PEB manipulation" << std::endl;
    std::cout << "  UNLINK_LDR               - Unlink from LDR lists" << std::endl;
    std::cout << "  PURGE_WORKING_SET        - Purge working set" << std::endl;
    std::cout << "  VEH_PROTECTION           - VEH memory protection" << std::endl;
    std::cout << "  CORRUPT_CHECKSUM         - Corrupt PE checksum" << std::endl;
    std::cout << "  INVALIDATE_DOS_STUB      - Invalid DOS stub" << std::endl;
    std::cout << "  SCRAMBLE_OPTIONAL_HEADER - Scramble optional header" << std::endl;
    std::cout << "  HIDE_SECTION_NAMES       - Hide section names" << std::endl;
    std::cout << "  CORRUPT_RELOCATIONS      - Corrupt relocation table" << std::endl;
    std::cout << "  WIPE_RICH_HEADER         - Remove Rich header" << std::endl;
    std::cout << "  CORRUPT_COFF_HEADER      - Corrupt COFF header" << std::endl;
    std::cout << "  CORRUPT_DOS_HEADER       - Corrupt DOS header" << std::endl;
    std::cout << "  INVALIDATE_NT_SIGNATURE  - Break PE signature" << std::endl;
    std::cout << "  SCRAMBLE_SECTION_ALIGN   - Scramble section alignment" << std::endl;
    std::cout << "  MANGLE_ENTRY_POINT       - Obfuscate entry point" << std::endl;
    
    // Minimal: Just header protection (less aggressive)
    std::cout << "\n--- Minimal Anti-Dump (Headers Only) ---" << std::endl;
    
    auto minimal = Omamori::ProtectionConfig()
        .WithAntiDump(true,
            ERASE_PE_HEADER |
            WIPE_DEBUG_DIRECTORY
        )
        .WithAntiDebug(false)
        .WithAntiVM(false);
    
    printBitmask("antidump_techniques", minimal.antidump_techniques);
    
    // Presets
    std::cout << "\n--- Preset: MINIMAL ---" << std::endl;
    printBitmask("MINIMAL", MINIMAL);
    
    std::cout << "\n--- Preset: STANDARD ---" << std::endl;
    printBitmask("STANDARD", STANDARD);
    
    std::cout << "\n--- Preset: AGGRESSIVE ---" << std::endl;
    printBitmask("AGGRESSIVE", AGGRESSIVE);
    
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
        // Layer 1: Anti-VM (disabled for VM compatibility)
        .WithAntiVM(false)
        
        // Layer 2: Anti-Debug (fast, reliable checks)
        .WithAntiDebug(true,
            AntiDebugTechniques::PEB_BEING_DEBUGGED |
            AntiDebugTechniques::PEB_NT_GLOBAL_FLAG |
            AntiDebugTechniques::PROCESS_DEBUG_PORT |
            AntiDebugTechniques::HARDWARE_BREAKPOINTS
        )
        .WithAntiDebugThread(true, 1000)  // Check every 1 second
        
        // Layer 3: Anti-Dump (minimal - just header erasure)
        .WithAntiDump(true,
            AntiDumpTechniques::ERASE_PE_HEADER |
            AntiDumpTechniques::WIPE_DEBUG_DIRECTORY |
            AntiDumpTechniques::CORRUPT_CHECKSUM
            // NOT: CORRUPT_IMPORT_DIRECTORY (keep imports working)
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

void example_single_technique() {
    std::cout << "\n╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Example 5: Single Technique Mode                          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    
    using namespace Omamori;
    
    std::cout << "\nUsing SingleTechnique() factory method..." << std::endl;
    
    // Enable only CPUID check for VM detection (Layer 1, single technique)
    auto vm_cpuid_only = ProtectionConfig::SingleTechnique(1, AntiVMTechniques::CPUID_CHECK);
    std::cout << "  Layer 1 (CPUID only):" << std::endl;
    printBitmask("    antivm_techniques", vm_cpuid_only.antivm_techniques);
    
    // Enable only PEB check for debug detection (Layer 2, single technique)
    auto debug_peb_only = ProtectionConfig::SingleTechnique(2, AntiDebugTechniques::PEB_BEING_DEBUGGED);
    std::cout << "  Layer 2 (PEB only):" << std::endl;
    printBitmask("    antidebug_techniques", debug_peb_only.antidebug_techniques);
    
    // Enable only PE header erasure (Layer 3, single technique)
    auto dump_header_only = ProtectionConfig::SingleTechnique(3, AntiDumpTechniques::ERASE_PE_HEADER);
    std::cout << "  Layer 3 (PE header only):" << std::endl;
    printBitmask("    antidump_techniques", dump_header_only.antidump_techniques);
    
    std::cout << "\n✓ Single technique configurations ready" << std::endl;
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   OMAMORI GRANULAR CONFIGURATION EXAMPLES (Windows)            ║" << std::endl;
    std::cout << "║   Demonstrating Technique-Level Bitmask Selection              ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
    
    std::cout << "\n📖 This example demonstrates how to select SPECIFIC TECHNIQUES" << std::endl;
    std::cout << "   within each protection layer using bitmasks." << std::endl;
    
    // Show all examples (only last one that calls Initialize() will take effect)
    // example_granular_antidebug();  // Uncomment to run (will initialize)
    example_granular_antivm();
    example_granular_antidump();
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
    std::cout << "  • Test your configuration in target environment" << std::endl;
    
    return 0;
}
