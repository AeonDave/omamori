#pragma once

/**
 * Omamori - Modern Protection Library Configuration
 * 
 * Provides granular control over protection layers and individual techniques.
 * Each layer can be enabled/disabled independently, and within each layer
 * specific techniques can be selected using bitmasks.
 */

#include <cstdint>

namespace Omamori {

// ============================================================================
// Layer 1: Anti-VM Technique Flags
// ============================================================================
namespace AntiVMTechniques {
    enum Flags : uint32_t {
        NONE                 = 0x00000000,
        CPUID_CHECK          = 0x00000001,
        REGISTRY_CHECK       = 0x00000002,  // Windows: Registry keys
        DMI_CHECK            = REGISTRY_CHECK,  // Linux alias: /sys/class/dmi
        WMI_CHECK            = 0x00000004,  // Windows: WMI queries
        PROC_CPUINFO         = WMI_CHECK,   // Linux alias: /proc/cpuinfo
        TIMING_ATTACK        = 0x00000008,
        MAC_ADDRESS          = 0x00000010,
        DEVICE_CHECK         = 0x00000020,
        DRIVER_CHECK         = 0x00000040,
        PROCESS_CHECK        = 0x00000080,
        SYSTEMD_DETECT_VIRT  = PROCESS_CHECK,  // Linux alias: systemd-detect-virt
        SERVICE_CHECK        = 0x00000100,
        DOCKER_CHECK         = SERVICE_CHECK,  // Linux alias: container detection
        FILE_CHECK           = 0x00000200,
        KVM_CHECK            = FILE_CHECK,     // Linux alias: KVM detection
        VMWARE_CHECK         = 0x00000400,
        VIRTUALBOX_CHECK     = 0x00000800,
        HYPERV_CHECK         = 0x00001000,
        QEMU_CHECK           = 0x00002000,
        PARALLELS_CHECK      = 0x00004000,
        ACPI_TABLES          = 0x00008000,
        DISK_MODEL           = 0x00010000,
        SCSI_MODEL           = DISK_MODEL,     // Linux alias: SCSI model check
        DISPLAY_ADAPTER      = 0x00020000,
        FIRMWARE_TABLES      = 0x00040000,
        SMBIOS_CHECK         = FIRMWARE_TABLES,  // Linux alias: SMBIOS data
        HYPERVISOR_VENDOR    = 0x00080000,
        ALL                  = 0xFFFFFFFF,
        // Preset: Safe checks only (no timing-based, low false positive)
        SAFE = CPUID_CHECK | REGISTRY_CHECK | MAC_ADDRESS | DEVICE_CHECK |
               DRIVER_CHECK | PROCESS_CHECK | SERVICE_CHECK | FILE_CHECK |
               ACPI_TABLES | DISK_MODEL | DISPLAY_ADAPTER | FIRMWARE_TABLES |
               HYPERVISOR_VENDOR
    };
}

// ============================================================================
// Layer 2: Anti-Debug Technique Flags
// ============================================================================
namespace AntiDebugTechniques {
    enum Flags : uint32_t {
        NONE                     = 0x00000000,
        PEB_BEING_DEBUGGED       = 0x00000001,
        PEB_NT_GLOBAL_FLAG       = 0x00000002,
        PEB_HEAP_FLAGS           = 0x00000004,
        PROC_SELF_STATUS         = PEB_HEAP_FLAGS,  // Linux alias: /proc/self/status
        REMOTE_DEBUGGER_PRESENT  = 0x00000008,
        HARDWARE_BREAKPOINTS     = 0x00000010,
        TIMING_RDTSC             = 0x00000020,
        TIMING_BASED             = TIMING_RDTSC,    // Linux alias
        TIMING_QPC               = 0x00000040,
        PROCESS_DEBUG_PORT       = 0x00000080,
        PROCESS_DEBUG_FLAGS      = 0x00000100,
        DEBUG_OBJECT_HANDLE      = 0x00000200,
        SIGNAL_BASED             = DEBUG_OBJECT_HANDLE,  // Linux alias: signal handlers
        SYSTEM_KERNEL_DEBUGGER   = 0x00000400,
        GDB_SPECIFIC             = SYSTEM_KERNEL_DEBUGGER,  // Linux alias: GDB detection
        CLOSE_HANDLE_EXCEPTION   = 0x00000800,
        OUTPUT_DEBUG_STRING      = 0x00001000,
        PARENT_PROCESS_CHECK     = 0x00002000,
        INT_2D_CHECK             = 0x00004000,
        DEBUG_FILTER_STATE       = 0x00008000,
        NAMESPACE_DETECTION      = DEBUG_FILTER_STATE,  // Linux alias: namespace check
        THREAD_CONTEXT_CHECK     = 0x00010000,
        MEMORY_BREAKPOINT        = 0x00020000,
        // Linux-specific (no Windows equivalent)
        PTRACE_TRACEME           = 0x00040000,
        PROC_STATUS_TRACERPID    = 0x00080000,
        PROC_MAPS_CHECK          = 0x00100000,
        LD_PRELOAD_CHECK         = 0x00200000,
        FRIDA_DETECTION          = 0x00400000,
        SECCOMP_DETECTION        = 0x00800000,
        EBPF_DETECTION           = 0x01000000,
        PERSONALITY_CHECK        = 0x02000000,  // Linux: personality flags (ASLR)
        ALL                      = 0xFFFFFFFF,
        // Preset: Fast checks only (no timing, no exception)
        FAST = PEB_BEING_DEBUGGED | PEB_NT_GLOBAL_FLAG | REMOTE_DEBUGGER_PRESENT |
               PROCESS_DEBUG_PORT | PROCESS_DEBUG_FLAGS | PTRACE_TRACEME |
               PROC_STATUS_TRACERPID,
        STEALTH = PEB_BEING_DEBUGGED | TIMING_RDTSC | PARENT_PROCESS_CHECK |
                  PTRACE_TRACEME | PROC_MAPS_CHECK
    };
}

// ============================================================================
// Layer 3: Anti-Dump Technique Flags
// ============================================================================
namespace AntiDumpTechniques {
    enum Flags : uint32_t {
        NONE                     = 0x00000000,
        ERASE_PE_HEADER          = 0x00000001,
        CORRUPT_PE_HEADER        = 0x00000002,
        RANDOMIZE_PE_FIELDS      = 0x00000004,
        WIPE_DEBUG_DIRECTORY     = 0x00000008,
        WIPE_EXPORT_DIRECTORY    = 0x00000010,
        CORRUPT_IMPORT_DIRECTORY = 0x00000020,
        WIPE_IAT                 = 0x00000040,
        WIPE_TLS_DIRECTORY       = 0x00000080,
        WIPE_EXCEPTION_DIRECTORY = 0x00000100,
        WIPE_RESOURCE_DIRECTORY  = 0x00000200,
        ENCRYPT_SECTION_HEADERS  = 0x00000400,
        MANIPULATE_PEB           = 0x00000800,
        UNLINK_LDR               = 0x00001000,
        SPOOF_MODULE_INFO        = 0x00002000,
        PURGE_WORKING_SET        = 0x00004000,
        VEH_PROTECTION           = 0x00008000,
        CORRUPT_CHECKSUM         = 0x00010000,
        INVALIDATE_DOS_STUB      = 0x00020000,
        SCRAMBLE_OPTIONAL_HEADER = 0x00040000,
        HIDE_SECTION_NAMES       = 0x00080000,
        CORRUPT_RELOCATIONS      = 0x00100000,
        // Anti-reconstruction techniques (Windows) / Advanced techniques (Linux)
        // These flags are reused across platforms since they're mutually exclusive
        WIPE_RICH_HEADER         = 0x00200000,  // Windows: Wipe Rich header
        WIPE_BUILD_ID            = WIPE_RICH_HEADER,  // Linux alias: Wipe .note.gnu.build-id
        CORRUPT_COFF_HEADER      = 0x00400000,  // Windows: Corrupt COFF header
        CORRUPT_DYNAMIC_SECTION  = CORRUPT_COFF_HEADER,  // Linux alias: Corrupt .dynamic
        CORRUPT_DOS_HEADER       = 0x00800000,  // Windows: Corrupt DOS header
        WIPE_ALL_METADATA        = CORRUPT_DOS_HEADER,  // Linux alias: Wipe all ELF metadata
        INVALIDATE_NT_SIGNATURE  = 0x01000000,  // Windows: Break NT signature (aggressive)
        SELF_DELETE_EXECUTABLE   = INVALIDATE_NT_SIGNATURE,  // Linux alias: Delete /proc/self/exe link
        SCRAMBLE_SECTION_ALIGN   = 0x02000000,  // Windows: Scramble alignment values
        MASK_PROC_MAPS           = SCRAMBLE_SECTION_ALIGN,  // Linux alias: Mask /proc/self/maps
        MANGLE_ENTRY_POINT       = 0x04000000,  // Windows: XOR entry point (aggressive)
        // Core dump protection (Linux-specific)
        DISABLE_CORE_DUMPS       = 0x08000000,
        PRCTL_DUMPABLE           = 0x10000000,  // PR_SET_DUMPABLE = 0
        PRCTL_PROTECTION         = PRCTL_DUMPABLE,  // Alias for backwards compatibility
        MADVISE_DONTDUMP         = 0x20000000,  // madvise MADV_DONTDUMP
        // Header erasure (cross-platform concept)
        WIPE_ELF_HEADER          = 0x40000000,  // Linux: Wipe ELF header
        OBFUSCATE_PHDR           = 0x80000000,  // Linux: Obfuscate program headers
        ALL                      = 0xFFFFFFFF,
        // Preset: Minimal (just header erasure)
        MINIMAL = ERASE_PE_HEADER | WIPE_ELF_HEADER | DISABLE_CORE_DUMPS,
        // Preset: Standard (common techniques)
        STANDARD = ERASE_PE_HEADER | CORRUPT_PE_HEADER | WIPE_DEBUG_DIRECTORY |
                   WIPE_EXPORT_DIRECTORY | MANIPULATE_PEB | DISABLE_CORE_DUMPS |
                   PRCTL_DUMPABLE | WIPE_ELF_HEADER,
        // Preset: Aggressive (most techniques)
        AGGRESSIVE = ALL & ~(CORRUPT_IMPORT_DIRECTORY | WIPE_IAT) // Keep imports working
    };
}

// ============================================================================
// Layer 4: Memory Encryption Technique Flags
// ============================================================================
namespace MemoryEncryptionTechniques {
    enum Flags : uint32_t {
        NONE                     = 0x00000000,
        CHACHA20_ENCRYPTION      = 0x00000001,
        PAGE_GUARD_PROTECTION    = 0x00000002,
        ON_DEMAND_DECRYPTION     = 0x00000004,
        AUTO_RE_ENCRYPTION       = 0x00000008,
        PER_PAGE_KEYS            = 0x00000010,
        SECURE_KEY_GENERATION    = 0x00000020,
        ALL                      = 0xFFFFFFFF,
        // Preset: Standard encryption
        STANDARD = CHACHA20_ENCRYPTION | PAGE_GUARD_PROTECTION | 
                   ON_DEMAND_DECRYPTION | PER_PAGE_KEYS | SECURE_KEY_GENERATION
    };
}

// ============================================================================
// Main Protection Configuration
// ============================================================================

/**
 * Protection configuration structure
 * Allows selective activation of protection layers and individual techniques
 */
struct ProtectionConfig {
    // ========== Layer 1: Anti-Virtualization ==========
    bool enable_antivm;
    uint32_t antivm_techniques;  // Bitmask from AntiVMTechniques::Flags
    
    // ========== Layer 2: Anti-Debug ==========
    bool enable_antidebug;
    uint32_t antidebug_techniques;  // Bitmask from AntiDebugTechniques::Flags
    bool enable_antidebug_thread;
    uint32_t antidebug_check_interval_ms;
    bool antidebug_terminate_on_detect;
    
    // ========== Layer 3: Anti-Dump ==========
    bool enable_antidump;
    uint32_t antidump_techniques;  // Bitmask from AntiDumpTechniques::Flags
    bool antidump_continuous;  // Enable continuous protection thread
    
    // ========== Layer 4: Memory Encryption ==========
    bool enable_memory_encryption;
    uint32_t memory_encryption_techniques;  // Bitmask from MemoryEncryptionTechniques::Flags
    bool memory_auto_init;  // Auto-initialize on startup
    
    // ========== Callbacks ==========
    using DetectionCallback = void(*)(const char* layer, const char* technique);
    DetectionCallback on_detection;  // Called when threat detected (nullptr = terminate)
    
    // Default constructor - balanced defaults
    ProtectionConfig() 
        : enable_antivm(false)
        , antivm_techniques(AntiVMTechniques::SAFE)
        , enable_antidebug(true)
        , antidebug_techniques(AntiDebugTechniques::ALL)
        , enable_antidebug_thread(true)
        , antidebug_check_interval_ms(500)
        , antidebug_terminate_on_detect(true)
        , enable_antidump(true)
        , antidump_techniques(AntiDumpTechniques::STANDARD)
        , antidump_continuous(false)
        , enable_memory_encryption(false)
        , memory_encryption_techniques(MemoryEncryptionTechniques::STANDARD)
        , memory_auto_init(false)
        , on_detection(nullptr)
    {}
    
    // ========== Builder Pattern Methods ==========
    
    // Layer 1 configuration
    ProtectionConfig& WithAntiVM(bool enable, uint32_t techniques = AntiVMTechniques::SAFE) {
        enable_antivm = enable;
        antivm_techniques = techniques;
        return *this;
    }
    
    // Layer 2 configuration
    ProtectionConfig& WithAntiDebug(bool enable, uint32_t techniques = AntiDebugTechniques::ALL) {
        enable_antidebug = enable;
        antidebug_techniques = techniques;
        return *this;
    }
    
    ProtectionConfig& WithAntiDebugThread(bool enable, uint32_t interval_ms = 500) {
        enable_antidebug_thread = enable;
        antidebug_check_interval_ms = interval_ms;
        return *this;
    }
    
    // Layer 3 configuration
    ProtectionConfig& WithAntiDump(bool enable, uint32_t techniques = AntiDumpTechniques::STANDARD) {
        enable_antidump = enable;
        antidump_techniques = techniques;
        return *this;
    }
    
    ProtectionConfig& WithContinuousDumpProtection(bool enable) {
        antidump_continuous = enable;
        return *this;
    }
    
    // Layer 4 configuration
    ProtectionConfig& WithMemoryEncryption(bool enable, uint32_t techniques = MemoryEncryptionTechniques::STANDARD) {
        enable_memory_encryption = enable;
        memory_encryption_techniques = techniques;
        return *this;
    }
    
    // Callback configuration
    ProtectionConfig& WithCallback(DetectionCallback callback) {
        on_detection = callback;
        antidebug_terminate_on_detect = (callback == nullptr);
        return *this;
    }
    
    // ========== Helper Methods ==========
    
    // Check if specific technique is enabled
    bool IsAntiVMTechniqueEnabled(uint32_t technique) const {
        return enable_antivm && (antivm_techniques & technique);
    }
    
    bool IsAntiDebugTechniqueEnabled(uint32_t technique) const {
        return enable_antidebug && (antidebug_techniques & technique);
    }
    
    bool IsAntiDumpTechniqueEnabled(uint32_t technique) const {
        return enable_antidump && (antidump_techniques & technique);
    }
    
    bool IsMemoryEncryptionTechniqueEnabled(uint32_t technique) const {
        return enable_memory_encryption && (memory_encryption_techniques & technique);
    }
    
    // ========== Presets ==========
    
    // Maximum Protection (all layers, all techniques)
    static ProtectionConfig MaximumProtection() {
        return ProtectionConfig()
            .WithAntiVM(true, AntiVMTechniques::ALL)
            .WithAntiDebug(true, AntiDebugTechniques::ALL)
            .WithAntiDebugThread(true, 100)
            .WithAntiDump(true, AntiDumpTechniques::ALL)
            .WithContinuousDumpProtection(true)
            .WithMemoryEncryption(true, MemoryEncryptionTechniques::ALL);
    }
    
    // Production (no VM detection, standard protection)
    static ProtectionConfig Production() {
        return ProtectionConfig()
            .WithAntiVM(false)
            .WithAntiDebug(true, AntiDebugTechniques::FAST)
            .WithAntiDebugThread(true, 500)
            .WithAntiDump(true, AntiDumpTechniques::STANDARD)
            .WithMemoryEncryption(false);
    }
    
    // Debug-Only (Layer 2 only, fast checks)
    static ProtectionConfig DebugOnly() {
        return ProtectionConfig()
            .WithAntiVM(false)
            .WithAntiDebug(true, AntiDebugTechniques::FAST)
            .WithAntiDebugThread(true)
            .WithAntiDump(false)
            .WithMemoryEncryption(false);
    }
    
    // Stealth (hard to detect protection)
    static ProtectionConfig Stealth() {
        return ProtectionConfig()
            .WithAntiVM(false)
            .WithAntiDebug(true, AntiDebugTechniques::STEALTH)
            .WithAntiDebugThread(false)  // No background thread
            .WithAntiDump(true, AntiDumpTechniques::MINIMAL)
            .WithMemoryEncryption(false);
    }
    
    // Memory-Only (Layer 4 only)
    static ProtectionConfig MemoryOnly() {
        return ProtectionConfig()
            .WithAntiVM(false)
            .WithAntiDebug(false)
            .WithAntiDump(false)
            .WithMemoryEncryption(true, MemoryEncryptionTechniques::ALL);
    }
    
    // Minimal (just core protections)
    static ProtectionConfig Minimal() {
        return ProtectionConfig()
            .WithAntiVM(false)
            .WithAntiDebug(true, AntiDebugTechniques::PEB_BEING_DEBUGGED | 
                                  AntiDebugTechniques::PTRACE_TRACEME)
            .WithAntiDebugThread(false)
            .WithAntiDump(true, AntiDumpTechniques::MINIMAL)
            .WithMemoryEncryption(false);
    }
    
    // Custom: Single Layer Only
    static ProtectionConfig LayerOnly(int layer) {
        ProtectionConfig config;
        config.enable_antivm = (layer == 1);
        config.enable_antidebug = (layer == 2);
        config.enable_antidump = (layer == 3);
        config.enable_memory_encryption = (layer == 4);
        return config;
    }
    
    // Custom: Single Technique Only
    static ProtectionConfig SingleTechnique(int layer, uint32_t technique) {
        ProtectionConfig config;
        config.enable_antivm = false;
        config.enable_antidebug = false;
        config.enable_antidump = false;
        config.enable_memory_encryption = false;
        
        switch (layer) {
            case 1:
                config.enable_antivm = true;
                config.antivm_techniques = technique;
                break;
            case 2:
                config.enable_antidebug = true;
                config.antidebug_techniques = technique;
                config.enable_antidebug_thread = false;
                break;
            case 3:
                config.enable_antidump = true;
                config.antidump_techniques = technique;
                break;
            case 4:
                config.enable_memory_encryption = true;
                config.memory_encryption_techniques = technique;
                break;
        }
        return config;
    }
};

} // namespace Omamori
