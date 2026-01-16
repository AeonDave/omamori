#pragma once

/**
 * Omamori - Modern Protection Library Configuration
 * 
 * Provides granular control over protection layers.
 * Each layer can be enabled/disabled independently.
 */

#include <cstdint>

namespace Omamori {

/**
 * Protection configuration structure
 * Allows selective activation of protection layers
 */
struct ProtectionConfig {
    // Layer 1: Anti-Virtualization
    bool enable_antivm;
    uint32_t antivm_methods;  // Bitmask of detection methods
    
    // Layer 2: Anti-Debug
    bool enable_antidebug;
    bool enable_antidebug_thread;
    uint32_t antidebug_check_interval_ms;
    
    // Layer 3: Anti-Dump
    bool enable_antidump;
    bool erase_headers;
    bool disable_core_dumps;
    bool enable_prctl_protection;  // Linux only
    
    // Layer 4: Memory Encryption
    bool enable_memory_encryption;
    
    // Default constructor - all enabled
    ProtectionConfig() 
        : enable_antivm(false)              // Disabled by default (production)
        , antivm_methods(0xFFFFFFFF)        // All methods if enabled
        , enable_antidebug(true)
        , enable_antidebug_thread(true)
        , antidebug_check_interval_ms(500)
        , enable_antidump(true)
        , erase_headers(true)
        , disable_core_dumps(true)
        , enable_prctl_protection(true)
        , enable_memory_encryption(false)   // Manual activation
    {}
    
    // Preset: Maximum Protection (all layers)
    static ProtectionConfig MaximumProtection() {
        ProtectionConfig config;
        config.enable_antivm = true;
        config.enable_antidebug = true;
        config.enable_antidebug_thread = true;
        config.enable_antidump = true;
        config.enable_memory_encryption = true;
        return config;
    }
    
    // Preset: Production (no VM detection, all else enabled)
    static ProtectionConfig Production() {
        ProtectionConfig config;
        config.enable_antivm = false;  // Often disabled in production
        config.enable_antidebug = true;
        config.enable_antidebug_thread = true;
        config.enable_antidump = true;
        config.enable_memory_encryption = false;
        return config;
    }
    
    // Preset: Debug-Only Protection (Layer 2 only)
    static ProtectionConfig DebugOnly() {
        ProtectionConfig config;
        config.enable_antivm = false;
        config.enable_antidebug = true;
        config.enable_antidebug_thread = true;
        config.enable_antidump = false;
        config.enable_memory_encryption = false;
        return config;
    }
    
    // Preset: Memory-Only Protection (Layer 4 only)
    static ProtectionConfig MemoryOnly() {
        ProtectionConfig config;
        config.enable_antivm = false;
        config.enable_antidebug = false;
        config.enable_antidebug_thread = false;
        config.enable_antidump = false;
        config.enable_memory_encryption = true;
        return config;
    }
    
    // Preset: Minimal (Layer 2 + Layer 4)
    static ProtectionConfig Minimal() {
        ProtectionConfig config;
        config.enable_antivm = false;
        config.enable_antidebug = true;
        config.enable_antidebug_thread = false;  // No background thread
        config.enable_antidump = false;
        config.enable_memory_encryption = true;
        return config;
    }
};

} // namespace Omamori
