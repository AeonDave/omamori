#pragma once

/**
 * Omamori - Modern Protection Library
 * 
 * A cross-platform protection library implementing advanced
 * anti-debugging, anti-dumping, and anti-VM techniques.
 * 
 * Platforms: Windows, Linux
 * Architecture: x86, x64, ARM64
 */

#include <cstdio>
#include "omamori_config.hpp"

#define OMAMORI_VERSION_MAJOR 1
#define OMAMORI_VERSION_MINOR 0
#define OMAMORI_VERSION_PATCH 0

// Common modules (cross-platform)
#include "../common/include/sec_string.hpp"
#include "../common/include/memory_encryption.hpp"

// Platform-specific modules
#if defined(_WIN32) || defined(_WIN64)
    #ifndef OMAMORI_PLATFORM_WINDOWS
    #define OMAMORI_PLATFORM_WINDOWS
    #endif
    #include "../windows/include/internal.hpp"
    #include "../windows/include/antidebug.hpp"
    #include "../windows/include/antidump.hpp"
    #include "../windows/include/antivm.hpp"
    #include "../windows/include/syscall.hpp"
    
    namespace Omamori {
        using namespace Windows;
    }
    
#elif defined(__linux__)
    #ifndef OMAMORI_PLATFORM_LINUX
    #define OMAMORI_PLATFORM_LINUX
    #endif
    #include "../linux/include/antidebug.hpp"
    #include "../linux/include/antidump.hpp"
    #include "../linux/include/antivm.hpp"
    
    namespace Omamori {
        using namespace Linux;
    }
    
#else
    #error "Unsupported platform"
#endif

namespace Omamori {

/**
 * Initialize Omamori protection with custom configuration
 * @param config Protection configuration (default: Production preset)
 * @return true if initialization succeeded
 */
inline bool Initialize(const ProtectionConfig& config = ProtectionConfig::Production()) {
    bool success = true;
    
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    
    // Layer 1: Anti-Virtualization
    if (config.enable_antivm) {
        if (Windows::AntiVM::Detector::IsVirtualMachine(config.antivm_methods)) {
            Windows::AntiVM::Detector::TerminateIfVM();
        }
    }
    
    // Layer 2: Anti-Debug
    if (config.enable_antidebug) {
        Windows::AntiDebug::Detector::EnableAntiDebug();
        
        if (config.enable_antidebug_thread) {
            Windows::AntiDebug::ProtectionThread::Start(config.antidebug_check_interval_ms);
        }
    }
    
    // Layer 3: Anti-Dump
    if (config.enable_antidump) {
        Windows::AntiDump::PEProtector protector;
        if (config.erase_headers) {
            protector.EnableFullProtection();
        }
    }
    
    // Layer 4: Memory Encryption (manual - not auto-initialized)
    // Use EncryptionManager::AllocateEncrypted() or EncryptedBuffer<T>
    
    #elif defined(OMAMORI_PLATFORM_LINUX)
    
    // Layer 1: Anti-Virtualization
    if (config.enable_antivm) {
        if (Linux::AntiVM::Detector::IsVirtualMachine(config.antivm_methods)) {
            Linux::AntiVM::Detector::TerminateIfVM();
        }
    }
    
    // Layer 2: Anti-Debug
    if (config.enable_antidebug) {
        Linux::AntiDebug::Detector::EnableAntiDebug();
        
        if (config.enable_antidebug_thread) {
            Linux::AntiDebug::ProtectionThread::Start(config.antidebug_check_interval_ms);
        }
    }
    
    // Layer 3: Anti-Dump
    if (config.enable_antidump) {
        if (config.disable_core_dumps) {
            Linux::AntiDump::CoreDumpProtection::DisableCoreDumps();
        }
        
        if (config.enable_prctl_protection) {
            Linux::AntiDump::CoreDumpProtection::InstallPrctlProtection();
        }
        
        if (config.erase_headers) {
            Linux::AntiDump::ELFProtector protector;
            protector.EnableFullProtection();
        }
    }
    
    // Layer 4: Memory Encryption (manual - not auto-initialized)
    // Use EncryptionManager::AllocateEncrypted() or EncryptedBuffer<T>
    
    #endif
    
    return success;
}

/**
 * Quick check for debugger presence
 */
inline bool IsDebugged() {
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    return Windows::AntiDebug::Detector::IsDebuggerPresent();
    #elif defined(OMAMORI_PLATFORM_LINUX)
    return Linux::AntiDebug::Detector::IsDebuggerPresent();
    #endif
    return false;
}

/**
 * Terminate if debugger is detected
 */
inline void TerminateIfDebugged() {
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    Windows::AntiDebug::Detector::TerminateIfDebugged();
    #elif defined(OMAMORI_PLATFORM_LINUX)
    Linux::AntiDebug::Detector::TerminateIfDebugged();
    #endif
}

/**
 * Enable full protection (all 4 layers) - LEGACY
 * For fine-grained control, use Initialize(config) instead
 */
inline bool EnableFullProtection() {
    return Initialize(ProtectionConfig::MaximumProtection());
}

/**
 * Get library version string
 */
inline const char* GetVersion() {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d", 
             OMAMORI_VERSION_MAJOR, 
             OMAMORI_VERSION_MINOR, 
             OMAMORI_VERSION_PATCH);
    return version;
}

} // namespace Omamori
