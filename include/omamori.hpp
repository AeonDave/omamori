#pragma once

/**
 * Omamori - Modern Protection Library
 * 
 * A cross-platform protection library implementing advanced
 * anti-debugging, anti-dumping, and anti-VM techniques.
 * 
 * Platforms: Windows, Linux
 * Architecture: x86, x64
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

#if defined(OMAMORI_PLATFORM_LINUX)
namespace Detail {
    inline uint32_t MapLinuxAntiVMTechniques(uint32_t techniques) {
        uint32_t mapped = 0;
        if (techniques & AntiVMTechniques::CPUID_CHECK) {
            mapped |= Linux::AntiVM::CPUID_CHECK;
        }
        if (techniques & AntiVMTechniques::REGISTRY_CHECK) {
            mapped |= Linux::AntiVM::DMI_CHECK;
        }
        if (techniques & AntiVMTechniques::WMI_CHECK) {
            mapped |= Linux::AntiVM::PROC_CPUINFO;
        }
        if (techniques & AntiVMTechniques::TIMING_ATTACK) {
            mapped |= Linux::AntiVM::TIMING_ATTACK;
        }
        if (techniques & AntiVMTechniques::MAC_ADDRESS) {
            mapped |= Linux::AntiVM::MAC_ADDRESS;
        }
        if (techniques & AntiVMTechniques::DEVICE_CHECK) {
            mapped |= Linux::AntiVM::DEVICE_CHECK;
        }
        if (techniques & AntiVMTechniques::PROCESS_CHECK) {
            mapped |= Linux::AntiVM::SYSTEMD_DETECT_VIRT;
        }
        if (techniques & AntiVMTechniques::SERVICE_CHECK) {
            mapped |= Linux::AntiVM::DOCKER_CHECK;
        }
        if (techniques & AntiVMTechniques::FILE_CHECK) {
            mapped |= Linux::AntiVM::KVM_CHECK;
        }
        if (techniques & AntiVMTechniques::VMWARE_CHECK) {
            mapped |= Linux::AntiVM::VMWARE_CHECK;
        }
        if (techniques & AntiVMTechniques::VIRTUALBOX_CHECK) {
            mapped |= Linux::AntiVM::VIRTUALBOX_CHECK;
        }
        if (techniques & AntiVMTechniques::QEMU_CHECK) {
            mapped |= Linux::AntiVM::QEMU_CHECK;
        }
        if (techniques & AntiVMTechniques::ACPI_TABLES) {
            mapped |= Linux::AntiVM::ACPI_CHECK;
        }
        if (techniques & AntiVMTechniques::DISK_MODEL) {
            mapped |= Linux::AntiVM::SCSI_MODEL;
        }
        if (techniques & AntiVMTechniques::FIRMWARE_TABLES) {
            mapped |= Linux::AntiVM::SMBIOS_CHECK;
        }
        if (techniques & AntiVMTechniques::HYPERVISOR_VENDOR) {
            mapped |= Linux::AntiVM::HYPERVISOR_VENDOR;
        }
        return mapped;
    }

    inline uint32_t MapLinuxAntiDebugTechniques(uint32_t techniques) {
        uint32_t mapped = 0;
        if (techniques & AntiDebugTechniques::PEB_HEAP_FLAGS) {
            mapped |= Linux::AntiDebug::PROC_SELF_STATUS;
        }
        if (techniques & AntiDebugTechniques::TIMING_RDTSC) {
            mapped |= Linux::AntiDebug::TIMING_BASED;
        }
        if (techniques & AntiDebugTechniques::DEBUG_OBJECT_HANDLE) {
            mapped |= Linux::AntiDebug::SIGNAL_BASED;
        }
        if (techniques & AntiDebugTechniques::SYSTEM_KERNEL_DEBUGGER) {
            mapped |= Linux::AntiDebug::GDB_SPECIFIC;
        }
        if (techniques & AntiDebugTechniques::PARENT_PROCESS_CHECK) {
            mapped |= Linux::AntiDebug::PARENT_PROCESS_CHECK;
        }
        if (techniques & AntiDebugTechniques::DEBUG_FILTER_STATE) {
            mapped |= Linux::AntiDebug::NAMESPACE_DETECTION;
        }
        if (techniques & AntiDebugTechniques::MEMORY_BREAKPOINT) {
            mapped |= Linux::AntiDebug::MEMORY_BREAKPOINT;
        }
        if (techniques & AntiDebugTechniques::PTRACE_TRACEME) {
            mapped |= Linux::AntiDebug::PTRACE_TRACEME;
        }
        if (techniques & AntiDebugTechniques::PROC_STATUS_TRACERPID) {
            mapped |= Linux::AntiDebug::PROC_STATUS_TRACERPID;
        }
        if (techniques & AntiDebugTechniques::PROC_MAPS_CHECK) {
            mapped |= Linux::AntiDebug::PROC_MAPS_CHECK;
        }
        if (techniques & AntiDebugTechniques::LD_PRELOAD_CHECK) {
            mapped |= Linux::AntiDebug::LD_PRELOAD_CHECK;
        }
        if (techniques & AntiDebugTechniques::FRIDA_DETECTION) {
            mapped |= Linux::AntiDebug::FRIDA_DETECTION;
        }
        if (techniques & AntiDebugTechniques::SECCOMP_DETECTION) {
            mapped |= Linux::AntiDebug::SECCOMP_DETECTION;
        }
        if (techniques & AntiDebugTechniques::EBPF_DETECTION) {
            mapped |= Linux::AntiDebug::EBPF_DETECTION;
        }
        if (techniques & AntiDebugTechniques::PERSONALITY_CHECK) {
            mapped |= Linux::AntiDebug::PERSONALITY_CHECK;
        }
        return mapped;
    }
}
#endif

/**
 * Initialize Omamori protection with custom configuration
 * @param config Protection configuration (default: Production preset)
 * @return true if initialization succeeded
 */
inline bool Initialize(const ProtectionConfig& config = ProtectionConfig::Production()) {
    bool success = true;
    
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    
    // ========== Layer 1: Anti-Virtualization ==========
    if (config.enable_antivm) {
        if (Windows::AntiVM::Detector::IsVirtualMachine(config.antivm_techniques)) {
            if (config.on_detection) {
                config.on_detection("AntiVM", "VirtualMachineDetected");
            } else {
                Windows::AntiVM::Detector::TerminateIfVM();
            }
        }
    }
    
    // ========== Layer 2: Anti-Debug ==========
    if (config.enable_antidebug) {
        // Apply enabled techniques via bitmask
        Windows::AntiDebug::Detector::EnableAntiDebug();
        
        // Check with specific techniques
        if (Windows::AntiDebug::Detector::IsDebuggerPresent(config.antidebug_techniques)) {
            if (config.on_detection) {
                config.on_detection("AntiDebug", "DebuggerDetected");
            } else if (config.antidebug_terminate_on_detect) {
                Windows::AntiDebug::Detector::TerminateIfDebugged();
            }
        }
        
        if (config.enable_antidebug_thread) {
            Windows::AntiDebug::ProtectionThread::Start(config.antidebug_check_interval_ms);
        }
    }
    
    // ========== Layer 3: Anti-Dump ==========
    if (config.enable_antidump) {
        Windows::AntiDump::PEProtector protector;
        
        // Apply techniques based on bitmask
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::ERASE_PE_HEADER)) {
            protector.ErasePEHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_PE_HEADER)) {
            protector.CorruptPEHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::RANDOMIZE_PE_FIELDS)) {
            protector.RandomizePEFields();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_DEBUG_DIRECTORY)) {
            protector.WipeDebugDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_EXPORT_DIRECTORY)) {
            protector.WipeExportDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_IMPORT_DIRECTORY)) {
            protector.CorruptImportDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_IAT)) {
            protector.WipeImportAddressTable();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_TLS_DIRECTORY)) {
            protector.WipeTLSDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_EXCEPTION_DIRECTORY)) {
            protector.WipeExceptionDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_RESOURCE_DIRECTORY)) {
            protector.WipeResourceDirectory();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::ENCRYPT_SECTION_HEADERS)) {
            protector.EncryptSectionHeaders();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::MANIPULATE_PEB)) {
            protector.ManipulatePEBModuleList();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::UNLINK_LDR)) {
            protector.UnlinkFromLdrDataTable();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::SPOOF_MODULE_INFO)) {
            protector.SpoofModuleInformation();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_CHECKSUM)) {
            Windows::AntiDump::DumpProtection::CorruptPEChecksum();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::INVALIDATE_DOS_STUB)) {
            Windows::AntiDump::DumpProtection::InvalidateDOSStub();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::SCRAMBLE_OPTIONAL_HEADER)) {
            Windows::AntiDump::DumpProtection::ScrambleOptionalHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::HIDE_SECTION_NAMES)) {
            Windows::AntiDump::DumpProtection::HideSectionNames();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_RELOCATIONS)) {
            Windows::AntiDump::DumpProtection::CorruptRelocations();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_RICH_HEADER)) {
            Windows::AntiDump::AntiReconstruction::WipeRichHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_COFF_HEADER)) {
            Windows::AntiDump::AntiReconstruction::CorruptCOFFHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_DOS_HEADER)) {
            Windows::AntiDump::AntiReconstruction::CorruptDOSHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::INVALIDATE_NT_SIGNATURE)) {
            Windows::AntiDump::AntiReconstruction::InvalidateNTSignature();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::SCRAMBLE_SECTION_ALIGN)) {
            Windows::AntiDump::AntiReconstruction::ScrambleSectionAlignment();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::MANGLE_ENTRY_POINT)) {
            Windows::AntiDump::AntiReconstruction::MangleEntryPoint();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::VEH_PROTECTION)) {
            Windows::AntiDump::MemoryProtection::InstallVEHProtection();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::PURGE_WORKING_SET)) {
            Windows::AntiDump::MemoryProtection::PurgeWorkingSet();
        }
        
        // Continuous protection
        if (config.antidump_continuous) {
            Windows::AntiDump::DumpProtection::Start();
        }
    }
    
    // ========== Layer 4: Memory Encryption ==========
    if (config.enable_memory_encryption && config.memory_auto_init) {
        MemoryEncryption::EncryptionManager::GetInstance().Initialize();
    }
    
    #elif defined(OMAMORI_PLATFORM_LINUX)
    
    // ========== Layer 1: Anti-Virtualization ==========
    if (config.enable_antivm) {
        if (Linux::AntiVM::Detector::IsVirtualMachine(Detail::MapLinuxAntiVMTechniques(config.antivm_techniques))) {
            if (config.on_detection) {
                config.on_detection("AntiVM", "VirtualMachineDetected");
            } else {
                Linux::AntiVM::Detector::TerminateIfVM();
            }
        }
    }
    
    // ========== Layer 2: Anti-Debug ==========
    if (config.enable_antidebug) {
        Linux::AntiDebug::Detector::EnableAntiDebug();
        
        if (Linux::AntiDebug::Detector::IsDebuggerPresent(Detail::MapLinuxAntiDebugTechniques(config.antidebug_techniques))) {
            if (config.on_detection) {
                config.on_detection("AntiDebug", "DebuggerDetected");
            } else if (config.antidebug_terminate_on_detect) {
                Linux::AntiDebug::Detector::TerminateIfDebugged();
            }
        }
        
        if (config.enable_antidebug_thread) {
            Linux::AntiDebug::ProtectionThread::Start(config.antidebug_check_interval_ms);
        }
    }
    
    // ========== Layer 3: Anti-Dump ==========
    if (config.enable_antidump) {
        // Core dump protection
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::DISABLE_CORE_DUMPS)) {
            Linux::AntiDump::CoreDumpProtection::DisableCoreDumps();
            Linux::AntiDump::CoreDumpProtection::SetResourceLimits();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::PRCTL_DUMPABLE)) {
            Linux::AntiDump::CoreDumpProtection::InstallPrctlProtection();
            Linux::AntiDump::CoreDumpProtection::SetDumpFilter();
            Linux::AntiDump::CoreDumpProtection::InstallSignalHandlers();
            Linux::AntiDump::CoreDumpProtection::PreventPtraceDump();
        }
        
        // ELF protection
        Linux::AntiDump::ELFProtector protector;
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_ELF_HEADER)) {
            Linux::AntiDump::MemoryProtection::EraseELFHeader();
            Linux::AntiDump::DumpProtection::CorruptELFMagic();
            Linux::AntiDump::AntiReconstruction::CorruptElfHeader();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::OBFUSCATE_PHDR)) {
            Linux::AntiDump::MemoryProtection::HideProgramHeaders();
            Linux::AntiDump::DumpProtection::InvalidateProgramHeaders();
            Linux::AntiDump::DumpProtection::ScrambleSectionOffsets();
            Linux::AntiDump::AntiReconstruction::InvalidatePhdr();
            Linux::AntiDump::AntiReconstruction::ScrambleShdr();
        }
        
        // Memory advice
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::MADVISE_DONTDUMP)) {
            if (Linux::AntiDump::MemoryProtection::GetModuleInfo()) {
                Linux::AntiDump::MemoryProtection::SetMadvDontDump(
                    Linux::AntiDump::MemoryProtection::moduleBase,
                    Linux::AntiDump::MemoryProtection::moduleSize
                );
            }
            Linux::AntiDump::MemoryProtection::ExcludeFromCoreDump();
            Linux::AntiDump::MemoryProtection::ProtectAllMappings();
        }

        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::MASK_PROC_MAPS) ||
            config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::MADVISE_DONTDUMP)) {
            Linux::AntiDump::ProcProtection::MaskProcMaps();
        }

        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_ALL_METADATA)) {
            protector.WipeAllMetadata();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::WIPE_BUILD_ID)) {
            Linux::AntiDump::AntiReconstruction::WipeBuildId();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::CORRUPT_DYNAMIC_SECTION)) {
            Linux::AntiDump::AntiReconstruction::CorruptDynamicSection();
        }
        if (config.IsAntiDumpTechniqueEnabled(AntiDumpTechniques::SELF_DELETE_EXECUTABLE)) {
            Linux::AntiDump::ProcProtection::SelfDeleteExecutable();
        }

        // Continuous protection
        if (config.antidump_continuous) {
            Linux::AntiDump::DumpProtection::Start();
        }
    }
    
    // ========== Layer 4: Memory Encryption ==========
    if (config.enable_memory_encryption && config.memory_auto_init) {
        MemoryEncryption::EncryptionManager::GetInstance().Initialize();
    }
    
    #endif
    
    return success;
}

/**
 * Quick check for debugger presence with specific techniques
 * @param techniques Bitmask of techniques to use (default: all)
 */
inline bool IsDebugged(uint32_t techniques = AntiDebugTechniques::ALL) {
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    return Windows::AntiDebug::Detector::IsDebuggerPresent(techniques);
    #elif defined(OMAMORI_PLATFORM_LINUX)
    return Linux::AntiDebug::Detector::IsDebuggerPresent(Detail::MapLinuxAntiDebugTechniques(techniques));
    #endif
    return false;
}

/**
 * Quick check for VM presence with specific techniques
 * @param techniques Bitmask of techniques to use (default: safe)
 */
inline bool IsInVM(uint32_t techniques = AntiVMTechniques::SAFE) {
    #if defined(OMAMORI_PLATFORM_WINDOWS)
    return Windows::AntiVM::Detector::IsVirtualMachine(techniques);
    #elif defined(OMAMORI_PLATFORM_LINUX)
    return Linux::AntiVM::Detector::IsVirtualMachine(Detail::MapLinuxAntiVMTechniques(techniques));
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
