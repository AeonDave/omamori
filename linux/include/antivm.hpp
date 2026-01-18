#pragma once
#include <cstdint>

namespace Omamori {
namespace Linux {
namespace AntiVM {

enum VMDetectionMethod : uint32_t {
    // Values aligned with omamori_config.hpp AntiVMTechniques
    CPUID_CHECK              = 0x00000001,
    DMI_CHECK                = 0x00000002,  // = REGISTRY_CHECK alias
    PROC_CPUINFO             = 0x00000004,  // = WMI_CHECK alias
    TIMING_ATTACK            = 0x00000008,
    MAC_ADDRESS              = 0x00000010,
    DEVICE_CHECK             = 0x00000020,
    SYSTEMD_DETECT_VIRT      = 0x00000080,  // = PROCESS_CHECK alias
    DOCKER_CHECK             = 0x00000100,  // = SERVICE_CHECK alias
    KVM_CHECK                = 0x00000200,  // = FILE_CHECK alias
    VMWARE_CHECK             = 0x00000400,
    VIRTUALBOX_CHECK         = 0x00000800,
    QEMU_CHECK               = 0x00002000,
    // CERTAIN detection methods (no false positives)
    HYPERVISOR_VENDOR        = 0x00080000,
    SMBIOS_CHECK             = 0x00040000,  // = FIRMWARE_TABLES alias
    ACPI_CHECK               = 0x00008000,  // = ACPI_TABLES
    SCSI_MODEL               = 0x00010000,  // = DISK_MODEL alias
    ALL_CHECKS               = 0xFFFFFFFF,
    // Recommended: only CERTAIN checks (no timing-based)
    SAFE_CHECKS              = CPUID_CHECK | DMI_CHECK | PROC_CPUINFO | MAC_ADDRESS |
                               DEVICE_CHECK | SYSTEMD_DETECT_VIRT |
                               DOCKER_CHECK | HYPERVISOR_VENDOR | SMBIOS_CHECK |
                               ACPI_CHECK | SCSI_MODEL
};

class Detector {
public:
    // CPU-based detection
    static bool CheckCPUID();
    static bool CheckHypervisorBit();
    
    // Hardware detection
    static bool CheckDMI();
    static bool CheckMACAddress();
    static bool CheckDevices();
    
    // VM-specific detection
    static bool CheckVMware();
    static bool CheckVirtualBox();
    static bool CheckKVM();
    static bool CheckQEMU();
    
    // Container detection
    static bool CheckDocker();
    
    // Timing-based detection (use with caution)
    static bool CheckTimingAnomaly();
    
    // New CERTAIN detection methods (no false positives)
    static bool CheckHypervisorVendor();  // CPUID hypervisor vendor (MOST RELIABLE)
    static bool CheckSMBIOS();            // /sys/class/dmi SMBIOS data
    static bool CheckACPITables();        // ACPI table signatures
    static bool CheckSCSIModel();         // Virtual SCSI/disk model
    
private:
    // /proc based detection
    static bool CheckProcCpuinfo();
    static bool CheckProcModules();
    
    // System detection
    static bool CheckSystemdDetectVirt();
    
public:
    // Main detection function
    static bool IsVirtualMachine(uint32_t methods = ALL_CHECKS);
    
    // Information gathering
    static const char* GetVMType();
    static bool IsContainerized();
    
    // Protection
    static void TerminateIfVM();
};

// Hardware information
class HardwareInfo {
public:
    static bool HasHypervisor();
    static const char* GetCPUVendor();
    static bool HasVMCPUIDSignature();
};

} // namespace AntiVM
} // namespace Linux
} // namespace Omamori
