#pragma once
#include <cstdint>

namespace Omamori {
namespace Windows {
namespace AntiVM {

enum VMDetectionMethod : uint32_t {
    CPUID_CHECK              = 0x00000001,
    REGISTRY_CHECK           = 0x00000002,
    WMI_CHECK                = 0x00000004,
    TIMING_ATTACK            = 0x00000008,
    MAC_ADDRESS              = 0x00000010,
    DEVICE_CHECK             = 0x00000020,
    DRIVER_CHECK             = 0x00000040,
    PROCESS_CHECK            = 0x00000080,
    SERVICE_CHECK            = 0x00000100,
    FILE_CHECK               = 0x00000200,
    VMWARE_CHECK             = 0x00000400,
    VIRTUALBOX_CHECK         = 0x00000800,
    HYPERV_CHECK             = 0x00001000,
    QEMU_CHECK               = 0x00002000,
    PARALLELS_CHECK          = 0x00004000,
    // New CERTAIN detection methods (no false positives)
    ACPI_TABLES              = 0x00008000,  // ACPI table signatures
    DISK_MODEL               = 0x00010000,  // Virtual disk model names
    DISPLAY_ADAPTER          = 0x00020000,  // Virtual GPU detection
    FIRMWARE_TABLES          = 0x00040000,  // SMBIOS firmware strings
    HYPERVISOR_VENDOR        = 0x00080000,  // CPUID hypervisor vendor (CERTAIN)
    ALL_CHECKS               = 0xFFFFFFFF,
    // Recommended: only CERTAIN checks (no timing-based)
    SAFE_CHECKS              = CPUID_CHECK | REGISTRY_CHECK | MAC_ADDRESS | DEVICE_CHECK | 
                               DRIVER_CHECK | PROCESS_CHECK | SERVICE_CHECK | FILE_CHECK |
                               ACPI_TABLES | DISK_MODEL | DISPLAY_ADAPTER | FIRMWARE_TABLES |
                               HYPERVISOR_VENDOR
};

class Detector {
public:
    // CPU-based detection
    static bool CheckCPUID();
    static bool CheckHypervisorBit();
    static bool CheckBIOSInfo();

private:
    // Registry-based detection
    static bool CheckRegistry();
    static bool CheckRegistryKeys();

    // Hardware detection
    static bool CheckMACAddress();
    static bool CheckDevices();
    static bool CheckDrivers();
    
    // VM-specific detection
    static bool CheckVMware();
    static bool CheckVirtualBox();
    static bool CheckHyperV();
    static bool CheckQEMU();
    static bool CheckParallels();
    
    // Process/Service detection
    static bool CheckVMProcesses();
    static bool CheckVMServices();
    static bool CheckVMFiles();
    
    // Timing-based detection (use with caution - can have false positives)
    static bool CheckTimingAnomaly();
    
    // WMI-based detection
    static bool CheckWMI();
    
    // New CERTAIN detection methods (no false positives)
    static bool CheckACPITables();        // ACPI table signatures
    static bool CheckDiskModel();         // Virtual disk model names
    static bool CheckDisplayAdapter();    // Virtual GPU detection
    static bool CheckFirmwareTables();    // SMBIOS firmware strings
    static bool CheckHypervisorVendor();  // CPUID hypervisor vendor (MOST RELIABLE)
    
public:
    // Main detection function
    static bool IsVirtualMachine(uint32_t methods = ALL_CHECKS);
    
    // Information gathering
    static const char* GetVMType();
    
    // Protection
    static void TerminateIfVM();
};

// Hardware information
class HardwareInfo {
public:
    static bool HasHypervisor();
    static const char* GetCPUVendor();
    static bool HasVMCPUIDSignature();
    static bool CheckSMBIOS();
};

} // namespace AntiVM
} // namespace Windows
} // namespace Omamori
