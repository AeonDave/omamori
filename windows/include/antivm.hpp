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
    ALL_CHECKS               = 0xFFFFFFFF
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
    
    // Timing-based detection
    static bool CheckTimingAnomaly();
    
    // WMI-based detection
    static bool CheckWMI();
    
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
