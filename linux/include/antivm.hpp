#pragma once
#include <cstdint>

namespace Omamori {
namespace Linux {
namespace AntiVM {

enum VMDetectionMethod : uint32_t {
    CPUID_CHECK              = 0x00000001,
    DMI_CHECK                = 0x00000002,
    PROC_CPUINFO             = 0x00000004,
    TIMING_ATTACK            = 0x00000008,
    MAC_ADDRESS              = 0x00000010,
    DEVICE_CHECK             = 0x00000020,
    DRIVER_CHECK             = 0x00000040,
    SYSTEMD_DETECT_VIRT      = 0x00000080,
    DOCKER_CHECK             = 0x00000100,
    KVM_CHECK                = 0x00000200,
    QEMU_CHECK               = 0x00000400,
    VMWARE_CHECK             = 0x00000800,
    VIRTUALBOX_CHECK         = 0x00001000,
    ALL_CHECKS               = 0xFFFFFFFF
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
    
    // Timing-based detection
    static bool CheckTimingAnomaly();
    
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
