#include "../include/antivm.hpp"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cpuid.h>

namespace Omamori {
namespace Linux {
namespace AntiVM {

// CPU-based detection
bool Detector::CheckCPUID() {
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    
    // Check for hypervisor bit
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 31)) != 0; // Hypervisor bit
    }
    #endif
    
    return false;
}

bool Detector::CheckHypervisorBit() {
    return CheckCPUID();
}

// /proc based detection
bool Detector::CheckProcCpuinfo() {
    FILE* f = fopen("/proc/cpuinfo", "r");
    if (!f) return false;
    
    char line[256];
    bool isVM = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "hypervisor") || 
            strstr(line, "QEMU") ||
            strstr(line, "VirtualBox") ||
            strstr(line, "VMware")) {
            isVM = true;
            break;
        }
    }
    
    fclose(f);
    return isVM;
}

bool Detector::CheckProcModules() {
    FILE* f = fopen("/proc/modules", "r");
    if (!f) return false;
    
    char line[256];
    bool isVM = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "vboxguest") ||
            strstr(line, "vboxsf") ||
            strstr(line, "vmw_") ||
            strstr(line, "vmxnet") ||
            strstr(line, "vmware")) {
            isVM = true;
            break;
        }
    }
    
    fclose(f);
    return isVM;
}

// Hardware detection
bool Detector::CheckDMI() {
    const char* dmiFiles[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        nullptr
    };
    
    for (int i = 0; dmiFiles[i] != nullptr; i++) {
        FILE* f = fopen(dmiFiles[i], "r");
        if (!f) continue;
        
        char content[256] = {0};
        fread(content, 1, sizeof(content) - 1, f);
        fclose(f);
        
        if (strstr(content, "VMware") ||
            strstr(content, "VirtualBox") ||
            strstr(content, "QEMU") ||
            strstr(content, "KVM") ||
            strstr(content, "Xen") ||
            strstr(content, "innotek") ||
            strstr(content, "Parallels")) {
            return true;
        }
    }
    
    return false;
}

bool Detector::CheckMACAddress() {
    FILE* f = fopen("/sys/class/net/eth0/address", "r");
    if (!f) {
        f = fopen("/sys/class/net/ens33/address", "r");
    }
    if (!f) return false;
    
    char mac[32] = {0};
    fread(mac, 1, sizeof(mac) - 1, f);
    fclose(f);
    
    // Check for VM MAC prefixes
    const char* vmPrefixes[] = {
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "00:16:3E", // Xen
        "52:54:00", // KVM/QEMU
        nullptr
    };
    
    for (int i = 0; vmPrefixes[i] != nullptr; i++) {
        if (strncasecmp(mac, vmPrefixes[i], 8) == 0) {
            return true;
        }
    }
    
    return false;
}

bool Detector::CheckDevices() {
    const char* vmDevices[] = {
        "/dev/vboxguest",
        "/dev/vboxuser",
        "/dev/vmci",
        "/dev/vmmemctl",
        nullptr
    };
    
    for (int i = 0; vmDevices[i] != nullptr; i++) {
        struct stat st;
        if (stat(vmDevices[i], &st) == 0) {
            return true;
        }
    }
    
    return false;
}

// VM-specific detection
bool Detector::CheckVMware() {
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        char vendor[13] = {0};
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        
        if (strcmp(vendor, "VMwareVMware") == 0) {
            return true;
        }
    }
    #endif
    
    return CheckDMI() && strstr("VMware", "VMware");
}

bool Detector::CheckVirtualBox() {
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        char vendor[13] = {0};
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        
        if (strcmp(vendor, "VBoxVBoxVBox") == 0) {
            return true;
        }
    }
    #endif
    
    struct stat st;
    return stat("/dev/vboxguest", &st) == 0;
}

bool Detector::CheckKVM() {
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    
    if (__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        char vendor[13] = {0};
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        
        if (strstr(vendor, "KVMKVMKVM")) {
            return true;
        }
    }
    #endif
    
    return false;
}

bool Detector::CheckQEMU() {
    return CheckProcCpuinfo() || CheckDMI();
}

bool Detector::CheckDocker() {
    // Check for .dockerenv file
    struct stat st;
    if (stat("/.dockerenv", &st) == 0) {
        return true;
    }
    
    // Check cgroup
    FILE* f = fopen("/proc/self/cgroup", "r");
    if (!f) return false;
    
    char line[256];
    bool isDocker = false;
    
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "docker") || strstr(line, "containerd")) {
            isDocker = true;
            break;
        }
    }
    
    fclose(f);
    return isDocker;
}

// Timing-based detection
bool Detector::CheckTimingAnomaly() {
    // VMs typically have timing anomalies
    return false;
}

// System detection
bool Detector::CheckSystemdDetectVirt() {
    FILE* fp = popen("systemd-detect-virt 2>/dev/null", "r");
    if (!fp) return false;
    
    char output[128] = {0};
    fread(output, 1, sizeof(output) - 1, fp);
    pclose(fp);
    
    return (strcmp(output, "none\n") != 0 && strlen(output) > 0);
}

// Main detection function
bool Detector::IsVirtualMachine(uint32_t methods) {
    if (methods & CPUID_CHECK && CheckCPUID()) return true;
    if (methods & DMI_CHECK && CheckDMI()) return true;
    if (methods & PROC_CPUINFO && CheckProcCpuinfo()) return true;
    if (methods & MAC_ADDRESS && CheckMACAddress()) return true;
    if (methods & DEVICE_CHECK && CheckDevices()) return true;
    if (methods & DOCKER_CHECK && CheckDocker()) return true;
    if (methods & KVM_CHECK && CheckKVM()) return true;
    if (methods & QEMU_CHECK && CheckQEMU()) return true;
    if (methods & VMWARE_CHECK && CheckVMware()) return true;
    if (methods & VIRTUALBOX_CHECK && CheckVirtualBox()) return true;
    if (methods & SYSTEMD_DETECT_VIRT && CheckSystemdDetectVirt()) return true;
    
    return false;
}

// Information gathering
const char* Detector::GetVMType() {
    if (CheckVMware()) return "VMware";
    if (CheckVirtualBox()) return "VirtualBox";
    if (CheckKVM()) return "KVM";
    if (CheckQEMU()) return "QEMU";
    if (CheckDocker()) return "Docker";
    return "Unknown";
}

bool Detector::IsContainerized() {
    return CheckDocker();
}

// Protection
void Detector::TerminateIfVM() {
    if (IsVirtualMachine()) {
        _exit(1);
    }
}

// HardwareInfo implementation
bool HardwareInfo::HasHypervisor() {
    return Detector::CheckCPUID();
}

const char* HardwareInfo::GetCPUVendor() {
    #if defined(__x86_64__) || defined(__i386__)
    static char vendor[13] = {0};
    unsigned int eax, ebx, ecx, edx;
    
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        memcpy(vendor + 0, &ebx, 4);
        memcpy(vendor + 4, &edx, 4);
        memcpy(vendor + 8, &ecx, 4);
        return vendor;
    }
    #endif
    
    return "Unknown";
}

bool HardwareInfo::HasVMCPUIDSignature() {
    return Detector::CheckHypervisorBit();
}

} // namespace AntiVM
} // namespace Linux
} // namespace Omamori
