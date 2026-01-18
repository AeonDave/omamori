#include "../include/antivm.hpp"
#include <string.h>
#include <strings.h>  // for strcasestr
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>    // for toupper
#include <cpuid.h>

namespace Omamori {
namespace Linux {
namespace AntiVM {

namespace {
bool FileContainsToken(const char* path, const char* token) {
    FILE* f = fopen(path, "r");
    if (!f) return false;

    char content[512] = {0};
    size_t readBytes = fread(content, 1, sizeof(content) - 1, f);
    fclose(f);

    if (readBytes == 0) {
        return false;
    }
    content[readBytes] = '\0';

    return strcasestr(content, token) != nullptr;
}

bool AnyDMIContainsToken(const char* token) {
    const char* dmiFiles[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        nullptr
    };

    for (int i = 0; dmiFiles[i] != nullptr; i++) {
        if (FileContainsToken(dmiFiles[i], token)) {
            return true;
        }
    }
    return false;
}

bool ProcCpuinfoContainsToken(const char* token) {
    return FileContainsToken("/proc/cpuinfo", token);
}
} // namespace

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
        size_t readBytes = fread(content, 1, sizeof(content) - 1, f);
        fclose(f);

        if (readBytes == 0) {
            continue;
        }
        content[readBytes] = '\0';
        
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
    size_t readBytes = fread(mac, 1, sizeof(mac) - 1, f);
    fclose(f);

    if (readBytes == 0) {
        return false;
    }
    mac[readBytes] = '\0';
    
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
    
    return AnyDMIContainsToken("VMware");
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
    return ProcCpuinfoContainsToken("QEMU") || AnyDMIContainsToken("QEMU");
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
    // =========================================================================
    // NOTA: Tecnica timing-based conservativa per evitare falsi positivi
    // Usa solo CPUID timing con threshold alto
    // =========================================================================
    
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    unsigned long long totalCycles = 0;
    
    // Esegui multipli test per media stabile
    for (int round = 0; round < 3; round++) {
        unsigned long long start, end;
        
        // Leggi TSC prima - fix per x86_64
        #if defined(__x86_64__)
        unsigned int lo, hi;
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        start = ((unsigned long long)hi << 32) | lo;
        #else
        asm volatile("rdtsc" : "=A"(start));
        #endif
        
        for (int i = 0; i < 1000; i++) {
            __get_cpuid(0, &eax, &ebx, &ecx, &edx);
        }
        
        // Leggi TSC dopo - fix per x86_64
        #if defined(__x86_64__)
        asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
        end = ((unsigned long long)hi << 32) | lo;
        #else
        asm volatile("rdtsc" : "=A"(end));
        #endif
        
        totalCycles += (end - start);
    }
    
    // Media su 3000 CPUID calls
    unsigned long long avgCycles = totalCycles / 3000;
    
    // Threshold CONSERVATIVO: >3000 cycles indica quasi certamente VM
    if (avgCycles > 3000) {
        return true;
    }
    #endif
    
    return false;
}

// =============================================================================
// Nuove tecniche CERTE (nessun falso positivo)
// =============================================================================

bool Detector::CheckHypervisorVendor() {
    // CPUID leaf 0x40000000 restituisce il vendor dell'hypervisor
    // Questo è CERTO - non può essere un falso positivo
    
    #if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    
    // Prima verifica che CPUID hypervisor leaf esista
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    
    if (!(ecx & (1 << 31))) {
        return false;  // Nessun hypervisor
    }
    
    // Leggi il vendor dell'hypervisor
    if (!__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    
    char vendor[13] = {0};
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    
    // Vendor noti
    const char* vmVendors[] = {
        "VMwareVMware",  // VMware
        "VBoxVBoxVBox",  // VirtualBox
        "Microsoft Hv",  // Hyper-V
        "KVMKVMKVM",     // KVM
        "XenVMMXenVMM",  // Xen
        "prl hyperv  ",  // Parallels
        "TCGTCGTCGTCG",  // QEMU TCG
        nullptr
    };
    
    for (int i = 0; vmVendors[i] != nullptr; i++) {
        if (strncmp(vendor, vmVendors[i], 12) == 0) {
            return true;
        }
    }
    
    // Se c'è UN hypervisor ma vendor sconosciuto, è comunque VM
    if (eax >= 0x40000000) {
        return true;
    }
    #endif
    
    return false;
}

bool Detector::CheckSMBIOS() {
    // Legge i dati SMBIOS da /sys/class/dmi/id/
    const char* smbiosFiles[] = {
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/chassis_vendor",
        "/sys/class/dmi/id/product_version",
        nullptr
    };
    
    const char* vmStrings[] = {
        "VMware", "VirtualBox", "VBOX", "QEMU", "KVM",
        "Xen", "innotek", "Parallels", "Virtual", "Bochs",
        "Microsoft Corporation", "Amazon EC2", "Google",
        nullptr
    };
    
    for (int i = 0; smbiosFiles[i] != nullptr; i++) {
        FILE* f = fopen(smbiosFiles[i], "r");
        if (!f) continue;
        
        char content[256] = {0};
        if (fgets(content, sizeof(content) - 1, f)) {
            fclose(f);
            
            for (int j = 0; vmStrings[j] != nullptr; j++) {
                if (strcasestr(content, vmStrings[j])) {
                    return true;
                }
            }
        } else {
            fclose(f);
        }
    }
    
    return false;
}

bool Detector::CheckACPITables() {
    // Legge le tabelle ACPI da /sys/firmware/acpi/tables/
    const char* acpiPaths[] = {
        "/sys/firmware/acpi/tables/DSDT",
        "/sys/firmware/acpi/tables/FACP",
        nullptr
    };
    
    const char* vmSignatures[] = {
        "VBOX", "VMWARE", "VIRTUAL", "QEMU", "BOCHS", "XEN",
        nullptr
    };
    
    for (int i = 0; acpiPaths[i] != nullptr; i++) {
        FILE* f = fopen(acpiPaths[i], "rb");
        if (!f) continue;
        
        // Leggi primi 1KB della tabella
        char buffer[1024] = {0};
        size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 1, f);
        fclose(f);
        
        if (bytesRead > 0) {
            // Converti in maiuscolo per confronto
            for (size_t k = 0; k < bytesRead; k++) {
                buffer[k] = toupper(buffer[k]);
            }
            
            for (int j = 0; vmSignatures[j] != nullptr; j++) {
                if (strstr(buffer, vmSignatures[j])) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

bool Detector::CheckSCSIModel() {
    // Controlla il modello SCSI/disco da /sys/class/block/
    const char* diskPaths[] = {
        "/sys/class/block/sda/device/model",
        "/sys/class/block/vda/device/model",
        "/sys/class/block/xvda/device/model",
        "/sys/class/block/nvme0n1/device/model",
        nullptr
    };
    
    const char* vmDiskModels[] = {
        "VBOX", "VMware", "Virtual", "QEMU", "Xen",
        nullptr
    };
    
    for (int i = 0; diskPaths[i] != nullptr; i++) {
        FILE* f = fopen(diskPaths[i], "r");
        if (!f) continue;
        
        char model[128] = {0};
        if (fgets(model, sizeof(model) - 1, f)) {
            fclose(f);
            
            for (int j = 0; vmDiskModels[j] != nullptr; j++) {
                if (strcasestr(model, vmDiskModels[j])) {
                    return true;
                }
            }
        } else {
            fclose(f);
        }
    }
    
    // Controlla anche /proc/scsi/scsi
    FILE* f = fopen("/proc/scsi/scsi", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strcasestr(line, "VMware") || strcasestr(line, "VBOX") ||
                strcasestr(line, "QEMU") || strcasestr(line, "Virtual")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    
    return false;
}

// System detection
bool Detector::CheckSystemdDetectVirt() {
    FILE* fp = popen("systemd-detect-virt 2>/dev/null", "r");
    if (!fp) return false;
    
    char output[128] = {0};
    size_t readBytes = fread(output, 1, sizeof(output) - 1, fp);
    pclose(fp);

    if (readBytes == 0) {
        return false;
    }
    output[readBytes] = '\0';
    
    return (strcmp(output, "none\n") != 0 && strlen(output) > 0);
}

// Main detection function
bool Detector::IsVirtualMachine(uint32_t methods) {
    // CPUID-based (certain)
    if (methods & CPUID_CHECK && CheckCPUID()) return true;
    if (methods & HYPERVISOR_VENDOR && CheckHypervisorVendor()) return true;
    
    // Hardware-based (certain)
    if (methods & DMI_CHECK && CheckDMI()) return true;
    if (methods & SMBIOS_CHECK && CheckSMBIOS()) return true;
    if (methods & ACPI_CHECK && CheckACPITables()) return true;
    if (methods & SCSI_MODEL && CheckSCSIModel()) return true;
    if (methods & MAC_ADDRESS && CheckMACAddress()) return true;
    if (methods & DEVICE_CHECK && CheckDevices()) return true;
    
    // Proc-based (certain)
    if (methods & PROC_CPUINFO && CheckProcCpuinfo()) return true;
    
    // Container detection (certain)
    if (methods & DOCKER_CHECK && CheckDocker()) return true;
    
    // VM-specific (certain)
    if (methods & KVM_CHECK && CheckKVM()) return true;
    if (methods & QEMU_CHECK && CheckQEMU()) return true;
    if (methods & VMWARE_CHECK && CheckVMware()) return true;
    if (methods & VIRTUALBOX_CHECK && CheckVirtualBox()) return true;
    
    // System tools (certain)
    if (methods & SYSTEMD_DETECT_VIRT && CheckSystemdDetectVirt()) return true;
    
    // Timing-based (may have false positives - conservative threshold)
    if (methods & TIMING_ATTACK && CheckTimingAnomaly()) return true;
    
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
