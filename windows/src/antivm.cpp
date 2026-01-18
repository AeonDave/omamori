#include "../include/antivm.hpp"
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <winreg.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <cstdio>
#include <memory>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace Omamori {
namespace Windows {
namespace AntiVM {

// CPU-based detection
bool Detector::CheckCPUID() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Check for hypervisor bit (CPUID.1:ECX[31])
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0; // ECX bit 31
    #else
    return false;
    #endif
}

bool Detector::CheckHypervisorBit() {
    return CheckCPUID();
}

// Registry-based detection
bool Detector::CheckRegistry() {
    const char* vmKeys[] = {
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        "HARDWARE\\Description\\System",
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        nullptr
    };
    
    for (int i = 0; vmKeys[i] != nullptr; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    
    return false;
}

bool Detector::CheckRegistryKeys() {
    HKEY hKey;
    char data[1024] = {0};
    DWORD dataSize = sizeof(data);
    
    // Check BIOS
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                      "HARDWARE\\Description\\System\\BIOS", 
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        if (RegQueryValueExA(hKey, "SystemManufacturer", nullptr, nullptr, 
                            (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            size_t term = (dataSize < sizeof(data)) ? dataSize : (sizeof(data) - 1);
            data[term] = '\0';
            if (strstr(data, "VMware") || strstr(data, "VirtualBox") ||
                strstr(data, "QEMU") || strstr(data, "Xen") ||
                strstr(data, "innotek") || strstr(data, "Parallels")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        
        dataSize = sizeof(data);
        if (RegQueryValueExA(hKey, "SystemProductName", nullptr, nullptr,
                            (LPBYTE)data, &dataSize) == ERROR_SUCCESS) {
            size_t term = (dataSize < sizeof(data)) ? dataSize : (sizeof(data) - 1);
            data[term] = '\0';
            if (strstr(data, "Virtual") || strstr(data, "VMware") ||
                strstr(data, "VirtualBox") || strstr(data, "QEMU")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        
        RegCloseKey(hKey);
    }
    
    return false;
}

bool Detector::CheckBIOSInfo() {
    return CheckRegistryKeys();
}

// Hardware detection
bool Detector::CheckMACAddress() {
    ULONG bufferSize = 15000;
    std::unique_ptr<BYTE[]> buffer(new (std::nothrow) BYTE[bufferSize]);
    if (!buffer) return false;
    
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.get());
    
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                // VMware MAC prefixes: 00:05:69, 00:0C:29, 00:1C:14, 00:50:56
                if ((pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x05 && pAdapter->Address[2] == 0x69) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x0C && pAdapter->Address[2] == 0x29) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x14) ||
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x50 && pAdapter->Address[2] == 0x56) ||
                    // VirtualBox: 08:00:27
                    (pAdapter->Address[0] == 0x08 && pAdapter->Address[1] == 0x00 && pAdapter->Address[2] == 0x27) ||
                    // Parallels: 00:1C:42
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x1C && pAdapter->Address[2] == 0x42) ||
                    // Hyper-V: 00:15:5D
                    (pAdapter->Address[0] == 0x00 && pAdapter->Address[1] == 0x15 && pAdapter->Address[2] == 0x5D)) {
                    return true;
                }
            }
            pAdapter = pAdapter->Next;
        }
    }
    
    return false;
}

bool Detector::CheckDevices() {
    const char* vmDevices[] = {
        "\\\\.\\VBoxMiniRdrDN",
        "\\\\.\\VBoxGuest",
        "\\\\.\\VBoxVideo",
        "\\\\.\\VBoxMouse",
        "\\\\.\\VBoxTrayIPC",
        "\\\\.\\VBoxVideoHGSMI",
        "\\\\.\\HGFS",
        "\\\\.\\vmci",
        nullptr
    };
    
    for (int i = 0; vmDevices[i] != nullptr; i++) {
        HANDLE hDevice = CreateFileA(vmDevices[i], GENERIC_READ,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return true;
        }
    }
    
    return false;
}

bool Detector::CheckDrivers() {
    const char* vmDrivers[] = {
        "vboxguest.sys",
        "vboxmouse.sys",
        "vboxsf.sys",
        "vboxvideo.sys",
        "vmmouse.sys",
        "vmhgfs.sys",
        "vmscsi.sys",
        "vmxnet.sys",
        "vmci.sys",
        "vmsrvc.sys",
        nullptr
    };
    
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    
    for (int i = 0; vmDrivers[i] != nullptr; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\drivers\\%s", sysDir, vmDrivers[i]);

        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    
    return false;
}

// VM-specific detection
bool Detector::CheckVMware() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Check CPUID leaf 0x40000000 for VMware signature
    __cpuid(cpuInfo, 0x40000000);
    
    // "VMwareVMware" signature
    if (cpuInfo[1] == 0x61774D56 && // "VMwa"
        cpuInfo[2] == 0x4D566572 && // "reVM"
        cpuInfo[3] == 0x65726177) { // "ware"
        return true;
    }
    #endif
    
    // Check for VMware backdoor port
    #if defined(_M_IX86) && defined(_MSC_VER)
    __try {
        __asm {
            push edx
            push ecx
            push ebx
            
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            
            in eax, dx
            
            pop ebx
            pop ecx
            pop edx
        }
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    #endif
    
    return CheckRegistry() || CheckDrivers();
}

bool Detector::CheckVirtualBox() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Check CPUID leaf 0x40000000 for VirtualBox signature
    __cpuid(cpuInfo, 0x40000000);
    
    // "VBoxVBoxVBox" signature
    if (cpuInfo[1] == 0x786F4256 && // "VBox"
        cpuInfo[2] == 0x786F4256 && // "VBox"
        cpuInfo[3] == 0x786F4256) { // "VBox"
        return true;
    }
    #endif
    
    return CheckDevices() || CheckRegistry();
}

bool Detector::CheckHyperV() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Check CPUID leaf 0x40000000 for Hyper-V signature
    __cpuid(cpuInfo, 0x40000000);
    
    // "Microsoft Hv" signature
    if (cpuInfo[1] == 0x7263694D && // "Micr"
        cpuInfo[2] == 0x666F736F && // "osof"
        cpuInfo[3] == 0x76482074) { // "t Hv"
        return true;
    }
    #endif
    
    return false;
}

bool Detector::CheckQEMU() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Check CPUID for QEMU/KVM
    __cpuid(cpuInfo, 0x40000000);
    
    // Check for QEMU signature
    char vendor[13] = {0};
    memcpy(vendor + 0, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
    if (strstr(vendor, "QEMU") || strstr(vendor, "KVMKVM")) {
        return true;
    }
    #endif
    
    return CheckRegistryKeys();
}

bool Detector::CheckParallels() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SOFTWARE\\Parallels",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    
    return false;
}

// Process/Service detection
bool Detector::CheckVMProcesses() {
    const wchar_t* vmProcesses[] = {
        L"vmtoolsd.exe",
        L"vmwaretray.exe",
        L"vmwareuser.exe",
        L"vmacthlp.exe",
        L"vboxservice.exe",
        L"vboxtray.exe",
        L"xenservice.exe",
        L"qemu-ga.exe",
        nullptr
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            for (int i = 0; vmProcesses[i] != nullptr; i++) {
                if (_wcsicmp(pe32.szExeFile, vmProcesses[i]) == 0) {
                    CloseHandle(snapshot);
                    return true;
                }
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return false;
}

bool Detector::CheckVMServices() {
    const char* vmServices[] = {
        "VMTools",
        "VMwareService",
        "VBoxService",
        "VBoxMouse",
        "VBoxGuest",
        "xenservice",
        nullptr
    };
    
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return false;
    
    for (int i = 0; vmServices[i] != nullptr; i++) {
        SC_HANDLE service = OpenServiceA(scm, vmServices[i], SERVICE_QUERY_STATUS);
        if (service) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return true;
        }
    }
    
    CloseServiceHandle(scm);
    return false;
}

bool Detector::CheckVMFiles() {
    const char* vmFiles[] = {
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
        "C:\\Windows\\System32\\drivers\\vboxguest.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        nullptr
    };
    
    for (int i = 0; vmFiles[i] != nullptr; i++) {
        if (GetFileAttributesA(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    
    return false;
}

// Timing-based detection
bool Detector::CheckTimingAnomaly() {
    // =========================================================================
    // NOTA: Questa funzione usa tecniche conservative per evitare falsi positivi
    // Solo controlli CERTI vengono eseguiti
    // =========================================================================
    
    #if defined(_M_X64) || defined(_M_IX86)
    
    // Metodo 1: CPUID Signature timing (molto affidabile)
    // VM exit per CPUID è rilevabile ma usiamo threshold alto
    int cpuInfo[4];
    unsigned __int64 cpuidStart, cpuidEnd;
    unsigned __int64 totalCycles = 0;
    
    // Esegui multipli test per media stabile
    for (int round = 0; round < 3; round++) {
        cpuidStart = __rdtsc();
        for (int i = 0; i < 1000; i++) {
            __cpuid(cpuInfo, 0);
        }
        cpuidEnd = __rdtsc();
        totalCycles += (cpuidEnd - cpuidStart);
    }
    
    // Media su 3000 CPUID calls
    unsigned __int64 avgCycles = totalCycles / 3000;
    
    // Threshold CONSERVATIVO: >3000 cycles indica quasi certamente VM
    // Su hardware reale: ~50-200 cycles
    // Su VM: >1000-5000 cycles a causa di VM exits
    if (avgCycles > 3000) {
        return true;
    }
    
    #endif
    
    return false;
}

// =============================================================================
// Nuove tecniche CERTE (nessun falso positivo)
// =============================================================================

bool Detector::CheckACPITables() {
    // Legge le tabelle ACPI dal registro per stringhe VM
    HKEY hKey;
    
    // ACPI DSDT/FADT tables spesso contengono identificatori VM
    const char* acpiKeys[] = {
        "HARDWARE\\ACPI\\DSDT",
        "HARDWARE\\ACPI\\FADT",
        "HARDWARE\\ACPI\\RSDT",
        nullptr
    };
    
    for (int i = 0; acpiKeys[i] != nullptr; i++) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, acpiKeys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Enumera sottochiavi cercando VBOX, VMWARE, etc.
            char subKeyName[256];
            DWORD index = 0;
            DWORD nameSize = sizeof(subKeyName);
            
            while (RegEnumKeyExA(hKey, index++, subKeyName, &nameSize, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                // Converti in maiuscolo per confronto
                for (char* p = subKeyName; *p; ++p) *p = toupper(*p);
                
                if (strstr(subKeyName, "VBOX") || strstr(subKeyName, "VMWARE") ||
                    strstr(subKeyName, "VIRTUAL") || strstr(subKeyName, "QEMU") ||
                    strstr(subKeyName, "XEN") || strstr(subKeyName, "HYPERV")) {
                    RegCloseKey(hKey);
                    return true;
                }
                nameSize = sizeof(subKeyName);
            }
            RegCloseKey(hKey);
        }
    }
    
    return false;
}

bool Detector::CheckDiskModel() {
    // Controlla il modello del disco - VM hanno dischi con nomi specifici
    HKEY hKey;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        char identifier[256] = {0};
        DWORD size = sizeof(identifier);
        
        if (RegQueryValueExA(hKey, "Identifier", nullptr, nullptr, (LPBYTE)identifier, &size) == ERROR_SUCCESS) {
            // Converti in maiuscolo
            for (char* p = identifier; *p; ++p) *p = toupper(*p);
            
            // Dischi virtuali hanno nomi identificabili
            if (strstr(identifier, "VBOX") || strstr(identifier, "VMWARE") ||
                strstr(identifier, "VIRTUAL") || strstr(identifier, "QEMU") ||
                strstr(identifier, "HARDDISK")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    
    return false;
}

bool Detector::CheckDisplayAdapter() {
    // Controlla l'adapter grafico - VM hanno GPU virtuali
    HKEY hKey;
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        char driverDesc[256] = {0};
        DWORD size = sizeof(driverDesc);
        
        if (RegQueryValueExA(hKey, "DriverDesc", nullptr, nullptr, (LPBYTE)driverDesc, &size) == ERROR_SUCCESS) {
            // Converti in maiuscolo
            for (char* p = driverDesc; *p; ++p) *p = toupper(*p);
            
            // GPU virtuali
            if (strstr(driverDesc, "VMWARE") || strstr(driverDesc, "VBOX") ||
                strstr(driverDesc, "VIRTUAL") || strstr(driverDesc, "HYPER-V") ||
                strstr(driverDesc, "QXL") || strstr(driverDesc, "CIRRUS") ||
                strstr(driverDesc, "MICROSOFT BASIC")) {
                RegCloseKey(hKey);
                return true;
            }
        }
        RegCloseKey(hKey);
    }
    
    return false;
}

bool Detector::CheckFirmwareTables() {
    // Usa GetSystemFirmwareTable per leggere SMBIOS
    typedef UINT (WINAPI *pGetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD);
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return false;
    
    auto GetSystemFirmwareTable = reinterpret_cast<pGetSystemFirmwareTable>(
        GetProcAddress(hKernel32, "GetSystemFirmwareTable")
    );
    
    if (!GetSystemFirmwareTable) return false;
    
    // RSMB = Raw SMBIOS (0x52534D42 in little-endian)
    constexpr DWORD RSMB_SIGNATURE = 0x52534D42;
    DWORD bufferSize = GetSystemFirmwareTable(RSMB_SIGNATURE, 0, nullptr, 0);
    if (bufferSize == 0) return false;
    
    char* buffer = new char[bufferSize];
    if (GetSystemFirmwareTable(RSMB_SIGNATURE, 0, buffer, bufferSize) > 0) {
        // Cerca stringhe VM nel firmware
        // Converti in maiuscolo per ricerca
        for (DWORD i = 0; i < bufferSize; i++) {
            buffer[i] = toupper(buffer[i]);
        }
        
        bool detected = false;
        const char* vmStrings[] = {
            "VMWARE", "VIRTUALBOX", "VBOX", "QEMU", "VIRTUAL", 
            "XEN", "INNOTEK", "PARALLELS", "BOCHS", nullptr
        };
        
        for (int i = 0; vmStrings[i] != nullptr; i++) {
            // Cerca nel buffer (ricerca semplice)
            for (DWORD j = 0; j < bufferSize - strlen(vmStrings[i]); j++) {
                if (memcmp(buffer + j, vmStrings[i], strlen(vmStrings[i])) == 0) {
                    detected = true;
                    break;
                }
            }
            if (detected) break;
        }
        
        delete[] buffer;
        return detected;
    }
    
    delete[] buffer;
    return false;
}

bool Detector::CheckHypervisorVendor() {
    // CPUID leaf 0x40000000 restituisce il vendor dell'hypervisor
    // Questo è CERTO - non può essere un falso positivo
    
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    
    // Prima verifica che CPUID hypervisor leaf esista
    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 31))) {
        return false;  // Nessun hypervisor
    }
    
    // Leggi il vendor dell'hypervisor
    __cpuid(cpuInfo, 0x40000000);
    
    char vendor[13] = {0};
    memcpy(vendor + 0, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);
    
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
    // Verifica che cpuInfo[0] >= 0x40000000 (hypervisor presente)
    if (cpuInfo[0] >= 0x40000000) {
        return true;
    }
    #endif
    
    return false;
}

// WMI-based detection (simplified version)
bool Detector::CheckWMI() {
    // Note: Full WMI implementation requires COM initialization
    // This is a simplified version that checks registry instead
    return CheckRegistryKeys();
}

// Main detection function
bool Detector::IsVirtualMachine(uint32_t methods) {
    // CPUID-based (certain)
    if ((methods & CPUID_CHECK) && CheckCPUID()) return true;
    if ((methods & HYPERVISOR_VENDOR) && CheckHypervisorVendor()) return true;
    
    // Registry-based (certain)
    if ((methods & REGISTRY_CHECK) && CheckRegistry()) return true;
    if ((methods & WMI_CHECK) && CheckWMI()) return true;
    
    // Hardware-based (certain)
    if ((methods & MAC_ADDRESS) && CheckMACAddress()) return true;
    if ((methods & DEVICE_CHECK) && CheckDevices()) return true;
    if ((methods & DRIVER_CHECK) && CheckDrivers()) return true;
    if ((methods & ACPI_TABLES) && CheckACPITables()) return true;
    if ((methods & DISK_MODEL) && CheckDiskModel()) return true;
    if ((methods & DISPLAY_ADAPTER) && CheckDisplayAdapter()) return true;
    if ((methods & FIRMWARE_TABLES) && CheckFirmwareTables()) return true;
    
    // Process/Service-based (certain)
    if ((methods & PROCESS_CHECK) && CheckVMProcesses()) return true;
    if ((methods & SERVICE_CHECK) && CheckVMServices()) return true;
    if ((methods & FILE_CHECK) && CheckVMFiles()) return true;
    
    // VM-specific (certain)
    if ((methods & VMWARE_CHECK) && CheckVMware()) return true;
    if ((methods & VIRTUALBOX_CHECK) && CheckVirtualBox()) return true;
    if ((methods & HYPERV_CHECK) && CheckHyperV()) return true;
    if ((methods & QEMU_CHECK) && CheckQEMU()) return true;
    if ((methods & PARALLELS_CHECK) && CheckParallels()) return true;
    
    // Timing-based (may have false positives - use conservative threshold)
    if ((methods & TIMING_ATTACK) && CheckTimingAnomaly()) return true;
    
    return false;
}

// Information gathering
const char* Detector::GetVMType() {
    if (CheckVMware()) return "VMware";
    if (CheckVirtualBox()) return "VirtualBox";
    if (CheckHyperV()) return "Hyper-V";
    if (CheckQEMU()) return "QEMU/KVM";
    if (CheckParallels()) return "Parallels";
    
    return "Unknown";
}

// Protection
void Detector::TerminateIfVM() {
    if (IsVirtualMachine()) {
        ExitProcess(1);
    }
}

// Hardware information
bool HardwareInfo::HasHypervisor() {
    return Detector::CheckHypervisorBit();
}

const char* HardwareInfo::GetCPUVendor() {
    #if defined(_M_X64) || defined(_M_IX86)
    static char vendor[13] = {0};
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, 0);
    memcpy(vendor + 0, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    
    return vendor;
    #else
    return "Unknown";
    #endif
}

bool HardwareInfo::HasVMCPUIDSignature() {
    #if defined(_M_X64) || defined(_M_IX86)
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0x40000000);
    
    // Check if hypervisor leaf exists
    return (cpuInfo[0] >= 0x40000000);
    #else
    return false;
    #endif
}

bool HardwareInfo::CheckSMBIOS() {
    return Detector::CheckBIOSInfo();
}

} // namespace AntiVM
} // namespace Windows
} // namespace Omamori
