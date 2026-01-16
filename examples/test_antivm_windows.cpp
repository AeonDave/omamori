// Windows Anti-VM Test
#include <windows.h>
#include <stdio.h>

// Forward declarations
namespace Omamori {
namespace Windows {
namespace AntiVM {
    bool CheckCPUID();
    bool CheckVMware();
    bool CheckVirtualBox();
    bool CheckHyperV();
    bool CheckQEMU();
    bool CheckParallels();
    bool CheckRegistry();
    bool CheckMACAddress();
    bool CheckDevices();
    bool CheckDrivers();
    bool CheckVMProcesses();
    bool CheckVMServices();
    bool IsVirtualMachine(unsigned int methods);
    const char* GetVMType();
}}}

int main() {
    printf("=== Omamori Anti-VM Test (Windows) ===\n\n");
    
    using namespace Omamori::Windows::AntiVM;
    
    int detections = 0;
    
    // Test 1: CPUID Check
    printf("[TEST 1] CPUID Hypervisor Bit...\n");
    if (CheckCPUID()) {
        printf("  [DETECTED] Hypervisor bit set\n");
        detections++;
    } else {
        printf("  [PASS] No hypervisor bit detected\n");
    }
    
    // Test 2: VMware Detection
    printf("\n[TEST 2] VMware Detection...\n");
    if (CheckVMware()) {
        printf("  [DETECTED] VMware signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No VMware detected\n");
    }
    
    // Test 3: VirtualBox Detection
    printf("\n[TEST 3] VirtualBox Detection...\n");
    if (CheckVirtualBox()) {
        printf("  [DETECTED] VirtualBox signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No VirtualBox detected\n");
    }
    
    // Test 4: Hyper-V Detection
    printf("\n[TEST 4] Hyper-V Detection...\n");
    if (CheckHyperV()) {
        printf("  [DETECTED] Hyper-V signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No Hyper-V detected\n");
    }
    
    // Test 5: QEMU/KVM Detection
    printf("\n[TEST 5] QEMU/KVM Detection...\n");
    if (CheckQEMU()) {
        printf("  [DETECTED] QEMU/KVM signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No QEMU/KVM detected\n");
    }
    
    // Test 6: Parallels Detection
    printf("\n[TEST 6] Parallels Detection...\n");
    if (CheckParallels()) {
        printf("  [DETECTED] Parallels signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No Parallels detected\n");
    }
    
    // Test 7: Registry Check
    printf("\n[TEST 7] Registry Check...\n");
    if (CheckRegistry()) {
        printf("  [DETECTED] VM artifacts in registry\n");
        detections++;
    } else {
        printf("  [PASS] No VM registry artifacts\n");
    }
    
    // Test 8: MAC Address Check
    printf("\n[TEST 8] MAC Address Check...\n");
    if (CheckMACAddress()) {
        printf("  [DETECTED] VM MAC address prefix\n");
        detections++;
    } else {
        printf("  [PASS] No VM MAC address detected\n");
    }
    
    // Test 9: Device Check
    printf("\n[TEST 9] VM Devices Check...\n");
    if (CheckDevices()) {
        printf("  [DETECTED] VM devices found\n");
        detections++;
    } else {
        printf("  [PASS] No VM devices detected\n");
    }
    
    // Test 10: Driver Check
    printf("\n[TEST 10] VM Drivers Check...\n");
    if (CheckDrivers()) {
        printf("  [DETECTED] VM drivers found\n");
        detections++;
    } else {
        printf("  [PASS] No VM drivers detected\n");
    }
    
    // Test 11: Process Check
    printf("\n[TEST 11] VM Processes Check...\n");
    if (CheckVMProcesses()) {
        printf("  [DETECTED] VM processes found\n");
        detections++;
    } else {
        printf("  [PASS] No VM processes detected\n");
    }
    
    // Test 12: Service Check
    printf("\n[TEST 12] VM Services Check...\n");
    if (CheckVMServices()) {
        printf("  [DETECTED] VM services found\n");
        detections++;
    } else {
        printf("  [PASS] No VM services detected\n");
    }
    
    // Final comprehensive check
    printf("\n=== Comprehensive VM Detection ===\n");
    if (IsVirtualMachine(0xFFFFFFFF)) {
        printf("[RESULT] VIRTUAL MACHINE DETECTED\n");
        printf("VM Type: %s\n", GetVMType());
    } else {
        printf("[RESULT] PHYSICAL MACHINE\n");
    }
    
    printf("\nDetections: %d/12\n", detections);
    
    return 0;
}
