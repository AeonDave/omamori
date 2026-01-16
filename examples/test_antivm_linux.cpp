// Linux Anti-VM Test
#include "../linux/include/antivm.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace Omamori::Linux::AntiVM;

int main() {
    printf("=== Omamori Anti-VM Test (Linux) ===\n\n");
    
    int detections = 0;
    
    // Test 1: CPUID Check
    printf("[TEST 1] CPUID Hypervisor Bit...\n");
    if (Detector::CheckCPUID()) {
        printf("  [DETECTED] Hypervisor bit set\n");
        detections++;
    } else {
        printf("  [PASS] No hypervisor bit detected\n");
    }
    
    // Test 2: DMI/SMBIOS Check
    printf("\n[TEST 2] DMI/SMBIOS Fingerprinting...\n");
    if (Detector::CheckDMI()) {
        printf("  [DETECTED] VM signatures in DMI/SMBIOS\n");
        detections++;
    } else {
        printf("  [PASS] No VM signatures in DMI/SMBIOS\n");
    }
    
    // Test 3: MAC Address Check
    printf("\n[TEST 3] MAC Address Check...\n");
    if (Detector::CheckMACAddress()) {
        printf("  [DETECTED] VM MAC address prefix\n");
        detections++;
    } else {
        printf("  [PASS] No VM MAC address detected\n");
    }
    
    // Test 4: VM Devices Check
    printf("\n[TEST 4] VM Devices Check...\n");
    if (Detector::CheckDevices()) {
        printf("  [DETECTED] VM device nodes found\n");
        detections++;
    } else {
        printf("  [PASS] No VM devices detected\n");
    }
    
    // Test 5: VMware Detection
    printf("\n[TEST 5] VMware Detection...\n");
    if (Detector::CheckVMware()) {
        printf("  [DETECTED] VMware signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No VMware detected\n");
    }
    
    // Test 6: VirtualBox Detection
    printf("\n[TEST 6] VirtualBox Detection...\n");
    if (Detector::CheckVirtualBox()) {
        printf("  [DETECTED] VirtualBox signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No VirtualBox detected\n");
    }
    
    // Test 7: KVM Detection
    printf("\n[TEST 7] KVM Detection...\n");
    if (Detector::CheckKVM()) {
        printf("  [DETECTED] KVM signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No KVM detected\n");
    }
    
    // Test 8: QEMU Detection
    printf("\n[TEST 8] QEMU Detection...\n");
    if (Detector::CheckQEMU()) {
        printf("  [DETECTED] QEMU signatures found\n");
        detections++;
    } else {
        printf("  [PASS] No QEMU detected\n");
    }
    
    // Test 9: Docker/Container Detection
    printf("\n[TEST 9] Docker/Container Detection...\n");
    if (Detector::CheckDocker()) {
        printf("  [DETECTED] Running in container\n");
        detections++;
    } else {
        printf("  [PASS] Not running in container\n");
    }
    
    // Test 10: Container Check
    printf("\n[TEST 10] Container Check (cgroups)...\n");
    if (Detector::IsContainerized()) {
        printf("  [DETECTED] Containerized environment\n");
        detections++;
    } else {
        printf("  [PASS] Not containerized\n");
    }
    
    // Test 11: Timing Anomaly
    printf("\n[TEST 11] Timing Anomaly Check...\n");
    if (Detector::CheckTimingAnomaly()) {
        printf("  [DETECTED] Timing anomaly (VM characteristic)\n");
        detections++;
    } else {
        printf("  [PASS] Normal timing behavior\n");
    }
    
    // Final comprehensive check
    printf("\n=== Comprehensive VM Detection ===\n");
    if (Detector::IsVirtualMachine(ALL_CHECKS)) {
        printf("[RESULT] VIRTUAL MACHINE DETECTED\n");
        printf("VM Type: %s\n", Detector::GetVMType());
        
        if (Detector::IsContainerized()) {
            printf("Container: YES\n");
        }
        
        // Hardware info
        printf("\n=== Hardware Information ===\n");
        printf("CPU Vendor: %s\n", HardwareInfo::GetCPUVendor());
        printf("Has Hypervisor: %s\n", 
               HardwareInfo::HasHypervisor() ? "YES" : "NO");
        printf("VM CPUID Signature: %s\n",
               HardwareInfo::HasVMCPUIDSignature() ? "YES" : "NO");
    } else {
        printf("[RESULT] PHYSICAL MACHINE\n");
    }
    
    printf("\nDetections: %d/11\n", detections);
    
    // Performance test
    printf("\n=== Performance Test ===\n");
    printf("Running 1000 VM detection cycles...\n");
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < 1000; i++) {
        Detector::IsVirtualMachine(CPUID_CHECK | DMI_CHECK);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + 
                          (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;
    double avg_us = (elapsed_ns / 1000.0) / 1000.0;
    
    printf("Total time: %.2f ms\n", elapsed_ms);
    printf("Average per check: %.2f μs\n", avg_us);
    
    printf("\n=== Test Complete ===\n");
    
    return 0;
}
