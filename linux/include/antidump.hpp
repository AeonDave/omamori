#pragma once
#include <cstdint>
#include <sys/types.h>

namespace Omamori {
namespace Linux {
namespace AntiDump {

// Memory protection class
class MemoryProtection {
public:
    static void* moduleBase;
    static size_t moduleSize;
    
    static bool GetModuleInfo();
    static bool ProtectRegion(void* addr, size_t size, int prot);
    
    // Main protection methods
    static bool ProtectHeaders();
    static bool ProtectSections();
    static bool EnableFullProtection();
    
    // Memory manipulation
    static bool EraseELFHeader();
    static bool CorruptSectionHeaders();
    static bool HideProgramHeaders();
    
    // Advanced techniques
    static bool RemapWithNoHeaders();
    static bool InstallSegfaultHandler();
};

// ELF manipulation
class ELFProtector {
private:
    void* base;
    
    void CorruptELFHeader();
    void WipeSectionTable();
    void ManipulateDynamicSection();
    void HideSymbols();
    
public:
    explicit ELFProtector(void* moduleBase = nullptr);
    
    void ObfuscateELF();
    void HideModule();
    void ProtectMemory();
    void EnableFullProtection();
};

// /proc/self protection
class ProcProtection {
public:
    static bool HideFromProcMaps();
    static bool CorruptProcMem();
    static bool ProtectProcAccess();
    
private:
    static bool RemapMemoryRegion(void* addr, size_t size);
};

// Continuous dump protection
class DumpProtection {
private:
    static bool active;
    static pthread_t threadHandle;
    static void* ProtectionThread(void* param);
    
public:
    static bool Start();
    static void Stop();
    
    // Protection techniques
    static void EraseHeaders();
    static void RandomizeMemory();
    static void DetectMemoryAccess();
};

// Core dump protection
class CoreDumpProtection {
public:
    static bool DisableCoreDumps();
    static bool SetResourceLimits();
    static bool InstallPrctlProtection();
};

} // namespace AntiDump
} // namespace Linux
} // namespace Omamori
