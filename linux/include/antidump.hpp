#pragma once
#include <cstdint>
#include <sys/types.h>
#include <pthread.h>

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
    
    // NEW: Enhanced memory protection
    static bool SetMadvDontDump(void* addr, size_t size);
    static bool ExcludeFromCoreDump();
    static bool ProtectAllMappings();
};

// ELF manipulation
class ELFProtector {
private:
    void* base;
    
    void CorruptELFHeader();
    void WipeSectionTable();
    void ManipulateDynamicSection();
    void HideSymbols();
    
    // NEW: Additional ELF manipulation
    void CorruptGOT();
    void WipeDynamicStringTable();
    void InvalidateNotes();
    void ScramblePhdrOffsets();
    
public:
    explicit ELFProtector(void* moduleBase = nullptr);
    
    void ObfuscateELF();
    void HideModule();
    void ProtectMemory();
    void EnableFullProtection();
    
    // NEW: Advanced protection
    void WipeAllMetadata();
};

// /proc/self protection
class ProcProtection {
public:
    // Proc protection techniques
    static bool SelfDeleteExecutable();
    static bool MaskProcMaps();
    
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
    
    // NEW: Enhanced protection
    static bool CorruptELFMagic();
    static bool InvalidateProgramHeaders();
    static bool ScrambleSectionOffsets();
};

// Core dump protection
class CoreDumpProtection {
public:
    static bool DisableCoreDumps();
    static bool SetResourceLimits();
    static bool InstallPrctlProtection();
    
    // NEW: Enhanced core dump protection
    static bool SetDumpFilter();
    static bool InstallSignalHandlers();
    static bool PreventPtraceDump();
};

// NEW: Anti-reconstruction class for Linux
class AntiReconstruction {
public:
    // Prevent ELF reconstruction
    static bool CorruptElfHeader();
    static bool InvalidatePhdr();
    static bool ScrambleShdr();
    static bool WipeBuildId();
    
    // Anti-GDB/objdump techniques
    static bool CorruptDynamicSection();
};

} // namespace AntiDump
} // namespace Linux
} // namespace Omamori
