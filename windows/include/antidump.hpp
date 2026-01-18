#pragma once
#include <windows.h>
#include <cstdint>

namespace Omamori {
namespace Windows {
namespace AntiDump {

class PEProtector {
private:
    void* moduleBase;
    
public:
    explicit PEProtector(void* base = nullptr);

    // Header manipulation
    void ErasePEHeader();
    void CorruptPEHeader();
    void RandomizePEFields();
    
    // Directory manipulation
    void WipeDebugDirectory();
    void WipeExportDirectory();
    void CorruptImportDirectory();
    
    // NEW: Additional directory manipulation
    void WipeImportAddressTable();
    void WipeTLSDirectory();
    void WipeExceptionDirectory();
    void WipeResourceDirectory();
    void EncryptSectionHeaders();
    
    // PEB/LDR manipulation
    void ManipulatePEBModuleList();
    void UnlinkFromLdrDataTable();
    void SpoofModuleInformation();
    
    // Main protection methods
    void ObfuscatePE();
    void HideModule();
    void ProtectMemory();
    void EnableFullProtection();
    
    // NEW: Advanced protection
    void WipeAllDirectories();
};

// Memory protection techniques
class MemoryProtection {
public:
    // PAGE_NOACCESS protection
    static bool GuardWithNoAccess(void* address, size_t size);
    
    // PAGE_GUARD protection
    static bool GuardWithPageGuard(void* address, size_t size);
    
    // Execute-only memory
    static bool SetExecuteOnly(void* address, size_t size);
    
    // VEH-based protection
    static bool InstallVEHProtection();
    static void RemoveVEHProtection();
    
    // NEW: Advanced memory protection
    static bool PurgeWorkingSet();
    static bool LockCriticalPages(void* address, size_t size);
    static bool ProtectVirtualMemoryRegions();
    
private:
    static LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS pExceptionInfo);
    static PVOID vehHandle;
};

// Anti-dumping continuous protection
class DumpProtection {
private:
    static bool active;
    static HANDLE threadHandle;
    static DWORD WINAPI ProtectionThread(LPVOID param);
    
public:
    static bool Start();
    static void Stop();
    
    // Advanced techniques
    static void EraseHeaders();
    static void CorruptRelocations();
    
    // NEW: Enhanced dump protection
    static bool CorruptPEChecksum();
    static bool InvalidateDOSStub();
    static bool ScrambleOptionalHeader();
    static bool HideSectionNames();
};

// Code section protection
class CodeProtection {
public:
    static bool ProtectCodeSection(void* moduleBase = nullptr);
    
    // Code integrity protection
    static bool SetCodeReadOnly(void* moduleBase = nullptr);
    static bool CalculateCodeHash(void* moduleBase, uint32_t* outHash);
    static bool VerifyCodeIntegrity(void* moduleBase, uint32_t expectedHash);
};

// NEW: Anti-reconstruction class
class AntiReconstruction {
public:
    // Prevent PE reconstruction
    static bool CorruptDOSHeader();
    static bool InvalidateNTSignature();
    static bool ScrambleSectionAlignment();
    static bool WipeRichHeader();
    
    // Anti-IDA/Ghidra techniques
    static bool CorruptCOFFHeader();
    static bool MangleEntryPoint();
};

} // namespace AntiDump
} // namespace Windows
} // namespace Omamori
