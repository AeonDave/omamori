#pragma once
#include <windows.h>
#include <cstdint>

namespace Omamori {
namespace Windows {
namespace AntiDump {

class PEProtector {
private:
    void* moduleBase;
    
    // Header manipulation
    void ErasePEHeader();
    void CorruptPEHeader();
    void RandomizePEFields();
    
    // Directory manipulation
    void WipeDebugDirectory();
    void WipeExportDirectory();
    void CorruptImportDirectory();
    
    // PEB/LDR manipulation
    void ManipulatePEBModuleList();
    void UnlinkFromLdrDataTable();
    void SpoofModuleInformation();
    
public:
    explicit PEProtector(void* base = nullptr);
    
    // Main protection methods
    void ObfuscatePE();
    void HideModule();
    void ProtectMemory();
    void EnableFullProtection();
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
    static void CreateFakeSections();
    static void CorruptRelocations();
};

// Code section protection
class CodeProtection {
public:
    static bool ProtectCodeSection(void* moduleBase = nullptr);
    static bool ScrambleNonExecutedCode();
    static bool InstallInlineChecks();
};

} // namespace AntiDump
} // namespace Windows
} // namespace Omamori
