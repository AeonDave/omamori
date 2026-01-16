#include "../include/antidump.hpp"
#include "../include/internal.hpp"
#include <winternl.h>

namespace Omamori {
namespace Windows {
namespace AntiDump {

// PEProtector implementation
PEProtector::PEProtector(void* base) 
    : moduleBase(base ? base : GetModuleHandle(nullptr)) {
}

void PEProtector::ErasePEHeader() {
    if (!moduleBase) return;
    
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(moduleBase, &mbi, sizeof(mbi)) == 0) return;
    
    DWORD oldProtect;
    if (VirtualProtect(moduleBase, 0x1000, PAGE_READWRITE, &oldProtect)) {
        Internal::SecureZeroMemory(moduleBase, 0x1000);
        VirtualProtect(moduleBase, 0x1000, oldProtect, &oldProtect);
    }
}

void PEProtector::CorruptPEHeader() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        // Corrupt signature
        ntHeaders->Signature = 0xDEADBEEF;
        
        // Corrupt file header
        ntHeaders->FileHeader.NumberOfSections ^= 0xFFFF;
        ntHeaders->FileHeader.TimeDateStamp = GetTickCount();
        
        // Corrupt optional header
        ntHeaders->OptionalHeader.CheckSum = 0;
        ntHeaders->OptionalHeader.SizeOfImage += (GetTickCount() % 0x10000);
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

void PEProtector::RandomizePEFields() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        // Randomize fields
        ntHeaders->OptionalHeader.Win32VersionValue = GetTickCount();
        ntHeaders->OptionalHeader.SizeOfHeapReserve = GetTickCount64();
        ntHeaders->OptionalHeader.SizeOfStackReserve = GetTickCount64();
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

void PEProtector::WipeDebugDirectory() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        IMAGE_DATA_DIRECTORY* debugDir = 
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        
        debugDir->VirtualAddress = 0;
        debugDir->Size = 0;
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

void PEProtector::WipeExportDirectory() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        IMAGE_DATA_DIRECTORY* exportDir = 
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        
        exportDir->VirtualAddress = 0;
        exportDir->Size = 0;
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

void PEProtector::CorruptImportDirectory() {
    // Note: This will break IAT-dependent functionality
    // Use with caution
}

void PEProtector::ManipulatePEBModuleList() {
    PEB* peb = Internal::READ_PEB();
    
    // Walk LDR data table
    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return;
    
    // Find our module in InMemoryOrderModuleList
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        
        if (entry->DllBase == moduleBase) {
            // Corrupt entry
            entry->SizeOfImage = GetTickCount();
            entry->Flags ^= 0xDEAD;
            break;
        }
        
        current = current->Flink;
    }
}

void PEProtector::UnlinkFromLdrDataTable() {
    PEB* peb = Internal::READ_PEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    if (!ldr) return;
    
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );
        
        if (entry->DllBase == moduleBase) {
            // Unlink from all lists
            current->Flink->Blink = current->Blink;
            current->Blink->Flink = current->Flink;
            break;
        }
        
        current = current->Flink;
    }
}

void PEProtector::SpoofModuleInformation() {
    ManipulatePEBModuleList();
}

void PEProtector::ObfuscatePE() {
    CorruptPEHeader();
    RandomizePEFields();
    WipeDebugDirectory();
    WipeExportDirectory();
}

void PEProtector::HideModule() {
    UnlinkFromLdrDataTable();
    SpoofModuleInformation();
}

void PEProtector::ProtectMemory() {
    if (!moduleBase) return;
    
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* address = static_cast<BYTE*>(moduleBase);
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.AllocationBase != moduleBase) break;
        
        if (mbi.Protect == PAGE_EXECUTE_READ || 
            mbi.Protect == PAGE_EXECUTE_READWRITE) {
            // Don't touch executable sections
        } else {
            DWORD oldProtect;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, 
                          PAGE_NOACCESS, &oldProtect);
        }
        
        address += mbi.RegionSize;
    }
}

void PEProtector::EnableFullProtection() {
    ObfuscatePE();
    HideModule();
    ProtectMemory();
}

// MemoryProtection implementation
PVOID MemoryProtection::vehHandle = nullptr;

bool MemoryProtection::GuardWithNoAccess(void* address, size_t size) {
    DWORD oldProtect;
    return VirtualProtect(address, size, PAGE_NOACCESS, &oldProtect) != 0;
}

bool MemoryProtection::GuardWithPageGuard(void* address, size_t size) {
    DWORD oldProtect;
    return VirtualProtect(address, size, PAGE_GUARD | PAGE_READWRITE, &oldProtect) != 0;
}

bool MemoryProtection::SetExecuteOnly(void* address, size_t size) {
    DWORD oldProtect;
    return VirtualProtect(address, size, PAGE_EXECUTE, &oldProtect) != 0;
}

LONG CALLBACK MemoryProtection::VEHHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE) {
        // Detected memory access attempt - terminate
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

bool MemoryProtection::InstallVEHProtection() {
    if (vehHandle) return false;
    vehHandle = AddVectoredExceptionHandler(1, VEHHandler);
    return vehHandle != nullptr;
}

void MemoryProtection::RemoveVEHProtection() {
    if (vehHandle) {
        RemoveVectoredExceptionHandler(vehHandle);
        vehHandle = nullptr;
    }
}

// DumpProtection implementation
bool DumpProtection::active = false;
HANDLE DumpProtection::threadHandle = nullptr;

DWORD WINAPI DumpProtection::ProtectionThread(LPVOID param) {
    void* moduleBase = GetModuleHandle(nullptr);
    
    while (active) {
        // Continuously re-corrupt headers
        EraseHeaders();
        Sleep(1000);
    }
    
    return 0;
}

bool DumpProtection::Start() {
    if (active) return false;
    
    active = true;
    threadHandle = CreateThread(nullptr, 0, ProtectionThread, nullptr, 0, nullptr);
    return threadHandle != nullptr;
}

void DumpProtection::Stop() {
    active = false;
    if (threadHandle) {
        WaitForSingleObject(threadHandle, INFINITE);
        CloseHandle(threadHandle);
        threadHandle = nullptr;
    }
}

void DumpProtection::EraseHeaders() {
    void* moduleBase = GetModuleHandle(nullptr);
    DWORD oldProtect;
    
    if (VirtualProtect(moduleBase, 0x1000, PAGE_READWRITE, &oldProtect)) {
        Internal::SecureZeroMemory(moduleBase, 0x1000);
        VirtualProtect(moduleBase, 0x1000, oldProtect, &oldProtect);
    }
}

void DumpProtection::CreateFakeSections() {
    // Create decoy PE sections in memory to confuse dumpers
}

void DumpProtection::CorruptRelocations() {
    void* moduleBase = GetModuleHandle(nullptr);
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    IMAGE_DATA_DIRECTORY* relocDir = 
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocDir->VirtualAddress) {
        void* relocSection = reinterpret_cast<BYTE*>(moduleBase) + relocDir->VirtualAddress;
        DWORD oldProtect;
        
        if (VirtualProtect(relocSection, relocDir->Size, PAGE_READWRITE, &oldProtect)) {
            Internal::SecureZeroMemory(relocSection, relocDir->Size);
            VirtualProtect(relocSection, relocDir->Size, oldProtect, &oldProtect);
        }
    }
}

// CodeProtection implementation
bool CodeProtection::ProtectCodeSection(void* moduleBase) {
    if (!moduleBase) moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            void* sectionAddr = reinterpret_cast<BYTE*>(moduleBase) + section->VirtualAddress;
            MemoryProtection::SetExecuteOnly(sectionAddr, section->Misc.VirtualSize);
        }
    }
    
    return true;
}

bool CodeProtection::ScrambleNonExecutedCode() {
    // Advanced technique: identify cold code paths and scramble them
    return false;
}

bool CodeProtection::InstallInlineChecks() {
    // Insert integrity checks inline in code
    return false;
}

} // namespace AntiDump
} // namespace Windows
} // namespace Omamori
