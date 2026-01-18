#include "../include/antidump.hpp"
#include "../include/internal.hpp"
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>

// Define missing structure members for LDR
typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    // ...
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

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

// NEW: Wipe Import Address Table
void PEProtector::WipeImportAddressTable() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    IMAGE_DATA_DIRECTORY* iatDir = 
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    
    if (iatDir->VirtualAddress == 0 || iatDir->Size == 0) return;
    
    // Just zero out the directory entry, not the actual IAT (would crash)
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        iatDir->VirtualAddress = 0;
        iatDir->Size = 0;
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

// NEW: Wipe TLS Directory
void PEProtector::WipeTLSDirectory() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        IMAGE_DATA_DIRECTORY* tlsDir = 
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        
        tlsDir->VirtualAddress = 0;
        tlsDir->Size = 0;
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

// NEW: Wipe Exception Directory
void PEProtector::WipeExceptionDirectory() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        IMAGE_DATA_DIRECTORY* exceptionDir = 
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        
        exceptionDir->VirtualAddress = 0;
        exceptionDir->Size = 0;
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

// NEW: Wipe Resource Directory entry (not the actual resources)
void PEProtector::WipeResourceDirectory() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
        IMAGE_DATA_DIRECTORY* resourceDir = 
            &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        
        resourceDir->VirtualAddress = 0;
        resourceDir->Size = 0;
        
        VirtualProtect(ntHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
    }
}

// NEW: Encrypt section headers with XOR
void PEProtector::EncryptSectionHeaders() {
    if (!moduleBase) return;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;
    
    DWORD oldProtect;
    size_t sectionTableSize = numSections * sizeof(IMAGE_SECTION_HEADER);
    
    if (VirtualProtect(section, sectionTableSize, PAGE_READWRITE, &oldProtect)) {
        // XOR each byte with a key based on its position
        BYTE* sectionBytes = reinterpret_cast<BYTE*>(section);
        for (size_t i = 0; i < sectionTableSize; i++) {
            sectionBytes[i] ^= static_cast<BYTE>((i * 0x37) ^ 0xAB);
        }
        VirtualProtect(section, sectionTableSize, oldProtect, &oldProtect);
    }
}

// NEW: Wipe all PE directories
void PEProtector::WipeAllDirectories() {
    WipeDebugDirectory();
    WipeExportDirectory();
    WipeImportAddressTable();
    WipeTLSDirectory();
    WipeExceptionDirectory();
    WipeResourceDirectory();
}

void PEProtector::ManipulatePEBModuleList() {
    auto peb = Internal::ReadPEB();

    // Walk LDR data table
    PPEB_LDR_DATA ldr = static_cast<PPEB_LDR_DATA>(peb->Ldr);
    if (!ldr) return;
    
    // Find our module in InMemoryOrderModuleList
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            MY_LDR_DATA_TABLE_ENTRY,
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
    auto peb = Internal::ReadPEB();
    PPEB_LDR_DATA ldr = static_cast<PPEB_LDR_DATA>(peb->Ldr);
    if (!ldr) return;
    
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
    
    while (current != head) {
        PMY_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
            current,
            MY_LDR_DATA_TABLE_ENTRY,
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

// Set code section as read-only (prevents self-modifying code attacks)
bool CodeProtection::SetCodeReadOnly(void* moduleBase) {
    if (!moduleBase) moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            void* sectionAddr = reinterpret_cast<BYTE*>(moduleBase) + section->VirtualAddress;
            DWORD oldProtect;
            VirtualProtect(sectionAddr, section->Misc.VirtualSize, PAGE_EXECUTE_READ, &oldProtect);
        }
    }
    
    return true;
}

// NEW: Calculate simple hash of code section
bool CodeProtection::CalculateCodeHash(void* moduleBase, uint32_t* outHash) {
    if (!moduleBase) moduleBase = GetModuleHandle(nullptr);
    if (!outHash) return false;
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    uint32_t hash = 0x811C9DC5; // FNV-1a offset basis
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE* sectionAddr = reinterpret_cast<BYTE*>(moduleBase) + section->VirtualAddress;
            for (DWORD j = 0; j < section->Misc.VirtualSize; j++) {
                hash ^= sectionAddr[j];
                hash *= 0x01000193; // FNV-1a prime
            }
        }
    }
    
    *outHash = hash;
    return true;
}

// NEW: Verify code integrity against expected hash
bool CodeProtection::VerifyCodeIntegrity(void* moduleBase, uint32_t expectedHash) {
    uint32_t currentHash;
    if (!CalculateCodeHash(moduleBase, &currentHash)) {
        return false;
    }
    return currentHash == expectedHash;
}

// NEW: MemoryProtection advanced methods

// Purge working set to remove pages from physical memory
bool MemoryProtection::PurgeWorkingSet() {
    HANDLE hProcess = GetCurrentProcess();
    return EmptyWorkingSet(hProcess) != 0;
}

// Lock critical pages in memory (prevents them from being swapped/dumped easily)
bool MemoryProtection::LockCriticalPages(void* address, size_t size) {
    return VirtualLock(address, size) != 0;
}

// Protect all virtual memory regions with suspicious access patterns
bool MemoryProtection::ProtectVirtualMemoryRegions() {
    void* moduleBase = GetModuleHandle(nullptr);
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* address = static_cast<BYTE*>(moduleBase);
    bool success = true;
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.AllocationBase != moduleBase) break;
        
        // Make data sections harder to dump
        if (mbi.Protect == PAGE_READWRITE) {
            DWORD oldProtect;
            // Add PAGE_GUARD to data sections
            if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, 
                               PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
                success = false;
            }
        }
        
        address += mbi.RegionSize;
    }
    
    return success;
}

// NEW: DumpProtection enhanced methods

// Corrupt PE checksum
bool DumpProtection::CorruptPEChecksum() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->OptionalHeader.CheckSum, sizeof(DWORD), 
                      PAGE_READWRITE, &oldProtect)) {
        ntHeaders->OptionalHeader.CheckSum = 0xDEADC0DE;
        VirtualProtect(&ntHeaders->OptionalHeader.CheckSum, sizeof(DWORD), 
                      oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Invalidate DOS stub
bool DumpProtection::InvalidateDOSStub() {
    void* moduleBase = GetModuleHandle(nullptr);
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);

    if (!dosHeader || dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    if (dosHeader->e_lfanew <= sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    DWORD oldProtect;
    // Zero out DOS stub (from after DOS header to NT headers)
    size_t stubSize = dosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    if (stubSize == 0) {
        return false;
    }
    void* stubStart = reinterpret_cast<BYTE*>(moduleBase) + sizeof(IMAGE_DOS_HEADER);
    
    if (VirtualProtect(stubStart, stubSize, PAGE_READWRITE, &oldProtect)) {
        Internal::SecureZeroMemory(stubStart, stubSize);
        VirtualProtect(stubStart, stubSize, oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Scramble optional header fields
bool DumpProtection::ScrambleOptionalHeader() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 
                      PAGE_READWRITE, &oldProtect)) {
        // Scramble non-critical fields
        ntHeaders->OptionalHeader.MajorLinkerVersion = 0xFF;
        ntHeaders->OptionalHeader.MinorLinkerVersion = 0xFF;
        ntHeaders->OptionalHeader.Win32VersionValue = 0xDEADBEEF;
        ntHeaders->OptionalHeader.LoaderFlags = 0xCAFEBABE;
        ntHeaders->OptionalHeader.SizeOfHeapReserve = 0xFFFFFFFFFFFFFFFF;
        ntHeaders->OptionalHeader.SizeOfHeapCommit = 0xFFFFFFFFFFFFFFFF;
        ntHeaders->OptionalHeader.SizeOfStackReserve = 0xFFFFFFFFFFFFFFFF;
        ntHeaders->OptionalHeader.SizeOfStackCommit = 0xFFFFFFFFFFFFFFFF;
        
        VirtualProtect(&ntHeaders->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 
                      oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Hide section names by zeroing them
bool DumpProtection::HideSectionNames() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    DWORD oldProtect;
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (VirtualProtect(section->Name, IMAGE_SIZEOF_SHORT_NAME, 
                          PAGE_READWRITE, &oldProtect)) {
            Internal::SecureZeroMemory(section->Name, IMAGE_SIZEOF_SHORT_NAME);
            VirtualProtect(section->Name, IMAGE_SIZEOF_SHORT_NAME, 
                          oldProtect, &oldProtect);
        }
    }
    return true;
}

// NEW: AntiReconstruction implementation

// Corrupt DOS header to prevent reconstruction
bool AntiReconstruction::CorruptDOSHeader() {
    void* moduleBase = GetModuleHandle(nullptr);
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    
    DWORD oldProtect;
    if (VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &oldProtect)) {
        // Keep e_magic and e_lfanew valid (needed for execution)
        // Corrupt other fields
        dosHeader->e_cblp = 0xFFFF;
        dosHeader->e_cp = 0xFFFF;
        dosHeader->e_crlc = 0xFFFF;
        dosHeader->e_cparhdr = 0xFFFF;
        dosHeader->e_minalloc = 0xFFFF;
        dosHeader->e_maxalloc = 0xFFFF;
        dosHeader->e_ss = 0xFFFF;
        dosHeader->e_sp = 0xFFFF;
        dosHeader->e_csum = 0xFFFF;
        dosHeader->e_ip = 0xFFFF;
        dosHeader->e_cs = 0xFFFF;
        dosHeader->e_lfarlc = 0xFFFF;
        dosHeader->e_ovno = 0xFFFF;
        
        VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Invalidate NT signature (makes PE invalid for tools)
bool AntiReconstruction::InvalidateNTSignature() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->Signature, sizeof(DWORD), PAGE_READWRITE, &oldProtect)) {
        ntHeaders->Signature = 0xDEADBEEF;
        VirtualProtect(&ntHeaders->Signature, sizeof(DWORD), oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Scramble section alignment values
bool AntiReconstruction::ScrambleSectionAlignment() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 
                      PAGE_READWRITE, &oldProtect)) {
        ntHeaders->OptionalHeader.FileAlignment = 0x1;
        ntHeaders->OptionalHeader.SectionAlignment = 0x1;
        VirtualProtect(&ntHeaders->OptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), 
                      oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Wipe Rich header (compiler fingerprint)
bool AntiReconstruction::WipeRichHeader() {
    void* moduleBase = GetModuleHandle(nullptr);
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    
    // Rich header is between DOS header and NT header
    BYTE* start = reinterpret_cast<BYTE*>(moduleBase) + sizeof(IMAGE_DOS_HEADER);
    BYTE* end = reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew;
    
    // Search for "Rich" signature
    for (BYTE* p = start; p < end - 4; p++) {
        if (*(DWORD*)p == 0x68636952) { // "Rich" in little-endian
            DWORD oldProtect;
            size_t richSize = end - start;
            
            if (VirtualProtect(start, richSize, PAGE_READWRITE, &oldProtect)) {
                Internal::SecureZeroMemory(start, richSize);
                VirtualProtect(start, richSize, oldProtect, &oldProtect);
                return true;
            }
        }
    }
    return false;
}

// Corrupt COFF header
bool AntiReconstruction::CorruptCOFFHeader() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER), 
                      PAGE_READWRITE, &oldProtect)) {
        // Corrupt non-critical fields
        ntHeaders->FileHeader.TimeDateStamp = 0xDEADBEEF;
        ntHeaders->FileHeader.PointerToSymbolTable = 0xFFFFFFFF;
        ntHeaders->FileHeader.NumberOfSymbols = 0xFFFFFFFF;
        
        VirtualProtect(&ntHeaders->FileHeader, sizeof(IMAGE_FILE_HEADER), 
                      oldProtect, &oldProtect);
        return true;
    }
    return false;
}

// Mangle entry point information
bool AntiReconstruction::MangleEntryPoint() {
    void* moduleBase = GetModuleHandle(nullptr);
    
    PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
    );
    
    DWORD oldProtect;
    if (VirtualProtect(&ntHeaders->OptionalHeader.AddressOfEntryPoint, sizeof(DWORD), 
                      PAGE_READWRITE, &oldProtect)) {
        // Store original, XOR with key
        ntHeaders->OptionalHeader.AddressOfEntryPoint ^= 0xCAFEBABE;
        VirtualProtect(&ntHeaders->OptionalHeader.AddressOfEntryPoint, sizeof(DWORD), 
                      oldProtect, &oldProtect);
        return true;
    }
    return false;
}

} // namespace AntiDump
} // namespace Windows
} // namespace Omamori
