#include "../include/antidump.hpp"
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

namespace Omamori {
namespace Linux {
namespace AntiDump {

// MemoryProtection static members
void* MemoryProtection::moduleBase = nullptr;
size_t MemoryProtection::moduleSize = 0;

bool MemoryProtection::GetModuleInfo() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    bool first = true;
    
    while (fgets(line, sizeof(line), f)) {
        if (first && strstr(line, "r-xp")) {
            unsigned long start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            moduleBase = reinterpret_cast<void*>(start);
            moduleSize = end - start;
            first = false;
            break;
        }
    }
    
    fclose(f);
    return moduleBase != nullptr;
}

bool MemoryProtection::ProtectRegion(void* addr, size_t size, int prot) {
    return mprotect(addr, size, prot) == 0;
}

bool MemoryProtection::ProtectHeaders() {
    if (!GetModuleInfo()) return false;
    
    // Protect first page (ELF header) as PROT_NONE
    return ProtectRegion(moduleBase, 4096, PROT_NONE);
}

bool MemoryProtection::ProtectSections() {
    if (!GetModuleInfo()) return false;
    
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "rw-p") && !strstr(line, "[stack]") && !strstr(line, "[heap]")) {
            unsigned long start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            
            // Protect data sections
            mprotect(reinterpret_cast<void*>(start), end - start, PROT_READ);
        }
    }
    
    fclose(f);
    return true;
}

bool MemoryProtection::EnableFullProtection() {
    bool success = true;
    success &= EraseELFHeader();
    success &= ProtectHeaders();
    success &= InstallSegfaultHandler();
    return success;
}

bool MemoryProtection::EraseELFHeader() {
    if (!GetModuleInfo()) return false;
    
    // Overwrite ELF magic and header
    if (mprotect(moduleBase, 4096, PROT_READ | PROT_WRITE) == 0) {
        memset(moduleBase, 0, sizeof(Elf64_Ehdr));
        mprotect(moduleBase, 4096, PROT_READ);
        return true;
    }
    
    return false;
}

bool MemoryProtection::CorruptSectionHeaders() {
    if (!GetModuleInfo()) return false;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(moduleBase);
    
    if (ehdr->e_shoff == 0) return false;
    
    Elf64_Shdr* shdr = reinterpret_cast<Elf64_Shdr*>(
        static_cast<char*>(moduleBase) + ehdr->e_shoff
    );
    
    if (mprotect(shdr, ehdr->e_shnum * sizeof(Elf64_Shdr), 
                 PROT_READ | PROT_WRITE) == 0) {
        memset(shdr, 0, ehdr->e_shnum * sizeof(Elf64_Shdr));
        return true;
    }
    
    return false;
}

bool MemoryProtection::HideProgramHeaders() {
    if (!GetModuleInfo()) return false;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(moduleBase);
    
    if (mprotect(moduleBase, 4096, PROT_READ | PROT_WRITE) == 0) {
        ehdr->e_phoff = 0;
        ehdr->e_phnum = 0;
        mprotect(moduleBase, 4096, PROT_READ);
        return true;
    }
    
    return false;
}

bool MemoryProtection::RemapWithNoHeaders() {
    // Advanced: remap memory without headers
    return false;
}

bool MemoryProtection::InstallSegfaultHandler() {
    struct sigaction sa;
    sa.sa_handler = [](int) { _exit(1); };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    return sigaction(SIGSEGV, &sa, nullptr) == 0;
}

// ELFProtector implementation
ELFProtector::ELFProtector(void* moduleBase) 
    : base(moduleBase) {
    if (!base) {
        MemoryProtection::GetModuleInfo();
        base = MemoryProtection::moduleBase;
    }
}

void ELFProtector::CorruptELFHeader() {
    if (!base) return;
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
        ehdr->e_ident[EI_MAG0] = 0;
        ehdr->e_ident[EI_MAG1] = 0;
        ehdr->e_ident[EI_MAG2] = 0;
        ehdr->e_ident[EI_MAG3] = 0;
        mprotect(base, 4096, PROT_READ);
    }
}

void ELFProtector::WipeSectionTable() {
    if (!base) return;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        ehdr->e_shoff = 0;
        ehdr->e_shnum = 0;
        ehdr->e_shstrndx = 0;
        mprotect(base, 4096, PROT_READ);
    }
}

void ELFProtector::ManipulateDynamicSection() {
    // Corrupt .dynamic section
}

void ELFProtector::HideSymbols() {
    // Strip symbol information
}

void ELFProtector::ObfuscateELF() {
    CorruptELFHeader();
    WipeSectionTable();
}

void ELFProtector::HideModule() {
    // Advanced module hiding
}

void ELFProtector::ProtectMemory() {
    MemoryProtection::ProtectHeaders();
    MemoryProtection::ProtectSections();
}

void ELFProtector::EnableFullProtection() {
    ObfuscateELF();
    ProtectMemory();
}

// ProcProtection implementation
bool ProcProtection::HideFromProcMaps() {
    // This is very difficult on Linux without kernel module
    return false;
}

bool ProcProtection::CorruptProcMem() {
    return false;
}

bool ProcProtection::ProtectProcAccess() {
    return false;
}

bool ProcProtection::RemapMemoryRegion(void* addr, size_t size) {
    void* newAddr = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (newAddr == MAP_FAILED) return false;
    
    memcpy(newAddr, addr, size);
    munmap(addr, size);
    
    return true;
}

// DumpProtection implementation
bool DumpProtection::active = false;
pthread_t DumpProtection::threadHandle = 0;

void* DumpProtection::ProtectionThread(void* param) {
    while (active) {
        EraseHeaders();
        sleep(1);
    }
    return nullptr;
}

bool DumpProtection::Start() {
    if (active) return false;
    
    active = true;
    return pthread_create(&threadHandle, nullptr, ProtectionThread, nullptr) == 0;
}

void DumpProtection::Stop() {
    active = false;
    if (threadHandle) {
        pthread_join(threadHandle, nullptr);
        threadHandle = 0;
    }
}

void DumpProtection::EraseHeaders() {
    MemoryProtection::EraseELFHeader();
}

void DumpProtection::RandomizeMemory() {
    // Randomize non-critical memory regions
}

void DumpProtection::DetectMemoryAccess() {
    // Detect suspicious memory access patterns
}

// CoreDumpProtection implementation
bool CoreDumpProtection::DisableCoreDumps() {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    return setrlimit(RLIMIT_CORE, &rl) == 0;
}

bool CoreDumpProtection::SetResourceLimits() {
    return DisableCoreDumps();
}

bool CoreDumpProtection::InstallPrctlProtection() {
    // PR_SET_DUMPABLE: disable core dumps
    return prctl(PR_SET_DUMPABLE, 0) == 0;
}

} // namespace AntiDump
} // namespace Linux
} // namespace Omamori
