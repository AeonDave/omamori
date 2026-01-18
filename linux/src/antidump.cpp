#include "../include/antidump.hpp"
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>

// MADV_DONTDUMP may not be available on older kernels
#ifndef MADV_DONTDUMP
#define MADV_DONTDUMP 16
#endif

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

// NEW: Mark memory as excluded from core dumps
bool MemoryProtection::SetMadvDontDump(void* addr, size_t size) {
    return madvise(addr, size, MADV_DONTDUMP) == 0;
}

// NEW: Exclude entire process memory from core dumps
bool MemoryProtection::ExcludeFromCoreDump() {
    if (!GetModuleInfo()) return false;
    
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    bool success = true;
    
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            // Exclude each mapping from core dump
            if (madvise(reinterpret_cast<void*>(start), end - start, MADV_DONTDUMP) != 0) {
                // Ignore errors for special mappings
            }
        }
    }
    
    fclose(f);
    return success;
}

// NEW: Protect all mapped regions
bool MemoryProtection::ProtectAllMappings() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;
    
    char line[512];
    
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            // Skip stack, heap, and vdso
            if (strstr(line, "[stack]") || strstr(line, "[heap]") || 
                strstr(line, "[vdso]") || strstr(line, "[vsyscall]")) {
                continue;
            }
            
            // Mark data regions as DONTDUMP
            if (perms[0] == 'r' && perms[1] == 'w') {
                madvise(reinterpret_cast<void*>(start), end - start, MADV_DONTDUMP);
            }
        }
    }
    
    fclose(f);
    return true;
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

// NEW: Corrupt GOT (Global Offset Table) entries for analysis tools
void ELFProtector::CorruptGOT() {
    // Note: This is dangerous and could break the program if not careful
    // We only corrupt entries we know are not needed at runtime
}

// NEW: Wipe dynamic string table
void ELFProtector::WipeDynamicStringTable() {
    if (!base) return;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        // Zero the dynamic string table index
        ehdr->e_shstrndx = 0;
        mprotect(base, 4096, PROT_READ);
    }
}

// NEW: Invalidate ELF notes section
void ELFProtector::InvalidateNotes() {
    if (!base) return;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(
        static_cast<char*>(base) + ehdr->e_phoff
    );
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_NOTE) {
            void* noteAddr = static_cast<char*>(base) + phdr[i].p_vaddr;
            
            // Try to zero out the note section
            if (mprotect(reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(noteAddr) & ~0xFFFUL), 
                4096, PROT_READ | PROT_WRITE) == 0) {
                memset(noteAddr, 0, phdr[i].p_filesz);
            }
        }
    }
}

// NEW: Scramble program header offsets
void ELFProtector::ScramblePhdrOffsets() {
    if (!base) return;
    
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        // Save original values needed for execution, corrupt the rest
        Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(
            static_cast<char*>(base) + ehdr->e_phoff
        );
        
        for (int i = 0; i < ehdr->e_phnum; i++) {
            // Only corrupt p_filesz for PT_NULL or unused types
            if (phdr[i].p_type == PT_NULL) {
                phdr[i].p_offset = 0xDEADBEEF;
                phdr[i].p_filesz = 0xCAFEBABE;
            }
        }
        
        mprotect(base, 4096, PROT_READ);
    }
}

// NEW: Wipe all metadata
void ELFProtector::WipeAllMetadata() {
    WipeSectionTable();
    WipeDynamicStringTable();
    InvalidateNotes();
    ScramblePhdrOffsets();
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
bool ProcProtection::SelfDeleteExecutable() {
    char exePath[256];
    ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    
    if (len == -1) return false;
    exePath[len] = '\0';
    
    // Try to unlink the executable
    // This may fail due to permissions but worth trying
    return unlink(exePath) == 0;
}

bool ProcProtection::MaskProcMaps() {
    // On Linux, we can't truly hide from /proc/self/maps without kernel module
    // But we can make analysis harder by fragmenting memory
    
    // Allocate decoy regions to confuse analysis
    for (int i = 0; i < 10; i++) {
        void* decoy = mmap(nullptr, 4096, PROT_NONE, 
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (decoy != MAP_FAILED) {
            // Mark as DONTDUMP
            madvise(decoy, 4096, MADV_DONTDUMP);
        }
    }
    
    return true;
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
    (void)param; // Silence unused parameter warning
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

// NEW: Corrupt ELF magic bytes
bool DumpProtection::CorruptELFMagic() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
        
        // Corrupt magic bytes
        ehdr->e_ident[EI_MAG0] = 0x00;
        ehdr->e_ident[EI_MAG1] = 0x00;
        ehdr->e_ident[EI_MAG2] = 0x00;
        ehdr->e_ident[EI_MAG3] = 0x00;
        
        mprotect(base, 4096, PROT_READ);
        return true;
    }
    return false;
}

// NEW: Invalidate program headers
bool DumpProtection::InvalidateProgramHeaders() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        // Zero out program header info
        ehdr->e_phnum = 0;
        ehdr->e_phoff = 0;
        ehdr->e_phentsize = 0;
        
        mprotect(base, 4096, PROT_READ);
        return true;
    }
    return false;
}

// NEW: Scramble section offsets
bool DumpProtection::ScrambleSectionOffsets() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        // Invalid section header info
        ehdr->e_shoff = 0xDEADBEEF;
        ehdr->e_shnum = 0xFFFF;
        ehdr->e_shentsize = 0;
        
        mprotect(base, 4096, PROT_READ);
        return true;
    }
    return false;
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

// NEW: Set dump filter via /proc/self/coredump_filter
bool CoreDumpProtection::SetDumpFilter() {
    // coredump_filter bits:
    // 0: anonymous private memory
    // 1: anonymous shared memory
    // 2: file-backed private memory
    // 3: file-backed shared memory
    // 4: ELF header pages
    // Setting to 0 excludes everything
    
    int fd = open("/proc/self/coredump_filter", O_WRONLY);
    if (fd == -1) return false;
    
    const char* filter = "0x0";
    ssize_t written = write(fd, filter, strlen(filter));
    close(fd);
    
    return written > 0;
}

// NEW: Install signal handlers for dump-related signals
bool CoreDumpProtection::InstallSignalHandlers() {
    struct sigaction sa;
    sa.sa_handler = [](int) { 
        // Prevent core dump by exiting cleanly
        _exit(0); 
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    bool success = true;
    
    // Handle signals that could generate core dumps
    success &= (sigaction(SIGABRT, &sa, nullptr) == 0);
    success &= (sigaction(SIGQUIT, &sa, nullptr) == 0);
    success &= (sigaction(SIGBUS, &sa, nullptr) == 0);
    success &= (sigaction(SIGFPE, &sa, nullptr) == 0);
    success &= (sigaction(SIGSYS, &sa, nullptr) == 0);
    
    return success;
}

// NEW: Prevent ptrace-based memory dumping
bool CoreDumpProtection::PreventPtraceDump() {
    // Try to ptrace ourselves - if successful, no other process can ptrace us
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
        // Already being traced or can't trace
        return false;
    }
    
    // Also set dumpable to 0
    prctl(PR_SET_DUMPABLE, 0);
    
    return true;
}

// NEW: AntiReconstruction implementation

// Corrupt ELF header for anti-reconstruction
bool AntiReconstruction::CorruptElfHeader() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    
    if (mprotect(base, 4096, PROT_READ | PROT_WRITE) == 0) {
        Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
        
        // Corrupt version and other fields
        ehdr->e_version = 0xDEADBEEF;
        ehdr->e_flags = 0xCAFEBABE;
        ehdr->e_ehsize = 0;
        
        mprotect(base, 4096, PROT_READ);
        return true;
    }
    return false;
}

// Invalidate program headers
bool AntiReconstruction::InvalidatePhdr() {
    return DumpProtection::InvalidateProgramHeaders();
}

// Scramble section headers
bool AntiReconstruction::ScrambleShdr() {
    return DumpProtection::ScrambleSectionOffsets();
}

// Wipe Build ID (GNU build-id for identification)
bool AntiReconstruction::WipeBuildId() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(
        static_cast<char*>(base) + ehdr->e_phoff
    );
    
    // Find PT_NOTE segment containing GNU build-id
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_NOTE) {
            void* noteAddr = static_cast<char*>(base) + phdr[i].p_vaddr;
            size_t noteSize = phdr[i].p_filesz;
            
            // Calculate page-aligned address
            uintptr_t pageAddr = reinterpret_cast<uintptr_t>(noteAddr) & ~0xFFFUL;
            size_t offset = reinterpret_cast<uintptr_t>(noteAddr) - pageAddr;
            
            if (mprotect(reinterpret_cast<void*>(pageAddr), 
                        offset + noteSize + 4096, PROT_READ | PROT_WRITE) == 0) {
                memset(noteAddr, 0, noteSize);
                mprotect(reinterpret_cast<void*>(pageAddr), 
                        offset + noteSize + 4096, PROT_READ);
                return true;
            }
        }
    }
    return false;
}

// Corrupt dynamic section
bool AntiReconstruction::CorruptDynamicSection() {
    if (!MemoryProtection::GetModuleInfo()) return false;
    
    void* base = MemoryProtection::moduleBase;
    Elf64_Ehdr* ehdr = static_cast<Elf64_Ehdr*>(base);
    Elf64_Phdr* phdr = reinterpret_cast<Elf64_Phdr*>(
        static_cast<char*>(base) + ehdr->e_phoff
    );
    
    // Find PT_DYNAMIC segment
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf64_Dyn* dyn = reinterpret_cast<Elf64_Dyn*>(
                static_cast<char*>(base) + phdr[i].p_vaddr
            );
            
            uintptr_t pageAddr = reinterpret_cast<uintptr_t>(dyn) & ~0xFFFUL;
            
            if (mprotect(reinterpret_cast<void*>(pageAddr), 
                        phdr[i].p_filesz + 4096, PROT_READ | PROT_WRITE) == 0) {
                // Corrupt DT_NEEDED entries (library names)
                while (dyn->d_tag != DT_NULL) {
                    if (dyn->d_tag == DT_STRTAB || dyn->d_tag == DT_SYMTAB) {
                        // Zero these table pointers
                        dyn->d_un.d_ptr = 0;
                    }
                    dyn++;
                }
                mprotect(reinterpret_cast<void*>(pageAddr), 
                        phdr[i].p_filesz + 4096, PROT_READ);
                return true;
            }
        }
    }
    return false;
}

} // namespace AntiDump
} // namespace Linux
} // namespace Omamori