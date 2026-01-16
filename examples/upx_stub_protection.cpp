/**
 * UPX Stub Protection - Minimal Integration Example
 * 
 * Questo esempio mostra come proteggere SOLO lo stub/loader di UPX
 * senza aggiungere overhead al payload decompresso.
 * 
 * Usa solo tecniche lightweight per mantenere lo stub piccolo.
 */

#ifdef __linux__
#include "../linux/include/antidebug.hpp"
#include "../linux/include/antidump.hpp"
#else
#include "../windows/include/antidebug.hpp"
#include "../windows/include/antidump.hpp"
#endif

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

namespace UPXStubProtection {

/**
 * Protezione minimale dello stub (chiamata PRIMA della decompressione)
 * Overhead: ~2-3ms, Size: ~2KB
 */
inline void ProtectStubEarly() {
    #ifdef __linux__
    using namespace Omamori::Linux;
    
    // 1. Blocca ptrace immediato (1 syscall)
    AntiDebug::Detector::BlockPtraceAdvanced();
    
    // 2. Check rapido debugger (2 syscalls: stat + open)
    // Note: In test mode non exit, in production usa std::exit(1)
    #ifndef BUILD_TEST
    if (AntiDebug::Detector::IsDebuggerPresent()) {
        std::exit(1);  // Exit silenzioso
    }
    #endif
    
    #elif _WIN32
    using namespace Omamori::Windows;
    
    // 1. Check PEB rapido (solo memory read, no syscall)
    if (AntiDebug::Detector::CheckPEB()) {
        ExitProcess(1);
    }
    
    // 2. Check RemoteDebugger (1 syscall)
    if (AntiDebug::Detector::CheckRemoteDebuggerPresent()) {
        ExitProcess(1);
    }
    #endif
}

/**
 * Protezione stub dopo decompressione (PRIMA di saltare al payload)
 * Corrompe lo stub per prevenire dump
 */
inline void ProtectStubLate() {
    #ifdef __linux__
    using namespace Omamori::Linux::AntiDump;
    
    // 1. Disabilita core dumps (2 syscalls: setrlimit + prctl)
    CoreDumpProtection::DisableCoreDumps();
    
    // 2. Obfuscate ELF header dello stub (solo in production)
    #ifndef BUILD_TEST
    ELFProtector protector;
    protector.ObfuscateELF();
    #endif
    
    // Note: NON usare DumpProtection (background thread) nello stub
    // perché aggiungerebbe overhead al payload
    
    #elif _WIN32
    using namespace Omamori::Windows::AntiDump;
    
    // 1. Corrompi PE header dello stub
    PEProtector protector;
    protector.CorruptPEHeader();
    
    // 2. Wipe debug directory
    protector.WipeDebugDirectory();
    
    // Note: NON usare VEH handlers o continuous protection nello stub
    #endif
}

/**
 * Protezione completa stub (early + late)
 * Chiamata dall'entry point dello stub prima di decomprimere
 */
inline void ProtectStubComplete() {
    ProtectStubEarly();
    
    // [QUI va il codice di decompressione UPX]
    
    ProtectStubLate();
    
    // [QUI salta al payload decompresso]
}

} // namespace UPXStubProtection

// ============================================================================
// ESEMPIO: Integrazione nello stub UPX
// ============================================================================

#ifdef EXAMPLE_UPX_STUB_INTEGRATION

extern "C" {
    // Funzioni dello stub UPX (da implementare)
    void upx_decompress_payload(void* dst, void* src, size_t size);
    void* upx_get_original_entry_point();
}

/**
 * Entry point dello stub UPX protetto
 */
extern "C" void __attribute__((section(".text.upx_entry")))
upx_stub_entry_protected() {
    
    // ========================================
    // FASE 1: Protezione Early
    // ========================================
    UPXStubProtection::ProtectStubEarly();
    
    // ========================================
    // FASE 2: Decompressione
    // ========================================
    
    // Ottieni parametri decompressione (dipende da implementazione UPX)
    void* compressed_data = nullptr;   // TODO: punta ai dati compressi
    void* decompressed_dst = nullptr;  // TODO: punta alla memoria destinazione
    size_t compressed_size = 0;        // TODO: dimensione dati compressi
    
    // Decomprimi payload
    upx_decompress_payload(decompressed_dst, compressed_data, compressed_size);
    
    // ========================================
    // FASE 3: Protezione Late
    // ========================================
    UPXStubProtection::ProtectStubLate();
    
    // ========================================
    // FASE 4: Jump al payload
    // ========================================
    
    void* original_entry = upx_get_original_entry_point();
    
    // Jump al codice decompresso (assembly inline)
    #ifdef __linux__
    #ifdef __x86_64__
    __asm__ volatile(
        "jmp *%0"
        : 
        : "r"(original_entry)
    );
    #else // i386
    __asm__ volatile(
        "jmp *%0"
        :
        : "r"(original_entry)
    );
    #endif
    #elif _WIN32
    #ifdef _WIN64
    ((void(*)())original_entry)();
    #else
    __asm {
        jmp dword ptr [original_entry]
    }
    #endif
    #endif
    
    // Unreachable
    __builtin_unreachable();
}

/**
 * Variante inline assembly per stub assembly puro
 */
#ifdef __linux__
__asm__(
    ".section .text.upx_entry\n"
    ".globl _upx_stub_protected\n"
    ".type _upx_stub_protected, @function\n"
    "_upx_stub_protected:\n"
    
    // Salva registri
    "    push %rbp\n"
    "    mov %rsp, %rbp\n"
    "    push %rbx\n"
    "    push %r12\n"
    "    push %r13\n"
    "    push %r14\n"
    "    push %r15\n"
    
    // Anti-ptrace inline (velocissimo)
    "    mov $101, %rax\n"           // SYS_ptrace
    "    xor %rdi, %rdi\n"           // PTRACE_TRACEME
    "    xor %rsi, %rsi\n"
    "    xor %rdx, %rdx\n"
    "    xor %r10, %r10\n"
    "    syscall\n"
    "    cmp $-1, %rax\n"
    "    je .exit_protected\n"       // Se fallisce = debugger presente
    
    // Chiama protezione C++
    "    call UPXStubProtection::ProtectStubEarly\n"
    
    // [QUI inserire codice decompressione UPX]
    // call upx_decompress
    
    // Protezione late
    "    call UPXStubProtection::ProtectStubLate\n"
    
    // [QUI jump al payload - dipende da implementazione UPX]
    
    // Ripristina registri e return
    "    pop %r15\n"
    "    pop %r14\n"
    "    pop %r13\n"
    "    pop %r12\n"
    "    pop %rbx\n"
    "    pop %rbp\n"
    "    ret\n"
    
    ".exit_protected:\n"
    "    mov $60, %rax\n"            // SYS_exit
    "    mov $1, %rdi\n"             // exit code 1
    "    syscall\n"
);
#endif

#endif // EXAMPLE_UPX_STUB_INTEGRATION

// ============================================================================
// ESEMPIO: Stub protection per UPX modificato con stub C
// ============================================================================

#ifdef EXAMPLE_C_STUB

#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

/**
 * Versione C puro per stub UPX (se non puoi usare C++)
 */
void upx_stub_protect_c(void) {
    #ifdef __linux__
    // Anti-ptrace
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        _exit(1);
    }
    
    // Disabilita core dumps
    struct rlimit rlim = {0, 0};
    setrlimit(RLIMIT_CORE, &rlim);
    prctl(PR_SET_DUMPABLE, 0);
    
    // Check /proc/self/status per TracerPid
    char buf[256];
    int fd = open("/proc/self/status", 0); // O_RDONLY = 0
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
        
        // Cerca "TracerPid:\t0"
        if (strstr(buf, "TracerPid:\t") && 
            strstr(buf, "TracerPid:\t0") == NULL) {
            _exit(1);
        }
    }
    
    #elif _WIN32
    // Check PEB.BeingDebugged (assembly inline)
    #ifdef _WIN64
    unsigned char being_debugged = 0;
    __asm {
        mov rax, gs:[60h]        ; PEB address
        mov al, [rax + 2h]       ; BeingDebugged offset
        mov being_debugged, al
    }
    #else
    unsigned char being_debugged = 0;
    __asm {
        mov eax, fs:[30h]        ; PEB address
        mov al, [eax + 2h]       ; BeingDebugged offset
        mov being_debugged, al
    }
    #endif
    
    if (being_debugged) {
        ExitProcess(1);
    }
    #endif
}

#endif // EXAMPLE_C_STUB

// ============================================================================
// TESTING
// ============================================================================

#ifdef BUILD_TEST

int main() {
    printf("[*] Testing UPX stub protection...\n");
    
    printf("[+] Early protection...\n");
    UPXStubProtection::ProtectStubEarly();
    printf("[✓] Early protection OK\n");
    
    printf("[+] Simulating decompression...\n");
    // Simula decompressione
    volatile int dummy = 0;
    for (int i = 0; i < 1000000; i++) {
        dummy += i;
    }
    
    printf("[+] Late protection...\n");
    UPXStubProtection::ProtectStubLate();
    printf("[✓] Late protection OK\n");
    
    printf("[✓] Stub protection test completed\n");
    return 0;
}

#endif
