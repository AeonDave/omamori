#include "../../common/include/memory_encryption.hpp"
#include <windows.h>
#include <cstring>

namespace Omamori {
namespace MemoryEncryption {

// ============================================================================
// Windows-specific Implementation
// ============================================================================

PVOID EncryptionManager::vehHandle_ = nullptr;

void* EncryptionManager::AllocateEncrypted(size_t size) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    size_t pageSize = sysInfo.dwPageSize;
    
    size_t allocSize = ((size + pageSize - 1) / pageSize) * pageSize;
    
    void* ptr = VirtualAlloc(nullptr, allocSize,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);
    
    if (!ptr) {
        return nullptr;
    }
    
    if (!RegisterPage(ptr, allocSize)) {
        VirtualFree(ptr, 0, MEM_RELEASE);
        return nullptr;
    }
    
    ProtectAndEncrypt(ptr, allocSize);
    
    return ptr;
}

void EncryptionManager::FreeEncrypted(void* ptr) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pages_.find(ptr);
    if (it == pages_.end()) {
        return;
    }
    
    EncryptedPage* page = it->second.get();
    
    if (page->encrypted) {
        DecryptPage(page);
    }
    
    DWORD oldProtect;
    VirtualProtect(page->address, page->size, PAGE_READWRITE, &oldProtect);
    
    VirtualFree(page->address, 0, MEM_RELEASE);
    
    pages_.erase(it);
    stats_.totalPages--;
}

bool EncryptionManager::ProtectAndEncrypt(void* address, size_t size) {
    if (!EncryptRegion(address, size)) {
        return false;
    }
    
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_NOACCESS, &oldProtect)) {
        return false;
    }
    
    return true;
}

bool EncryptionManager::UnprotectAndDecrypt(void* address, size_t size) {
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_READWRITE, &oldProtect)) {
        return false;
    }
    
    return DecryptRegion(address, size);
}

void EncryptionManager::InstallHandlers() {
    vehHandle_ = AddVectoredExceptionHandler(1, VehHandler);
}

void EncryptionManager::RemoveHandlers() {
    if (vehHandle_) {
        RemoveVectoredExceptionHandler(vehHandle_);
        vehHandle_ = nullptr;
    }
}

LONG WINAPI EncryptionManager::VehHandler(EXCEPTION_POINTERS* exceptionInfo) {
    // Check se è access violation
    if (exceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Ottieni indirizzo che ha causato fault
    void* faultAddr = reinterpret_cast<void*>(
        exceptionInfo->ExceptionRecord->ExceptionInformation[1]
    );
    
    EncryptionManager& manager = EncryptionManager::GetInstance();
    
    EncryptedPage* page = manager.FindPage(faultAddr);
    
    if (page && page->encrypted) {
        // DECRYPTION ON-DEMAND
        
        DWORD oldProtect;
        VirtualProtect(page->address, page->size, PAGE_READWRITE, &oldProtect);
        
        manager.DecryptPage(page);
        
        page->accessCount++;
        manager.stats_.pageFaults++;
        
        // Handler gestito
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    // Non è nostra pagina
    return EXCEPTION_CONTINUE_SEARCH;
}

} // namespace MemoryEncryption
} // namespace Omamori
