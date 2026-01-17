#include "../../common/include/memory_encryption.hpp"
#include <windows.h>
#include <cstring>
#include <random> // For rand()

namespace Omamori {
namespace MemoryEncryption {

// ============================================================================
// StreamCipher Implementation
// ============================================================================

StreamCipher::StreamCipher() : nonce_(0), counter_(0) {
    memset(key_, 0, sizeof(key_));
}

StreamCipher::StreamCipher(const uint8_t* key, size_t keySize) : nonce_(0), counter_(0) {
    size_t copySize = keySize < sizeof(key_) ? keySize : sizeof(key_);
    memset(key_, 0, sizeof(key_));
    memcpy(key_, key, copySize);
}

void StreamCipher::Encrypt(uint8_t* data, size_t size) {
    XorKeystream(data, size);
}

void StreamCipher::Decrypt(uint8_t* data, size_t size) {
    XorKeystream(data, size);
}

void StreamCipher::Reset() {
    nonce_ = 0;
    counter_ = 0;
}

void StreamCipher::GenerateKey(uint8_t* key, size_t keySize) {
    for(size_t i=0; i<keySize; i++) {
        key[i] = static_cast<uint8_t>(rand() % 256);
    }
}

void StreamCipher::XorKeystream(uint8_t* data, size_t size) {
    for(size_t i=0; i<size; i++) {
        data[i] ^= key_[(i + counter_) % 32];
        counter_++;
    }
}

void StreamCipher::GenerateKeystream(uint8_t* stream, size_t size) {
    // Unused in simple implementation
    (void)stream;
    (void)size;
}

// ============================================================================
// Windows-specific Implementation
// ============================================================================

EncryptionManager& EncryptionManager::GetInstance() {
    static EncryptionManager instance;
    return instance;
}

EncryptionManager::EncryptionManager() {
    srand(GetTickCount());
}

EncryptionManager::~EncryptionManager() {
    Shutdown();
}

bool EncryptionManager::Initialize() {
    InstallHandlers();
    return true;
}

void EncryptionManager::Shutdown() {
    RemoveHandlers();
    std::lock_guard<std::mutex> lock(mutex_);
    for(auto& pair : pages_) {
        // Decrypt before freeing if needed?
        // VirtualFree handles it, but maybe we should decrypt?
        if(pair.second->encrypted) {
             // We can't decrypt if memory is protected or freed, just clear entry
        }
    }
    pages_.clear();
}

bool EncryptionManager::RegisterPage(void* address, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto page = std::make_unique<EncryptedPage>();
    page->address = address;
    page->size = size;
    page->encrypted = false;
    page->accessCount = 0;

    uint8_t key[32];
    StreamCipher::GenerateKey(key, 32);
    page->cipher = StreamCipher(key, 32);

    pages_[address] = std::move(page);
    stats_.totalPages++;
    return true;
}

EncryptedPage* EncryptionManager::FindPage(void* address) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Check exact match first
    auto it = pages_.find(address);
    if(it != pages_.end()) return it->second.get();

    // Check range
    uintptr_t target = reinterpret_cast<uintptr_t>(address);
    for(auto& pair : pages_) {
        uintptr_t base = reinterpret_cast<uintptr_t>(pair.first);
        if (target >= base && target < base + pair.second->size) {
            return pair.second.get();
        }
    }
    return nullptr;
}

void EncryptionManager::EncryptPage(EncryptedPage* page) {
    if(!page || page->encrypted) return;
    page->cipher.Encrypt(static_cast<uint8_t*>(page->address), page->size);
    page->encrypted = true;
    stats_.encryptedPages++;
    stats_.encryptOperations++;
}

void EncryptionManager::DecryptPage(EncryptedPage* page) {
    if(!page || !page->encrypted) return;
    page->cipher.Decrypt(static_cast<uint8_t*>(page->address), page->size);
    page->encrypted = false;
    if(stats_.encryptedPages > 0) stats_.encryptedPages--;
    stats_.decryptOperations++;
}

bool EncryptionManager::EncryptRegion(void* address, size_t size) {
    EncryptedPage* page = FindPage(address);
    if(page) {
        EncryptPage(page);
        return true;
    }
    return false;
}

bool EncryptionManager::DecryptRegion(void* address, size_t size) {
    EncryptedPage* page = FindPage(address);
    if(page) {
        DecryptPage(page);
        return true;
    }
    return false;
}

EncryptionManager::Stats EncryptionManager::GetStats() const {
    return stats_;
}

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
