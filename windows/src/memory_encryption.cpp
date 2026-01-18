#include "../../common/include/memory_encryption.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <intrin.h>
#include <cstring>
#include <random>
#include <chrono>

namespace Omamori {
namespace MemoryEncryption {

// ============================================================================
// ChaCha20-like StreamCipher Implementation (Improved from simple XOR)
// ============================================================================

// Quarter round for ChaCha20
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static inline void QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = ROTL32(d, 16);
    c += d; b ^= c; b = ROTL32(b, 12);
    a += b; d ^= a; d = ROTL32(d, 8);
    c += d; b ^= c; b = ROTL32(b, 7);
}

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
    // Use CryptGenRandom if available, otherwise fallback
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, (DWORD)keySize, key);
        CryptReleaseContext(hProv, 0);
    } else {
        // Fallback to RDTSC-seeded PRNG
        uint64_t seed = __rdtsc() ^ GetTickCount64();
        for (size_t i = 0; i < keySize; i++) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            key[i] = static_cast<uint8_t>(seed >> 56);
        }
    }
}

void StreamCipher::XorKeystream(uint8_t* data, size_t size) {
    // ChaCha20-like keystream generation
    uint8_t keystream[64];
    size_t keystreamPos = 64;  // Force generation on first use
    
    for (size_t i = 0; i < size; i++) {
        if (keystreamPos >= 64) {
            GenerateKeystream(keystream, 64);
            keystreamPos = 0;
            counter_++;
        }
        data[i] ^= keystream[keystreamPos++];
    }
}

void StreamCipher::GenerateKeystream(uint8_t* stream, size_t size) {
    // ChaCha20-like state initialization
    uint32_t state[16];
    
    // "expand 32-byte k" constant
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (8 words)
    memcpy(&state[4], key_, 32);
    
    // Counter and nonce
    state[12] = static_cast<uint32_t>(counter_);
    state[13] = static_cast<uint32_t>(counter_ >> 32);
    state[14] = static_cast<uint32_t>(nonce_);
    state[15] = static_cast<uint32_t>(nonce_ >> 32);
    
    // Working state
    uint32_t working[16];
    memcpy(working, state, sizeof(state));
    
    // 20 rounds (10 double rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QuarterRound(working[0], working[4], working[8],  working[12]);
        QuarterRound(working[1], working[5], working[9],  working[13]);
        QuarterRound(working[2], working[6], working[10], working[14]);
        QuarterRound(working[3], working[7], working[11], working[15]);
        // Diagonal rounds
        QuarterRound(working[0], working[5], working[10], working[15]);
        QuarterRound(working[1], working[6], working[11], working[12]);
        QuarterRound(working[2], working[7], working[8],  working[13]);
        QuarterRound(working[3], working[4], working[9],  working[14]);
    }
    
    // Add original state
    for (int i = 0; i < 16; i++) {
        working[i] += state[i];
    }
    
    // Output
    size_t outSize = size < 64 ? size : 64;
    memcpy(stream, working, outSize);
}

// ============================================================================
// Windows-specific Implementation
// ============================================================================

EncryptionManager& EncryptionManager::GetInstance() {
    static EncryptionManager instance;
    return instance;
}

EncryptionManager::EncryptionManager()
    : initialized_(false)
    , autoReEncrypt_(true)
    , decryptTimeoutMs_(100)
    , reencryptRunning_(false)
    , reencryptThreadHandle_(nullptr)
    , signalPagesHead_(nullptr)
    , signalPageFaults_(0)
    , signalDecryptOperations_(0)
{
    std::memset(&stats_, 0, sizeof(stats_));
    StreamCipher::GenerateKey(masterKey_, sizeof(masterKey_));
    srand(GetTickCount());
}

EncryptionManager::~EncryptionManager() {
    Shutdown();
}

bool EncryptionManager::Initialize() {
    bool shouldStartThread = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            return true;
        }

        InstallHandlers();
        shouldStartThread = autoReEncrypt_;
        initialized_ = true;
    }
    // Start thread outside lock to avoid MinGW threading issues
    if (shouldStartThread) {
        StartReencryptThread();
    }
    return true;
}

void EncryptionManager::Shutdown() {
    StopReencryptThread();

    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    RemoveHandlers();
    for(auto& pair : pages_) {
        // Decrypt before freeing if needed?
        // VirtualFree handles it, but maybe we should decrypt?
        if(pair.second->encrypted) {
             // We can't decrypt if memory is protected or freed, just clear entry
        }
    }
    pages_.clear();
    retiredPages_.clear();
    signalPagesHead_.store(nullptr, std::memory_order_release);
    initialized_ = false;
}

bool EncryptionManager::RegisterPage(void* address, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto page = std::make_unique<EncryptedPage>();
    page->address = address;
    page->size = size;
    page->encrypted = false;
    page->accessCount = 0;
    page->lastDecryptedNs = 0;
    page->next = nullptr;
    page->active = true;

    uint8_t key[32];
    StreamCipher::GenerateKey(key, 32);
    page->cipher = StreamCipher(key, 32);

    pages_[address] = std::move(page);
    stats_.totalPages++;

    // Publish to signal-safe list (no-op for Windows handler, but keeps structure consistent)
    EncryptedPage* published = pages_[address].get();
    EncryptedPage* head = signalPagesHead_.load(std::memory_order_relaxed);
    do {
        published->next = head;
    } while (!signalPagesHead_.compare_exchange_weak(
        head, published, std::memory_order_release, std::memory_order_relaxed));
    return true;
}

EncryptedPage* EncryptionManager::FindPage(void* address) {
    std::lock_guard<std::mutex> lock(mutex_);
    return FindPageUnsafe(address);
}

EncryptedPage* EncryptionManager::FindPageUnsafe(void* address) {
    // Lock-free version for VEH/signal handler context
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

EncryptedPage* EncryptionManager::FindPageSignalSafe(void* address) {
    return FindPageUnsafe(address);
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
    page->lastDecryptedNs = GetTimeNs();
    if(stats_.encryptedPages > 0) stats_.encryptedPages--;
    stats_.decryptOperations++;
}

bool EncryptionManager::EncryptRegion(void* address, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    EncryptedPage* page = FindPageUnsafe(address);
    if(page) {
        EncryptPage(page);
        return true;
    }
    return false;
}

bool EncryptionManager::DecryptRegion(void* address, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    EncryptedPage* page = FindPageUnsafe(address);
    if(page) {
        DecryptPage(page);
        return true;
    }
    return false;
}

EncryptionManager::Stats EncryptionManager::GetStats() const {
    Stats snapshot = stats_;
    snapshot.pageFaults += signalPageFaults_.load(std::memory_order_relaxed);
    snapshot.decryptOperations += signalDecryptOperations_.load(std::memory_order_relaxed);
    return snapshot;
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

    page->active = false;
    retiredPages_.push_back(std::move(it->second));
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

    // Use lock-free version to avoid deadlock in exception handler
    EncryptedPage* page = manager.FindPageUnsafe(faultAddr);

    if (page && page->encrypted) {
        // DECRYPTION ON-DEMAND

        DWORD oldProtect;
        VirtualProtect(page->address, page->size, PAGE_READWRITE, &oldProtect);

        // Decrypt in-place (lock-free operation)
        page->cipher.Decrypt(static_cast<uint8_t*>(page->address), page->size);
        page->encrypted = false;
        page->lastDecryptedNs = GetTimeNs();
        if(manager.stats_.encryptedPages > 0) manager.stats_.encryptedPages--;
        manager.stats_.decryptOperations++;

        page->accessCount++;
        manager.stats_.pageFaults++;

        // Handler gestito
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Non è nostra pagina
    return EXCEPTION_CONTINUE_SEARCH;
}

uint64_t EncryptionManager::GetTimeNs() {
    LARGE_INTEGER freq;
    LARGE_INTEGER counter;
    if (!QueryPerformanceFrequency(&freq)) {
        return 0;
    }
    if (!QueryPerformanceCounter(&counter)) {
        return 0;
    }
    return static_cast<uint64_t>((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
}

void EncryptionManager::StartReencryptThread() {
    if (reencryptRunning_) {
        return;
    }

    reencryptRunning_ = true;
    
    // Use native Windows thread API for compatibility with MinGW win32 thread model
    reencryptThreadHandle_ = CreateThread(
        nullptr,
        0,
        ReencryptThreadProc,
        this,
        0,
        nullptr
    );
}

void EncryptionManager::StopReencryptThread() {
    if (!reencryptRunning_) {
        return;
    }

    reencryptRunning_ = false;
    if (reencryptThreadHandle_ != nullptr) {
        WaitForSingleObject(reencryptThreadHandle_, INFINITE);
        CloseHandle(reencryptThreadHandle_);
        reencryptThreadHandle_ = nullptr;
    }
}

DWORD WINAPI EncryptionManager::ReencryptThreadProc(LPVOID param) {
    EncryptionManager* manager = static_cast<EncryptionManager*>(param);
    manager->ReencryptLoop();
    return 0;
}

void EncryptionManager::ReencryptLoop() {
    while (reencryptRunning_) {
        Sleep(decryptTimeoutMs_);

        if (!autoReEncrypt_) {
            continue;
        }

        const uint64_t now = GetTimeNs();
        if (now == 0) {
            continue;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : pages_) {
            EncryptedPage* page = pair.second.get();
            if (!page || page->encrypted || page->lastDecryptedNs == 0) {
                continue;
            }

            uint64_t elapsedNs = now - page->lastDecryptedNs;
            if (elapsedNs < static_cast<uint64_t>(decryptTimeoutMs_) * 1000000ULL) {
                continue;
            }

            EncryptPage(page);
            DWORD oldProtect;
            VirtualProtect(page->address, page->size, PAGE_NOACCESS, &oldProtect);
        }
    }
}

} // namespace MemoryEncryption
} // namespace Omamori
