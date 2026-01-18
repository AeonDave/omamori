#include "../../common/include/memory_encryption.hpp"
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <random>
#include <chrono>

namespace Omamori {
namespace MemoryEncryption {

// ============================================================================
// ChaCha20 StreamCipher Implementation (Aligned with Windows)
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
    GenerateKey(key_, sizeof(key_));
}

StreamCipher::StreamCipher(const uint8_t* key, size_t keySize) 
    : nonce_(0), counter_(0) 
{
    size_t copySize = (keySize < sizeof(key_)) ? keySize : sizeof(key_);
    std::memcpy(key_, key, copySize);
    if (copySize < sizeof(key_)) {
        std::memset(key_ + copySize, 0, sizeof(key_) - copySize);
    }
}

void StreamCipher::GenerateKey(uint8_t* key, size_t keySize) {
    // Try /dev/urandom first (most secure)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t bytesRead = read(fd, key, keySize);
        close(fd);
        if (bytesRead == static_cast<ssize_t>(keySize)) {
            return;
        }
    }
    
    // Fallback to std::random_device + RDTSC-like entropy
    std::random_device rd;
    std::mt19937_64 gen(rd());
    
    // Mix with additional entropy sources
    uint64_t extraEntropy = 0;
    
    // Use clock_gettime for additional entropy
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        extraEntropy ^= static_cast<uint64_t>(ts.tv_nsec);
        extraEntropy ^= static_cast<uint64_t>(ts.tv_sec) << 32;
    }
    
    // Mix with process info
    extraEntropy ^= static_cast<uint64_t>(getpid()) << 16;
    extraEntropy ^= static_cast<uint64_t>(getppid()) << 24;
    
    gen.seed(gen() ^ extraEntropy);
    
    for (size_t i = 0; i < keySize; ++i) {
        key[i] = static_cast<uint8_t>(gen() & 0xFF);
    }
}

void StreamCipher::Encrypt(uint8_t* data, size_t size) {
    XorKeystream(data, size);
}

void StreamCipher::Decrypt(uint8_t* data, size_t size) {
    // XOR is symmetric: decrypt = encrypt
    XorKeystream(data, size);
}

void StreamCipher::Reset() {
    counter_ = 0;
    nonce_ = 0;
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
    // ChaCha20 state initialization
    uint32_t state[16];
    
    // "expand 32-byte k" constant
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (8 words = 32 bytes)
    std::memcpy(&state[4], key_, 32);
    
    // Counter and nonce
    state[12] = static_cast<uint32_t>(counter_);
    state[13] = static_cast<uint32_t>(counter_ >> 32);
    state[14] = static_cast<uint32_t>(nonce_);
    state[15] = static_cast<uint32_t>(nonce_ >> 32);
    
    // Working state
    uint32_t working[16];
    std::memcpy(working, state, sizeof(state));
    
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
    std::memcpy(stream, working, outSize);
}

// ============================================================================
// EncryptionManager Implementation
// ============================================================================

struct sigaction EncryptionManager::oldSigaction_;

EncryptionManager& EncryptionManager::GetInstance() {
    static EncryptionManager instance;
    return instance;
}

EncryptionManager::EncryptionManager() 
    : initialized_(false)
    , autoReEncrypt_(true)
    , decryptTimeoutMs_(100)
    , reencryptRunning_(false)
    , signalPagesHead_(nullptr)
    , signalPageFaults_(0)
    , signalDecryptOperations_(0)
{
    std::memset(&stats_, 0, sizeof(stats_));
    StreamCipher::GenerateKey(masterKey_, sizeof(masterKey_));
}

EncryptionManager::~EncryptionManager() {
    Shutdown();
}

bool EncryptionManager::Initialize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_) {
        return true;
    }
    
    // Install signal handler per page faults
    InstallHandlers();

    if (autoReEncrypt_) {
        StartReencryptThread();
    }
    
    initialized_ = true;
    return true;
}

void EncryptionManager::Shutdown() {
    StopReencryptThread();

    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return;
    }
    
    // Decrypt e free tutte le pagine
    for (auto& pair : pages_) {
        if (pair.second->encrypted) {
            DecryptPage(pair.second.get());
        }
    }
    
    pages_.clear();
    retiredPages_.clear();
    signalPagesHead_.store(nullptr, std::memory_order_release);
    
    RemoveHandlers();
    initialized_ = false;
}

void* EncryptionManager::AllocateEncrypted(size_t size) {
    // Alloca memoria aligned a page boundary
    size_t pageSize = sysconf(_SC_PAGESIZE);
    size_t allocSize = ((size + pageSize - 1) / pageSize) * pageSize;
    
    void* ptr = mmap(nullptr, allocSize, 
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (ptr == MAP_FAILED) {
        return nullptr;
    }
    
    // Registra e cifra
    if (!RegisterPage(ptr, allocSize)) {
        munmap(ptr, allocSize);
        return nullptr;
    }
    
    // Cifra e proteggi
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
    
    // Decrypt prima di free
    if (page->encrypted) {
        DecryptPage(page);
    }
    
    // Unprotect
    mprotect(page->address, page->size, PROT_READ | PROT_WRITE);
    
    // Free memoria
    munmap(page->address, page->size);
    
    // Rimuovi tracking
    pages_.erase(it);
    stats_.totalPages--;
}

bool EncryptionManager::EncryptRegion(void* address, size_t size) {
    (void)size;
    std::lock_guard<std::mutex> lock(mutex_);
    
    EncryptedPage* page = FindPageUnsafe(address);
    if (!page) {
        return false;
    }
    
    if (page->encrypted) {
        return true; // Already encrypted
    }
    
    EncryptPage(page);
    return true;
}

bool EncryptionManager::DecryptRegion(void* address, size_t size) {
    (void)size;
    std::lock_guard<std::mutex> lock(mutex_);
    
    EncryptedPage* page = FindPageUnsafe(address);
    if (!page) {
        return false;
    }
    
    if (!page->encrypted) {
        return true; // Already decrypted
    }
    
    DecryptPage(page);
    return true;
}

bool EncryptionManager::ProtectAndEncrypt(void* address, size_t size) {
    // Prima cifra
    if (!EncryptRegion(address, size)) {
        return false;
    }
    
    // Poi proteggi (PROT_NONE = nessun accesso)
    if (mprotect(address, size, PROT_NONE) != 0) {
        return false;
    }
    
    return true;
}

bool EncryptionManager::UnprotectAndDecrypt(void* address, size_t size) {
    // Prima unprotect
    if (mprotect(address, size, PROT_READ | PROT_WRITE) != 0) {
        return false;
    }
    
    // Poi decifra
    return DecryptRegion(address, size);
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
    
    // Generate unique per-page key (aligned with Windows implementation)
    uint8_t pageKey[32];
    StreamCipher::GenerateKey(pageKey, 32);
    page->cipher = StreamCipher(pageKey, 32);
    
    pages_[address] = std::move(page);
    stats_.totalPages++;

    // Publish to signal-safe list
    EncryptedPage* published = pages_[address].get();
    EncryptedPage* head = signalPagesHead_.load(std::memory_order_relaxed);
    do {
        published->next = head;
    } while (!signalPagesHead_.compare_exchange_weak(
        head, published, std::memory_order_release, std::memory_order_relaxed));
    
    return true;
}

bool EncryptionManager::UnregisterPage(void* address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pages_.find(address);
    if (it == pages_.end()) {
        return false;
    }
    
    it->second->active = false;
    retiredPages_.push_back(std::move(it->second));
    pages_.erase(it);
    stats_.totalPages--;
    return true;
}

EncryptedPage* EncryptionManager::FindPage(void* address) {
    // Thread-safe version with lock
    std::lock_guard<std::mutex> lock(mutex_);
    return FindPageUnsafe(address);
}

EncryptedPage* EncryptionManager::FindPageUnsafe(void* address) {
    // Lock-free version for signal handler context
    // IMPORTANT: Only safe when called from signal handler or with lock held
    
    auto it = pages_.find(address);
    if (it != pages_.end()) {
        return it->second.get();
    }
    
    // Cerca in range (l'address potrebbe essere dentro una pagina)
    for (auto& pair : pages_) {
        EncryptedPage* page = pair.second.get();
        uintptr_t pageStart = reinterpret_cast<uintptr_t>(page->address);
        uintptr_t pageEnd = pageStart + page->size;
        uintptr_t addr = reinterpret_cast<uintptr_t>(address);
        
        if (addr >= pageStart && addr < pageEnd) {
            return page;
        }
    }
    
    return nullptr;
}

EncryptedPage* EncryptionManager::FindPageSignalSafe(void* address) {
    uintptr_t addr = reinterpret_cast<uintptr_t>(address);
    EncryptedPage* current = signalPagesHead_.load(std::memory_order_acquire);
    while (current) {
        if (current->active) {
            uintptr_t start = reinterpret_cast<uintptr_t>(current->address);
            uintptr_t end = start + current->size;
            if (addr >= start && addr < end) {
                return current;
            }
        }
        current = current->next;
    }
    return nullptr;
}

void EncryptionManager::EncryptPage(EncryptedPage* page) {
    if (page->encrypted) {
        return;
    }
    
    uint8_t* data = static_cast<uint8_t*>(page->address);
    page->cipher.Encrypt(data, page->size);
    page->encrypted = true;
    
    stats_.encryptOperations++;
    stats_.encryptedPages++;
}

void EncryptionManager::DecryptPage(EncryptedPage* page) {
    if (!page->encrypted) {
        return;
    }
    
    uint8_t* data = static_cast<uint8_t*>(page->address);
    page->cipher.Decrypt(data, page->size);
    page->encrypted = false;
    page->lastDecryptedNs = GetTimeNs();
    
    stats_.decryptOperations++;
    if (stats_.encryptedPages > 0) stats_.encryptedPages--;
}

void EncryptionManager::InstallHandlers() {
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = SigSegvHandler;
    
    sigaction(SIGSEGV, &sa, &oldSigaction_);
}

void EncryptionManager::RemoveHandlers() {
    sigaction(SIGSEGV, &oldSigaction_, nullptr);
}

void EncryptionManager::SigSegvHandler(int sig, siginfo_t* info, void* context) {
    (void)sig;
    (void)context;
    
    // Ottieni indirizzo che ha causato page fault
    void* faultAddr = info->si_addr;
    
    EncryptionManager& manager = EncryptionManager::GetInstance();
    
    // Trova pagina corrispondente (signal-safe traversal)
    EncryptedPage* page = manager.FindPageSignalSafe(faultAddr);
    
    if (page && page->encrypted) {
        // DECRYPTION ON-DEMAND
        
        // Unprotect temporaneamente
        mprotect(page->address, page->size, PROT_READ | PROT_WRITE);
        
        // Decrypt in-place (lock-free operation)
        uint8_t* data = static_cast<uint8_t*>(page->address);
        page->cipher.Decrypt(data, page->size);
        page->encrypted = false;
        page->lastDecryptedNs = GetTimeNs();
        
        page->accessCount++;
        manager.signalPageFaults_.fetch_add(1, std::memory_order_relaxed);
        manager.signalDecryptOperations_.fetch_add(1, std::memory_order_relaxed);
        
        // Se auto-reencrypt abilitato, schedule re-encryption
        if (manager.autoReEncrypt_) {
            // TODO: Schedule timer per re-encrypt dopo timeout
            // Per ora lascia decifrato fino al prossimo ProtectAndEncrypt
        }
        
        // Handler gestito, ritorna
        return;
    }
    
    // Non è una nostra pagina cifrata, chiama handler originale
    if (oldSigaction_.sa_flags & SA_SIGINFO) {
        oldSigaction_.sa_sigaction(sig, info, context);
    } else if (oldSigaction_.sa_handler != SIG_DFL && 
               oldSigaction_.sa_handler != SIG_IGN) {
        oldSigaction_.sa_handler(sig);
    } else {
        // Default: termina
        _exit(128 + sig);
    }
}

EncryptionManager::Stats EncryptionManager::GetStats() const {
    Stats snapshot = stats_;
    snapshot.pageFaults += signalPageFaults_.load(std::memory_order_relaxed);
    snapshot.decryptOperations += signalDecryptOperations_.load(std::memory_order_relaxed);
    return snapshot;
}

uint64_t EncryptionManager::GetTimeNs() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
               static_cast<uint64_t>(ts.tv_nsec);
    }
    return 0;
}

void EncryptionManager::StartReencryptThread() {
    if (reencryptRunning_) {
        return;
    }

    reencryptRunning_ = true;
    reencryptThread_ = std::thread(&EncryptionManager::ReencryptLoop, this);
}

void EncryptionManager::StopReencryptThread() {
    if (!reencryptRunning_) {
        return;
    }

    reencryptRunning_ = false;
    if (reencryptThread_.joinable()) {
        reencryptThread_.join();
    }
}

void EncryptionManager::ReencryptLoop() {
    while (reencryptRunning_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(decryptTimeoutMs_));

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
            mprotect(page->address, page->size, PROT_NONE);
        }
    }
}

} // namespace MemoryEncryption
} // namespace Omamori
