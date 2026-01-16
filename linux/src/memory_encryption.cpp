#include "../../common/include/memory_encryption.hpp"
#include <cstring>
#include <cstdlib>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <random>

namespace Omamori {
namespace MemoryEncryption {

// ============================================================================
// StreamCipher Implementation
// ============================================================================

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
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint8_t> dis(0, 255);
    
    for (size_t i = 0; i < keySize; ++i) {
        key[i] = dis(gen);
    }
}

void StreamCipher::Encrypt(uint8_t* data, size_t size) {
    XorKeystream(data, size);
    counter_ += size;
}

void StreamCipher::Decrypt(uint8_t* data, size_t size) {
    // XOR è simmetrico: decrypt = encrypt
    XorKeystream(data, size);
    counter_ += size;
}

void StreamCipher::Reset() {
    counter_ = 0;
    nonce_++;
}

void StreamCipher::XorKeystream(uint8_t* data, size_t size) {
    // Simple XOR stream cipher (ChaCha20-like)
    // Per production: usa ChaCha20 reale
    
    uint8_t keystream[64];
    size_t offset = 0;
    
    while (offset < size) {
        GenerateKeystream(keystream, sizeof(keystream));
        
        size_t chunkSize = (size - offset < sizeof(keystream)) 
                          ? (size - offset) 
                          : sizeof(keystream);
        
        for (size_t i = 0; i < chunkSize; ++i) {
            data[offset + i] ^= keystream[i];
        }
        
        offset += chunkSize;
    }
}

void StreamCipher::GenerateKeystream(uint8_t* stream, size_t size) {
    // Semplificato: combina key + nonce + counter
    // Per production: implementa ChaCha20 completo
    
    for (size_t i = 0; i < size; ++i) {
        uint64_t mix = counter_ + nonce_ + i;
        
        // Mix con key
        for (size_t k = 0; k < sizeof(key_); ++k) {
            mix ^= static_cast<uint64_t>(key_[k]) << ((k % 8) * 8);
            mix = (mix << 13) | (mix >> 51); // Rotate
        }
        
        stream[i] = static_cast<uint8_t>(mix & 0xFF);
    }
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
    
    initialized_ = true;
    return true;
}

void EncryptionManager::Shutdown() {
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
    std::lock_guard<std::mutex> lock(mutex_);
    
    EncryptedPage* page = FindPage(address);
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
    std::lock_guard<std::mutex> lock(mutex_);
    
    EncryptedPage* page = FindPage(address);
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
    
    // Inizializza cipher con master key
    page->cipher = StreamCipher(masterKey_, sizeof(masterKey_));
    
    pages_[address] = std::move(page);
    stats_.totalPages++;
    
    return true;
}

bool EncryptionManager::UnregisterPage(void* address) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pages_.find(address);
    if (it == pages_.end()) {
        return false;
    }
    
    pages_.erase(it);
    stats_.totalPages--;
    return true;
}

EncryptedPage* EncryptionManager::FindPage(void* address) {
    // Lock già acquisito dal chiamante
    
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
    
    stats_.decryptOperations++;
    stats_.encryptedPages--;
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
    
    // Trova pagina corrispondente
    EncryptedPage* page = manager.FindPage(faultAddr);
    
    if (page && page->encrypted) {
        // DECRYPTION ON-DEMAND
        
        // Unprotect temporaneamente
        mprotect(page->address, page->size, PROT_READ | PROT_WRITE);
        
        // Decrypt
        manager.DecryptPage(page);
        
        page->accessCount++;
        manager.stats_.pageFaults++;
        
        // Se auto-reencrypt abilitato, schedule re-encryption
        if (manager.autoReEncrypt_) {
            // TODO: Schedule timer per re-encrypt dopo timeout
            // Per ora lascia decifrato fino al prossimo access
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
    return stats_;
}

} // namespace MemoryEncryption
} // namespace Omamori
