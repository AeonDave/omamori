#pragma once

#include <cstdint>
#include <cstddef>
#include <memory>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

#ifdef __linux__
#include <signal.h>
#elif _WIN32
#include <windows.h>
#endif

namespace Omamori {
namespace MemoryEncryption {

/**
 * Stream Cipher per memory encryption
 * Usa ChaCha20-like algorithm (lightweight)
 */
class StreamCipher {
public:
    StreamCipher();
    explicit StreamCipher(const uint8_t* key, size_t keySize);
    
    // Cifra/decifra buffer in-place
    void Encrypt(uint8_t* data, size_t size);
    void Decrypt(uint8_t* data, size_t size);
    
    // Reset cipher state
    void Reset();
    
    // Generate new random key
    static void GenerateKey(uint8_t* key, size_t keySize);
    
private:
    uint8_t key_[32];
    uint64_t nonce_;
    uint64_t counter_;
    
    void XorKeystream(uint8_t* data, size_t size);
    void GenerateKeystream(uint8_t* stream, size_t size);
};

/**
 * Page-level encrypted memory region
 */
struct EncryptedPage {
    void* address;           // Page base address
    size_t size;             // Page size (usually 4KB)
    bool encrypted;          // Current state
    uint64_t accessCount;    // Statistics
    uint64_t lastDecryptedNs; // Timestamp of last decrypt (for auto re-encrypt)
    StreamCipher cipher;     // Per-page cipher
    EncryptedPage* next;      // Lock-free list for signal-safe lookup (Linux)
    bool active;              // True if page is valid (Linux signal handler)
};

/**
 * Memory Encryption Manager
 * Gestisce memoria cifrata trasparente per l'applicazione
 */
class EncryptionManager {
public:
    static EncryptionManager& GetInstance();
    
    // Inizializza memory encryption layer
    bool Initialize();
    void Shutdown();
    
    // Alloca memoria cifrata
    void* AllocateEncrypted(size_t size);
    void FreeEncrypted(void* ptr);
    
    // Cifra memoria esistente
    bool EncryptRegion(void* address, size_t size);
    bool DecryptRegion(void* address, size_t size);
    
    // Protezione automatica (cifra + PROT_NONE)
    bool ProtectAndEncrypt(void* address, size_t size);
    bool UnprotectAndDecrypt(void* address, size_t size);
    
    // Statistics
    struct Stats {
        uint64_t totalPages;
        uint64_t encryptedPages;
        uint64_t pageFaults;
        uint64_t decryptOperations;
        uint64_t encryptOperations;
    };
    Stats GetStats() const;
    
    // Configuration
    void SetAutoReEncrypt(bool enable) { autoReEncrypt_ = enable; }
    void SetDecryptTimeout(uint32_t ms) { decryptTimeoutMs_ = ms; }
    
private:
    EncryptionManager();
    ~EncryptionManager();
    
    // Disable copy
    EncryptionManager(const EncryptionManager&) = delete;
    EncryptionManager& operator=(const EncryptionManager&) = delete;
    
    // Internal management
    bool RegisterPage(void* address, size_t size);
    bool UnregisterPage(void* address);
    EncryptedPage* FindPage(void* address);
    EncryptedPage* FindPageUnsafe(void* address);  // Lock-free version for signal handlers
    EncryptedPage* FindPageSignalSafe(void* address); // Linux-only signal-safe list traversal
    
    // Encryption operations
    void EncryptPage(EncryptedPage* page);
    void DecryptPage(EncryptedPage* page);

    // Auto re-encryption thread
    void StartReencryptThread();
    void StopReencryptThread();
    void ReencryptLoop();
    static uint64_t GetTimeNs();
    
    // Platform-specific signal/exception handlers
    static void InstallHandlers();
    static void RemoveHandlers();
    
#ifdef __linux__
    static void SigSegvHandler(int sig, siginfo_t* info, void* context);
    static struct sigaction oldSigaction_;
#elif _WIN32
    static LONG WINAPI VehHandler(EXCEPTION_POINTERS* exceptionInfo);
    static PVOID vehHandle_;
    static DWORD WINAPI ReencryptThreadProc(LPVOID param);
    HANDLE reencryptThreadHandle_;
#endif
    
    // Data members
    std::unordered_map<void*, std::unique_ptr<EncryptedPage>> pages_;
    std::vector<std::unique_ptr<EncryptedPage>> retiredPages_; // Keep pages alive for signal safety
    std::mutex mutex_;
    Stats stats_;
    
    bool initialized_;
    bool autoReEncrypt_;
    uint32_t decryptTimeoutMs_;

#ifdef __linux__
    std::thread reencryptThread_;
#endif
    std::atomic<bool> reencryptRunning_;
    std::atomic<EncryptedPage*> signalPagesHead_;
    std::atomic<uint64_t> signalPageFaults_;
    std::atomic<uint64_t> signalDecryptOperations_;
    
    // Master key per session
    uint8_t masterKey_[32];
};

/**
 * RAII wrapper per memoria cifrata
 * Uso: EncryptedBuffer<int> buffer(1024); // 1024 ints cifrati
 */
template<typename T>
class EncryptedBuffer {
public:
    explicit EncryptedBuffer(size_t count)
        : size_(count * sizeof(T))
        , data_(nullptr)
    {
        data_ = static_cast<T*>(
            EncryptionManager::GetInstance().AllocateEncrypted(size_)
        );
    }
    
    ~EncryptedBuffer() {
        if (data_) {
            EncryptionManager::GetInstance().FreeEncrypted(data_);
        }
    }
    
    // Access (trigger automatic decryption)
    T& operator[](size_t index) {
        return data_[index];
    }
    
    const T& operator[](size_t index) const {
        return data_[index];
    }
    
    T* data() { return data_; }
    const T* data() const { return data_; }
    size_t size() const { return size_ / sizeof(T); }
    
private:
    size_t size_;
    T* data_;
};

/**
 * Helper macro per proteggere variabili
 */
#define ENCRYPTED_VAR(type, name, value) \
    Omamori::MemoryEncryption::EncryptedBuffer<type> name##_encrypted(1); \
    name##_encrypted[0] = value

#define ENCRYPTED_ARRAY(type, name, size) \
    Omamori::MemoryEncryption::EncryptedBuffer<type> name(size)

} // namespace MemoryEncryption
} // namespace Omamori
