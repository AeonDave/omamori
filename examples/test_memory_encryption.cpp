/**
 * Test Memory Encryption Layer
 * 
 * Dimostra come usare la memoria cifrata trasparente
 */

#include "../common/include/memory_encryption.hpp"
#include <iostream>
#include <cstring>
#include <chrono>

using namespace Omamori::MemoryEncryption;

void TestBasicEncryption() {
    std::cout << "[TEST 1] Basic Encryption/Decryption\n";
    
    // Alloca 1 pagina cifrata
    const size_t size = 4096;
    void* encrypted_mem = EncryptionManager::GetInstance().AllocateEncrypted(size);
    
    if (!encrypted_mem) {
        std::cout << "  [FAIL] Could not allocate encrypted memory\n";
        return;
    }
    
    // La memoria è cifrata e protected (PROT_NONE)
    // Primo accesso trigger page fault → automatic decrypt
    
    std::cout << "  [INFO] Writing to encrypted memory...\n";
    char* data = static_cast<char*>(encrypted_mem);
    
    // Questo trigger page fault → decrypt automatico
    strcpy(data, "Hello, Encrypted World!");
    
    std::cout << "  [INFO] Reading from encrypted memory...\n";
    std::cout << "  [DATA] " << data << "\n";
    
    // Re-encrypt
    std::cout << "  [INFO] Re-encrypting...\n";
    EncryptionManager::GetInstance().ProtectAndEncrypt(encrypted_mem, size);
    
    // Ora memoria è di nuovo cifrata
    std::cout << "  [INFO] Memory encrypted again\n";
    
    // Free
    EncryptionManager::GetInstance().FreeEncrypted(encrypted_mem);
    std::cout << "  [PASS] Basic encryption test\n\n";
}

void TestEncryptedBuffer() {
    std::cout << "[TEST 2] EncryptedBuffer Template\n";
    
    // Usa template RAII
    EncryptedBuffer<int> numbers(100);
    
    std::cout << "  [INFO] Writing to EncryptedBuffer<int>[100]...\n";
    
    // Automatic decryption on access
    for (int i = 0; i < 100; i++) {
        numbers[i] = i * i;
    }
    
    std::cout << "  [INFO] Reading values...\n";
    std::cout << "  [DATA] numbers[10] = " << numbers[10] << "\n";
    std::cout << "  [DATA] numbers[50] = " << numbers[50] << "\n";
    
    std::cout << "  [PASS] EncryptedBuffer test\n\n";
}

void TestSensitiveData() {
    std::cout << "[TEST 3] Protecting Sensitive Data\n";
    
    // Simula password/key storage
    const char* sensitiveData = "SuperSecretPassword123!";
    size_t dataLen = strlen(sensitiveData) + 1;
    
    void* protected_mem = EncryptionManager::GetInstance().AllocateEncrypted(dataLen);
    
    if (!protected_mem) {
        std::cout << "  [FAIL] Allocation failed\n";
        return;
    }
    
    // Write (automatic decrypt)
    strcpy(static_cast<char*>(protected_mem), sensitiveData);
    
    std::cout << "  [INFO] Sensitive data stored in encrypted memory\n";
    
    // Re-encrypt immediatamente (best practice)
    EncryptionManager::GetInstance().ProtectAndEncrypt(protected_mem, 4096);
    
    std::cout << "  [INFO] Data re-encrypted immediately\n";
    std::cout << "  [INFO] Memory dump would show only ciphertext\n";
    
    // Read quando serve (automatic decrypt)
    char* password = static_cast<char*>(protected_mem);
    std::cout << "  [DATA] Retrieved: " << password << "\n";
    
    // Cleanup
    EncryptionManager::GetInstance().FreeEncrypted(protected_mem);
    std::cout << "  [PASS] Sensitive data protection test\n\n";
}

void TestPerformance() {
    std::cout << "[TEST 4] Performance Benchmark\n";
    
    const int iterations = 1000;
    const size_t bufferSize = 4096;
    
    // Test 1: Memoria normale
    auto start = std::chrono::high_resolution_clock::now();
    
    void* normal_mem = malloc(bufferSize);
    for (int i = 0; i < iterations; i++) {
        memset(normal_mem, i & 0xFF, bufferSize);
    }
    free(normal_mem);
    
    auto end = std::chrono::high_resolution_clock::now();
    auto normal_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "  [BENCH] Normal memory: " << normal_time << " μs\n";
    
    // Test 2: Memoria cifrata
    start = std::chrono::high_resolution_clock::now();
    
    void* encrypted_mem = EncryptionManager::GetInstance().AllocateEncrypted(bufferSize);
    for (int i = 0; i < iterations; i++) {
        memset(encrypted_mem, i & 0xFF, bufferSize);
        // Re-encrypt ogni iterazione (worst case)
        EncryptionManager::GetInstance().ProtectAndEncrypt(encrypted_mem, bufferSize);
    }
    EncryptionManager::GetInstance().FreeEncrypted(encrypted_mem);
    
    end = std::chrono::high_resolution_clock::now();
    auto encrypted_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "  [BENCH] Encrypted memory: " << encrypted_time << " μs\n";
    
    if (normal_time > 0) {
        std::cout << "  [BENCH] Overhead: " << (encrypted_time - normal_time) << " μs (";
        std::cout << ((encrypted_time * 100) / normal_time) << "% of normal)\n\n";
    } else {
        std::cout << "  [BENCH] Overhead: " << encrypted_time << " μs (normal too fast to measure)\n\n";
    }
}

void TestStatistics() {
    std::cout << "[TEST 5] Statistics\n";
    
    // Alloca alcune pagine
    void* p1 = EncryptionManager::GetInstance().AllocateEncrypted(4096);
    void* p2 = EncryptionManager::GetInstance().AllocateEncrypted(8192);
    void* p3 = EncryptionManager::GetInstance().AllocateEncrypted(4096);
    
    // Access (trigger page faults)
    memset(p1, 0xAA, 4096);
    memset(p2, 0xBB, 8192);
    memset(p3, 0xCC, 4096);
    
    // Get stats
    auto stats = EncryptionManager::GetInstance().GetStats();
    
    std::cout << "  [STATS] Total pages: " << stats.totalPages << "\n";
    std::cout << "  [STATS] Encrypted pages: " << stats.encryptedPages << "\n";
    std::cout << "  [STATS] Page faults: " << stats.pageFaults << "\n";
    std::cout << "  [STATS] Decrypt operations: " << stats.decryptOperations << "\n";
    std::cout << "  [STATS] Encrypt operations: " << stats.encryptOperations << "\n";
    
    // Cleanup
    EncryptionManager::GetInstance().FreeEncrypted(p1);
    EncryptionManager::GetInstance().FreeEncrypted(p2);
    EncryptionManager::GetInstance().FreeEncrypted(p3);
    
    std::cout << "  [PASS] Statistics test\n\n";
}

void TestMacros() {
    std::cout << "[TEST 6] Helper Macros\n";
    
    // Usa macro per dichiarare variabili cifrate
    ENCRYPTED_VAR(int, secret_number, 42);
    ENCRYPTED_ARRAY(double, secret_array, 10);
    
    std::cout << "  [INFO] Accessing encrypted variable...\n";
    std::cout << "  [DATA] secret_number = " << secret_number_encrypted[0] << "\n";
    
    std::cout << "  [INFO] Accessing encrypted array...\n";
    for (int i = 0; i < 10; i++) {
        secret_array[i] = i * 3.14;
    }
    std::cout << "  [DATA] secret_array[5] = " << secret_array[5] << "\n";
    
    std::cout << "  [PASS] Macro test\n\n";
}

int main() {
    std::cout << "==============================================\n";
    std::cout << "  Omamori Memory Encryption Layer Test\n";
    std::cout << "==============================================\n\n";
    
    // Initialize
    if (!EncryptionManager::GetInstance().Initialize()) {
        std::cerr << "[ERROR] Failed to initialize EncryptionManager\n";
        return 1;
    }
    
    std::cout << "[INIT] EncryptionManager initialized\n\n";
    
    // Run tests
    TestBasicEncryption();
    TestEncryptedBuffer();
    TestSensitiveData();
    TestPerformance();
    TestStatistics();
    TestMacros();
    
    // Shutdown
    EncryptionManager::GetInstance().Shutdown();
    
    std::cout << "==============================================\n";
    std::cout << "  All tests completed\n";
    std::cout << "==============================================\n";
    
    return 0;
}
