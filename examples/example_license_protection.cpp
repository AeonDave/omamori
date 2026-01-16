/**
 * Example: Protecting License Keys with Memory Encryption
 * 
 * Shows how to store and validate license keys securely
 * using Omamori's transparent memory encryption.
 */

#include "../common/include/memory_encryption.hpp"
#include <iostream>
#include <cstring>
#include <ctime>

using namespace Omamori::MemoryEncryption;

// License structure (will be stored encrypted)
struct License {
    char product_name[64];
    char license_key[128];
    uint64_t issued_date;
    uint64_t expiry_date;
    uint32_t user_id;
    bool is_valid;
};

// Simulate license validation (network call, signature check, etc.)
bool validate_license_online(const char* key) {
    std::cout << "  [API] Validating license: " << key << "\n";
    // In real app: check signature, call server, etc.
    return strstr(key, "VALID") != nullptr;
}

int main() {
    std::cout << "==============================================\n";
    std::cout << "  License Protection Example\n";
    std::cout << "==============================================\n\n";
    
    // Initialize encryption manager
    if (!EncryptionManager::GetInstance().Initialize()) {
        std::cerr << "[ERROR] Failed to initialize encryption\n";
        return 1;
    }
    
    std::cout << "[INIT] Memory encryption initialized\n\n";
    
    // ========================================
    // STEP 1: Load License (from file/network)
    // ========================================
    
    std::cout << "[STEP 1] Loading license...\n";
    
    // Use encrypted buffer for license data
    EncryptedBuffer<License> license(1);
    
    // Simulate loading from file
    // In real app: read from disk, decrypt config, etc.
    strcpy(license[0].product_name, "MyAwesomeApp Pro");
    strcpy(license[0].license_key, "VALID-1234-5678-ABCD-EFGH");
    license[0].issued_date = time(nullptr);
    license[0].expiry_date = time(nullptr) + (365 * 24 * 60 * 60); // 1 year
    license[0].user_id = 12345;
    license[0].is_valid = false;
    
    std::cout << "  [INFO] License loaded: " << license[0].product_name << "\n";
    std::cout << "  [INFO] License key: " << license[0].license_key << "\n\n";
    
    // ========================================
    // STEP 2: Validate License
    // ========================================
    
    std::cout << "[STEP 2] Validating license...\n";
    
    // Access is transparent - automatic decryption
    if (validate_license_online(license[0].license_key)) {
        license[0].is_valid = true;
        std::cout << "  [✓] License valid!\n\n";
    } else {
        license[0].is_valid = false;
        std::cout << "  [✗] License invalid!\n\n";
        return 1;
    }
    
    // ========================================
    // STEP 3: Memory Protection
    // ========================================
    
    std::cout << "[STEP 3] Memory protection status\n";
    
    // Get stats
    auto stats = EncryptionManager::GetInstance().GetStats();
    std::cout << "  [STATS] Total encrypted pages: " << stats.totalPages << "\n";
    std::cout << "  [STATS] Page faults handled: " << stats.pageFaults << "\n";
    std::cout << "  [STATS] Decrypt operations: " << stats.decryptOperations << "\n";
    
    std::cout << "\n  [INFO] License data is encrypted in memory!\n";
    std::cout << "  [INFO] Memory dump would show only CIPHERTEXT\n\n";
    
    // ========================================
    // STEP 4: Use License Throughout App
    // ========================================
    
    std::cout << "[STEP 4] Using license in application...\n";
    
    // Check expiry (transparent access)
    time_t now = time(nullptr);
    if (now < license[0].expiry_date) {
        std::cout << "  [✓] License not expired\n";
    } else {
        std::cout << "  [✗] License expired!\n";
        return 1;
    }
    
    // Check validity (transparent access)
    if (license[0].is_valid) {
        std::cout << "  [✓] License valid, running protected code...\n";
        
        // Your protected application code here
        std::cout << "  [APP] Starting main application...\n";
        std::cout << "  [APP] User ID: " << license[0].user_id << "\n";
        
    } else {
        std::cout << "  [✗] No valid license, exiting\n";
        return 1;
    }
    
    std::cout << "\n";
    
    // ========================================
    // STEP 5: Demonstrate Memory Scanning Resistance
    // ========================================
    
    std::cout << "[STEP 5] Memory scanning resistance\n";
    std::cout << "  [TEST] Simulating memory scanner...\n";
    
    // Get actual memory address
    void* license_addr = license.data();
    std::cout << "  [INFO] License stored at: " << license_addr << "\n";
    
    // At this point, if we try to scan memory externally (gcore, /proc/mem)
    // we would see ENCRYPTED data, not plaintext
    
    std::cout << "  [INFO] External memory scan would see CIPHERTEXT\n";
    std::cout << "  [INFO] Plaintext only visible during active access\n\n";
    
    // ========================================
    // STEP 6: Cleanup
    // ========================================
    
    std::cout << "[STEP 6] Secure cleanup\n";
    
    // Zero sensitive data before freeing
    memset(&license[0], 0, sizeof(License));
    std::cout << "  [INFO] License data zeroed\n";
    
    // EncryptedBuffer auto-frees on scope exit
    std::cout << "  [INFO] Memory will be freed automatically\n";
    
    std::cout << "\n==============================================\n";
    std::cout << "  License protection demo completed\n";
    std::cout << "==============================================\n";
    
    EncryptionManager::GetInstance().Shutdown();
    
    return 0;
}
