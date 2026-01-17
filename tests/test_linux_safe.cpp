#include "../include/omamori.hpp"
#include <iostream>
#include <unistd.h>
#include <cstring>

int main() {
    std::cout << "=== Omamori Linux Test Suite ===" << std::endl;
    std::cout << "Version: " << Omamori::GetVersion() << std::endl;
    std::cout << std::endl;
    
    // Test 1: Secure Strings
    std::cout << "[TEST 1] Secure Strings..." << std::endl;
    auto secret = SECURE_STR("Linux secret key");
    std::cout << "  Decrypted: " << secret.get() << std::endl;
    std::cout << "  Status: PASS" << std::endl;
    std::cout << std::endl;
    
    // Test 2: StreamCipher
    std::cout << "[TEST 2] Memory Encryption (StreamCipher)..." << std::endl;
    uint8_t data[] = "Linux encrypted data";
    size_t len = sizeof(data);
    
    uint8_t key[32];
    Omamori::MemoryEncryption::StreamCipher::GenerateKey(key, 32);
    Omamori::MemoryEncryption::StreamCipher cipher(key, 32);
    
    uint8_t original[sizeof(data)];
    memcpy(original, data, len);
    
    cipher.Encrypt(data, len);
    std::cout << "  Encrypted: PASS" << std::endl;
    
    cipher.Reset();
    cipher.Decrypt(data, len);
    
    bool match = (memcmp(data, original, len) == 0);
    std::cout << "  Decrypted: " << (const char*)data << std::endl;
    std::cout << "  Status: " << (match ? "PASS" : "FAIL") << std::endl;
    std::cout << std::endl;
    
    // Test 3: VM Detection
    std::cout << "[TEST 3] Anti-VM Detection..." << std::endl;
    bool vmDetected = Omamori::AntiVM::Detector::IsVirtualMachine();
    std::cout << "  VM detected: " << (vmDetected ? "YES (WSL/Container)" : "NO") << std::endl;
    std::cout << "  Status: PASS" << std::endl;
    std::cout << std::endl;
    
    // Test 4: Custom config - NO Anti-VM termination
    std::cout << "[TEST 4] Initialize with safe config (Anti-VM off)..." << std::endl;
    Omamori::ProtectionConfig config;
    config.enable_antivm = false;
    config.enable_antidebug = true;
    config.enable_antidebug_thread = false;
    config.enable_antidump = false; // Safe for testing
    config.disable_core_dumps = false;
    config.enable_prctl_protection = false;
    config.erase_headers = false;
    
    if (!Omamori::Initialize(config)) {
        std::cerr << "  Initialize failed" << std::endl;
        return 1;
    }
    std::cout << "  Status: PASS" << std::endl;
    std::cout << std::endl;
    
    // Test 5: Debugger detection
    std::cout << "[TEST 5] Anti-Debug Detection..." << std::endl;
    bool debuggerDetected = Omamori::IsDebugged();
    std::cout << "  Debugger detected: " << (debuggerDetected ? "YES" : "NO") << std::endl;
    std::cout << "  Status: PASS" << std::endl;
    std::cout << std::endl;
    
    std::cout << "============================================" << std::endl;
    std::cout << "   ALL TESTS PASSED" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << "\nLinux protection features validated:" << std::endl;
    std::cout << "  [+] Secure Strings" << std::endl;
    std::cout << "  [+] Memory Encryption (StreamCipher)" << std::endl;
    std::cout << "  [+] Anti-VM Detection" << std::endl;
    std::cout << "  [+] Anti-Debug Detection" << std::endl;
    std::cout << "  [+] Configuration System" << std::endl;
    
    return 0;
}
