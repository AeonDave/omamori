#pragma once
#include <cstdint>
#include <cstddef>

namespace Omamori {
namespace Crypto {

template<typename Char, size_t N>
class XString {
private:
    Char encrypted[N];
    static constexpr uint8_t KEY = 0x42 ^ (__LINE__ & 0xFF);
    
    constexpr void encrypt(const Char* str) {
        for(size_t i = 0; i < N; ++i) {
            encrypted[i] = str[i] ^ (KEY + static_cast<uint8_t>(i));
        }
    }
    
public:
    constexpr XString(const Char* str) : encrypted{} {
        encrypt(str);
    }
    
    void decrypt(Char* buffer) const {
        for(size_t i = 0; i < N; ++i) {
            buffer[i] = encrypted[i] ^ (KEY + static_cast<uint8_t>(i));
        }
    }
    
    static constexpr size_t size() { return N; }
};

template<size_t N>
class SecureString {
private:
    char buffer[N];
    
public:
    SecureString(const XString<char, N>& xstr) {
        xstr.decrypt(buffer);
    }
    
    ~SecureString() {
        // Wipe buffer on destruction
        volatile char* p = buffer;
        for(size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }
    
    const char* get() const { return buffer; }
    operator const char*() const { return buffer; }
};

template<size_t N>
class SecureWString {
private:
    wchar_t buffer[N];
    
public:
    SecureWString(const XString<wchar_t, N>& xstr) {
        xstr.decrypt(buffer);
    }
    
    ~SecureWString() {
        volatile wchar_t* p = buffer;
        for(size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }
    
    const wchar_t* get() const { return buffer; }
    operator const wchar_t*() const { return buffer; }
};

} // namespace Crypto
} // namespace Omamori

// Macro for easy usage
#define SECURE_STR(str) \
    Omamori::Crypto::SecureString<sizeof(str)>( \
        Omamori::Crypto::XString<char, sizeof(str)>(str) \
    )

#define SECURE_WSTR(str) \
    Omamori::Crypto::SecureWString<sizeof(str)/sizeof(wchar_t)>( \
        Omamori::Crypto::XString<wchar_t, sizeof(str)/sizeof(wchar_t)>(str) \
    )
