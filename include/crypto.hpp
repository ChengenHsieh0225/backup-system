#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <openssl/evp.h>

// Helper utility to print binary data in hex format
inline void print_hex(const std::string& label, const unsigned char* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl; // Reset to decimal format
}

// Step 1: PBKDF2-HMAC-SHA256 Key Derivation Function
// Derives a secure cryptographic key from a user password and salt
inline std::vector<unsigned char> derive_key(const std::string& password, const std::string& salt, int iterations, int key_len) {
    std::vector<unsigned char> derived_key(key_len);
    
    // Call OpenSSL standard PBKDF2 implementation
    if (PKCS5_PBKDF2_HMAC(
            password.c_str(), password.length(),
            reinterpret_cast<const unsigned char*>(salt.c_str()), salt.length(),
            iterations, 
            EVP_sha256(), // Utilize SHA-256 as the underlying PRF
            key_len, 
            derived_key.data()) != 1) {
        throw std::runtime_error("PBKDF2 derivation failed!");
    }
    
    return derived_key;
}