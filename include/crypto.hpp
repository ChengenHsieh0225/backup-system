#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

// Step 2-1: Generate cryptographically secure random bytes
inline std::vector<unsigned char> generate_random_bytes(size_t len) {
    std::vector<unsigned char> buf(len);
    if (RAND_bytes(buf.data(), len) != 1) {
        throw std::runtime_error("Failed to generate random bytes!");
    }
    return buf;
}

// Step 2-2: Encrypt data using AES-256-GCM
inline void aes_256_gcm_encrypt(const std::vector<unsigned char>& plaintext,
                                const std::vector<unsigned char>& key,
                                std::vector<unsigned char>& ciphertext,
                                std::vector<unsigned char>& iv,
                                std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    // Initialize encryption operation with AES-256-GCM
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize GCM encryption");
    }

    // Set IV length (Standard is 12 bytes)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }

    // Initialize Key and IV
    if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set Key and IV");
    }

    // Encrypt plaintext
    int len = 0;
    ciphertext.resize(plaintext.size());
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during Update");
    }

    // Finalize encryption
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed during Final");
    }

    // Get GCM authentication tag (Standard is 16 bytes)
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to retrieve GCM authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);
}