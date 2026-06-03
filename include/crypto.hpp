#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <fstream>
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
// Step 3-1: Decrypt data using AES-256-GCM
inline void aes_256_gcm_decrypt(const std::vector<unsigned char>& ciphertext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                const std::vector<unsigned char>& tag,
                                std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) ||
        1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize GCM decryption pipeline");
    }

    int len = 0;
    plaintext.resize(ciphertext.size());
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed during Update");
    }

    // Set expected authentication tag received from the vault/file
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<unsigned char*>(tag.data()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set expected GCM tag");
    }

    int final_len = 0;
    // EVP_DecryptFinal_ex returns > 0 if the tag matches and plaintext integrity is verified
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption authentication failed! (Data tampered or wrong password)");
    }

    EVP_CIPHER_CTX_free(ctx);
}

// Step 3-2: Encrypt a single file and prepend metadata [IV(12B)] + [Tag(16B)] + [Ciphertext]
inline void encrypt_file(const std::string& src, const std::string& dest, const std::vector<unsigned char>& key) {
    std::ifstream in(src, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Failed to open source file: " + src);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<unsigned char> plaintext(size);
    in.read(reinterpret_cast<char*>(plaintext.data()), size);
    in.close();

    auto iv = generate_random_bytes(12);
    std::vector<unsigned char> tag(16);
    std::vector<unsigned char> ciphertext;

    aes_256_gcm_encrypt(plaintext, key, ciphertext, iv, tag);

    std::ofstream out(dest, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open destination file: " + dest);
    out.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    out.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    out.close();
}

// Step 3-3: Decrypt a single file by parsing metadata header
inline void decrypt_file(const std::string& src, const std::string& dest, const std::vector<unsigned char>& key) {
    std::ifstream in(src, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("Failed to open encrypted file: " + src);
    std::streamsize size = in.tellg();
    
    if (size < 28) throw std::runtime_error("Encrypted file is truncated or corrupted: " + src);

    std::vector<unsigned char> iv(12);
    std::vector<unsigned char> tag(16);
    std::vector<unsigned char> ciphertext(size - 28);

    in.seekg(0, std::ios::beg);
    in.read(reinterpret_cast<char*>(iv.data()), iv.size());
    in.read(reinterpret_cast<char*>(tag.data()), tag.size());
    in.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext.size());
    in.close();

    std::vector<unsigned char> plaintext;
    aes_256_gcm_decrypt(ciphertext, key, iv, tag, plaintext);

    std::ofstream out(dest, std::ios::binary);
    if (!out) throw std::runtime_error("Failed to open restored file: " + dest);
    out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    out.close();
}