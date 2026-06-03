#include "crypto.hpp"
#include <fstream>

int main() {
    // 1. Inputs for the key derivation pipeline
    std::string user_password = "my_super_secret_passphrase";
    std::string salt = "c2_backup_system_salt"; 
    
    int iterations = 10000; // Work factor to deter brute-force attacks
    int key_len = 32;       // 32 bytes = 256 bits, standard for AES-256

    try {
        std::cout << "=== Phase 1: Step 1 (Key Derivation) ===" << std::endl;

        // Execute the key derivation
        auto derived_key = derive_key(user_password, salt, iterations, key_len);
        print_hex("Derived Key (256-bit Hex)", derived_key.data(), derived_key.size());

        std::cout << "\n=== Phase 1: Step 2 (Master Vault Generation) ===" << std::endl;
        
        // 1. Generate random Data AES Key (The actual key used for file backup later)
        auto data_aes_key = generate_random_bytes(32); // 256 bits
        print_hex("Plaintext Data AES Key", data_aes_key.data(), data_aes_key.size());

        // 2. Prepare GCM parameters
        auto iv = generate_random_bytes(12);  // 12-byte initialization vector
        std::vector<unsigned char> tag(16);   // 16-byte auth tag container
        std::vector<unsigned char> ciphertext;

        // 3. Encrypt the Data AES Key using the Derived Key
        aes_256_gcm_encrypt(data_aes_key, derived_key, ciphertext, iv, tag);
        std::cout << "Data AES Key successfully encrypted." << std::endl;
        print_hex("Ciphertext Payload", ciphertext.data(), ciphertext.size());
        print_hex("GCM Auth Tag", tag.data(), tag.size());

        // 4. Export to local file (Simulating secure upload to Server)
        std::ofstream server_vault("vault.dat", std::ios::binary);
        if (!server_vault) {
            throw std::runtime_error("Failed to open vault.dat for writing");
        }

        // Structure format: [IV (12B)] + [Tag (16B)] + [Ciphertext (32B)]
        server_vault.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        server_vault.write(reinterpret_cast<const char*>(tag.data()), tag.size());
        server_vault.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        server_vault.close();

        std::cout << "\n>> Master Vault saved successfully to 'vault.dat'." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Pipeline Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}