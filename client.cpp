#include "crypto.hpp"

int main() {
    // 1. Inputs for the key derivation pipeline
    std::string user_password = "my_super_secret_passphrase";
    std::string salt = "c2_backup_system_salt"; 
    
    int iterations = 10000; // Work factor to deter brute-force attacks
    int key_len = 32;       // 32 bytes = 256 bits, standard for AES-256

    try {
        std::cout << "=== Phase 1: Step 1 (Key Derivation) ===" << std::endl;
        std::cout << "User Password: " << user_password << std::endl;
        
        // Execute the key derivation
        auto derived_key = derive_key(user_password, salt, iterations, key_len);
        
        // Print the derived key to verify success
        print_hex("Derived Key (256-bit Hex)", derived_key.data(), derived_key.size());
        std::cout << "Step 1 completed successfully." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Pipeline Error during Step 1: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}