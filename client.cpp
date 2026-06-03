#include "crypto.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;

int main() {
    std::string user_password = "my_super_secret_passphrase";
    std::string salt = "c2_backup_system_salt"; 
    std::string backup_dir = "backup_server_storage";
    std::string default_target_dir = "target_documents";
    std::string default_restore_dir = "restored_documents";
    
    // 1. Login Phase
    std::cout << "Enter Login Password (Press Enter for default): ";
    std::getline(std::cin, user_password);
    if (user_password.empty()) {
        user_password = "my_super_secret_passphrase";
    }

    std::vector<unsigned char> derived_key;
    std::vector<unsigned char> plaintext_aes_key;

    try {
        // Derive the key from user input password
        int iterations = 10000; // Work factor to deter brute-force attacks
        int key_len = 32;       // 32 bytes = 256 bits, standard for AES-256
        derived_key = derive_key(user_password, salt, iterations, key_len);

        // 2. Vault Verification & Automatic Generation
        if (!fs::exists("vault.dat")) {
            std::cout << "[System] vault.dat not found. Automatically generating new Master Vault..." << std::endl;
            
            // Generate a fresh random Data AES Key
            auto data_aes_key = generate_random_bytes(32);
            auto iv = generate_random_bytes(12);
            std::vector<unsigned char> tag(16);
            std::vector<unsigned char> ciphertext;

            // Encrypt the Data AES Key using the Derived Key
            aes_256_gcm_encrypt(data_aes_key, derived_key, ciphertext, iv, tag);

            // Save the newly created vault to disk
            std::ofstream out("vault.dat", std::ios::binary);
            if (!out) throw std::runtime_error("Failed to create vault.dat");
            out.write(reinterpret_cast<const char*>(iv.data()), iv.size());
            out.write(reinterpret_cast<const char*>(tag.data()), tag.size());
            out.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
            out.close();

            plaintext_aes_key = data_aes_key;
            std::cout << "[System] New Master Vault created and saved to vault.dat." << std::endl;
        } else {
            std::cout << "[System] vault.dat detected. Loading and unlocking..." << std::endl;
            
            // Read the existing vault file
            std::ifstream in("vault.dat", std::ios::binary);
            if (!in) throw std::runtime_error("Failed to open vault.dat");
            
            std::vector<unsigned char> v_iv(12), v_tag(16), v_ciphertext(32);
            in.read(reinterpret_cast<char*>(v_iv.data()), v_iv.size());
            in.read(reinterpret_cast<char*>(v_tag.data()), v_tag.size());
            in.read(reinterpret_cast<char*>(v_ciphertext.data()), v_ciphertext.size());
            in.close();

            // Decrypt to extract the Data AES Key (will throw if password is wrong)
            aes_256_gcm_decrypt(v_ciphertext, derived_key, v_iv, v_tag, plaintext_aes_key);
            std::cout << "[Auth] Master Vault unlocked successfully." << std::endl;
        }

        // Ensure server backup repository directory exists
        fs::create_directories(backup_dir);

        // 3. Interactive Menu Loop
        std::string choice;
        while (true) {
            std::cout << "\n=== Backup System Menu ===" << std::endl;
            std::cout << "1. Set target_dir and execute backup" << std::endl;
            std::cout << "2. Restore backup content to restore_dir" << std::endl;
            std::cout << "3. Exit" << std::endl;
            std::cout << "Select an option (1-3): ";
            std::getline(std::cin, choice);

            if (choice == "1") {
                std::string target_dir;
                std::cout << "Enter target directory path to backup (default: target_documents): ";
                std::getline(std::cin, target_dir);
                if (target_dir.empty()) {
                    target_dir = default_target_dir;
                }

                // Auto-create directory and dummy file if it doesn't exist
                if (!fs::exists(target_dir)) {
                    fs::create_directories(target_dir);
                    std::ofstream dummy(target_dir + "/dummy.txt");
                    dummy << "Initial mock data for " << target_dir << std::endl;
                    dummy.close();
                    std::cout << "[System] Created new target directory with a dummy.txt file." << std::endl;
                }

                std::cout << "\n--- Starting Directory Backup ---" << std::endl;
                int count = 0;
                for (const auto& entry : fs::directory_iterator(target_dir)) {
                    if (entry.is_regular_file()) {
                        std::string src_path = entry.path().string();
                        std::string dest_path = backup_dir + "/" + entry.path().filename().string() + ".enc";
                        encrypt_file(src_path, dest_path, plaintext_aes_key);
                        std::cout << "-> Encrypted: " << src_path << " -> " << dest_path << std::endl;
                        count++;
                    }
                }
                std::cout << "--- Backup Completed (" << count << " files processed) ---" << std::endl;
            } else if (choice == "2") {
                std::string restore_dir;
                std::cout << "Enter restore directory path (default: restored_documents): ";
                std::getline(std::cin, restore_dir);
                if (restore_dir.empty()) {
                    restore_dir = default_restore_dir;
                }

                fs::create_directories(restore_dir);

                std::cout << "\n--- Starting Directory Restore ---" << std::endl;
                int count = 0;
                for (const auto& entry : fs::directory_iterator(backup_dir)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".enc") {
                        std::string src_path = entry.path().string();
                        std::string original_name = entry.path().stem().string();
                        std::string dest_path = restore_dir + "/" + original_name;

                        decrypt_file(src_path, dest_path, plaintext_aes_key);
                        std::cout << "-> Decrypted: " << src_path << " -> " << dest_path << std::endl;
                        count++;
                    }
                }
                std::cout << "--- Restore Completed (" << count << " files processed) ---" << std::endl;
            } else if (choice == "3") {
                std::cout << "Exiting system. Goodbye!" << std::endl;
                break;
            } else {
                std::cout << "[Error] Invalid option. Please try again." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "\n[Fatal Error] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}