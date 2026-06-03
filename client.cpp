#include "crypto.hpp"
#include <fstream>
#include <filesystem>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace fs = std::filesystem;

int connect_server() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        throw std::runtime_error("Server connection failed. Is server running?");
    }
    return sock;
}

int main() {
    std::string user_password, salt = "c2_backup_system_salt";
    std::string user_default_pass = "my_super_secret_passphrase";
    std::string default_target_dir = "target_documents";
    std::string default_restore_dir = "restored_documents";
    std::vector<unsigned char> plaintext_aes_key;
    std::vector<unsigned char> current_vault(120);
    
    try {
        // 1. Sync Vault with Server
        int sock = connect_server();
        char cmd = 'Q'; send_all(sock, &cmd, 1);
        char status; recv_all(sock, &status, 1);

        if (status == '0') {
            // Initialization: Setup initial password and generate Recovery Code
            std::cout << "[System] No vault found on server. Initializing..." << std::endl;
            std::string init_pass;
            std::cout << "Set your initial Login Password (Enter for default): ";
            std::getline(std::cin, init_pass);
            if (init_pass.empty()) init_pass = user_default_pass;

            // Derive the key from user input password
            int iterations = 10000; // Work factor to deter brute-force attacks
            int key_len = 32;       // 32 bytes = 256 bits, standard for AES-256
            auto derived_key = derive_key(init_pass, salt, iterations, key_len);
            auto data_aes_key = generate_random_bytes(32);
            std::string recovery_code = generate_recovery_code();
            auto rc_derived_key = derive_key(recovery_code, salt, iterations, key_len);

            std::cout << "\n==================================================" << std::endl;
            std::cout << "[CRITICAL] YOUR DISASTER RECOVERY CODE: " << recovery_code << std::endl;
            std::cout << "Please store this safely. It cannot be recovered." << std::endl;
            std::cout << "==================================================\n" << std::endl;

            // Slot 1: Encrypt Data Key with Password Derived Key
            std::vector<unsigned char> iv1 = generate_random_bytes(12), tag1(16), cipher1;
            aes_256_gcm_encrypt(data_aes_key, derived_key, cipher1, iv1, tag1);

            // Slot 2: Encrypt Data Key with Recovery Code Derived Key
            std::vector<unsigned char> iv2 = generate_random_bytes(12), tag2(16), cipher2;
            aes_256_gcm_encrypt(data_aes_key, rc_derived_key, cipher2, iv2, tag2);

            // Pack into 120-byte payload
            current_vault.clear();
            current_vault.insert(current_vault.end(), iv1.begin(), iv1.end());
            current_vault.insert(current_vault.end(), tag1.begin(), tag1.end());
            current_vault.insert(current_vault.end(), cipher1.begin(), cipher1.end());
            current_vault.insert(current_vault.end(), iv2.begin(), iv2.end());
            current_vault.insert(current_vault.end(), tag2.begin(), tag2.end());
            current_vault.insert(current_vault.end(), cipher2.begin(), cipher2.end());

            close(sock);
            sock = connect_server();
            char save_cmd = 'S'; send_all(sock, &save_cmd, 1);
            send_all(sock, current_vault.data(), 120);
            close(sock);

            plaintext_aes_key = data_aes_key;
            std::cout << "[Client] Initialization successful. Logged in." << std::endl;
        } else {
            // Vault exists: Download full vault payload for local verification
            recv_all(sock, current_vault.data(), 120);
            close(sock);

            bool authenticated = false;
            while (!authenticated) {
                std::cout << "\n=== Welcome to Backup System ===" << std::endl;
                std::cout << "1. Login with Password" << std::endl;
                std::cout << "2. Reset Password via Recovery Code" << std::endl;
                std::cout << "Select verification method (1-2): ";
                std::string auth_choice;
                std::getline(std::cin, auth_choice);

                if (auth_choice == "1") {
                    std::string user_password;
                    std::cout << "Enter Password (Enter for default): ";
                    std::getline(std::cin, user_password);
                    if (user_password.empty()) user_password = "my_super_secret_passphrase";

                    try {
                        auto derived_key = derive_key(user_password, salt, 10000, 32);
                        std::vector<unsigned char> v_iv(current_vault.begin(), current_vault.begin() + 12);
                        std::vector<unsigned char> v_tag(current_vault.begin() + 12, current_vault.begin() + 28);
                        std::vector<unsigned char> v_cipher(current_vault.begin() + 28, current_vault.begin() + 60);

                        aes_256_gcm_decrypt(v_cipher, derived_key, v_iv, v_tag, plaintext_aes_key);
                        std::cout << "[Auth] Login successful!" << std::endl;
                        authenticated = true;
                    } catch (const std::exception&) {
                        std::cout << "[Error] Incorrect password. Access denied." << std::endl;
                    }
                } else if (auth_choice == "2") {
                    std::string input_rc;
                    std::cout << "Enter your 24-character Recovery Code: ";
                    std::getline(std::cin, input_rc);

                    try {
                        auto rc_derived_key = derive_key(input_rc, salt, 10000, 32);
                        std::vector<unsigned char> r_iv(current_vault.begin() + 60, current_vault.begin() + 72);
                        std::vector<unsigned char> r_tag(current_vault.begin() + 72, current_vault.begin() + 88);
                        std::vector<unsigned char> r_cipher(current_vault.begin() + 88, current_vault.end());

                        // Unlock Master AES Key using the recovery code
                        aes_256_gcm_decrypt(r_cipher, rc_derived_key, r_iv, r_tag, plaintext_aes_key);
                        std::cout << "[Auth] Recovery code verified! Identity confirmed." << std::endl;

                        // Enforce setting a new login password
                        std::string new_pass;
                        std::cout << "Enter NEW password: ";
                        std::getline(std::cin, new_pass);
                        if (new_pass.empty()) new_pass = "my_super_secret_passphrase";

                        auto new_derived_key = derive_key(new_pass, salt, 10000, 32);

                        // Re-encrypt Slot 1 with the new password derived key
                        std::vector<unsigned char> new_iv = generate_random_bytes(12), new_tag(16), new_cipher;
                        aes_256_gcm_encrypt(plaintext_aes_key, new_derived_key, new_cipher, new_iv, new_tag);

                        std::copy(new_iv.begin(), new_iv.end(), current_vault.begin());
                        std::copy(new_tag.begin(), new_tag.end(), current_vault.begin() + 12);
                        std::copy(new_cipher.begin(), new_cipher.end(), current_vault.begin() + 28);

                        // Synchronize updated vault container back to server
                        sock = connect_server();
                        char save_cmd = 'S'; send_all(sock, &save_cmd, 1);
                        send_all(sock, current_vault.data(), 120);
                        close(sock);

                        std::cout << "[Success] Password reset complete. Automatically logged in." << std::endl;
                        authenticated = true;
                    } catch (const std::exception&) {
                        std::cout << "[Error] Invalid recovery code! Reset denied." << std::endl;
                    }
                }
            }
        }

        // 2. Main Functional Menu Loop (Accessible only after successful authentication)
        std::string choice;
        while (true) {
            std::cout << "\n=== Distributed Backup System Menu ===" << std::endl;
            std::cout << "1. Set target_dir and execute backup upload" << std::endl;
            std::cout << "2. Download and Restore backup content to restore_dir" << std::endl;
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
                if (!fs::exists(target_dir)) {
                    std::cout << "[Error] Invalid directory: " << target_dir << std::endl; continue;
                }

                std::cout << "\n--- Starting Directory Backup ---" << std::endl;
                int count = 0;
                for (const auto& entry : fs::directory_iterator(target_dir)) {
                    if (entry.is_regular_file()) {
                        std::string src_path = entry.path().string();
                        std::string filename = entry.path().filename().string();
                        auto packed_data = encrypt_file_to_buffer(src_path, plaintext_aes_key);

                        sock = connect_server();
                        char b_cmd = 'B'; send_all(sock, &b_cmd, 1);
                        uint32_t name_len = filename.length();
                        uint32_t file_size = packed_data.size();
                        send_all(sock, &name_len, 4);
                        send_all(sock, &file_size, 4);
                        send_all(sock, filename.data(), name_len);
                        send_all(sock, packed_data.data(), file_size);
                        close(sock);
                        std::cout << "-> Uploaded Encrypted: " << filename << std::endl;
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

                sock = connect_server();
                char r_cmd = 'R'; send_all(sock, &r_cmd, 1);
                uint32_t file_count = 0; recv_all(sock, &file_count, 4);

                for (uint32_t i = 0; i < file_count; ++i) {
                    uint32_t name_len = 0, file_size = 0;
                    recv_all(sock, &name_len, 4);
                    std::string filename(name_len, '\0');
                    recv_all(sock, &filename[0], name_len);
                    recv_all(sock, &file_size, 4);
                    std::vector<unsigned char> file_data(file_size);
                    recv_all(sock, file_data.data(), file_size);

                    // Remove .enc extension
                    std::string original_name = fs::path(filename).stem().string();
                    decrypt_buffer_to_file(file_data, restore_dir + "/" + original_name, plaintext_aes_key);
                    std::cout << "-> Decrypted & Restored: " << original_name << std::endl;
                }
                close(sock);

                std::cout << "--- Restore Completed (" << file_count << " files processed) ---" << std::endl;
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