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
    std::string default_target_dir = "target_documents";
    std::string default_restore_dir = "restored_documents";
    
    // 1. Login Phase
    std::cout << "Enter Login Password (Press Enter for default): ";
    std::getline(std::cin, user_password);
    if (user_password.empty()) {
        user_password = "my_super_secret_passphrase";
    }

    try {
        // Derive the key from user input password
        int iterations = 10000; // Work factor to deter brute-force attacks
        int key_len = 32;       // 32 bytes = 256 bits, standard for AES-256
        auto derived_key = derive_key(user_password, salt, iterations, key_len);
        std::vector<unsigned char> plaintext_aes_key;

        // 2. Sync Vault with Server
        int sock = connect_server();
        char cmd = 'Q'; send_all(sock, &cmd, 1);
        char status; recv_all(sock, &status, 1);

        if (status == '0') { // Server has no vault, generate and upload
            std::cout << "[Client] Server has no vault. Generating new Master Vault..." << std::endl;
            auto data_aes_key = generate_random_bytes(32);
            auto iv = generate_random_bytes(12);
            std::vector<unsigned char> tag(16), ciphertext;
            aes_256_gcm_encrypt(data_aes_key, derived_key, ciphertext, iv, tag);

            std::vector<unsigned char> packed_vault;
            packed_vault.insert(packed_vault.end(), iv.begin(), iv.end());
            packed_vault.insert(packed_vault.end(), tag.begin(), tag.end());
            packed_vault.insert(packed_vault.end(), ciphertext.begin(), ciphertext.end());

            close(sock);
            sock = connect_server();
            char save_cmd = 'S'; send_all(sock, &save_cmd, 1);
            send_all(sock, packed_vault.data(), 60);
            
            plaintext_aes_key = data_aes_key;
            std::cout << "[Client] Master Vault generated and securely uploaded." << std::endl;
        } else { // Vault exists, download and unlock locally
            std::vector<unsigned char> packed_vault(60);
            recv_all(sock, packed_vault.data(), 60);
            
            std::vector<unsigned char> v_iv(packed_vault.begin(), packed_vault.begin() + 12);
            std::vector<unsigned char> v_tag(packed_vault.begin() + 12, packed_vault.begin() + 28);
            std::vector<unsigned char> v_ciphertext(packed_vault.begin() + 28, packed_vault.end());
            
            aes_256_gcm_decrypt(v_ciphertext, derived_key, v_iv, v_tag, plaintext_aes_key);
            std::cout << "[Auth] Server Master Vault loaded and unlocked successfully." << std::endl;
        }
        close(sock);

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