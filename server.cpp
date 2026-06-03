#include "crypto.hpp"
#include <filesystem>
#include <fstream>
#include <netinet/in.h>

namespace fs = std::filesystem;

void handle_client(int client_sock) {
    fs::create_directories("server_storage");
    char cmd;
    if (!recv_all(client_sock, &cmd, 1)) return;

    if (cmd == 'Q') { // Query Vault Status
        char status = fs::exists("server_storage/vault.dat") ? '1' : '0';
        send_all(client_sock, &status, 1);
        if (status == '1') {
            std::vector<unsigned char> buf(120); // (12 + 16 + 32) * 2
            std::ifstream in("server_storage/vault.dat", std::ios::binary);
            in.read(reinterpret_cast<char*>(buf.data()), 120);
            send_all(client_sock, buf.data(), 120);
        }
    } 
    else if (cmd == 'S') { // Save/Update Vault
        std::vector<unsigned char> buf(120);
        if (recv_all(client_sock, buf.data(), 120)) {
            std::ofstream out("server_storage/vault.dat", std::ios::binary);
            out.write(reinterpret_cast<const char*>(buf.data()), 120);
            std::cout << "[Server] Master Vault saved successfully." << std::endl;
        }
    } 
    else if (cmd == 'B') { // Backup File Upload
        uint32_t name_len = 0, file_size = 0;
        if (!recv_all(client_sock, &name_len, 4) || !recv_all(client_sock, &file_size, 4)) return;
        
        std::string filename(name_len, '\0');
        std::vector<unsigned char> file_data(file_size);
        if (!recv_all(client_sock, &filename[0], name_len) || !recv_all(client_sock, file_data.data(), file_size)) return;

        std::ofstream out("server_storage/" + filename + ".enc", std::ios::binary);
        out.write(reinterpret_cast<const char*>(file_data.data()), file_size);
        std::cout << "[Server] Saved encrypted backup file: " << filename << ".enc" << std::endl;
    } 
    else if (cmd == 'R') { // Restore Request (Download All)
        // Count eligible files
        uint32_t file_count = 0;
        for (const auto& e : fs::directory_iterator("server_storage")) {
            if (e.is_regular_file() && e.path().extension() == ".enc") file_count++;
        }
        send_all(client_sock, &file_count, 4);

        for (const auto& e : fs::directory_iterator("server_storage")) {
            if (e.is_regular_file() && e.path().extension() == ".enc") {
                std::string filename = e.path().filename().string();
                uint32_t name_len = filename.length();
                uint32_t file_size = fs::file_size(e.path());

                std::ifstream in(e.path(), std::ios::binary);
                std::vector<unsigned char> buf(file_size);
                in.read(reinterpret_cast<char*>(buf.data()), file_size);

                send_all(client_sock, &name_len, 4);
                send_all(client_sock, filename.data(), name_len);
                send_all(client_sock, &file_size, 4);
                send_all(client_sock, buf.data(), file_size);
            }
        }
    }
    close(client_sock);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8080);

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 3);
    std::cout << "[Server] Storage node listening on port 8080..." << std::endl;

    while (true) {
        int client_sock = accept(server_fd, nullptr, nullptr);
        if (client_sock >= 0) handle_client(client_sock);
    }
    close(server_fd);
    return 0;
}