#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <algorithm>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 54000
#define BUFFER_SIZE 1024

struct ClientInfo {
    int socket;
    std::string username;
};

std::vector<ClientInfo> clients;
std::mutex clients_mutex;

std::vector<std::string> chat_logs;
std::mutex logs_mutex;

std::string server_access_key;
std::mutex key_mutex;

std::string xorCipher(std::string data, const std::string& key) {
    std::string output = data;
    for (size_t i = 0; i < data.size(); ++i) {
        output[i] = data[i] ^ key[i % key.size()];
    }
    return output;
}

void clearScreen() {
    std::cout << "\033[2J\033[1;1H";
}

void pauseMenu() {
    std::cout << "\n\033[36mPress Enter to continue...\033[0m";
    std::string dummy;
    std::getline(std::cin, dummy);
}

void broadcast(const std::string& message, int sender_socket = -1) {
    {
        std::lock_guard<std::mutex> lock(logs_mutex);
        chat_logs.push_back(message);
    }

    std::string encrypted = xorCipher(message, server_access_key);

    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto& client : clients) {
        if (client.socket != sender_socket) {
            send(client.socket, encrypted.c_str(), encrypted.size(), 0);
        }
    }
}

void handle_client(int clientSocket) {
    char buffer[BUFFER_SIZE];
    
    for (int i = 0; i < BUFFER_SIZE; ++i) buffer[i] = 0;
    int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
    if (bytesReceived <= 0) {
        close(clientSocket);
        return;
    }

    std::string raw_auth(buffer, bytesReceived);
    std::string auth_payload;
    {
        std::lock_guard<std::mutex> lock(key_mutex);
        auth_payload = xorCipher(raw_auth, server_access_key);
    }

    size_t delimiter_pos = auth_payload.find(':');
    if (delimiter_pos == std::string::npos) {
        std::string err = xorCipher("AUTH_FAIL:Invalid format\n", server_access_key);
        send(clientSocket, err.c_str(), err.size(), 0);
        close(clientSocket);
        return;
    }

    std::string username = auth_payload.substr(0, delimiter_pos);
    std::string provided_key = auth_payload.substr(delimiter_pos + 1);

    {
        std::lock_guard<std::mutex> lock(key_mutex);
        if (provided_key != server_access_key) {
            std::string err = xorCipher("AUTH_FAIL:Incorrect access key\n", server_access_key);
            send(clientSocket, err.c_str(), err.size(), 0);
            close(clientSocket);
            return;
        }
    }

    std::string success = xorCipher("AUTH_OK\n", server_access_key);
    send(clientSocket, success.c_str(), success.size(), 0);

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.push_back({clientSocket, username});
    }

    std::string join_msg = "[Server] " + username + " has joined the chat.";
    broadcast(join_msg, clientSocket);

    while (true) {
        for (int i = 0; i < BUFFER_SIZE; ++i) buffer[i] = 0;
        bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesReceived <= 0) break;

        std::string decrypted_msg;
        {
            std::lock_guard<std::mutex> lock(key_mutex);
            decrypted_msg = xorCipher(std::string(buffer, bytesReceived), server_access_key);
        }

        std::string msg = "[" + username + "]: " + decrypted_msg;
        broadcast(msg, clientSocket);
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.erase(std::remove_if(clients.begin(), clients.end(), [clientSocket](const ClientInfo& c) {
            return c.socket == clientSocket;
        }), clients.end());
    }
    close(clientSocket);

    std::string leave_msg = "[Server] " + username + " has left the chat.";
    broadcast(leave_msg);
}

void server_menu() {
    std::string command;
    while (true) {
        clearScreen();
        std::cout << "\033[1;32m=== SECURE CHAT SERVER CONTROL PANEL ===\033[0m\n";
        std::cout << "\033[33m1.\033[0m Change Access Key\n";
        std::cout << "\033[33m2.\033[0m List Active Users\n";
        std::cout << "\033[33m3.\033[0m Kick User\n";
        std::cout << "\033[33m4.\033[0m Broadcast Announcement\n";
        std::cout << "\033[33m5.\033[0m Show Chat Logs\n";
        std::cout << "\033[33m6.\033[0m Clear Logs\n";
        std::cout << "\033[33m7.\033[0m Exit Server\n";
        std::cout << "\033[1;36mSelect option: \033[0m";
        
        if (!(std::cin >> command)) break;
        std::cin.ignore();

        if (command == "1") {
            std::string new_key;
            std::cout << "Enter new access key: ";
            std::getline(std::cin, new_key);
            std::lock_guard<std::mutex> lock(key_mutex);
            server_access_key = new_key;
            std::cout << "\033[32m[Success] Access key updated!\033[0m\n";
            pauseMenu();
        } 
        else if (command == "2") {
            std::lock_guard<std::mutex> lock(clients_mutex);
            std::cout << "\n\033[1mActive Users (" << clients.size() << "):\033[0m\n";
            for (const auto& c : clients) {
                std::cout << " - \033[33m" << c.username << "\033[0m (Socket: " << c.socket << ")\n";
            }
            pauseMenu();
        }
        else if (command == "3") {
            int target_socket;
            std::cout << "Enter socket ID of user to kick: ";
            if (std::cin >> target_socket) {
                std::lock_guard<std::mutex> lock(clients_mutex);
                auto it = std::find_if(clients.begin(), clients.end(), [target_socket](const ClientInfo& c) {
                    return c.socket == target_socket;
                });
                if (it != clients.end()) {
                    close(it->socket);
                    clients.erase(it);
                    std::cout << "\033[31m[Success] User kicked.\033[0m\n";
                } else {
                    std::cout << "\033[31m[Error] User socket not found.\033[0m\n";
                }
            }
            std::cin.ignore();
            pauseMenu();
        }
        else if (command == "4") {
            std::string announcement;
            std::cout << "Enter announcement message: ";
            std::getline(std::cin, announcement);
            broadcast("[ANNOUNCEMENT] " + announcement);
            std::cout << "\033[32m[Success] Announcement broadcasted!\033[0m\n";
            pauseMenu();
        }
        else if (command == "5") {
            std::lock_guard<std::mutex> lock(logs_mutex);
            std::cout << "\n\033[1m=== Chat Logs (" << chat_logs.size() << " entries) ===\033[0m\n";
            if (chat_logs.empty()) {
                std::cout << " (No messages recorded yet)\n";
            } else {
                for (const auto& log : chat_logs) {
                    std::cout << " " << log << "\n";
                }
            }
            std::cout << "====================================\n";
            pauseMenu();
        } 
        else if (command == "6") {
            std::lock_guard<std::mutex> lock(logs_mutex);
            chat_logs.clear();
            std::cout << "\033[32m[Success] Logs cleared.\033[0m\n";
            pauseMenu();
        }
        else if (command == "7") {
            std::cout << "Shutting down server...\n";
            exit(0);
        } else {
            std::cout << "\033[31mInvalid option. Try again.\033[0m\n";
            pauseMenu();
        }
    }
}

int main() {
    clearScreen();
    std::cout << "\033[1;32m=== SECURE CHAT SERVER SETUP ===\033[0m\n";
    std::cout << "Enter access key to initialize server: ";
    std::getline(std::cin, server_access_key);

    if (server_access_key.empty()) {
        std::cout << "\033[31mAccess key cannot be empty. Exiting.\033[0m\n";
        return 1;
    }

    int listening = socket(AF_INET, SOCK_STREAM, 0);
    if (listening < 0) return 1;

    int opt = 1;
    setsockopt(listening, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in hint{};
    hint.sin_family = AF_INET;
    hint.sin_port = htons(PORT);
    hint.sin_addr.s_addr = INADDR_ANY;

    if (bind(listening, (sockaddr*)&hint, sizeof(hint)) < 0) return 1;
    if (listen(listening, SOMAXCONN) < 0) return 1;

    std::thread(server_menu).detach();

    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int clientSocket = accept(listening, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket < 0) continue;

        std::thread(handle_client, clientSocket).detach();
    }

    close(listening);
    return 0;
}