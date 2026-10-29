#include <iostream>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 54000
#define BUFFER_SIZE 1024

std::string global_key;

std::string xorCipher(std::string data, const std::string& key) {
    std::string output = data;
    for (size_t i = 0; i < data.size(); ++i) {
        output[i] = data[i] ^ key[i % key.size()];
    }
    return output;
}

void receive_messages(int sock) {
    char buffer[BUFFER_SIZE];
    while (true) {
        for (int i = 0; i < BUFFER_SIZE; ++i) buffer[i] = 0;
        int bytesReceived = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytesReceived <= 0) {
            std::cout << "\n\033[31mDisconnected from server.\033[0m\n";
            break;
        }

        std::string decrypted = xorCipher(std::string(buffer, bytesReceived), global_key);
        
        size_t bracket = decrypted.find(']');
        if (bracket != std::string::npos && decrypted[0] == '[') {
            std::string userPart = decrypted.substr(0, bracket + 1);
            std::string msgPart = decrypted.substr(bracket + 1);
            std::cout << "\n\033[33m" << userPart << "\033[37m" << msgPart << "\033[0m\n> ";
        } else {
            std::cout << "\n\033[36m" << decrypted << "\033[0m\n> ";
        }
        std::flush(std::cout);
    }
}

int main(int argc, char* argv[]) {
    std::string serverIP = "127.0.0.1";
    if (argc > 1) {
        serverIP = argv[1];
    }

    std::string username;
    std::cout << "Enter your username: ";
    std::cin >> username;
    std::cout << "Enter server access key: ";
    std::cin >> global_key;
    std::cin.ignore();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection failed.\n";
        close(sock);
        return 1;
    }

    std::string auth_raw = username + ":" + global_key;
    std::string auth_packet = xorCipher(auth_raw, global_key);
    send(sock, auth_packet.c_str(), auth_packet.size(), 0);

    char response_buf[BUFFER_SIZE];
    for (int i = 0; i < BUFFER_SIZE; ++i) response_buf[i] = 0;
    int resp_len = recv(sock, response_buf, BUFFER_SIZE, 0);
    if (resp_len <= 0) {
        std::cerr << "Authentication failed.\n";
        close(sock);
        return 1;
    }

    std::string response = xorCipher(std::string(response_buf, resp_len), global_key);
    if (response.rfind("AUTH_OK", 0) != 0) {
        std::cerr << "Incorrect access key or authentication rejected.\n";
        close(sock);
        return 1;
    }

    std::cout << "\033[32mConnected successfully! Type your messages below.\033[0m\n> ";

    std::thread recvThread(receive_messages, sock);
    recvThread.detach();

    std::string input;
    while (std::getline(std::cin, input)) {
        if (input.empty()) continue;
        std::string encrypted_msg = xorCipher(input, global_key);
        int sendResult = send(sock, encrypted_msg.c_str(), encrypted_msg.size(), 0);
        if (sendResult < 0) break;
        std::cout << "> ";
    }

    close(sock);
    return 0;
}