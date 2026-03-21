#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

#include "upf/adapters/network_adapters.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

#if defined(_WIN32)
using SocketType = SOCKET;
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
#else
using SocketType = int;
constexpr SocketType kInvalidSocket = -1;
#endif

void close_socket(SocketType sock) {
#if defined(_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

bool init_stack() {
#if defined(_WIN32)
    WSADATA data {};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
}

void run_tcp_mock_server(int port) {
    if (!init_stack()) {
        return;
    }

    SocketType server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == kInvalidSocket) {
        return;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));

    if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(server);
        return;
    }

    if (listen(server, 1) != 0) {
        close_socket(server);
        return;
    }

    sockaddr_in client_addr {};
    socklen_t client_len = sizeof(client_addr);
    SocketType client = accept(server, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client == kInvalidSocket) {
        close_socket(server);
        return;
    }

    char buffer[1024] {};
    recv(client, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
    const char response[] = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
    send(client, response, static_cast<int>(std::strlen(response)), 0);

    close_socket(client);
    close_socket(server);
}

}  // namespace

int main() {
    constexpr int kPort = 39006;
    std::thread server(run_tcp_mock_server, kPort);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkSbiAdapter sbi("127.0.0.1", kPort, "/nupf-event-exposure/v1/events", 500);
    const bool ok = sbi.publish_event("nupf-event-exposure", "session-up");

    server.join();
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
