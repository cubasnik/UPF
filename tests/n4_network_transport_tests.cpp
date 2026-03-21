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

void run_udp_mock_server(int port) {
    if (!init_stack()) {
        return;
    }

    SocketType sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        return;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock);
        return;
    }

    for (int i = 0; i < 3; ++i) {
        char buffer[1024] {};
        sockaddr_in peer {};
        socklen_t peer_len = sizeof(peer);
        const int recv_len = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (recv_len <= 0) {
            continue;
        }
        buffer[recv_len] = '\0';

        const std::string request(buffer);
        std::string response;
        if (request.rfind("HEARTBEAT", 0) == 0) {
            response = "ALIVE";
        } else if (request.rfind("USAGE", 0) == 0) {
            response = "USAGE bytes_ul=10 bytes_dl=20 packets_ul=1 packets_dl=2";
        } else {
            response = "OK cause=RequestAccepted version=42 detail=applied";
        }

        sendto(sock, response.c_str(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
}

}  // namespace

int main() {
    constexpr int kPort = 39005;
    std::thread server(run_udp_mock_server, kPort);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkN4Adapter n4("127.0.0.1", kPort, 500);

    if (!n4.send_heartbeat()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto usage = n4.query_usage_report("001", "1");
    if (!usage.has_value() || usage->bytes_ul != 10 || usage->bytes_dl != 20) {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest req {};
    req.imsi = "001010123456789";
    req.pdu_session_id = "11";
    req.teid = "0x1100";
    req.ue_ipv4 = "10.11.0.2";

    const auto response = n4.apply_pfcp(req, upf::PfcpOperation::Establish);
    if (!response.success || response.cause != upf::PfcpCause::RequestAccepted || response.session_version != 42) {
        server.join();
        return EXIT_FAILURE;
    }

    server.join();
    return EXIT_SUCCESS;
}
