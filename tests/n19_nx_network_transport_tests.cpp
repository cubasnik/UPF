#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
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

struct UdpCaptureState {
    std::mutex mutex;
    std::string payload;
};

void run_udp_capture_server(int port, UdpCaptureState* state) {
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

    char buffer[1024] {};
    sockaddr_in peer {};
    socklen_t peer_len = sizeof(peer);
    const int recv_len = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (recv_len > 0) {
        buffer[recv_len] = '\0';
        std::lock_guard<std::mutex> lock(state->mutex);
        state->payload = buffer;
    }

    close_socket(sock);
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

int main() {
    {
        constexpr int kN19Port = 39007;
        UdpCaptureState n19_state;
        std::thread n19_server(run_udp_capture_server, kN19Port, &n19_state);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));

        upf::NetworkN19Adapter n19("127.0.0.1:2152", true);
        if (!n19.is_enabled()) {
            n19_server.join();
            return EXIT_FAILURE;
        }
        if (n19.get_local_upf_endpoint() != "127.0.0.1:2152") {
            n19_server.join();
            return EXIT_FAILURE;
        }
        if (!n19.forward_to_local_upf("250200000000001", "9", "127.0.0.1:39007", 512)) {
            n19_server.join();
            return EXIT_FAILURE;
        }

        n19_server.join();
        {
            std::lock_guard<std::mutex> lock(n19_state.mutex);
            if (!contains(n19_state.payload, "N19_GTP_FWD") ||
                !contains(n19_state.payload, "imsi=250200000000001") ||
                !contains(n19_state.payload, "pdu=9") ||
                !contains(n19_state.payload, "bytes=512") ||
                !contains(n19_state.payload, "src=127.0.0.1:2152")) {
                return EXIT_FAILURE;
            }
        }

        upf::NetworkN19Adapter n19_disabled("127.0.0.1:2152", false);
        if (n19_disabled.forward_to_local_upf("001", "1", "127.0.0.1:39007", 1)) {
            return EXIT_FAILURE;
        }
        if (n19.forward_to_local_upf("001", "1", "127.0.0.1", 1)) {
            return EXIT_FAILURE;
        }
    }

    {
        constexpr int kNxPort = 39008;
        UdpCaptureState nx_state;
        std::thread nx_server(run_udp_capture_server, kNxPort, &nx_state);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));

        upf::NetworkNxAdapter nx(true);
        if (!nx.is_enabled()) {
            nx_server.join();
            return EXIT_FAILURE;
        }

        std::vector<upf::UplinkClassifierRule> rules;
        upf::UplinkClassifierRule low_priority {};
        low_priority.id = 2;
        low_priority.ue_subnet = "10.2.0.0/24";
        low_priority.target_upf_address = "127.0.0.1:39008";
        low_priority.precedence = 20;
        rules.push_back(low_priority);

        upf::UplinkClassifierRule high_priority {};
        high_priority.id = 1;
        high_priority.ue_subnet = "10.1.0.0/24";
        high_priority.target_upf_address = "127.0.0.1:39008";
        high_priority.precedence = 10;
        rules.push_back(high_priority);

        if (!nx.set_uplink_classifier_rules(rules)) {
            nx_server.join();
            return EXIT_FAILURE;
        }
        if (!nx.add_branch_upf_endpoint("branch-a", "127.0.0.1:39008")) {
            nx_server.join();
            return EXIT_FAILURE;
        }
        if (!nx.forward_uplink_classified("250200000000002", "10", "branch-a", 1024)) {
            nx_server.join();
            return EXIT_FAILURE;
        }

        nx_server.join();
        {
            std::lock_guard<std::mutex> lock(nx_state.mutex);
            if (!contains(nx_state.payload, "NX_UL_CLASSIFY") ||
                !contains(nx_state.payload, "imsi=250200000000002") ||
                !contains(nx_state.payload, "pdu=10") ||
                !contains(nx_state.payload, "bytes=1024") ||
                !contains(nx_state.payload, "target=127.0.0.1:39008")) {
                return EXIT_FAILURE;
            }
        }

        UdpCaptureState nx_fallback_state;
        std::thread nx_fallback_server(run_udp_capture_server, kNxPort, &nx_fallback_state);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        if (!nx.forward_uplink_classified("250200000000003", "11", "", 256)) {
            nx_fallback_server.join();
            return EXIT_FAILURE;
        }
        nx_fallback_server.join();
        {
            std::lock_guard<std::mutex> lock(nx_fallback_state.mutex);
            if (!contains(nx_fallback_state.payload, "imsi=250200000000003") ||
                !contains(nx_fallback_state.payload, "bytes=256") ||
                !contains(nx_fallback_state.payload, "target=127.0.0.1:39008")) {
                return EXIT_FAILURE;
            }
        }

        if (nx.add_branch_upf_endpoint("", "127.0.0.1:39008")) {
            return EXIT_FAILURE;
        }

        upf::NetworkNxAdapter nx_disabled(false);
        if (nx_disabled.forward_uplink_classified("001", "1", "127.0.0.1:39008", 1)) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}