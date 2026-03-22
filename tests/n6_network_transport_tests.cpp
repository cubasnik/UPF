#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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

struct CaptureState {
    std::mutex mutex;
    std::vector<std::string> payloads;
};

void run_udp_capture_server(int port, CaptureState* state, int expected_messages) {
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

#if defined(_WIN32)
    const DWORD timeout = static_cast<DWORD>(250);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval tv {};
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    int idle_polls = 0;
    while (idle_polls < 8) {
        char buffer[2048] {};
        sockaddr_in peer {};
        socklen_t peer_len = sizeof(peer);
        const int recv_len = recvfrom(sock,
                                      buffer,
                                      static_cast<int>(sizeof(buffer) - 1),
                                      0,
                                      reinterpret_cast<sockaddr*>(&peer),
                                      &peer_len);
        if (recv_len <= 0) {
            ++idle_polls;
            continue;
        }

        idle_polls = 0;
        buffer[recv_len] = '\0';
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            state->payloads.emplace_back(buffer);
            if (static_cast<int>(state->payloads.size()) >= expected_messages) {
                break;
            }
        }
    }

    close_socket(sock);
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool send_udp_payload(const std::string& host, int port, const std::string& payload) {
    if (!init_stack()) {
        return false;
    }

    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    const std::string port_text = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result) != 0 || result == nullptr) {
        return false;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return false;
    }

    const int sent = sendto(sock,
                            payload.c_str(),
                            static_cast<int>(payload.size()),
                            0,
                            result->ai_addr,
                            static_cast<int>(result->ai_addrlen));
    close_socket(sock);
    freeaddrinfo(result);
    return sent == static_cast<int>(payload.size());
}

}  // namespace

int main() {
    constexpr int kRemotePort = 39009;
    constexpr int kBindPort = 39010;
    CaptureState capture;
    std::thread server(run_udp_capture_server, kRemotePort, &capture, 3);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkN6Adapter n6("127.0.0.1", kRemotePort, "127.0.0.1:39010", 150, 1, "drop_newest");

    upf::N6SessionContext ipv4_session {};
    ipv4_session.imsi = "250200000000061";
    ipv4_session.pdu_session_id = "61";
    ipv4_session.dnn = "internet";
    ipv4_session.ue_ipv4 = "10.61.0.2";
    if (!n6.register_session(ipv4_session)) {
        server.join();
        return EXIT_FAILURE;
    }
    if (!n6.forward_to_data_network(ipv4_session.imsi, ipv4_session.pdu_session_id, 128)) {
        server.join();
        return EXIT_FAILURE;
    }

    upf::N6SessionContext ipv6_session {};
    ipv6_session.imsi = "250200000000062";
    ipv6_session.pdu_session_id = "62";
    ipv6_session.dnn = "ims";
    ipv6_session.ue_ipv6 = "2001:db8:62::2";
    ipv6_session.ipv6_enabled = true;
    if (!n6.register_session(ipv6_session)) {
        server.join();
        return EXIT_FAILURE;
    }
    if (!n6.forward_to_data_network(ipv6_session.imsi, ipv6_session.pdu_session_id, 256)) {
        server.join();
        return EXIT_FAILURE;
    }

    upf::N6SessionContext ethernet_session {};
    ethernet_session.imsi = "250200000000063";
    ethernet_session.pdu_session_id = "63";
    ethernet_session.dnn = "enterprise";
    ethernet_session.ue_mac = "02:11:22:33:44:55";
    ethernet_session.ethernet_enabled = true;
    if (!n6.register_session(ethernet_session)) {
        server.join();
        return EXIT_FAILURE;
    }
    if (!n6.forward_to_data_network(ethernet_session.imsi, ethernet_session.pdu_session_id, 64)) {
        server.join();
        return EXIT_FAILURE;
    }

    server.join();

    std::vector<std::string> payloads;
    {
        std::lock_guard<std::mutex> lock(capture.mutex);
        payloads = capture.payloads;
    }

    if (payloads.size() != 3) {
        return EXIT_FAILURE;
    }
    if (!contains(payloads[0], "protocol=IPv4") ||
        !contains(payloads[0], "imsi=250200000000061") ||
        !contains(payloads[0], "src_ipv4=10.61.0.2") ||
        !contains(payloads[0], "dst_ipv4=8.8.8.8")) {
        return EXIT_FAILURE;
    }
    if (!contains(payloads[1], "protocol=IPv6") ||
        !contains(payloads[1], "imsi=250200000000062") ||
        !contains(payloads[1], "src_ipv6=2001:db8:62::2") ||
        !contains(payloads[1], "dst_ipv6=2001:db8:1::10")) {
        return EXIT_FAILURE;
    }
    if (!contains(payloads[2], "protocol=Ethernet") ||
        !contains(payloads[2], "imsi=250200000000063") ||
        !contains(payloads[2], "src_mac=02:11:22:33:44:55") ||
        !contains(payloads[2], "dst_mac=02:00:00:00:00:01") ||
        !contains(payloads[2], "ether_type=2048")) {
        return EXIT_FAILURE;
    }

    const auto history = n6.get_forward_history();
    if (history.size() != 3) {
        return EXIT_FAILURE;
    }
    if (history[0].direction != upf::N6TrafficDirection::Uplink || history[0].packet.protocol != upf::N6Protocol::IPv4 || history[0].wire_bytes != 148) {
        return EXIT_FAILURE;
    }
    if (history[1].direction != upf::N6TrafficDirection::Uplink || history[1].packet.protocol != upf::N6Protocol::IPv6 || history[1].wire_bytes != 296) {
        return EXIT_FAILURE;
    }
    if (history[2].direction != upf::N6TrafficDirection::Uplink || history[2].packet.protocol != upf::N6Protocol::Ethernet || history[2].wire_bytes != 78) {
        return EXIT_FAILURE;
    }

    const auto empty_downlink_start = std::chrono::steady_clock::now();
    const auto empty_downlink = n6.receive_from_data_network(ipv6_session.imsi, ipv6_session.pdu_session_id, 32);
    const auto empty_downlink_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - empty_downlink_start);
    if (empty_downlink.has_value() || empty_downlink_elapsed.count() < 120) {
        return EXIT_FAILURE;
    }

    if (!send_udp_payload("127.0.0.1",
                          kBindPort,
                          "N6 protocol=IPv6 imsi=250200000099999 pdu=99 dnn=ims payload_bytes=32 src_ipv6=2001:db8:dead::1 dst_ipv6=2001:db8:99::2")) {
        return EXIT_FAILURE;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    if (!send_udp_payload("127.0.0.1",
                          kBindPort,
                          "N6 protocol=IPv6 imsi=250200000000062 pdu=62 dnn=ims payload_bytes=96 src_ipv6=2001:db8:feed::1 dst_ipv6=2001:db8:62::2")) {
        return EXIT_FAILURE;
    }
    if (!send_udp_payload("127.0.0.1",
                          kBindPort,
                          "N6 protocol=IPv6 imsi=250200000000062 pdu=62 dnn=ims payload_bytes=112 src_ipv6=2001:db8:feed::2 dst_ipv6=2001:db8:62::2")) {
        return EXIT_FAILURE;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    const auto buffer_status = n6.get_buffer_status();
    if (buffer_status.per_session_capacity != 1 ||
        buffer_status.overflow_policy != upf::N6BufferOverflowPolicy::DropNewest ||
        buffer_status.buffered_packets != 1 ||
        buffer_status.dropped_unknown_session != 1 ||
        buffer_status.dropped_overflow_newest != 1 ||
        buffer_status.rejected_by_policy != 1) {
        return EXIT_FAILURE;
    }

    const auto downlink = n6.receive_from_data_network(ipv6_session.imsi, ipv6_session.pdu_session_id, 96);
    if (!downlink.has_value() || downlink->protocol != upf::N6Protocol::IPv6 || downlink->destination_ipv6 != ipv6_session.ue_ipv6 || downlink->source_ipv6 != "2001:db8:feed::1") {
        return EXIT_FAILURE;
    }

    const auto history_after_downlink = n6.get_forward_history();
    if (history_after_downlink.size() != 4 || history_after_downlink.back().direction != upf::N6TrafficDirection::Downlink) {
        return EXIT_FAILURE;
    }

    ipv6_session.dnn = "enterprise";
    if (!n6.update_session(ipv6_session)) {
        return EXIT_FAILURE;
    }
    const auto updated_ipv6 = n6.get_session(ipv6_session.imsi, ipv6_session.pdu_session_id);
    if (!updated_ipv6.has_value() || updated_ipv6->dnn != "enterprise") {
        return EXIT_FAILURE;
    }

    if (!n6.remove_session(ipv4_session.imsi, ipv4_session.pdu_session_id)) {
        return EXIT_FAILURE;
    }
    if (n6.forward_to_data_network(ipv4_session.imsi, ipv4_session.pdu_session_id, 1)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}