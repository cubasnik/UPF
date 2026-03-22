#include <chrono>
#include <cstdlib>
#include <cstring>
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

bool send_udp_datagram(int port, const std::vector<std::uint8_t>& bytes) {
    if (!init_stack()) {
        return false;
    }

    SocketType sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        return false;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));

    const int sent = sendto(sock,
                            reinterpret_cast<const char*>(bytes.data()),
                            static_cast<int>(bytes.size()),
                            0,
                            reinterpret_cast<sockaddr*>(&addr),
                            sizeof(addr));
    close_socket(sock);
    return sent == static_cast<int>(bytes.size());
}

std::vector<std::uint8_t> send_udp_and_receive(int port, const std::vector<std::uint8_t>& bytes, int timeout_ms) {
    std::vector<std::uint8_t> response;

    if (!init_stack()) {
        return response;
    }

    SocketType sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        return response;
    }

    sockaddr_in local_addr {};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    local_addr.sin_port = htons(0);
    if (bind(sock, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) != 0) {
        close_socket(sock);
        return response;
    }

#if defined(_WIN32)
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval tv {};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    sockaddr_in remote_addr {};
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    remote_addr.sin_port = htons(static_cast<unsigned short>(port));

    const int sent = sendto(sock,
                            reinterpret_cast<const char*>(bytes.data()),
                            static_cast<int>(bytes.size()),
                            0,
                            reinterpret_cast<sockaddr*>(&remote_addr),
                            sizeof(remote_addr));
    if (sent != static_cast<int>(bytes.size())) {
        close_socket(sock);
        return response;
    }

    std::vector<std::uint8_t> buffer(1024);
    sockaddr_in peer {};
    socklen_t peer_len = sizeof(peer);
    const int recv_len = recvfrom(sock,
                                  reinterpret_cast<char*>(buffer.data()),
                                  static_cast<int>(buffer.size()),
                                  0,
                                  reinterpret_cast<sockaddr*>(&peer),
                                  &peer_len);
    if (recv_len > 0) {
        response.assign(buffer.begin(), buffer.begin() + recv_len);
    }

    close_socket(sock);
    return response;
}

struct CaptureResult {
    std::vector<std::uint8_t> bytes;
};

void run_udp_capture_server(int port, CaptureResult* out) {
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

    std::vector<std::uint8_t> buf(2048);
    sockaddr_in peer {};
    socklen_t peer_len = sizeof(peer);
    const int recv_len = recvfrom(sock,
                                  reinterpret_cast<char*>(buf.data()),
                                  static_cast<int>(buf.size()),
                                  0,
                                  reinterpret_cast<sockaddr*>(&peer),
                                  &peer_len);

    if (recv_len > 0) {
        out->bytes.assign(buf.begin(), buf.begin() + recv_len);
    }

    close_socket(sock);
}

}  // namespace

int main() {
    constexpr int kListenPort = 39252;
    constexpr int kCapturePort = 39253;
    constexpr std::uint32_t kTeid = 0xABC;

    upf::NetworkN3Adapter n3;
    upf::N3TunnelContext tunnel {};
    tunnel.teid = kTeid;
    tunnel.ue_ip = "10.20.0.2";
    tunnel.gnb_ip = "127.0.0.1";
    tunnel.gnb_port = static_cast<std::uint16_t>(kCapturePort);
    tunnel.imsi = "250200999999999";
    tunnel.pdu_session_id = "20";

    if (!n3.create_tunnel(tunnel)) {
        return EXIT_FAILURE;
    }
    if (!n3.start_listening(static_cast<std::uint16_t>(kListenPort))) {
        return EXIT_FAILURE;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // Valid UL packet with S flag and optional 4-byte part.
    std::vector<std::uint8_t> ul_packet {
        0x32, 0xFF,              // V1/PT + S flag, T-PDU
        0x00, 0x07,              // Message length = 4(optional) + 3(payload)
        0x00, 0x00, 0x0A, 0xBC,  // TEID
        0x00, 0x01, 0x00, 0x00,  // Optional 4 bytes (seq=1, n-pdu=0, next ext=0)
        0xAA, 0xBB, 0xCC         // Payload
    };

    if (!send_udp_datagram(kListenPort, ul_packet)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // Valid UL packet with E flag and one extension header chain element.
    std::vector<std::uint8_t> ul_packet_with_ext {
        0x34, 0xFF,              // V1/PT + E flag, T-PDU
        0x00, 0x0D,              // Message length = 4(optional) + 6(ext) + 3(payload)
        0x00, 0x00, 0x0A, 0xBC,  // TEID
        0x00, 0x02, 0x00, 0x85,  // Optional 4 bytes, next extension type=0x85
        0x01,                    // Extension length units
        0x11, 0x22, 0x33, 0x44,  // Extension content
        0x00,                    // Next extension type = no more extensions
        0x10, 0x20, 0x30         // Payload
    };
    if (!send_udp_datagram(kListenPort, ul_packet_with_ext)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // Echo request and Error Indication should be ignored for UL user traffic stats.
    std::vector<std::uint8_t> echo_request {
        0x30, 0x01,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    const auto echo_response = send_udp_and_receive(kListenPort, echo_request, 300);
    if (echo_response.size() < 8) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }
    if (echo_response[1] != 0x02) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }
    const std::uint16_t echo_len = static_cast<std::uint16_t>((echo_response[2] << 8) | echo_response[3]);
    if (echo_len != 0) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    std::vector<std::uint8_t> error_indication {
        0x30, 0x1A,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    if (!send_udp_datagram(kListenPort, error_indication)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // Supported Extension Headers Notification is control-plane and should not count as UL data.
    std::vector<std::uint8_t> supported_ext_headers_notification {
        0x30, 0x1F,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    if (!send_udp_datagram(kListenPort, supported_ext_headers_notification)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // G-PDU with TEID=0 is invalid and must be ignored.
    std::vector<std::uint8_t> data_packet_teid_zero {
        0x30, 0xFF,
        0x00, 0x03,
        0x00, 0x00, 0x00, 0x00,
        0x55, 0x66, 0x77
    };
    if (!send_udp_datagram(kListenPort, data_packet_teid_zero)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // Malformed packet with E flag and truncated extension header.
    std::vector<std::uint8_t> malformed_extension {
        0x34, 0xFF,
        0x00, 0x09,
        0x00, 0x00, 0x0A, 0xBC,
        0x00, 0x03, 0x00, 0x85,
        0x02, 0x99
    };
    if (!send_udp_datagram(kListenPort, malformed_extension)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    // Malformed packet: advertised length exceeds received bytes, should be ignored.
    std::vector<std::uint8_t> malformed {
        0x30, 0xFF,
        0x00, 0x20,
        0x00, 0x00, 0x0A, 0xBC,
        0xDE, 0xAD
    };
    if (!send_udp_datagram(kListenPort, malformed)) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    upf::UsageReport ul_usage;
    upf::NetworkN3Adapter::ControlPlaneStats cp_stats;
    for (int attempt = 0; attempt < 30; ++attempt) {
        ul_usage = n3.get_tunnel_usage(kTeid);
        cp_stats = n3.get_control_plane_stats();
        if (ul_usage.packets_ul == 2 && ul_usage.bytes_ul == 6 &&
            cp_stats.echo_requests_rx == 1 &&
            cp_stats.echo_responses_tx == 1 &&
            cp_stats.supported_ext_headers_notifications_rx == 1 &&
            cp_stats.error_indications_rx == 1) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    if (ul_usage.packets_ul != 2 || ul_usage.bytes_ul != 6) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    if (cp_stats.echo_requests_rx != 1 ||
        cp_stats.echo_responses_tx != 1 ||
        cp_stats.supported_ext_headers_notifications_rx != 1 ||
        cp_stats.error_indications_rx != 1) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    if (n3.send_gtp_u_packet(0, {0x01, 0x02}).has_value()) {
        n3.stop_listening();
        return EXIT_FAILURE;
    }

    CaptureResult capture;
    std::thread server(run_udp_capture_server, kCapturePort, &capture);
    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    std::vector<std::uint8_t> dl_payload {0x01, 0x02, 0x03, 0x04, 0x05};
    const auto dl_packet = n3.send_gtp_u_packet(kTeid, dl_payload);
    if (!dl_packet.has_value()) {
        n3.stop_listening();
        server.join();
        return EXIT_FAILURE;
    }

    server.join();
    n3.stop_listening();

    const upf::UsageReport dl_usage = n3.get_tunnel_usage(kTeid);
    if (dl_usage.packets_dl != 1 || dl_usage.bytes_dl != dl_payload.size()) {
        return EXIT_FAILURE;
    }

    if (capture.bytes.size() < 13) {
        return EXIT_FAILURE;
    }
    if (capture.bytes[1] != 0xFF) {
        return EXIT_FAILURE;
    }

    const std::uint16_t message_length = static_cast<std::uint16_t>((capture.bytes[2] << 8) | capture.bytes[3]);
    if (message_length != dl_payload.size()) {
        return EXIT_FAILURE;
    }

    const std::uint32_t captured_teid = (static_cast<std::uint32_t>(capture.bytes[4]) << 24) |
                                        (static_cast<std::uint32_t>(capture.bytes[5]) << 16) |
                                        (static_cast<std::uint32_t>(capture.bytes[6]) << 8) |
                                        static_cast<std::uint32_t>(capture.bytes[7]);
    if (captured_teid != kTeid) {
        return EXIT_FAILURE;
    }

    if (std::memcmp(capture.bytes.data() + 8, dl_payload.data(), dl_payload.size()) != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}