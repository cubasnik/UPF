#include <atomic>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "upf/protocol/pfcp_wire.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
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

std::atomic<bool> g_running {true};

void handle_signal(int) {
    g_running = false;
}

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

std::string session_key(const upf::pfcp::PfcpParsedMessage& request) {
    return upf::pfcp::first_ie_string(request, upf::pfcp::PfcpIeType::Imsi) + ":" +
           upf::pfcp::first_ie_string(request, upf::pfcp::PfcpIeType::PduSessionId);
}

std::string make_response(const upf::pfcp::PfcpParsedMessage& request,
                          upf::pfcp::PfcpMessageType response_type,
                          upf::PfcpCause cause,
                          std::uint64_t session_version,
                          const std::string& detail,
                          std::uint32_t recovery_time_stamp,
                          bool include_node_id,
                          bool include_fseid,
                          bool include_recovery_time,
                          bool include_feature_bitmap,
                          std::uint32_t feature_bitmap) {
    std::vector<std::uint8_t> ies;
    upf::pfcp::append_ie(&ies,
                         upf::pfcp::PfcpIeType::ResponseContext,
                         upf::pfcp::encode_response_context_group(cause, session_version, detail, recovery_time_stamp));
    if (include_node_id) {
        upf::pfcp::append_ie(&ies, upf::pfcp::PfcpIeType::NodeId, upf::pfcp::encode_node_id_ie_value("smf-peer"));
    }
    if (include_fseid) {
        const std::uint64_t seid = response_type == upf::pfcp::PfcpMessageType::CapabilityExchangeResponse ? 2U : 1U;
        upf::pfcp::append_ie(&ies, upf::pfcp::PfcpIeType::FSeid, upf::pfcp::encode_fseid_ie_value(seid, "127.0.0.2"));
    }
    if (include_recovery_time) {
        upf::pfcp::append_ie(&ies,
                             upf::pfcp::PfcpIeType::RecoveryTimeStamp,
                             upf::pfcp::encode_recovery_time_stamp_ie_value(recovery_time_stamp));
    }
    if (include_feature_bitmap) {
        upf::pfcp::append_ie_u32(&ies, upf::pfcp::PfcpIeType::FeatureBitmap, feature_bitmap);
    }
    return upf::pfcp::encode_pfcp_message(response_type,
                                          request.has_seid,
                                          request.has_seid ? request.seid : 0,
                                          request.sequence,
                                          ies);
}

}  // namespace

int main(int argc, char* argv[]) {
    int port = 8805;
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: n4_mock_peer.exe [--port <port>]\n";
            return 0;
        }
        if (arg == "--port" && index + 1 < argc) {
            port = std::stoi(argv[++index]);
        }
    }

    if (!init_stack()) {
        std::cerr << "Failed to initialize network stack\n";
        return 1;
    }

    std::signal(SIGINT, handle_signal);

    SocketType sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        std::cerr << "Failed to create UDP socket\n";
        return 1;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "Failed to bind 127.0.0.1:" << port << "\n";
        close_socket(sock);
        return 1;
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

    std::unordered_map<std::string, std::uint64_t> session_versions;
    std::uint32_t recovery_time_stamp = 1;

    std::cout << "N4 mock peer listening on 127.0.0.1:" << port << "\n";
    while (g_running) {
        char buffer[4096] {};
        sockaddr_in peer {};
        socklen_t peer_len = sizeof(peer);
        const int recv_len = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer)), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (recv_len <= 0) {
            continue;
        }

        const auto request = upf::pfcp::decode_pfcp_message(std::string(buffer, buffer + recv_len));
        if (!request.has_value()) {
            continue;
        }

        std::string response;
        switch (request->message_type) {
            case upf::pfcp::PfcpMessageType::AssociationSetupRequest:
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::AssociationSetupResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         1,
                                         "associated",
                                         recovery_time_stamp,
                                         true,
                                         true,
                                         true,
                                         false,
                                         0);
                break;
            case upf::pfcp::PfcpMessageType::CapabilityExchangeRequest:
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::CapabilityExchangeResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         2,
                                         "capabilities-ok",
                                         0,
                                         true,
                                         true,
                                         false,
                                         true,
                                         0x0000000FU);
                break;
            case upf::pfcp::PfcpMessageType::NodeFeaturesRequest:
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::NodeFeaturesResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         3,
                                         "node-features-ok",
                                         0,
                                         true,
                                         false,
                                         false,
                                         true,
                                         0x00000007U);
                break;
            case upf::pfcp::PfcpMessageType::HeartbeatRequest:
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::HeartbeatResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         4,
                                         "heartbeat-ok",
                                         recovery_time_stamp,
                                         false,
                                         false,
                                         false,
                                         false,
                                         0);
                break;
            case upf::pfcp::PfcpMessageType::SessionEstablishmentRequest: {
                const auto key = session_key(*request);
                const std::uint64_t version = ++session_versions[key];
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::SessionEstablishmentResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         version,
                                         "established",
                                         0,
                                         false,
                                         false,
                                         false,
                                         false,
                                         0);
                break;
            }
            case upf::pfcp::PfcpMessageType::SessionModificationRequest: {
                const auto key = session_key(*request);
                const std::uint64_t version = ++session_versions[key];
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::SessionModificationResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         version,
                                         "modified",
                                         0,
                                         false,
                                         false,
                                         false,
                                         false,
                                         0);
                break;
            }
            case upf::pfcp::PfcpMessageType::SessionDeletionRequest: {
                const auto key = session_key(*request);
                const std::uint64_t version = ++session_versions[key];
                session_versions.erase(key);
                response = make_response(*request,
                                         upf::pfcp::PfcpMessageType::SessionDeletionResponse,
                                         upf::PfcpCause::RequestAccepted,
                                         version,
                                         "deleted",
                                         0,
                                         false,
                                         false,
                                         false,
                                         false,
                                         0);
                break;
            }
            default:
                continue;
        }

        sendto(sock, response.data(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
    return 0;
}