#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include "pfcp_test_wire.hpp"

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

using namespace test_pfcp_wire;

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

std::vector<std::uint8_t> encode_response_context(std::uint32_t session_version,
                                                  const std::string& detail,
                                                  std::uint32_t recovery_time_stamp = 0) {
    return test_pfcp::encode_response_context(1,
                                              detail,
                                              static_cast<std::uint64_t>(session_version),
                                              recovery_time_stamp == 0 ? std::optional<std::uint32_t> {} : std::optional<std::uint32_t> {recovery_time_stamp});
}

void run_n4_mock_server(int port) {
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
    for (int i = 0; i < 24 && idle_polls < 8; ++i) {
        char buffer[4096] {};
        sockaddr_in peer {};
        socklen_t peer_len = sizeof(peer);
        const int recv_len = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer)), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (recv_len <= 0) {
            ++idle_polls;
            continue;
        }
        idle_polls = 0;

        const auto request = decode_pfcp_message(buffer, recv_len);
        if (!request.has_value()) {
            continue;
        }

        std::vector<std::uint8_t> ies;
        PfcpMessageType response_type = PfcpMessageType::HeartbeatResponse;
        const PfcpMessageType request_type = request->message_type;
        if (request_type == PfcpMessageType::AssociationSetupRequest) {
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(1, "associated"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FSeid, encode_fseid_value(1, "127.0.0.2"));
            append_ie(&ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(1));
            response_type = PfcpMessageType::AssociationSetupResponse;
        } else if (request_type == PfcpMessageType::CapabilityExchangeRequest) {
            const auto feature_bitmap = first_ie_value(*request, PfcpIeType::FeatureBitmap);
            if (!feature_bitmap.has_value()) {
                continue;
            }
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(2, "capabilities-ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2"));
            append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x0000000FU));
            response_type = PfcpMessageType::CapabilityExchangeResponse;
        } else if (request_type == PfcpMessageType::NodeFeaturesRequest) {
            const auto feature_bitmap = first_ie_value(*request, PfcpIeType::FeatureBitmap);
            if (!feature_bitmap.has_value()) {
                continue;
            }
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(3, "node-features-ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x00000007U));
            response_type = PfcpMessageType::NodeFeaturesResponse;
        } else if (request_type == PfcpMessageType::HeartbeatRequest) {
            std::uint32_t recovery_time_stamp = 1;
            const auto recovery_time_stamp_ie = first_ie_value(*request, PfcpIeType::RecoveryTimeStamp);
            if (recovery_time_stamp_ie.has_value() && recovery_time_stamp_ie->size() == 4) {
                recovery_time_stamp = read_u32(*recovery_time_stamp_ie, 0);
            }
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(4, "heartbeat-ok", recovery_time_stamp));
            response_type = PfcpMessageType::HeartbeatResponse;
        } else if (request_type == PfcpMessageType::SessionEstablishmentRequest) {
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(1, "established"));
            response_type = PfcpMessageType::SessionEstablishmentResponse;
        } else if (request_type == PfcpMessageType::SessionDeletionRequest) {
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(2, "deleted"));
            response_type = PfcpMessageType::SessionDeletionResponse;
        } else {
            continue;
        }

        const std::string response = encode_pfcp_message(response_type,
                                                         request->has_seid,
                                                         ies,
                                                         std::vector<std::uint8_t>(buffer, buffer + recv_len));
        sendto(sock, response.data(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
}

std::filesystem::path locate_binary(const std::filesystem::path& build_dir, const std::string& stem) {
    const auto exe_path = build_dir / (stem + ".exe");
    if (std::filesystem::exists(exe_path)) {
        return exe_path;
    }
    return build_dir / stem;
}

std::string quote_path(const std::filesystem::path& path) {
    return '"' + path.string() + '"';
}

std::string build_logged_command(const std::filesystem::path& binary,
                                 const std::string& args,
                                 const std::filesystem::path& log_path) {
#if defined(_WIN32)
    return "cmd /c \"" + quote_path(binary) +
           (args.empty() ? std::string() : " " + args) +
           " > " + quote_path(log_path) +
           " 2>&1\"";
#else
    return quote_path(binary) +
           (args.empty() ? std::string() : " " + args) +
           " > " + quote_path(log_path) +
           " 2>&1";
#endif
}

std::string read_all(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
}

bool contains(const std::string& text, const std::string& needle) {
    return text.find(needle) != std::string::npos;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc <= 0) {
        return EXIT_FAILURE;
    }

    const std::filesystem::path build_dir = std::filesystem::absolute(argv[0]).parent_path();
    const std::filesystem::path upf_binary = locate_binary(build_dir, "upf");
    const std::filesystem::path tool_binary = locate_binary(build_dir, "n6_traffic_tool");
    const std::filesystem::path upf_log = build_dir / "n6_runtime_upf.log";
    const std::filesystem::path tool_log = build_dir / "n6_runtime_tool.log";

    if (!std::filesystem::exists(upf_binary) || !std::filesystem::exists(tool_binary)) {
        return EXIT_FAILURE;
    }

    std::filesystem::current_path(build_dir);
    std::error_code ec;
    std::filesystem::remove(upf_log, ec);
    std::filesystem::remove(tool_log, ec);

    std::thread n4_server(run_n4_mock_server, 8805);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    int tool_exit_code = EXIT_FAILURE;
    std::thread tool_thread([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const std::string tool_command = build_logged_command(tool_binary,
                                                              "--delay-ms 200 --bytes 1440 --count 5 --interval-ms 120",
                                                              tool_log);
        tool_exit_code = std::system(tool_command.c_str());
    });

    const std::string upf_command = build_logged_command(upf_binary, std::string(), upf_log);
    const int upf_exit_code = std::system(upf_command.c_str());
    tool_thread.join();
    n4_server.join();

    if (upf_exit_code != 0 || tool_exit_code != 0) {
        return EXIT_FAILURE;
    }

    const std::string upf_output = read_all(upf_log);
    const std::string tool_output = read_all(tool_log);
    if (!contains(upf_output, "N6 downlink=delivered")) {
        return EXIT_FAILURE;
    }
    if (!contains(tool_output, "Using config:") || !contains(tool_output, "Sent N6 payload") || !contains(tool_output, "count=5")) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}