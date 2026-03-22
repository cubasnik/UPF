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

constexpr const char* kCustomImsi = "250200123450001";
constexpr const char* kCustomPdu = "21";
constexpr const char* kCustomPreset = "ims-ipv6";

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
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(2, "capabilities-ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2"));
            append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x0000000FU));
            response_type = PfcpMessageType::CapabilityExchangeResponse;
        } else if (request_type == PfcpMessageType::NodeFeaturesRequest) {
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(3, "node-features-ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x00000007U));
            response_type = PfcpMessageType::NodeFeaturesResponse;
        } else if (request_type == PfcpMessageType::HeartbeatRequest) {
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(4, "heartbeat-ok", 1));
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

std::string build_logged_command_with_input(const std::filesystem::path& binary,
                                            const std::string& args,
                                            const std::filesystem::path& input_path,
                                            const std::filesystem::path& log_path) {
#if defined(_WIN32)
    return "cmd /c \"" + quote_path(binary) +
           (args.empty() ? std::string() : " " + args) +
           " < " + quote_path(input_path) +
           " > " + quote_path(log_path) +
           " 2>&1\"";
#else
    return quote_path(binary) +
           (args.empty() ? std::string() : " " + args) +
           " < " + quote_path(input_path) +
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
    const std::filesystem::path upf_log = build_dir / "n6_runtime_interactive_upf.log";
    const std::filesystem::path command_file = build_dir / "n6_runtime_interactive_commands.txt";

    if (!std::filesystem::exists(upf_binary)) {
        return EXIT_FAILURE;
    }

    std::filesystem::current_path(build_dir);
    std::error_code ec;
    std::filesystem::remove(upf_log, ec);
    std::filesystem::remove(command_file, ec);

    {
        std::ofstream commands(command_file, std::ios::binary);
        commands << "help\n";
        commands << "show session-presets\n";
        commands << "show session-presets json\n";
        commands << "show session-matrix\n";
        commands << "show session-matrix json\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 json\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 tool-cmd\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 tool-cmd json\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 preset=" << kCustomPreset << "\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 preset=" << kCustomPreset << " tool-cmd json\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 compare=ims-ipv4,ims-ipv6\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 compare=ims-ipv4,ims-ipv6 json\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 999999999999999999999999999999 compare=ims-ipv4,ims-ipv6\n";
        commands << "show session-matrix 1440 " << kCustomImsi << ' ' << kCustomPdu << "\n";
        commands << "show session-compare " << kCustomImsi << ' ' << kCustomPdu << " 1440 compare=ims-ipv4,ims-ipv6\n";
        commands << "show session-compare " << kCustomImsi << ' ' << kCustomPdu << " 1440 compare=ims-ipv4,ims-ipv6 tool-cmd json\n";
        commands << "show session-compare 1440 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6\n";
        commands << "show session-compare abc " << kCustomPdu << " 1440 compare=ims-ipv4,ims-ipv6\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6 json\n";
        commands << "session validate tool-cmd 1440 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6 json\n";
        commands << "session validate json 1337 " << kCustomImsi << ' ' << kCustomPdu << " preset=" << kCustomPreset << "\n";
        commands << "session validate 1338 " << kCustomImsi << ' ' << kCustomPdu << " preset=" << kCustomPreset << " tool-cmd\n";
        commands << "session validate 999999999999999999999999999999 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6\n";
        commands << "session compare 1600 " << kCustomImsi << ' ' << kCustomPdu << " compare=internet-ipv4,enterprise-ethernet json\n";
        commands << "session compare json 1666 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6\n";
        commands << "session compare 1600 " << kCustomImsi << ' ' << kCustomPdu << " preset=ims-ipv6 compare=internet-ipv4,enterprise-ethernet\n";
        commands << "session compare 1600 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv6\n";
        commands << "session compare 1667 " << kCustomImsi << ' ' << kCustomPdu << " tool-cmd compare=ims-ipv4,ims-ipv6 json\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu << " preset=ims-ipv6 preset=ims-ipv4\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu << " dnn=ims profile=ipv6 profile=ipv4\n";
        commands << "session compare 1600 " << kCustomImsi << ' ' << kCustomPdu << " compare=ims-ipv4,ims-ipv6 compare=internet-ipv4,enterprise-ethernet\n";
        commands << "show session-matrix " << kCustomImsi << ' ' << kCustomPdu << " 1440 preset=ims-ipv6 preset=ims-ipv4\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu
             << " preset=" << kCustomPreset << "\n";
        commands << "session validate 1440 " << kCustomImsi << ' ' << kCustomPdu
             << " preset=" << kCustomPreset << " json\n";
        commands << "session validate tool-cmd 1440 " << kCustomImsi << ' ' << kCustomPdu
             << " preset=" << kCustomPreset << "\n";
        commands << "session validate tool-cmd 1440 " << kCustomImsi << ' ' << kCustomPdu
             << " preset=" << kCustomPreset << " json\n";
        commands << "session downlink 1440 " << kCustomImsi << " 999\n";
        commands << "session downlink-tool 1440 abc " << kCustomPdu << "\n";
        commands << "session downlink-tool 1440 " << kCustomImsi << " 999\n";
        commands << "session full-tool 1440 abc " << kCustomPdu << " preset=" << kCustomPreset << "\n";
        commands << "session full-tool 1440 " << kCustomImsi << " 999 preset=" << kCustomPreset << "\n";
        commands << "session full-tool 1440 " << kCustomImsi << ' ' << kCustomPdu
             << " preset=" << kCustomPreset << "\n";
        commands << "quit\n";
    }

    std::thread n4_server(run_n4_mock_server, 8805);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const std::string upf_command = build_logged_command_with_input(upf_binary,
                                                                    "--interactive",
                                                                    command_file,
                                                                    upf_log);
    const int upf_exit_code = std::system(upf_command.c_str());
    n4_server.join();

    if (upf_exit_code != 0) {
        return EXIT_FAILURE;
    }

    const std::string upf_output = read_all(upf_log);
    if (!contains(upf_output, "UPF interactive CLI") ||
        !contains(upf_output, "Compare Examples:") ||
        !contains(upf_output, "session compare 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6") ||
        !contains(upf_output, "show session-compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6") ||
        !contains(upf_output, "session-presets") ||
        !contains(upf_output, "ims-ipv6 -> dnn=ims profile=ipv6") ||
        !contains(upf_output, "\"schema\":\"upf.session-presets.v1\"") ||
        !contains(upf_output, "\"name\":\"ims-ipv6\"") ||
        !contains(upf_output, "\"dnn\":\"ims\"") ||
        !contains(upf_output, "\"profile\":\"ipv6\"") ||
        !contains(upf_output, "session-matrix imsi=250200123456789 pdu=10 bytes=1200") ||
        !contains(upf_output, "preset=enterprise-ethernet bytes=1200 imsi=250200123456789 pdu=10 dnn=enterprise profile=ethernet") ||
        !contains(upf_output, "\"schema\":\"upf.session-matrix.v1\"") ||
        !contains(upf_output, "\"preset\":\"enterprise-ethernet\"") ||
        !contains(upf_output, std::string("session-matrix imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440") ||
        !contains(upf_output, std::string("preset=ims-ipv6 bytes=1440 imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " dnn=ims profile=ipv6") ||
        !contains(upf_output, std::string("\"imsi\":\"") + kCustomImsi + '"') ||
        !contains(upf_output, std::string("\"pdu\":\"") + kCustomPdu + '"') ||
        !contains(upf_output, std::string("session-matrix imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440 tool-cmd") ||
        !contains(upf_output, std::string("preset=ims-ipv6 bytes=1440 imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " dnn=ims profile=ipv6 teid=") ||
        !contains(upf_output, std::string("preset=ims-ipv6 bytes=1440 imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " dnn=ims profile=ipv6") ||
        !contains(upf_output, "tool_path=") ||
        !contains(upf_output, "command=cmd /c") ||
        !contains(upf_output, "\"schema\":\"upf.session-matrix-tool-command.v1\"") ||
        !contains(upf_output, "\"tool_path\":") ||
        !contains(upf_output, "\"command\":") ||
        !contains(upf_output, std::string("session-matrix imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440 preset=" + kCustomPreset) ||
        !contains(upf_output, std::string("\"preset\":\"") + kCustomPreset + '"') ||
        !contains(upf_output, std::string("session-matrix imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440 compare=ims-ipv4,ims-ipv6") ||
        !contains(upf_output, "preset=ims-ipv4 bytes=1440") ||
        !contains(upf_output, "preset=ims-ipv6 bytes=1440") ||
        !contains(upf_output, "\"compare\":[\"ims-ipv4\",\"ims-ipv6\"]") ||
        !contains(upf_output, std::string("session-compare imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440 compare=ims-ipv4,ims-ipv6") ||
        !contains(upf_output, "\"schema\":\"upf.session-compare-tool-command.v1\"") ||
        !contains(upf_output, std::string("session-compare imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " bytes=1440 compare=ims-ipv4,ims-ipv6") ||
        !contains(upf_output, "\"schema\":\"upf.session-compare.v1\"") ||
        !contains(upf_output, "\"schema\":\"upf.session-compare-tool-command.v1\"") ||
        !contains(upf_output, std::string("\"bytes\":1337,\"imsi\":\"") + kCustomImsi + "\",\"pdu\":\"" + kCustomPdu + "\"") ||
        !contains(upf_output, std::string("bytes=1338 imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " dnn=ims profile=ipv6") ||
        !contains(upf_output, std::string("\"bytes\":1666,\"compare\":[\"ims-ipv4\",\"ims-ipv6\"]")) ||
        !contains(upf_output, std::string("\"bytes\":1667,\"compare\":[\"ims-ipv4\",\"ims-ipv6\"]")) ||
        !contains(upf_output, std::string("\"bytes\":1600,\"compare\":[\"internet-ipv4\",\"enterprise-ethernet\"]")) ||
        !contains(upf_output, "ERR: bytes must be an unsigned integer") ||
        !contains(upf_output, "ERR: imsi must contain only digits") ||
        !contains(upf_output, "ERR: pdu must be an unsigned integer in range 1..255") ||
        !contains(upf_output, "ERR: duplicate session option: preset") ||
        !contains(upf_output, "ERR: duplicate session option: profile") ||
        !contains(upf_output, "ERR: duplicate compare option") ||
        !contains(upf_output, "ERR: duplicate preset option") ||
        !contains(upf_output, "ERR: compare cannot be combined with preset, dnn, or profile") ||
        !contains(upf_output, "ERR: compare must be preset1,preset2") ||
        !contains(upf_output, std::string("bytes=1440 imsi=") + kCustomImsi + " pdu=" + kCustomPdu + " dnn=ims profile=ipv6") ||
        !contains(upf_output, std::string("request_id=session-") + kCustomImsi + '-' + kCustomPdu) ||
        !contains(upf_output, "\"schema\":\"upf.session-target.v1\"") ||
        !contains(upf_output, "\"bytes\":1440") ||
        !contains(upf_output, std::string("\"imsi\":\"") + kCustomImsi + '"') ||
        !contains(upf_output, std::string("\"pdu\":\"") + kCustomPdu + '"') ||
        !contains(upf_output, "\"dnn\":\"ims\"") ||
        !contains(upf_output, "\"profile\":\"ipv6\"") ||
        !contains(upf_output, std::string("\"request_id\":\"session-") + kCustomImsi + '-' + kCustomPdu + '"') ||
        !contains(upf_output, "tool_path=") ||
        !contains(upf_output, "config_path=") ||
        !contains(upf_output, "command=") ||
        !contains(upf_output, "n6_traffic_tool") ||
        !contains(upf_output, "--bytes 1440") ||
        !contains(upf_output, "--count 5 --interval-ms 120") ||
        !contains(upf_output, "\"schema\":\"upf.session-tool-command.v1\"") ||
        !contains(upf_output, "\"tool_path\":") ||
        !contains(upf_output, "\"config_path\":") ||
        !contains(upf_output, "\"command\":") ||
        !contains(upf_output, "Sent N6 payload") ||
        !contains(upf_output, std::string("imsi=") + kCustomImsi) ||
        !contains(upf_output, std::string("pdu=") + kCustomPdu) ||
        !contains(upf_output, "protocol=IPv6") ||
        !contains(upf_output, "count=5") ||
        !contains(upf_output, "[N3] Send GTP-U packet TEID=") ||
        !(contains(upf_output, "\r\nOK\r\n") || contains(upf_output, "\nOK\n")) ||
        contains(upf_output, "ERR: establish required") ||
        contains(upf_output, "ERR: n6_traffic_tool not found") ||
        contains(upf_output, "ERR: n6_traffic_tool failed") ||
        contains(upf_output, "ERR: downlink failed")) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}