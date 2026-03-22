#include <chrono>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "upf/config/runtime_config.hpp"

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

bool ensure_network_stack() {
#if defined(_WIN32)
    static bool initialized = false;
    static bool ok = false;
    if (!initialized) {
        WSADATA data {};
        ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
        initialized = true;
    }
    return ok;
#else
    return true;
#endif
}

bool parse_endpoint(const std::string& endpoint, std::string* out_host, int* out_port) {
    if (out_host == nullptr || out_port == nullptr || endpoint.empty()) {
        return false;
    }

    const std::size_t separator = endpoint.rfind(':');
    if (separator == std::string::npos) {
        return false;
    }

    char* end = nullptr;
    const long port = std::strtol(endpoint.substr(separator + 1).c_str(), &end, 10);
    if (end == nullptr || *end != '\0' || port <= 0 || port > 65535) {
        return false;
    }

    *out_host = endpoint.substr(0, separator);
    *out_port = static_cast<int>(port);
    return true;
}

std::optional<std::filesystem::path> resolve_config_path(const std::string& argv0,
                                                         const std::optional<std::string>& explicit_path) {
    if (explicit_path.has_value()) {
        const std::filesystem::path configured(*explicit_path);
        if (std::filesystem::exists(configured)) {
            return configured;
        }
    }

    std::vector<std::filesystem::path> candidates;
    const auto cwd = std::filesystem::current_path();
    candidates.push_back(cwd / "config" / "upf-config.yaml");
    candidates.push_back(cwd.parent_path() / "config" / "upf-config.yaml");

    if (!argv0.empty()) {
        const auto exe_dir = std::filesystem::absolute(std::filesystem::path(argv0)).parent_path();
        candidates.push_back(exe_dir / "config" / "upf-config.yaml");
        candidates.push_back(exe_dir.parent_path() / "config" / "upf-config.yaml");
    }

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::string normalize_destination_host(std::string host) {
    if (host.empty() || host == "0.0.0.0") {
        return "127.0.0.1";
    }
    if (host == "::" || host == "[::]") {
        return "::1";
    }
    return host;
}

std::string normalize_protocol(std::string protocol) {
    for (char& ch : protocol) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (protocol == "ipv6") {
        return "IPv6";
    }
    if (protocol == "ethernet") {
        return "Ethernet";
    }
    return "IPv4";
}

std::string default_source_for_protocol(const std::string& protocol) {
    if (protocol == "IPv6") {
        return "2001:db8:ffff::10";
    }
    if (protocol == "Ethernet") {
        return "02:00:00:00:00:01";
    }
    return "8.8.8.8";
}

std::string default_destination_for_protocol(const std::string& protocol) {
    if (protocol == "IPv6") {
        return "2001:db8:10::2";
    }
    if (protocol == "Ethernet") {
        return "02:10:10:00:00:02";
    }
    return "10.10.0.2";
}

std::string build_payload(const std::string& protocol,
                          const std::string& imsi,
                          const std::string& pdu_session_id,
                          const std::string& dnn,
                          std::size_t payload_bytes,
                          const std::string& source,
                          const std::string& destination) {
    std::ostringstream payload;
    payload << "N6 protocol=" << protocol
            << " imsi=" << imsi
            << " pdu=" << pdu_session_id
            << " dnn=" << dnn
            << " payload_bytes=" << payload_bytes;

    if (protocol == "IPv6") {
        payload << " src_ipv6=" << source
                << " dst_ipv6=" << destination;
    } else if (protocol == "Ethernet") {
        payload << " src_mac=" << source
                << " dst_mac=" << destination
                << " ether_type=2048";
    } else {
        payload << " src_ipv4=" << source
                << " dst_ipv4=" << destination;
    }

    return payload.str();
}

bool send_payload_to_endpoint(const std::string& endpoint, const std::string& payload) {
    if (!ensure_network_stack()) {
        return false;
    }

    std::string host;
    int port = 0;
    if (!parse_endpoint(endpoint, &host, &port)) {
        return false;
    }
    host = normalize_destination_host(host);

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

int main(int argc, char** argv) {
    std::optional<std::string> config_path;
    std::string endpoint;
    std::string imsi = "250200123456789";
    std::string pdu_session_id = "10";
    std::string dnn = "internet";
    std::string protocol;
    std::string source;
    std::string destination;
    std::size_t payload_bytes = 1200;
    int delay_ms = 0;
    int count = 1;
    int interval_ms = 0;

    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        auto read_value = [&](const char* name, std::string* target) -> bool {
            if (index + 1 >= argc || target == nullptr) {
                std::cerr << "Missing value for " << name << "\n";
                return false;
            }
            *target = argv[++index];
            return true;
        };

        auto read_int = [&](const char* name, int* target) -> bool {
            std::string value;
            if (!read_value(name, &value) || target == nullptr) {
                return false;
            }
            *target = static_cast<int>(std::strtol(value.c_str(), nullptr, 10));
            return true;
        };

        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: n6_traffic_tool.exe [--config <path>] [--endpoint <host:port>] [--imsi <imsi>] [--pdu <id>] [--dnn <dnn>] [--protocol <ipv4|ipv6|ethernet>] [--src <addr>] [--dst <addr>] [--bytes <n>] [--delay-ms <n>] [--count <n>] [--interval-ms <n>]\n";
            return EXIT_SUCCESS;
        }

        if (arg == "--config") {
            std::string value;
            if (!read_value("--config", &value)) {
                return EXIT_FAILURE;
            }
            config_path = value;
        } else if (arg == "--endpoint") {
            if (!read_value("--endpoint", &endpoint)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--imsi") {
            if (!read_value("--imsi", &imsi)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--pdu") {
            if (!read_value("--pdu", &pdu_session_id)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--dnn") {
            if (!read_value("--dnn", &dnn)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--protocol") {
            if (!read_value("--protocol", &protocol)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--src") {
            if (!read_value("--src", &source)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--dst") {
            if (!read_value("--dst", &destination)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--bytes") {
            std::string value;
            if (!read_value("--bytes", &value)) {
                return EXIT_FAILURE;
            }
            payload_bytes = static_cast<std::size_t>(std::strtoull(value.c_str(), nullptr, 10));
        } else if (arg == "--delay-ms") {
            if (!read_int("--delay-ms", &delay_ms)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--count") {
            if (!read_int("--count", &count)) {
                return EXIT_FAILURE;
            }
        } else if (arg == "--interval-ms") {
            if (!read_int("--interval-ms", &interval_ms)) {
                return EXIT_FAILURE;
            }
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return EXIT_FAILURE;
        }
    }

    count = std::max(1, count);
    interval_ms = std::max(0, interval_ms);

    const auto resolved_config = resolve_config_path(argc > 0 ? argv[0] : std::string(), config_path);
    const upf::RuntimeConfig cfg = upf::load_runtime_config(resolved_config.has_value() ? resolved_config->string() : std::string());
    if (endpoint.empty()) {
        endpoint = cfg.n6_bind;
    }

    const std::string normalized_protocol = normalize_protocol(protocol.empty() ? cfg.n6_default_protocol : protocol);
    if (source.empty()) {
        source = default_source_for_protocol(normalized_protocol);
    }
    if (destination.empty()) {
        destination = default_destination_for_protocol(normalized_protocol);
    }

    if (delay_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }

    for (int packet_index = 0; packet_index < count; ++packet_index) {
        const std::string payload = build_payload(normalized_protocol,
                                                  imsi,
                                                  pdu_session_id,
                                                  dnn,
                                                  payload_bytes,
                                                  source,
                                                  destination);
        if (!send_payload_to_endpoint(endpoint, payload)) {
            std::cerr << "Failed to send N6 payload to " << endpoint << "\n";
            return EXIT_FAILURE;
        }
        if (packet_index + 1 < count && interval_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    }

    if (resolved_config.has_value()) {
        std::cout << "Using config: " << resolved_config->string() << "\n";
    } else {
        std::cout << "Using built-in defaults (config file not found)\n";
    }

    std::cout << "Sent N6 payload to " << endpoint
              << " protocol=" << normalized_protocol
              << " imsi=" << imsi
              << " pdu=" << pdu_session_id
              << " bytes=" << payload_bytes
              << " count=" << count
              << "\n";
    return EXIT_SUCCESS;
}