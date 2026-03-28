#include <chrono>
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>

#include <thread>
#include <vector>
#include "upf/config/runtime_config.hpp"
#include "upf/upf.hpp"

#if defined(_WIN32)
#include <windows.h>
#endif

// Цветовые макросы для разных типов сообщений
#if defined(_WIN32)
inline void set_console_color(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
#define COLOR_CONFIG 11  // cyan
#define COLOR_START  14  // yellow
#define COLOR_INFO   9   // blue
#define COLOR_SENT   10  // green
#define COLOR_FINISH 13  // magenta
#define COLOR_ERROR  12  // red
#define COLOR_RESET  7   // default
#define PRINT_COLOR(type, msg) do { set_console_color(type); std::cout << msg << std::endl; set_console_color(COLOR_RESET); } while(0)
#define PRINT_COLOR_ERR(type, msg) do { set_console_color(type); std::cerr << msg << std::endl; set_console_color(COLOR_RESET); } while(0)
#else
#define COLOR_CONFIG "\033[36m"
#define COLOR_START  "\033[33m"
#define COLOR_INFO   "\033[34m"
#define COLOR_SENT   "\033[32m"
#define COLOR_FINISH "\033[35m"
#define COLOR_ERROR  "\033[31m"
#define COLOR_RESET  "\033[0m"
#define PRINT_COLOR(type, msg) std::cout << type << msg << COLOR_RESET << std::endl
#define PRINT_COLOR_ERR(type, msg) std::cerr << type << msg << COLOR_RESET << std::endl
#endif

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

// Вспомогательные функции (все они теперь внутри файла)
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
    if (!out_host || !out_port || endpoint.empty()) return false;

    const size_t sep = endpoint.rfind(':');
    if (sep == std::string::npos) return false;

    char* end = nullptr;
    long port = std::strtol(endpoint.substr(sep + 1).c_str(), &end, 10);
    if (end == endpoint.substr(sep + 1).c_str() || *end != '\0' || port <= 0 || port > 65535) {
        return false;
    }

    *out_host = endpoint.substr(0, sep);
    *out_port = static_cast<int>(port);
    return true;
}

std::string normalize_destination_host(std::string host) {
    if (host.empty() || host == "0.0.0.0") return "127.0.0.1";
    if (host == "::" || host == "[::]") return "::1";
    return host;
}

std::string normalize_protocol(std::string protocol) {
    std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);
    if (protocol == "ipv6") return "IPv6";
    if (protocol == "ethernet") return "Ethernet";
    return "IPv4";
}

std::string default_source_for_protocol(const std::string& protocol) {
    if (protocol == "IPv6") return "2001:db8:ffff::10";
    if (protocol == "Ethernet") return "02:00:00:00:00:01";
    return "8.8.8.8";
}

std::string default_destination_for_protocol(const std::string& protocol) {
    if (protocol == "IPv6") return "2001:db8:10::2";
    if (protocol == "Ethernet") return "02:10:10:00:00:02";
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
        payload << " src_ipv6=" << source << " dst_ipv6=" << destination;
    } else if (protocol == "Ethernet") {
        payload << " src_mac=" << source << " dst_mac=" << destination
                << " ether_type=2048";
    } else {
        payload << " src_ipv4=" << source << " dst_ipv4=" << destination;
    }

    return payload.str();
}

bool send_payload_to_endpoint(const std::string& endpoint, const std::string& payload) {
    if (!ensure_network_stack()) {
        std::cerr << "[ERROR] Failed to initialize network stack\n";
        return false;
    }

    std::string host;
    int port = 0;
    if (!parse_endpoint(endpoint, &host, &port)) {
        std::cerr << "[ERROR] Invalid endpoint format: " << endpoint << "\n";
        return false;
    }

    host = normalize_destination_host(host);

    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    std::string port_str = std::to_string(port);

    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result) != 0 || !result) {
        std::cerr << "[ERROR] getaddrinfo failed for " << host << ":" << port << "\n";
        return false;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        std::cerr << "[ERROR] socket creation failed\n";
        freeaddrinfo(result);
        return false;
    }

    int sent = sendto(sock,
                      payload.c_str(),
                      static_cast<int>(payload.size()),
                      0,
                      result->ai_addr,
                      static_cast<int>(result->ai_addrlen));

    close_socket(sock);
    freeaddrinfo(result);

    if (sent != static_cast<int>(payload.size())) {
        std::cerr << "[ERROR] sendto failed: sent " << sent << " of " << payload.size() << " bytes\n";
        return false;
    }

    return true;
}

// ===== RESOLVE CONFIG PATH (перенесено сюда, если нет в заголовке) =====
std::optional<std::filesystem::path> resolve_config_path(const std::string& argv0,
                                                         const std::optional<std::string>& explicit_path) {
    if (explicit_path && std::filesystem::exists(*explicit_path)) {
        return std::filesystem::path(*explicit_path);
    }

    const auto cwd = std::filesystem::current_path();
    std::vector<std::filesystem::path> candidates = {
        cwd / "runtime_config.json",
        cwd / "config" / "runtime_config.json",
        cwd.parent_path() / "config" / "runtime_config.json",
        cwd.parent_path() / "runtime_config.json"
    };

    for (const auto& c : candidates) {
        if (std::filesystem::exists(c)) {
            return c;
        }
    }

    return std::nullopt;
}
} // anonymous namespace

int main(int argc, char** argv) {
    PRINT_COLOR(COLOR_CONFIG, "=====================================");
    PRINT_COLOR(COLOR_CONFIG, "N6 Traffic Tool - vUPF test utility");
    PRINT_COLOR(COLOR_CONFIG, "=====================================\n");

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

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        auto read_value = [&](const char* name, std::string* target) -> bool {
            if (i + 1 >= argc || !target) {
                std::cerr << "Missing value for " << name << "\n";
                return false;
            }
            *target = argv[++i];
            return true;
        };

        auto read_int = [&](const char* name, int* target) -> bool {
            std::string value;
            if (!read_value(name, &value) || !target) return false;
            try {
                *target = std::stoi(value);
            } catch (...) {
                std::cerr << "Invalid integer for " << name << "\n";
                return false;
            }
            return true;
        };

        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: n6_traffic_tool.exe [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  --help              Show this help\n";
            std::cout << "  --config <path>     Config file\n";
            std::cout << "  --endpoint <host:port> Target endpoint\n";
            std::cout << "  --imsi <value>      IMSI\n";
            std::cout << "  --pdu <id>          PDU session ID\n";
            std::cout << "  --dnn <value>       DNN\n";
            std::cout << "  --protocol <ipv4|ipv6|ethernet>\n";
            std::cout << "  --src <addr>        Source IP/MAC\n";
            std::cout << "  --dst <addr>        Destination IP/MAC\n";
            std::cout << "  --bytes <n>         Payload size\n";
            std::cout << "  --delay-ms <n>      Initial delay\n";
            std::cout << "  --count <n>         Number of packets\n";
            std::cout << "  --interval-ms <n>   Delay between packets\n";
            return EXIT_SUCCESS;
        }
        else if (arg == "--config")      read_value("--config", &config_path.emplace());
        else if (arg == "--endpoint")    read_value("--endpoint", &endpoint);
        else if (arg == "--imsi")        read_value("--imsi", &imsi);
        else if (arg == "--pdu")         read_value("--pdu", &pdu_session_id);
        else if (arg == "--dnn")         read_value("--dnn", &dnn);
        else if (arg == "--protocol")    read_value("--protocol", &protocol);
        else if (arg == "--src")         read_value("--src", &source);
        else if (arg == "--dst")         read_value("--dst", &destination);
        else if (arg == "--bytes")       read_int("--bytes", reinterpret_cast<int*>(&payload_bytes));
        else if (arg == "--delay-ms")    read_int("--delay-ms", &delay_ms);
        else if (arg == "--count")       read_int("--count", &count);
        else if (arg == "--interval-ms") read_int("--interval-ms", &interval_ms);
        else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return EXIT_FAILURE;
        }
    }

    count = std::max(1, count);
    interval_ms = std::max(0, interval_ms);

    // Загрузка конфига
    const auto resolved = ::resolve_config_path(argc > 0 ? argv[0] : "", config_path);
    const upf::RuntimeConfig cfg = upf::load_runtime_config(resolved ? resolved->string() : "");

    if (endpoint.empty()) {
        endpoint = cfg.n6_bind.empty() ? "127.0.0.1:2152" : cfg.n6_bind;
    }

    const std::string norm_protocol = normalize_protocol(protocol.empty() ? cfg.n6_default_protocol : protocol);
    source = source.empty() ? default_source_for_protocol(norm_protocol) : source;
    destination = destination.empty() ? default_destination_for_protocol(norm_protocol) : destination;

    PRINT_COLOR(COLOR_START, std::string("[START] Sending ") + std::to_string(count) + " packet(s) to " + endpoint);
    PRINT_COLOR(COLOR_CONFIG, "  Protocol : " + norm_protocol);
    PRINT_COLOR(COLOR_CONFIG, "  IMSI     : " + imsi);
    PRINT_COLOR(COLOR_CONFIG, "  PDU ID   : " + pdu_session_id);
    PRINT_COLOR(COLOR_CONFIG, "  DNN      : " + dnn);
    PRINT_COLOR(COLOR_CONFIG, "  Payload  : " + std::to_string(payload_bytes) + " bytes");
    PRINT_COLOR(COLOR_CONFIG, "  Source   : " + source);
    PRINT_COLOR(COLOR_CONFIG, "  Dest     : " + destination);

    if (delay_ms > 0) {
        PRINT_COLOR(COLOR_INFO, std::string("[INFO] Initial delay: ") + std::to_string(delay_ms) + " ms");
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }

    for (int i = 0; i < count; ++i) {
        const std::string payload = build_payload(norm_protocol, imsi, pdu_session_id, dnn,
                                                  payload_bytes, source, destination);

        if (!send_payload_to_endpoint(endpoint, payload)) {
            PRINT_COLOR_ERR(COLOR_ERROR, std::string("[ERROR] Failed to send packet #") + std::to_string(i+1));
            return EXIT_FAILURE;
        }

        PRINT_COLOR(COLOR_SENT, std::string("[SENT] Packet #") + std::to_string(i+1) + " (" + std::to_string(payload_bytes) + " bytes)");

        if (i + 1 < count && interval_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    }

    PRINT_COLOR(COLOR_FINISH, "[FINISH] All packets sent successfully");
    return EXIT_SUCCESS;
}