#include "upf/adapters/network_adapters.hpp"

#include <sstream>
#include <string>
#include <unordered_map>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace upf {

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

void apply_recv_timeout(SocketType sock, int timeout_ms) {
#if defined(_WIN32)
    const DWORD timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval tv {};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

std::unordered_map<std::string, std::string> parse_tokens(const std::string& response) {
    std::unordered_map<std::string, std::string> out;
    std::istringstream iss(response);
    std::string token;
    while (iss >> token) {
        const std::size_t pos = token.find('=');
        if (pos != std::string::npos) {
            out[token.substr(0, pos)] = token.substr(pos + 1);
        }
    }
    return out;
}

PfcpCause parse_cause(const std::string& cause) {
    if (cause == "RequestAccepted") {
        return PfcpCause::RequestAccepted;
    }
    if (cause == "MandatoryIeMissing") {
        return PfcpCause::MandatoryIeMissing;
    }
    if (cause == "SessionContextNotFound") {
        return PfcpCause::SessionContextNotFound;
    }
    if (cause == "SemanticErrorInTheTft") {
        return PfcpCause::SemanticErrorInTheTft;
    }
    if (cause == "InvalidQfi") {
        return PfcpCause::InvalidQfi;
    }
    if (cause == "InvalidGateStatus") {
        return PfcpCause::InvalidGateStatus;
    }
    return PfcpCause::RuleCreationModificationFailure;
}

std::string operation_to_string(PfcpOperation operation) {
    switch (operation) {
        case PfcpOperation::Establish:
            return "ESTABLISH";
        case PfcpOperation::Modify:
            return "MODIFY";
        case PfcpOperation::Delete:
            return "DELETE";
    }
    return "UNKNOWN";
}

}  // namespace

bool NetworkN3Adapter::receive_uplink_packet(const std::string&, const std::string&, std::size_t) {
    return true;
}

bool NetworkN3Adapter::send_downlink_packet(const std::string&, const std::string&, std::size_t) {
    return true;
}

NetworkN4Adapter::NetworkN4Adapter(std::string remote_host, int remote_port, int timeout_ms)
    : remote_host_(std::move(remote_host)), remote_port_(remote_port), timeout_ms_(timeout_ms) {}

PfcpSessionResponse NetworkN4Adapter::apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) {
    std::ostringstream payload;
    payload << "PFCP op=" << operation_to_string(operation)
            << " imsi=" << request.imsi
            << " pdu=" << request.pdu_session_id
            << " teid=" << request.teid
            << " qers=" << request.rules.qers.size();
    if (!request.procedure.request_id.empty()) {
        payload << " req_id=" << request.procedure.request_id;
    }

    const auto response_text = send_udp_request(payload.str());
    if (!response_text.has_value()) {
        return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, "No response from N4 peer"};
    }

    PfcpSessionResponse response {};
    response.success = response_text->rfind("OK", 0) == 0;
    const auto tokens = parse_tokens(*response_text);
    const auto cause_it = tokens.find("cause");
    response.cause = cause_it != tokens.end() ? parse_cause(cause_it->second) : (response.success ? PfcpCause::RequestAccepted : PfcpCause::RuleCreationModificationFailure);
    const auto version_it = tokens.find("version");
    response.session_version = version_it != tokens.end() ? static_cast<std::uint64_t>(std::stoull(version_it->second)) : 0;
    const auto detail_it = tokens.find("detail");
    response.detail = detail_it != tokens.end() ? detail_it->second : *response_text;
    return response;
}

std::optional<std::string> NetworkN4Adapter::send_udp_request(const std::string& payload) const {
    if (!ensure_network_stack()) {
        return std::nullopt;
    }

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(remote_port_);
    if (getaddrinfo(remote_host_.c_str(), port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        return std::nullopt;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return std::nullopt;
    }
    apply_recv_timeout(sock, timeout_ms_);

    const int sent = sendto(sock, payload.c_str(), static_cast<int>(payload.size()), 0, result->ai_addr, static_cast<int>(result->ai_addrlen));
    if (sent < 0) {
        close_socket(sock);
        freeaddrinfo(result);
        return std::nullopt;
    }

    char buffer[1024] {};
    sockaddr_storage from {};
    socklen_t from_len = sizeof(from);
    const int received = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0, reinterpret_cast<sockaddr*>(&from), &from_len);

    close_socket(sock);
    freeaddrinfo(result);

    if (received <= 0) {
        return std::nullopt;
    }
    buffer[received] = '\0';
    return std::string(buffer);
}

std::optional<UsageReport> NetworkN4Adapter::query_usage_report(const std::string&, const std::string&) {
    const auto response_text = send_udp_request("USAGE");
    if (!response_text.has_value()) {
        return std::nullopt;
    }
    const auto tokens = parse_tokens(*response_text);

    const auto bytes_ul_it = tokens.find("bytes_ul");
    const auto bytes_dl_it = tokens.find("bytes_dl");
    const auto packets_ul_it = tokens.find("packets_ul");
    const auto packets_dl_it = tokens.find("packets_dl");
    if (bytes_ul_it == tokens.end() || bytes_dl_it == tokens.end() || packets_ul_it == tokens.end() || packets_dl_it == tokens.end()) {
        return std::nullopt;
    }

    UsageReport report {};
    report.bytes_ul = static_cast<std::uint64_t>(std::stoull(bytes_ul_it->second));
    report.bytes_dl = static_cast<std::uint64_t>(std::stoull(bytes_dl_it->second));
    report.packets_ul = static_cast<std::uint64_t>(std::stoull(packets_ul_it->second));
    report.packets_dl = static_cast<std::uint64_t>(std::stoull(packets_dl_it->second));
    return report;
}

bool NetworkN4Adapter::send_heartbeat() {
    const auto response_text = send_udp_request("HEARTBEAT");
    return response_text.has_value() && response_text->rfind("ALIVE", 0) == 0;
}

bool NetworkN6Adapter::forward_to_data_network(const std::string&, const std::string&, std::size_t) {
    return true;
}

bool NetworkN9Adapter::forward_to_branch_upf(const std::string&, const std::string&, std::size_t) {
    return enabled_;
}

bool NetworkN9Adapter::is_enabled() const {
    return enabled_;
}

NetworkSbiAdapter::NetworkSbiAdapter(std::string remote_host, int remote_port, std::string path, int timeout_ms)
    : remote_host_(std::move(remote_host)), remote_port_(remote_port), path_(std::move(path)), timeout_ms_(timeout_ms) {}

bool NetworkSbiAdapter::publish_event(const std::string& service_name, const std::string& payload) {
    if (!ensure_network_stack()) {
        return false;
    }

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(remote_port_);
    if (getaddrinfo(remote_host_.c_str(), port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        return false;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return false;
    }
    apply_recv_timeout(sock, timeout_ms_);

    if (connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        close_socket(sock);
        freeaddrinfo(result);
        return false;
    }
    freeaddrinfo(result);

    const std::string body = "{\"service\":\"" + service_name + "\",\"payload\":\"" + payload + "\"}";
    std::ostringstream request;
    request << "POST " << path_ << " HTTP/1.1\r\n"
            << "Host: " << remote_host_ << ':' << remote_port_ << "\r\n"
            << "Connection: Upgrade, HTTP2-Settings\r\n"
            << "Upgrade: h2c\r\n"
            << "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n\r\n"
            << body;

    const std::string wire = request.str();
    if (send(sock, wire.c_str(), static_cast<int>(wire.size()), 0) < 0) {
        close_socket(sock);
        return false;
    }

    char buffer[512] {};
    const int received = recv(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
    close_socket(sock);
    if (received <= 0) {
        return false;
    }
    buffer[received] = '\0';
    const std::string response(buffer);
    return response.find(" 200 ") != std::string::npos || response.find(" 201 ") != std::string::npos || response.find(" 101 ") != std::string::npos;
}

}  // namespace upf
