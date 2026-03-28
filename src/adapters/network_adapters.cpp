#include "upf/adapters/network_adapters.hpp"
#include "upf/modules/transport_serialization.hpp"
#include "upf/protocol/pfcp_wire.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

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

using namespace upf::pfcp;

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

bool sockaddr_to_ip_port(const sockaddr_storage& addr, socklen_t addr_len, std::string* out_ip, std::uint16_t* out_port) {
    char host[NI_MAXHOST] = {};
    char service[NI_MAXSERV] = {};
    const int rc = getnameinfo(reinterpret_cast<const sockaddr*>(&addr),
                               addr_len,
                               host,
                               static_cast<socklen_t>(sizeof(host)),
                               service,
                               static_cast<socklen_t>(sizeof(service)),
                               NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        return false;
    }

    if (out_ip != nullptr) {
        *out_ip = host;
    }
    if (out_port != nullptr) {
        *out_port = static_cast<std::uint16_t>(std::stoi(service));
    }
    return true;
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

bool parse_endpoint(const std::string& endpoint, std::string* out_host, int* out_port) {
    if (out_host == nullptr || out_port == nullptr || endpoint.empty()) {
        return false;
    }

    std::string host;
    std::string port_text;
    if (endpoint.front() == '[') {
        const std::size_t end_bracket = endpoint.find(']');
        if (end_bracket == std::string::npos || end_bracket + 2 > endpoint.size() || endpoint[end_bracket + 1] != ':') {
            return false;
        }
        host = endpoint.substr(1, end_bracket - 1);
        port_text = endpoint.substr(end_bracket + 2);
    } else {
        const std::size_t separator = endpoint.rfind(':');
        if (separator == std::string::npos) {
            return false;
        }
        host = endpoint.substr(0, separator);
        port_text = endpoint.substr(separator + 1);
    }

    char* end = nullptr;
    const long parsed_port = std::strtol(port_text.c_str(), &end, 10);
    if (end == port_text.c_str() || *end != '\0' || parsed_port <= 0 || parsed_port > 65535) {
        return false;
    }

    *out_host = host;
    *out_port = static_cast<int>(parsed_port);
    return true;
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

template <typename RuleCollection>
bool insert_rule_ids(const RuleCollection& rules,
                     const char* duplicate_detail,
                     std::unordered_set<std::uint32_t>* ids,
                     std::string* failure_detail) {
    for (const auto& rule : rules) {
        if (!ids->insert(rule.id).second) {
            if (failure_detail != nullptr) {
                *failure_detail = duplicate_detail;
            }
            return false;
        }
    }
    return true;
}

const char* n6_protocol_to_string(N6Protocol protocol) {
    switch (protocol) {
        case N6Protocol::IPv4:
            return "IPv4";
        case N6Protocol::IPv6:
            return "IPv6";
        case N6Protocol::Ethernet:
            return "Ethernet";
    }
    return "Unknown";
}

std::string n6_default_ipv4_destination(const std::string& dnn) {
    if (dnn == "internet") {
        return "8.8.8.8";
    }
    if (dnn == "ims") {
        return "198.18.0.10";
    }
    return "203.0.113.10";
}

std::string n6_default_ipv6_destination(const std::string& dnn) {
    if (dnn == "internet") {
        return "2001:4860:4860::8888";
    }
    if (dnn == "ims") {
        return "2001:db8:1::10";
    }
    return "2001:db8:ffff::10";
}

std::string n6_default_destination_mac(const std::string&) {
    return "02:00:00:00:00:01";
}

std::string normalize_n6_overflow_policy(std::string policy) {
    std::transform(policy.begin(), policy.end(), policy.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return policy == "drop_newest" ? policy : std::string("drop_oldest");
}

N6BufferOverflowPolicy parse_n6_overflow_policy(const std::string& policy) {
    return policy == "drop_newest" ? N6BufferOverflowPolicy::DropNewest : N6BufferOverflowPolicy::DropOldest;
}

}  // namespace

// N3 Adapter Implementation (GTP-U - 3GPP TS 29.281)
NetworkN3Adapter::NetworkN3Adapter(std::uint16_t listen_port, int max_workers)
    : listen_port_(listen_port) {
    (void)max_workers;  // Future use for worker thread pool
}

NetworkN3Adapter::~NetworkN3Adapter() {
    stop_listening();
}

bool NetworkN3Adapter::receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);

    const std::string key = imsi + ":" + pdu_session_id;
    const auto session_it = session_to_teid_.find(key);
    if (session_it == session_to_teid_.end()) {
        return false;
    }

    GtpUPacket packet {};
    packet.header.version = GtpVersion::V1;
    packet.header.protocol_type = true;
    packet.header.packet_type = GtpPacketType::Data;
    packet.header.teid = session_it->second;
    packet.payload.resize(bytes);
    packet.header.message_length = static_cast<std::uint16_t>(packet.payload.size());
    return process_gtp_u_packet(packet);
}

bool NetworkN3Adapter::send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);

    const std::string key = imsi + ":" + pdu_session_id;
    const auto session_it = session_to_teid_.find(key);
    if (session_it == session_to_teid_.end()) {
        return false;
    }
    if (session_it->second == 0U) {
        return false;
    }

    std::vector<std::uint8_t> payload(bytes);
    return send_gtp_u_packet(session_it->second, payload).has_value();
}

bool NetworkN3Adapter::create_tunnel(const N3TunnelContext& context) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    uint32_t teid = context.teid;
    if (teid == 0) {
        teid = next_teid_++;
    }
    
    N3TunnelContext tunnel = context;
    tunnel.teid = teid;
    tunnels_[teid] = tunnel;
    
    const std::string key = context.imsi + ":" + context.pdu_session_id;
    session_to_teid_[key] = teid;
    
    return true;
}

bool NetworkN3Adapter::delete_tunnel(std::uint32_t teid) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return false;
    }
    
    const std::string key = it->second.imsi + ":" + it->second.pdu_session_id;
    session_to_teid_.erase(key);
    tunnels_.erase(it);
    
    return true;
}

bool NetworkN3Adapter::update_tunnel_qos_flows(std::uint32_t teid, const std::vector<QosFlowMapping>& qos_flows) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return false;
    }
    
    it->second.qos_flows = qos_flows;
    return true;
}

std::optional<N3TunnelContext> NetworkN3Adapter::get_tunnel(std::uint32_t teid) const {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(teid);
    if (it != tunnels_.end()) {
        return it->second;
    }
    return std::nullopt;
}

// GTP-U Header Encoding (3GPP TS 29.281 Section 5.1)
std::vector<std::uint8_t> NetworkN3Adapter::encode_gtp_u_header(const GtpUHeader& header) {
    std::vector<std::uint8_t> buf;
    const bool has_optional_part = header.extension_headers_flag || header.sequence_flag || header.pn_flag;
    
    // First byte: version, PT, E, S, PN
    uint8_t first_byte = 0x30;  // GTP version 1, protocol type GTP
    if (header.extension_headers_flag) {
        first_byte |= 0x04;
    }
    if (header.sequence_flag) {
        first_byte |= 0x02;
    }
    if (header.pn_flag) {
        first_byte |= 0x01;
    }
    buf.push_back(first_byte);
    
    // Message type (0xFF for T-PDU)
    buf.push_back(static_cast<uint8_t>(header.packet_type));
    
    // Message length (2 bytes, big-endian)
    buf.push_back((header.message_length >> 8) & 0xFF);
    buf.push_back(header.message_length & 0xFF);
    
    // TEID (4 bytes, big-endian)
    buf.push_back((header.teid >> 24) & 0xFF);
    buf.push_back((header.teid >> 16) & 0xFF);
    buf.push_back((header.teid >> 8) & 0xFF);
    buf.push_back(header.teid & 0xFF);
    
    // Per TS 29.281, optional 4-byte part is present when any of E/S/PN flags is set.
    if (has_optional_part) {
        buf.push_back((header.sequence_number >> 8) & 0xFF);
        buf.push_back(header.sequence_number & 0xFF);
        buf.push_back(header.n_pdu_number);
        buf.push_back(header.next_extension_header_type);
    }
    
    return buf;
}

std::size_t NetworkN3Adapter::gtp_u_optional_part_size(const GtpUHeader& header) const {
    return (header.extension_headers_flag || header.sequence_flag || header.pn_flag) ? 4U : 0U;
}

std::optional<std::size_t> NetworkN3Adapter::decode_gtp_u_header_size(const std::vector<std::uint8_t>& data) const {
    if (data.size() < 8) {
        return std::nullopt;
    }

    const uint8_t first_byte = data[0];
    const bool extension_headers_flag = (first_byte & 0x04) != 0;
    const bool sequence_flag = (first_byte & 0x02) != 0;
    const bool pn_flag = (first_byte & 0x01) != 0;
    const std::size_t optional_part_size = (extension_headers_flag || sequence_flag || pn_flag) ? 4U : 0U;
    std::size_t header_size = 8U + optional_part_size;
    if (data.size() < header_size) {
        return std::nullopt;
    }

    if (!extension_headers_flag) {
        return header_size;
    }

    std::size_t cursor = 12U;
    std::uint8_t next_extension_type = data[11];
    while (next_extension_type != 0U) {
        if (data.size() < cursor + 2U) {
            return std::nullopt;
        }

        const std::uint8_t ext_len_units = data[cursor];
        const std::size_t ext_header_size = 2U + (static_cast<std::size_t>(ext_len_units) * 4U);
        if (data.size() < cursor + ext_header_size) {
            return std::nullopt;
        }

        next_extension_type = data[cursor + ext_header_size - 1U];
        cursor += ext_header_size;
    }

    header_size = cursor;
    return header_size;
}

// GTP-U Header Decoding
std::optional<GtpUHeader> NetworkN3Adapter::decode_gtp_u_header(const std::vector<std::uint8_t>& data) {
    const auto header_size_opt = decode_gtp_u_header_size(data);
    if (!header_size_opt.has_value()) {
        return std::nullopt;
    }
    const std::size_t header_size = *header_size_opt;
    
    GtpUHeader header;
    
    // Parse first byte
    uint8_t first_byte = data[0];
    header.version = static_cast<GtpVersion>((first_byte >> 5) & 0x07);
    header.protocol_type = (first_byte & 0x10) != 0;
    header.extension_headers_flag = (first_byte & 0x04) != 0;
    header.sequence_flag = (first_byte & 0x02) != 0;
    header.pn_flag = (first_byte & 0x01) != 0;
    
    // Message type
    header.packet_type = static_cast<GtpPacketType>(data[1]);
    
    // Message length
    header.message_length = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    // TEID
    header.teid = (static_cast<uint32_t>(data[4]) << 24) |
                  (static_cast<uint32_t>(data[5]) << 16) |
                  (static_cast<uint32_t>(data[6]) << 8) |
                  static_cast<uint32_t>(data[7]);

    if (header_size > 8U) {
        header.sequence_number = (static_cast<std::uint16_t>(data[8]) << 8) | data[9];
        header.n_pdu_number = data[10];
        header.next_extension_header_type = data[11];
    }

    const std::size_t header_extra_size = header_size - 8U;
    if (header.message_length < header_extra_size) {
        return std::nullopt;
    }
    const std::size_t required_total_size = 8U + static_cast<std::size_t>(header.message_length);
    if (data.size() < required_total_size) {
        return std::nullopt;
    }
    
    return header;
}

bool NetworkN3Adapter::process_gtp_u_packet(const GtpUPacket& packet) {
    if (packet.header.version != GtpVersion::V1 || !packet.header.protocol_type || packet.header.packet_type != GtpPacketType::Data) {
        return false;
    }
    if (packet.header.teid == 0U) {
        return false;
    }

    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(packet.header.teid);
    if (it == tunnels_.end()) {
        return false;
    }
    
    // Update statistics
    it->second.bytes_ul += packet.payload.size();
    it->second.packets_ul++;
    
    // Add to processing queue
    std::lock_guard<std::mutex> queue_lock(queue_mutex_);
    packet_queue_.push(packet);
    
    return true;
}

std::optional<GtpUPacket> NetworkN3Adapter::send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) {
    if (teid == 0U) {
        return std::nullopt;
    }

    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return std::nullopt;
    }
    
    const auto& tunnel = it->second;
    
    // Build GTP-U header
    GtpUHeader header;
    header.version = GtpVersion::V1;
    header.protocol_type = true;
    header.packet_type = GtpPacketType::Data;
    header.teid = teid;
    header.message_length = static_cast<std::uint16_t>(payload.size() + gtp_u_optional_part_size(header));
    
    // Encode header
    auto header_bytes = encode_gtp_u_header(header);
    
    // Build complete packet
    GtpUPacket packet;
    packet.header = header;
    packet.payload = payload;
    packet.source_ip = "127.0.0.1";  // Local UPF address
    packet.dest_ip = tunnel.gnb_ip;
    packet.source_port = 2152;
    packet.dest_port = tunnel.gnb_port;
    
    // Send via UDP
    std::vector<std::uint8_t> complete_packet = header_bytes;
    complete_packet.insert(complete_packet.end(), payload.begin(), payload.end());
    
    if (send_raw_udp(packet.dest_ip, packet.dest_port, complete_packet)) {
        it->second.bytes_dl += payload.size();
        it->second.packets_dl++;
        return packet;
    }
    
    return std::nullopt;
}

bool NetworkN3Adapter::start_listening(std::uint16_t port) {
    if (listening_.load()) {
        return false;
    }
    
    listen_port_ = port;
    listening_ = true;
    listener_thread_ = std::make_unique<std::thread>(&NetworkN3Adapter::udp_listener_thread, this);
    
    return true;
}

bool NetworkN3Adapter::stop_listening() {
    listening_ = false;
    if (listener_thread_ && listener_thread_->joinable()) {
        listener_thread_->join();
    }
    return true;
}

bool NetworkN3Adapter::is_listening() const {
    return listening_.load();
}

NetworkN3Adapter::ControlPlaneStats NetworkN3Adapter::get_control_plane_stats() const {
    std::lock_guard<std::mutex> lock(control_plane_stats_mutex_);
    return control_plane_stats_;
}

std::size_t NetworkN3Adapter::get_active_tunnels() const {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    return tunnels_.size();
}

UsageReport NetworkN3Adapter::get_tunnel_usage(std::uint32_t teid) {
    std::lock_guard<std::recursive_mutex> lock(tunnel_mutex_);
    
    auto it = tunnels_.find(teid);
    if (it != tunnels_.end()) {
        UsageReport report;
        report.bytes_ul = it->second.bytes_ul;
        report.bytes_dl = it->second.bytes_dl;
        report.packets_ul = it->second.packets_ul;
        report.packets_dl = it->second.packets_dl;
        return report;
    }
    
    return UsageReport{};
}

void NetworkN3Adapter::udp_listener_thread() {
    if (!ensure_network_stack()) {
        listening_ = false;
        return;
    }
    
    // Create UDP socket
    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_PASSIVE;
    
    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(listen_port_);
    if (getaddrinfo(nullptr, port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        listening_ = false;
        return;
    }
    
    SocketType listen_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listen_socket == kInvalidSocket) {
        freeaddrinfo(result);
        listening_ = false;
        return;
    }
    
    // Enable address reuse
#if defined(_WIN32)
    const char reuse = 1;
#else
    const int reuse = 1;
#endif
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    
    if (bind(listen_socket, result->ai_addr, static_cast<int>(result->ai_addrlen)) != 0) {
        close_socket(listen_socket);
        freeaddrinfo(result);
        listening_ = false;
        return;
    }
    
    freeaddrinfo(result);
    apply_recv_timeout(listen_socket, 500);  // 500ms timeout
    
    std::vector<uint8_t> buffer(65535);
    
    while (listening_.load()) {
        sockaddr_storage from {};
        socklen_t from_len = sizeof(from);
        
        const int received = recvfrom(listen_socket, reinterpret_cast<char*>(buffer.data()), 
                                     static_cast<int>(buffer.size()), 0, 
                                     reinterpret_cast<sockaddr*>(&from), &from_len);
        
        if (received <= 0) {
            continue;
        }
        
        // Decode GTP-U header
        std::vector<uint8_t> packet_data(buffer.begin(), buffer.begin() + received);
        auto header = decode_gtp_u_header(packet_data);
        
        if (!header.has_value()) {
            continue;
        }

        std::string source_ip;
        std::uint16_t source_port = 0;
        const bool has_source = sockaddr_to_ip_port(from, from_len, &source_ip, &source_port);

        // Handle control-plane Echo Request with immediate Echo Response.
        const auto packet_type_u8 = static_cast<std::uint8_t>(header->packet_type);
        if (packet_type_u8 == static_cast<std::uint8_t>(GtpMessageType::EchoRequest)) {
            {
                std::lock_guard<std::mutex> stats_lock(control_plane_stats_mutex_);
                control_plane_stats_.echo_requests_rx++;
            }
            std::clog << "[N3] RX Echo Request from " << source_ip << ':' << source_port << '\n';
            if (has_source) {
                GtpUHeader echo_response = *header;
                echo_response.packet_type = static_cast<GtpPacketType>(static_cast<std::uint8_t>(GtpMessageType::EchoResponse));
                echo_response.message_length = static_cast<std::uint16_t>(gtp_u_optional_part_size(echo_response));
                (void)send_raw_udp(source_ip, source_port, encode_gtp_u_header(echo_response));
                {
                    std::lock_guard<std::mutex> stats_lock(control_plane_stats_mutex_);
                    control_plane_stats_.echo_responses_tx++;
                }
                std::clog << "[N3] TX Echo Response to " << source_ip << ':' << source_port << '\n';
            }
            continue;
        }

        if (packet_type_u8 == static_cast<std::uint8_t>(GtpMessageType::SupportedExtensionHeadersNotification)) {
            std::lock_guard<std::mutex> stats_lock(control_plane_stats_mutex_);
            control_plane_stats_.supported_ext_headers_notifications_rx++;
            std::clog << "[N3] RX Supported Extension Headers Notification\n";
            continue;
        }

        if (packet_type_u8 == static_cast<std::uint8_t>(GtpMessageType::ErrorIndication)) {
            std::lock_guard<std::mutex> stats_lock(control_plane_stats_mutex_);
            control_plane_stats_.error_indications_rx++;
            std::clog << "[N3] RX Error Indication\n";
            continue;
        }

        if (packet_type_u8 != static_cast<std::uint8_t>(GtpPacketType::Data)) {
            std::lock_guard<std::mutex> stats_lock(control_plane_stats_mutex_);
            control_plane_stats_.other_signaling_rx++;
            std::clog << "[N3] RX other signaling type=" << static_cast<int>(packet_type_u8) << '\n';
            continue;
        }

        if (header->teid == 0U) {
            continue;
        }
        
        // Create GTP-U packet structure
        GtpUPacket packet;
        packet.header = header.value();
        const auto header_size_opt = decode_gtp_u_header_size(packet_data);
        if (!header_size_opt.has_value()) {
            continue;
        }
        const std::size_t header_size = *header_size_opt;
        const std::size_t payload_size = static_cast<std::size_t>(packet.header.message_length) - (header_size - 8U);
        packet.payload.assign(packet_data.begin() + header_size, packet_data.begin() + header_size + payload_size);
        if (has_source) {
            packet.source_ip = source_ip;
            packet.source_port = source_port;
        }
        
        // Store packet for processing
        process_gtp_u_packet(packet);
    }
    
    close_socket(listen_socket);
}

bool NetworkN3Adapter::send_raw_udp(const std::string& dest_ip, std::uint16_t dest_port, const std::vector<std::uint8_t>& data) {
    if (!ensure_network_stack()) {
        return false;
    }
    
    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(dest_port);
    if (getaddrinfo(dest_ip.c_str(), port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        return false;
    }
    
    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return false;
    }
    
    const int sent = sendto(sock, reinterpret_cast<const char*>(data.data()), 
                           static_cast<int>(data.size()), 0, result->ai_addr, 
                           static_cast<int>(result->ai_addrlen));
    
    close_socket(sock);
    freeaddrinfo(result);
    
    return sent > 0;
}



NetworkN4Adapter::NetworkN4Adapter(std::string remote_host, int remote_port, int timeout_ms, std::string local_node_id)
    : remote_host_(std::move(remote_host))
    , remote_port_(remote_port)
    , timeout_ms_(timeout_ms)
    , local_node_id_(std::move(local_node_id))
    , recovery_time_stamp_(static_cast<std::uint32_t>(std::time(nullptr))) {}

PfcpSessionResponse NetworkN4Adapter::apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) {
    if (!request.procedure.request_id.empty()) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        const auto replay_it = replay_cache_.find(request.procedure.request_id);
        if (replay_it != replay_cache_.end()) {
            PfcpSessionResponse replay = replay_it->second;
            replay.idempotent_replay = true;
            return replay;
        }
    }

    if (!ensure_association()) {
        PfcpSessionResponse out {false, PfcpCause::RuleCreationModificationFailure, 0, false, "PFCP association setup failed"};
        if (!request.procedure.request_id.empty()) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            replay_cache_[request.procedure.request_id] = out;
        }
        return out;
    }

    const PfcpSessionResponse validation = validate_request(request, operation);
    if (!validation.success) {
        if (!request.procedure.request_id.empty()) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            replay_cache_[request.procedure.request_id] = validation;
        }
        return validation;
    }

    const std::string key = session_key(request.imsi, request.pdu_session_id);
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        const bool exists = sessions_.find(key) != sessions_.end();
        if (operation == PfcpOperation::Establish && exists) {
            PfcpSessionResponse out {false, PfcpCause::RuleCreationModificationFailure, 0, false, "Session already exists"};
            if (!request.procedure.request_id.empty()) {
                replay_cache_[request.procedure.request_id] = out;
            }
            return out;
        }
        if ((operation == PfcpOperation::Modify || operation == PfcpOperation::Delete) && !exists) {
            PfcpSessionResponse out {false, PfcpCause::SessionContextNotFound, 0, false, "Session context not found"};
            if (!request.procedure.request_id.empty()) {
                replay_cache_[request.procedure.request_id] = out;
            }
            return out;
        }
    }

    const int request_timeout_ms = request.procedure.timeout_ms > 0
        ? static_cast<int>(request.procedure.timeout_ms)
        : timeout_ms_;
    const int request_attempts = std::max(1, static_cast<int>(request.procedure.max_retries) + 1);
    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    PfcpRuleSet previous_rules;
    if (operation == PfcpOperation::Modify) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        const auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            previous_rules = it->second.rules;
        }
    }

    const auto wire_request = encode_session_request_message(request,
                                                             operation,
                                                             sequence,
                                                             previous_rules,
                                                             local_node_id_,
                                                             local_fseid_ipv4_);
    const auto wire_response = send_udp_request(wire_request, request_timeout_ms, request_attempts);
    if (!wire_response.has_value()) {
        PfcpSessionResponse out {false, PfcpCause::RuleCreationModificationFailure, 0, false, "No response from N4 peer"};
        if (!request.procedure.request_id.empty()) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            replay_cache_[request.procedure.request_id] = out;
        }
        return out;
    }

    PfcpSessionResponse parsed = parse_wire_response(*wire_response,
                                                     static_cast<std::uint8_t>(pfcp_response_message_type(operation)),
                                                     sequence,
                                                     true,
                                                     make_pfcp_seid(request.imsi, request.pdu_session_id));
    if (!parsed.success) {
        if (!request.procedure.request_id.empty()) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            replay_cache_[request.procedure.request_id] = parsed;
        }
        return parsed;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        ++version_counter_;
        if (parsed.session_version == 0) {
            parsed.session_version = version_counter_;
        }
        parsed.cause = PfcpCause::RequestAccepted;

        if (operation == PfcpOperation::Delete) {
            sessions_.erase(key);
        } else {
            PfcpSessionState& state = sessions_[key];
            state.rules = request.rules;
            state.version = parsed.session_version;
        }

        if (!request.procedure.request_id.empty()) {
            replay_cache_[request.procedure.request_id] = parsed;
        }
    }

    return parsed;
}

std::string NetworkN4Adapter::session_key(const std::string& imsi, const std::string& pdu_session_id) const {
    return imsi + ":" + pdu_session_id;
}

PfcpSessionResponse NetworkN4Adapter::validate_request(const PfcpSessionRequest& request, PfcpOperation operation) const {
    if (request.imsi.empty() || request.pdu_session_id.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing IMSI or PDU session ID"};
    }

    if (operation == PfcpOperation::Delete) {
        return PfcpSessionResponse {true, PfcpCause::RequestAccepted, 0, false, "Delete validated"};
    }

    if (request.dnn.empty() || request.s_nssai.empty() || request.qos_profile.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing session profile IE"};
    }
    if (request.ue_ipv4.empty() && request.ue_ipv6.empty() && request.ue_mac.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing UE access identity"};
    }
    if (!parse_teid_value(request.teid).has_value()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Invalid TEID"};
    }
    if (!request.ue_ipv6.empty() && encode_ipv6_bytes(request.ue_ipv6).size() != 16) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Invalid UE IPv6"};
    }
    if (!request.ue_mac.empty() && encode_mac_bytes(request.ue_mac).size() != 6) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Invalid UE MAC"};
    }
    if (request.prefer_n6_ipv6 && request.ue_ipv6.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing UE IPv6 for requested IPv6 forwarding"};
    }
    if (request.prefer_n6_ethernet && request.ue_mac.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing UE MAC for requested Ethernet forwarding"};
    }

    const bool has_any_rules = !request.rules.pdrs.empty() || !request.rules.fars.empty() || !request.rules.urrs.empty() || !request.rules.qers.empty();
    std::string reference_failure_detail;
    if (has_any_rules && !validate_rule_references(request.rules, &reference_failure_detail)) {
        return PfcpSessionResponse {false,
                                    PfcpCause::RuleCreationModificationFailure,
                                    0,
                                    false,
                                    reference_failure_detail.empty() ? "Invalid PDR references to FAR/QER/URR" : reference_failure_detail};
    }

    PfcpCause qer_failure = PfcpCause::RequestAccepted;
    if (!validate_qers(request.rules.qers, &qer_failure)) {
        return PfcpSessionResponse {false, qer_failure, 0, false, "Invalid QER"};
    }

    std::string rule_failure_detail;
    if (!validate_rule_parameters(request.rules, &rule_failure_detail)) {
        return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, rule_failure_detail};
    }

    return PfcpSessionResponse {true, PfcpCause::RequestAccepted, 0, false, "Validated"};
}

bool NetworkN4Adapter::validate_rule_references(const PfcpRuleSet& rules, std::string* failure_detail) const {
    std::unordered_set<std::uint32_t> far_ids;
    std::unordered_set<std::uint32_t> qer_ids;
    std::unordered_set<std::uint32_t> urr_ids;
    std::unordered_set<std::uint32_t> pdr_ids;

    if (!insert_rule_ids(rules.fars, "Duplicate FAR ID", &far_ids, failure_detail) ||
        !insert_rule_ids(rules.qers, "Duplicate QER ID", &qer_ids, failure_detail) ||
        !insert_rule_ids(rules.urrs, "Duplicate URR ID", &urr_ids, failure_detail) ||
        !insert_rule_ids(rules.pdrs, "Duplicate PDR ID", &pdr_ids, failure_detail)) {
        return false;
    }

    for (const auto& pdr : rules.pdrs) {
        if (pdr.far_id == 0 || far_ids.find(pdr.far_id) == far_ids.end()) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid PDR references to FAR/QER/URR";
            }
            return false;
        }
        if (pdr.qer_id != 0 && qer_ids.find(pdr.qer_id) == qer_ids.end()) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid PDR references to FAR/QER/URR";
            }
            return false;
        }
        if (pdr.urr_id != 0 && urr_ids.find(pdr.urr_id) == urr_ids.end()) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid PDR references to FAR/QER/URR";
            }
            return false;
        }
    }

    return true;
}

bool NetworkN4Adapter::validate_qers(const std::vector<PfcpQer>& qers, PfcpCause* failure_cause) const {
    for (const auto& qer : qers) {
        if (qer.qfi == 0 || qer.qfi > 63) {
            if (failure_cause != nullptr) {
                *failure_cause = PfcpCause::InvalidQfi;
            }
            return false;
        }
        if (!is_valid_gate_status(qer.gate_status)) {
            if (failure_cause != nullptr) {
                *failure_cause = PfcpCause::InvalidGateStatus;
            }
            return false;
        }
        if (qer.gbr_ul_kbps > qer.mbr_ul_kbps || qer.gbr_dl_kbps > qer.mbr_dl_kbps) {
            if (failure_cause != nullptr) {
                *failure_cause = PfcpCause::RuleCreationModificationFailure;
            }
            return false;
        }
    }
    return true;
}

bool NetworkN4Adapter::validate_rule_parameters(const PfcpRuleSet& rules, std::string* failure_detail) const {
    for (const auto& far_rule : rules.fars) {
        if (!is_valid_apply_action(far_rule.action)) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid FAR action";
            }
            return false;
        }
        if (far_rule.action == "FORW") {
            if (far_rule.outer_header_creation_description == 0) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid FAR outer header creation";
                }
                return false;
            }
            if (far_rule.tunnel_peer_ipv4.empty() || !is_valid_ipv4_text(far_rule.tunnel_peer_ipv4)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid FAR tunnel peer IPv4";
                }
                return false;
            }
            if (far_rule.tunnel_peer_teid == 0) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid FAR tunnel peer TEID";
                }
                return false;
            }
        } else if (far_rule.action == "BUFF") {
            if (far_rule.buffering_duration_ms == 0) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid FAR buffering duration";
                }
                return false;
            }
        } else if (far_rule.action == "NOCP") {
            if (!far_rule.notify_control_plane) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid FAR notify control plane flag";
                }
                return false;
            }
        } else if (far_rule.action == "DROP") {
            if (!far_rule.forward_to.empty() || !far_rule.tunnel_peer_ipv4.empty() || far_rule.tunnel_peer_teid != 0 || far_rule.buffering_duration_ms != 0 || far_rule.notify_control_plane) {
                if (failure_detail != nullptr) {
                    *failure_detail = "DROP FAR must not carry forwarding, buffering, or notification parameters";
                }
                return false;
            }
        }
    }

    std::unordered_set<std::uint32_t> pdr_precedences;
    for (const auto& pdr_rule : rules.pdrs) {
        if (pdr_rule.precedence == 0) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid PDR precedence";
            }
            return false;
        }
        if (!pdr_precedences.insert(pdr_rule.precedence).second) {
            if (failure_detail != nullptr) {
                *failure_detail = "Duplicate PDR precedence";
            }
            return false;
        }
        if (!is_valid_pdr_source_interface(pdr_rule.source_interface)) {
            if (failure_detail != nullptr) {
                *failure_detail = "Invalid PDR source interface";
            }
            return false;
        }
        const auto filters = effective_sdf_filters(pdr_rule);
        if (filters.empty()) {
            if (failure_detail != nullptr) {
                *failure_detail = "PDR requires at least one SDF filter";
            }
            return false;
        }
        if (!pdr_rule.sdf_filters.empty() && has_explicit_legacy_pdr_filter_fields(pdr_rule) && !legacy_pdr_fields_match_primary_filter(pdr_rule, filters.front())) {
            if (failure_detail != nullptr) {
                *failure_detail = "Conflicting legacy and structured PDR filter fields";
            }
            return false;
        }
        for (const auto& filter : filters) {
            if (filter.packet_filter_id == 0) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR packet filter ID";
                }
                return false;
            }
            if (!is_valid_pdr_flow_direction(filter.flow_direction)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR flow direction";
                }
                return false;
            }
            if (!is_valid_pdr_protocol(filter.protocol_identifier)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR protocol identifier";
                }
                return false;
            }
            if ((filter.source_port != 0 || filter.destination_port != 0 || filter.source_port_end != 0 || filter.destination_port_end != 0) && !is_transport_protocol(filter.protocol_identifier)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "PDR ports require TCP or UDP protocol";
                }
                return false;
            }
            if (filter.source_port_end != 0 && (filter.source_port == 0 || filter.source_port_end < filter.source_port)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR source port range";
                }
                return false;
            }
            if (filter.destination_port_end != 0 && (filter.destination_port == 0 || filter.destination_port_end < filter.destination_port)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR destination port range";
                }
                return false;
            }
            if (!is_valid_ether_type(filter.ether_type)) {
                if (failure_detail != nullptr) {
                    *failure_detail = "Invalid PDR ether type";
                }
                return false;
            }
        }
    }

    return true;
}

std::vector<PfcpPdr::SdfFilterEntry> NetworkN4Adapter::effective_sdf_filters(const PfcpPdr& pdr) const {
    return build_effective_sdf_filters(pdr);
}

bool NetworkN4Adapter::is_valid_gate_status(const std::string& gate_status) const {
    return gate_status == "OPEN" || gate_status == "CLOSED";
}

bool NetworkN4Adapter::ensure_association() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (association_established_ && capabilities_exchanged_ && node_features_exchanged_) {
            return true;
        }
    }

    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (association_established_ && capabilities_exchanged_ && node_features_exchanged_) {
            return true;
        }
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    // Выводим параметры AssociationSetupRequest перед отправкой
    std::cout << "[PFCP] AssociationSetupRequest params:" << std::endl;
    std::cout << "  local_node_id: " << local_node_id_ << std::endl;
    std::cout << "  local_fseid_ipv4: " << local_fseid_ipv4_ << std::endl;
    std::cout << "  recovery_time_stamp: " << recovery_time_stamp_ << std::endl;
    std::cout << "  sequence: " << sequence << std::endl;

    auto cap_msg = encode_capability_exchange_request_message(local_node_id_,
                                                             local_fseid_ipv4_,
                                                             0x0000000FU,
                                                             sequence);
    std::cout << "[PFCP] CapabilityExchangeRequest params:" << std::endl;
    std::cout << "  local_node_id: " << local_node_id_ << std::endl;
    std::cout << "  local_fseid_ipv4: " << local_fseid_ipv4_ << std::endl;
    std::cout << "  up_function_features: 0x0000000F" << std::endl;
    std::cout << "  sequence: " << sequence << std::endl;
    std::cout << "[PFCP] CapabilityExchangeRequest (hex): ";
    for (unsigned char c : cap_msg) std::cout << std::hex << (int)c << " ";
    std::cout << std::dec << std::endl;
    const auto response_text = send_udp_request(cap_msg,
                                                timeout_ms_,
                                                1);
    if (!response_text.has_value()) {
        return false;
    }

    const auto message = decode_pfcp_message(*response_text);
    if (!message.has_value()) {
        return false;
    }

    const PfcpSessionResponse parsed = parse_wire_response(*response_text,
                                                           static_cast<std::uint8_t>(PfcpMessageType::AssociationSetupResponse),
                                                           sequence,
                                                           false,
                                                           0);
    if (!parsed.success) {
        return false;
    }
    if (!has_valid_association_context_response(*message)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        association_established_ = true;
    }
    return ensure_capabilities();
}

bool NetworkN4Adapter::ensure_capabilities() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (capabilities_exchanged_) {
            return true;
        }
    }

    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (capabilities_exchanged_) {
            return true;
        }
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    const auto response_text = send_udp_request(encode_capability_exchange_request_message(local_node_id_,
                                                                                           local_fseid_ipv4_,
                                                                                           0x0000000FU,
                                                                                           sequence),
                                                timeout_ms_,
                                                1);
    if (!response_text.has_value()) {
        return false;
    }

    const auto message = decode_pfcp_message(*response_text);
    if (!message.has_value()) {
        return false;
    }

    const PfcpSessionResponse parsed = parse_wire_response(*response_text,
                                                           static_cast<std::uint8_t>(PfcpMessageType::CapabilityExchangeResponse),
                                                           sequence,
                                                           false,
                                                           0);
    if (!parsed.success) {
        return false;
    }
    if (!has_valid_capability_context_response(*message)) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        capabilities_exchanged_ = true;
    }
    return ensure_node_features();
}

bool NetworkN4Adapter::ensure_node_features() {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (node_features_exchanged_) {
            return true;
        }
    }

    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (node_features_exchanged_) {
            return true;
        }
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    auto nf_msg = encode_node_features_request_message(local_node_id_,
                                                      0x00000007U,
                                                      sequence);
    std::cout << "[PFCP] NodeFeaturesRequest params:" << std::endl;
    std::cout << "  local_node_id: " << local_node_id_ << std::endl;
    std::cout << "  up_function_features: 0x00000007" << std::endl;
    std::cout << "  sequence: " << sequence << std::endl;
    std::cout << "[PFCP] NodeFeaturesRequest (hex): ";
    for (unsigned char c : nf_msg) std::cout << std::hex << (int)c << " ";
    std::cout << std::dec << std::endl;
    const auto response_text = send_udp_request(nf_msg,
                                                timeout_ms_,
                                                1);
    if (!response_text.has_value()) {
        return false;
    }

    const auto message = decode_pfcp_message(*response_text);
    if (!message.has_value()) {
        return false;
    }

    const PfcpSessionResponse parsed = parse_wire_response(*response_text,
                                                           static_cast<std::uint8_t>(PfcpMessageType::NodeFeaturesResponse),
                                                           sequence,
                                                           false,
                                                           0);
    if (!parsed.success) {
        return false;
    }
    if (!has_valid_node_feature_context_response(*message)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(state_mutex_);
    node_features_exchanged_ = true;
    return true;
}

PfcpSessionResponse NetworkN4Adapter::parse_wire_response(const std::string& response_text,
                                                          std::uint8_t expected_message_type,
                                                          std::uint32_t expected_sequence,
                                                          bool expect_seid,
                                                          std::uint64_t expected_seid) const {
    PfcpSessionResponse response {};
    const auto message = decode_pfcp_message(response_text);
    if (!message.has_value()) {
        response.success = false;
        response.cause = PfcpCause::RuleCreationModificationFailure;
        response.detail = "Invalid PFCP response";
        return response;
    }
    if (static_cast<std::uint8_t>(message->message_type) != expected_message_type) {
        response.success = false;
        response.cause = PfcpCause::RuleCreationModificationFailure;
        response.detail = "Unexpected PFCP message type";
        return response;
    }
    if (message->sequence != expected_sequence) {
        response.success = false;
        response.cause = PfcpCause::RuleCreationModificationFailure;
        response.detail = "Unexpected PFCP sequence";
        return response;
    }
    if (message->has_seid != expect_seid) {
        response.success = false;
        response.cause = PfcpCause::RuleCreationModificationFailure;
        response.detail = "Unexpected PFCP SEID presence";
        return response;
    }
    if (expect_seid && message->seid != expected_seid) {
        response.success = false;
        response.cause = PfcpCause::RuleCreationModificationFailure;
        response.detail = "Unexpected PFCP SEID";
        return response;
    }

    const auto response_context = first_ie_value(*message, PfcpIeType::ResponseContext);
    if (response_context.has_value()) {
        if (!has_strict_response_context_layout(*response_context)) {
            response.success = false;
            response.cause = PfcpCause::RuleCreationModificationFailure;
            response.detail = "Invalid PFCP response context";
            return response;
        }
        const auto cause_ie = decode_grouped_entry(*response_context, PfcpIeType::Cause);
        const auto version_ie = decode_grouped_entry(*response_context, PfcpIeType::SessionVersion);
        if (cause_ie.has_value() && !cause_ie->empty()) {
            response.cause = decode_pfcp_cause(cause_ie->front());
        } else {
            response.cause = PfcpCause::RuleCreationModificationFailure;
        }
        if (version_ie.has_value() && version_ie->size() == 8) {
            response.session_version = read_u64(*version_ie, 0);
        } else if (version_ie.has_value() && version_ie->size() == 4) {
            response.session_version = read_u32(*version_ie, 0);
        } else {
            response.session_version = 0;
        }
        response.detail = format_pfcp_default_response_detail(response.cause);
    } else {
        const auto cause_ie = first_ie_value(*message, PfcpIeType::Cause);
        if (cause_ie.has_value() && !cause_ie->empty()) {
            response.cause = decode_pfcp_cause(cause_ie->front());
        } else {
            response.cause = parse_cause(first_ie_string(*message, PfcpIeType::Cause));
        }
        response.session_version = first_ie_u64(*message, PfcpIeType::SessionVersion, 0);
        response.detail = format_pfcp_default_response_detail(response.cause);
    }
    response.success = response.cause == PfcpCause::RequestAccepted;
    return response;
}

std::optional<std::string> NetworkN4Adapter::send_udp_request(const std::string& payload, int timeout_ms, int max_attempts) const {
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
    apply_recv_timeout(sock, timeout_ms);

    const int attempts = std::max(1, max_attempts);
    char buffer[4096] {};
    int received = -1;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        const int sent = sendto(sock, payload.data(), static_cast<int>(payload.size()), 0, result->ai_addr, static_cast<int>(result->ai_addrlen));
        if (sent < 0) {
            continue;
        }

        sockaddr_storage from {};
        socklen_t from_len = sizeof(from);
        received = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        if (received > 0) {
            break;
        }
    }

    close_socket(sock);
    freeaddrinfo(result);

    if (received <= 0) {
        return std::nullopt;
    }
    return std::string(buffer, buffer + received);
}

std::optional<UsageReport> NetworkN4Adapter::query_usage_report(const std::string& imsi,
                                                                const std::string& pdu_session_id,
                                                                const std::vector<std::uint32_t>& urr_ids) {
    if (!ensure_association()) {
        return std::nullopt;
    }

    const std::string key = session_key(imsi, pdu_session_id);
    UsageReport cached_report {};
    bool has_cached_report = false;

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        const auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            cached_report = it->second.usage;
            has_cached_report = true;
        }
    }

    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    std::vector<std::uint8_t> ies;
    append_ie_string(&ies, PfcpIeType::Imsi, imsi);
    append_ie_string(&ies, PfcpIeType::PduSessionId, pdu_session_id);
    for (const std::uint32_t urr_id : urr_ids) {
        append_ie(&ies, PfcpIeType::UsageQueryContext, encode_usage_query_context_group(imsi, pdu_session_id, std::vector<std::uint32_t> {urr_id}));
    }
    const std::uint64_t seid = make_pfcp_seid(imsi, pdu_session_id);
    const auto response_text = send_udp_request(encode_pfcp_message(PfcpMessageType::SessionReportRequest,
                                                                    true,
                                                                    seid,
                                                                    sequence,
                                                                    ies),
                                                timeout_ms_,
                                                1);
    if (!response_text.has_value()) {
        if (has_cached_report) {
            return cached_report;
        }
        return std::nullopt;
    }

    const auto message = decode_pfcp_message(*response_text);
    if (!message.has_value() ||
        message->message_type != PfcpMessageType::SessionReportResponse ||
        !message->has_seid ||
        message->seid != seid ||
        message->sequence != sequence) {
        return std::nullopt;
    }

    UsageReport report {};
    const auto usage_contexts = all_ie_values(*message, PfcpIeType::UsageReportContext);
    if (usage_contexts.empty()) {
        return std::nullopt;
    }
    const std::unordered_set<std::uint32_t> requested_ids(urr_ids.begin(), urr_ids.end());
    std::unordered_set<std::uint32_t> rule_ids;
    for (const auto& usage_context : usage_contexts) {
        if (!has_strict_usage_report_context_layout(usage_context)) {
            return std::nullopt;
        }
        const auto rule_id = decode_grouped_entry(usage_context, PfcpIeType::UrrId);
        const auto measurement_method = decode_grouped_entry(usage_context, PfcpIeType::MeasurementMethodValue);
        const auto reporting_trigger = decode_grouped_entry(usage_context, PfcpIeType::ReportingTriggerValue);
        const auto report_cause_ie = decode_grouped_entry(usage_context, PfcpIeType::Cause);
        const auto bytes_ul = decode_grouped_entry(usage_context, PfcpIeType::BytesUl);
        const auto bytes_dl = decode_grouped_entry(usage_context, PfcpIeType::BytesDl);
        const auto packets_ul = decode_grouped_entry(usage_context, PfcpIeType::PacketsUl);
        const auto packets_dl = decode_grouped_entry(usage_context, PfcpIeType::PacketsDl);
        if (!rule_id.has_value() || rule_id->size() != 4 || !measurement_method.has_value() || !reporting_trigger.has_value() || !report_cause_ie.has_value() || report_cause_ie->size() != 1 ||
            !bytes_ul.has_value() || bytes_ul->size() != 8 || !bytes_dl.has_value() || bytes_dl->size() != 8 ||
            !packets_ul.has_value() || packets_ul->size() != 8 || !packets_dl.has_value() || packets_dl->size() != 8) {
            return std::nullopt;
        }
        const auto report_cause = decode_usage_report_cause(report_cause_ie->front());
        if (!report_cause.has_value()) {
            return std::nullopt;
        }
        const std::uint32_t decoded_rule_id = read_u32(*rule_id, 0);
        if (decoded_rule_id == 0 || !rule_ids.insert(decoded_rule_id).second) {
            return std::nullopt;
        }
        if (!requested_ids.empty() && requested_ids.find(decoded_rule_id) == requested_ids.end()) {
            return std::nullopt;
        }
        UsageReportEntry entry;
        entry.urr_id = decoded_rule_id;
        entry.measurement_method.assign(measurement_method->begin(), measurement_method->end());
        entry.reporting_trigger.assign(reporting_trigger->begin(), reporting_trigger->end());
        entry.report_cause = *report_cause;
        entry.detail = default_usage_report_detail(*report_cause);
        entry.threshold_value.reset();
        entry.quota_value.reset();
        entry.bytes_ul = read_u64(*bytes_ul, 0);
        entry.bytes_dl = read_u64(*bytes_dl, 0);
        entry.packets_ul = read_u64(*packets_ul, 0);
        entry.packets_dl = read_u64(*packets_dl, 0);
        report.urr_reports.push_back(entry);
        report.bytes_ul += read_u64(*bytes_ul, 0);
        report.bytes_dl += read_u64(*bytes_dl, 0);
        report.packets_ul += read_u64(*packets_ul, 0);
        report.packets_dl += read_u64(*packets_dl, 0);
    }

    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        const auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            it->second.usage = report;
        }
    }

    return report;
}

bool NetworkN4Adapter::send_heartbeat() {
    if (!ensure_association()) {
        return false;
    }

    std::uint32_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        sequence = next_pfcp_sequence(&sequence_counter_);
    }

    std::vector<std::uint8_t> ies;
    append_ie(&ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(recovery_time_stamp_));
    const auto response_text = send_udp_request(encode_pfcp_message(PfcpMessageType::HeartbeatRequest,
                                                                    false,
                                                                    0,
                                                                    sequence,
                                                                    ies),
                                                timeout_ms_,
                                                1);
    if (!response_text.has_value()) {
        return false;
    }

    const PfcpSessionResponse parsed = parse_wire_response(*response_text,
                                                           static_cast<std::uint8_t>(PfcpMessageType::HeartbeatResponse),
                                                           sequence,
                                                           false,
                                                           0);
    if (!parsed.success) {
        return false;
    }

    const auto message = decode_pfcp_message(*response_text);
    if (!message.has_value()) {
        return false;
    }

    const auto response_context = first_ie_value(*message, PfcpIeType::ResponseContext);
    if (response_context.has_value()) {
        const auto recovery_ie = decode_grouped_entry(*response_context, PfcpIeType::RecoveryTimeStamp);
        return recovery_ie.has_value() && recovery_ie->size() == 4 && read_u32(*recovery_ie, 0) != 0;
    }

    return first_ie_u32(*message, PfcpIeType::RecoveryTimeStamp, 0) != 0;
}

NetworkN6Adapter::NetworkN6Adapter(std::string remote_host,
                                   int remote_port,
                                   std::string bind_endpoint,
                                   int downlink_wait_timeout_ms,
                                   std::size_t downlink_buffer_capacity,
                                   std::string downlink_overflow_policy)
    : remote_host_(std::move(remote_host))
    , remote_port_(remote_port)
    , bind_endpoint_(std::move(bind_endpoint))
    , downlink_wait_timeout_ms_(downlink_wait_timeout_ms)
    , downlink_overflow_policy_(normalize_n6_overflow_policy(std::move(downlink_overflow_policy)))
    , downlink_overflow_policy_enum_(parse_n6_overflow_policy(downlink_overflow_policy_))
    , downlink_buffer_(downlink_buffer_capacity) {
    if (!bind_endpoint_.empty()) {
        listening_ = true;
        listener_thread_ = std::make_unique<std::thread>(&NetworkN6Adapter::downlink_listener_thread, this);
    }
}

NetworkN6Adapter::~NetworkN6Adapter() {
    stop_listener();
}

bool NetworkN6Adapter::register_session(const N6SessionContext& context) {
    if (!validate_session_context(context)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(state_mutex_);
    sessions_[session_key(context.imsi, context.pdu_session_id)] = context;
    return true;
}

bool NetworkN6Adapter::update_session(const N6SessionContext& context) {
    if (!validate_session_context(context)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(state_mutex_);
    const std::string key = session_key(context.imsi, context.pdu_session_id);
    if (sessions_.find(key) == sessions_.end()) {
        return false;
    }
    sessions_[key] = context;
    return true;
}

bool NetworkN6Adapter::remove_session(const std::string& imsi, const std::string& pdu_session_id) {
    const std::string key = session_key(imsi, pdu_session_id);
    downlink_buffer_.clear_session(key);
    std::lock_guard<std::mutex> lock(state_mutex_);
    return sessions_.erase(key) > 0;
}

std::optional<N6SessionContext> NetworkN6Adapter::get_session(const std::string& imsi, const std::string& pdu_session_id) const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto it = sessions_.find(session_key(imsi, pdu_session_id));
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool NetworkN6Adapter::forward_packet(const std::string& imsi, const std::string& pdu_session_id, const N6Packet& packet) {
    const auto session = get_session(imsi, pdu_session_id);
    if (!session.has_value()) {
        return false;
    }

    N6Packet outbound = packet;
    if (!finalize_packet(*session, &outbound)) {
        return false;
    }

    if (!send_payload(encode_packet(imsi, pdu_session_id, session->dnn, outbound))) {
        return false;
    }

    N6ForwardRecord record {};
    record.imsi = imsi;
    record.pdu_session_id = pdu_session_id;
    record.dnn = session->dnn;
    record.direction = N6TrafficDirection::Uplink;
    record.packet = outbound;
    record.wire_bytes = calculate_wire_bytes(outbound);

    std::lock_guard<std::mutex> lock(state_mutex_);
    history_.push_back(record);
    return true;
}

std::optional<N6Packet> NetworkN6Adapter::receive_from_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    const std::string key = session_key(imsi, pdu_session_id);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(std::max(0, downlink_wait_timeout_ms_));

    while (true) {
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            const auto session_it = sessions_.find(key);
            if (session_it == sessions_.end()) {
                return std::nullopt;
            }
        }

        if (auto packet = downlink_buffer_.dequeue(key); packet.has_value()) {
            std::lock_guard<std::mutex> lock(state_mutex_);
            const auto session_it = sessions_.find(key);
            if (session_it == sessions_.end()) {
                return std::nullopt;
            }

            N6ForwardRecord record {};
            record.imsi = imsi;
            record.pdu_session_id = pdu_session_id;
            record.dnn = session_it->second.dnn;
            record.direction = N6TrafficDirection::Downlink;
            record.packet = *packet;
            record.wire_bytes = calculate_wire_bytes(*packet);
            history_.push_back(record);
            return packet;
        }

        (void)bytes;
        if (std::chrono::steady_clock::now() >= deadline) {
            return std::nullopt;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool NetworkN6Adapter::forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    const auto session = get_session(imsi, pdu_session_id);
    if (!session.has_value()) {
        return false;
    }

    const auto packet = build_default_packet(*session, bytes);
    if (!packet.has_value()) {
        return false;
    }

    return forward_packet(imsi, pdu_session_id, *packet);
}

std::vector<N6ForwardRecord> NetworkN6Adapter::get_forward_history() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return history_;
}

N6BufferStatus NetworkN6Adapter::get_buffer_status() const {
    const auto stats = downlink_buffer_.stats();
    N6BufferStatus status {};
    status.per_session_capacity = downlink_buffer_.capacity();
    status.overflow_policy = downlink_overflow_policy_enum_;
    status.enqueued_packets = stats.enqueued_packets;
    status.dequeued_packets = stats.dequeued_packets;
    status.dropped_packets = stats.dropped_packets + unknown_session_drop_count_.load();
    status.buffered_packets = stats.buffered_packets;
    status.active_sessions = stats.active_sessions;
    status.dropped_overflow_oldest = stats.dropped_overflow_oldest;
    status.dropped_overflow_newest = stats.dropped_overflow_newest;
    status.dropped_session_removed = stats.dropped_session_removed;
    status.dropped_unknown_session = unknown_session_drop_count_.load();
    status.rejected_by_policy = stats.rejected_by_policy;
    return status;
}

std::size_t NetworkN6Adapter::buffered_packets_for_session(const std::string& imsi, const std::string& pdu_session_id) const {
    return downlink_buffer_.buffered_packets(session_key(imsi, pdu_session_id));
}

N6SessionBufferCounters NetworkN6Adapter::buffer_counters_for_session(const std::string& imsi, const std::string& pdu_session_id) const {
    const auto stats = downlink_buffer_.session_stats(session_key(imsi, pdu_session_id));
    return N6SessionBufferCounters {
        stats.enqueued_packets,
        stats.dequeued_packets,
        stats.dropped_packets,
        stats.dropped_overflow_oldest,
        stats.dropped_overflow_newest,
        stats.dropped_session_removed,
        stats.rejected_by_policy,
        buffered_packets_for_session(imsi, pdu_session_id)
    };
}

bool NetworkN6Adapter::parse_downlink_wire_payload(const std::string& payload, std::string* out_session_key, N6Packet* out_packet) const {
    if (out_session_key == nullptr || out_packet == nullptr) {
        return false;
    }

    const auto tokens = parse_tokens(payload);
    const auto imsi_it = tokens.find("imsi");
    const auto pdu_it = tokens.find("pdu");
    const auto protocol_it = tokens.find("protocol");
    if (imsi_it == tokens.end() || pdu_it == tokens.end() || protocol_it == tokens.end()) {
        return false;
    }

    N6Packet packet {};
    if (protocol_it->second == "IPv4") {
        packet.protocol = N6Protocol::IPv4;
        packet.source_ipv4 = tokens.count("src_ipv4") != 0 ? tokens.at("src_ipv4") : std::string();
        packet.destination_ipv4 = tokens.count("dst_ipv4") != 0 ? tokens.at("dst_ipv4") : std::string();
    } else if (protocol_it->second == "IPv6") {
        packet.protocol = N6Protocol::IPv6;
        packet.source_ipv6 = tokens.count("src_ipv6") != 0 ? tokens.at("src_ipv6") : std::string();
        packet.destination_ipv6 = tokens.count("dst_ipv6") != 0 ? tokens.at("dst_ipv6") : std::string();
    } else if (protocol_it->second == "Ethernet") {
        packet.protocol = N6Protocol::Ethernet;
        packet.source_mac = tokens.count("src_mac") != 0 ? tokens.at("src_mac") : std::string();
        packet.destination_mac = tokens.count("dst_mac") != 0 ? tokens.at("dst_mac") : std::string();
        packet.ether_type = tokens.count("ether_type") != 0 ? static_cast<std::uint16_t>(std::strtoul(tokens.at("ether_type").c_str(), nullptr, 10)) : 0x0800;
    } else {
        return false;
    }

    const std::size_t payload_bytes = tokens.count("payload_bytes") != 0
        ? static_cast<std::size_t>(std::strtoull(tokens.at("payload_bytes").c_str(), nullptr, 10))
        : 0U;
    packet.payload.resize(payload_bytes);

    *out_session_key = session_key(imsi_it->second, pdu_it->second);
    *out_packet = std::move(packet);
    return true;
}

void NetworkN6Adapter::downlink_listener_thread() {
    if (!ensure_network_stack()) {
        listening_ = false;
        return;
    }

    std::string bind_host;
    int bind_port = 0;
    if (!parse_endpoint(bind_endpoint_, &bind_host, &bind_port)) {
        listening_ = false;
        return;
    }

    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = bind_host.empty() ? AI_PASSIVE : 0;

    addrinfo* result = nullptr;
    const std::string port_text = std::to_string(bind_port);
    if (getaddrinfo(bind_host.empty() ? nullptr : bind_host.c_str(), port_text.c_str(), &hints, &result) != 0 || result == nullptr) {
        listening_ = false;
        return;
    }

    SocketType listen_socket = kInvalidSocket;
    for (addrinfo* entry = result; entry != nullptr; entry = entry->ai_next) {
        listen_socket = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (listen_socket == kInvalidSocket) {
            continue;
        }

        if (bind(listen_socket, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) == 0) {
            break;
        }

        close_socket(listen_socket);
        listen_socket = kInvalidSocket;
    }

    freeaddrinfo(result);
    if (listen_socket == kInvalidSocket) {
        listening_ = false;
        return;
    }

    apply_recv_timeout(listen_socket, 200);
    std::vector<char> buffer(2048);
    while (listening_.load()) {
        sockaddr_storage from {};
        socklen_t from_len = sizeof(from);
        const int received = recvfrom(listen_socket,
                                      buffer.data(),
                                      static_cast<int>(buffer.size() - 1),
                                      0,
                                      reinterpret_cast<sockaddr*>(&from),
                                      &from_len);
        if (received <= 0) {
            continue;
        }

        buffer[received] = '\0';
        std::string key;
        N6Packet packet {};
        if (!parse_downlink_wire_payload(std::string(buffer.data(), static_cast<std::size_t>(received)), &key, &packet)) {
            continue;
        }

        bool known_session = false;
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            known_session = sessions_.find(key) != sessions_.end();
        }
        if (!known_session) {
            ++unknown_session_drop_count_;
            continue;
        }

        downlink_buffer_.enqueue(key, std::move(packet), downlink_overflow_policy_enum_);
    }

    close_socket(listen_socket);
}

void NetworkN6Adapter::stop_listener() {
    listening_ = false;
    if (listener_thread_ && listener_thread_->joinable()) {
        listener_thread_->join();
    }
}

std::string NetworkN6Adapter::session_key(const std::string& imsi, const std::string& pdu_session_id) const {
    return imsi + "|" + pdu_session_id;
}

bool NetworkN6Adapter::validate_session_context(const N6SessionContext& context) const {
    if (context.imsi.empty() || context.pdu_session_id.empty() || context.dnn.empty()) {
        return false;
    }
    if (context.ue_ipv4.empty() && context.ue_ipv6.empty() && context.ue_mac.empty()) {
        return false;
    }
    if (context.ipv6_enabled && context.ue_ipv6.empty()) {
        return false;
    }
    if (context.ethernet_enabled && context.ue_mac.empty()) {
        return false;
    }
    return true;
}

bool NetworkN6Adapter::finalize_packet(const N6SessionContext& session, N6Packet* packet) const {
    if (packet == nullptr) {
        return false;
    }

    if (packet->protocol == N6Protocol::IPv4) {
        if (packet->source_ipv4.empty()) {
            packet->source_ipv4 = session.ue_ipv4;
        }
        if (packet->destination_ipv4.empty()) {
            packet->destination_ipv4 = n6_default_ipv4_destination(session.dnn);
        }
        if (packet->source_ipv4.empty() || packet->destination_ipv4.empty()) {
            return false;
        }
        packet->ether_type = 0x0800;
        return true;
    }

    if (packet->protocol == N6Protocol::IPv6) {
        if (packet->source_ipv6.empty()) {
            packet->source_ipv6 = session.ue_ipv6;
        }
        if (packet->destination_ipv6.empty()) {
            packet->destination_ipv6 = n6_default_ipv6_destination(session.dnn);
        }
        if (packet->source_ipv6.empty() || packet->destination_ipv6.empty()) {
            return false;
        }
        packet->ether_type = 0x86DD;
        return true;
    }

    if (packet->source_mac.empty()) {
        packet->source_mac = session.ue_mac;
    }
    if (packet->destination_mac.empty()) {
        packet->destination_mac = n6_default_destination_mac(session.dnn);
    }
    if (packet->source_mac.empty() || packet->destination_mac.empty()) {
        return false;
    }
    if (packet->ether_type == 0) {
        packet->ether_type = 0x0800;
    }
    return true;
}

std::optional<N6Packet> NetworkN6Adapter::build_default_packet(const N6SessionContext& session, std::size_t bytes) const {
    N6Packet packet {};
    packet.payload.resize(bytes);

    if (session.ipv6_enabled && !session.ue_ipv6.empty()) {
        packet.protocol = N6Protocol::IPv6;
        packet.source_ipv6 = session.ue_ipv6;
        packet.destination_ipv6 = n6_default_ipv6_destination(session.dnn);
        packet.ether_type = 0x86DD;
        return packet;
    }

    if (session.ethernet_enabled && !session.ue_mac.empty()) {
        packet.protocol = N6Protocol::Ethernet;
        packet.source_mac = session.ue_mac;
        packet.destination_mac = n6_default_destination_mac(session.dnn);
        packet.ether_type = 0x0800;
        return packet;
    }

    if (!session.ue_ipv4.empty()) {
        packet.protocol = N6Protocol::IPv4;
        packet.source_ipv4 = session.ue_ipv4;
        packet.destination_ipv4 = n6_default_ipv4_destination(session.dnn);
        packet.ether_type = 0x0800;
        return packet;
    }

    return std::nullopt;
}

std::size_t NetworkN6Adapter::calculate_wire_bytes(const N6Packet& packet) const {
    switch (packet.protocol) {
        case N6Protocol::IPv4:
            return packet.payload.size() + 20U;
        case N6Protocol::IPv6:
            return packet.payload.size() + 40U;
        case N6Protocol::Ethernet:
            return packet.payload.size() + 14U;
    }
    return packet.payload.size();
}

std::string NetworkN6Adapter::encode_packet(const std::string& imsi, const std::string& pdu_session_id, const std::string& dnn, const N6Packet& packet) const {
    std::ostringstream payload;
    payload << "N6 protocol=" << n6_protocol_to_string(packet.protocol)
            << " imsi=" << imsi
            << " pdu=" << pdu_session_id
            << " dnn=" << dnn
            << " payload_bytes=" << packet.payload.size();

    if (packet.protocol == N6Protocol::IPv4) {
        payload << " src_ipv4=" << packet.source_ipv4
                << " dst_ipv4=" << packet.destination_ipv4;
    } else if (packet.protocol == N6Protocol::IPv6) {
        payload << " src_ipv6=" << packet.source_ipv6
                << " dst_ipv6=" << packet.destination_ipv6;
    } else {
        payload << " src_mac=" << packet.source_mac
                << " dst_mac=" << packet.destination_mac
                << " ether_type=" << packet.ether_type;
    }

    return payload.str();
}

bool NetworkN6Adapter::send_payload(const std::string& payload) const {
    if (!ensure_network_stack()) {
        return false;
    }

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

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

bool NetworkN9Adapter::forward_to_branch_upf(const std::string&, const std::string&, std::size_t) {
    return enabled_;
}

bool NetworkN9Adapter::is_enabled() const {
    return enabled_;
}

// N19 Adapter Implementation
NetworkN19Adapter::NetworkN19Adapter(std::string local_upf_endpoint, bool enabled)
    : local_upf_endpoint_(std::move(local_upf_endpoint)), enabled_(enabled) {}

bool NetworkN19Adapter::forward_to_local_upf(const std::string& imsi, const std::string& pdu_session_id, 
                                            const std::string& target_upf_address, std::size_t bytes) {
    if (!enabled_) {
        return false;
    }

    std::ostringstream payload;
    payload << "N19_GTP_FWD imsi=" << imsi 
            << " pdu=" << pdu_session_id 
            << " bytes=" << bytes 
            << " src=" << local_upf_endpoint_;

    return send_gtp_packet(target_upf_address, payload.str()).has_value();
}

bool NetworkN19Adapter::is_enabled() const {
    return enabled_;
}

std::string NetworkN19Adapter::get_local_upf_endpoint() const {
    return local_upf_endpoint_;
}

std::optional<std::string> NetworkN19Adapter::send_gtp_packet(const std::string& target_address, 
                                                             const std::string& payload) const {
    if (!ensure_network_stack()) {
        return std::nullopt;
    }

    // Parse target_address as "host:port"
    const size_t colon_pos = target_address.find(':');
    if (colon_pos == std::string::npos) {
        return std::nullopt;
    }

    const std::string host = target_address.substr(0, colon_pos);
    const int port = std::stoi(target_address.substr(colon_pos + 1));

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        return std::nullopt;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return std::nullopt;
    }

    const int sent = sendto(sock, payload.c_str(), static_cast<int>(payload.size()), 0, result->ai_addr, static_cast<int>(result->ai_addrlen));
    close_socket(sock);
    freeaddrinfo(result);

    return (sent > 0) ? std::make_optional(std::string("OK")) : std::nullopt;
}

// Nx Adapter Implementation
bool NetworkNxAdapter::forward_uplink_classified(const std::string& imsi, const std::string& pdu_session_id, 
                                                const std::string& target_upf_address, std::size_t bytes) {
    if (!enabled_) {
        return false;
    }

    const std::string resolved_target = resolve_target_address(target_upf_address.empty()
        ? classify_uplink_packet(imsi, pdu_session_id)
        : target_upf_address);
    if (resolved_target.empty()) {
        return false;
    }

    std::ostringstream payload;
    payload << "NX_UL_CLASSIFY imsi=" << imsi 
            << " pdu=" << pdu_session_id 
            << " bytes=" << bytes 
            << " target=" << resolved_target;

    return send_gtp_packet(resolved_target, payload.str()).has_value();
}

bool NetworkNxAdapter::set_uplink_classifier_rules(const std::vector<UplinkClassifierRule>& rules) {
    ul_classifier_rules_ = rules;
    // Sort by precedence (higher precedence = lower number)
    std::sort(ul_classifier_rules_.begin(), ul_classifier_rules_.end(), 
              [](const UplinkClassifierRule& a, const UplinkClassifierRule& b) {
                  return a.precedence < b.precedence;
              });
    return true;
}

bool NetworkNxAdapter::add_branch_upf_endpoint(const std::string& upf_id, const std::string& address) {
    if (upf_id.empty() || address.find(':') == std::string::npos) {
        return false;
    }
    branch_upf_endpoints_[upf_id] = address;
    return true;
}

bool NetworkNxAdapter::is_enabled() const {
    return enabled_;
}

std::optional<std::string> NetworkNxAdapter::send_gtp_packet(const std::string& target_address, 
                                                            const std::string& payload) const {
    if (!ensure_network_stack()) {
        return std::nullopt;
    }

    const size_t colon_pos = target_address.find(':');
    if (colon_pos == std::string::npos) {
        return std::nullopt;
    }

    const std::string host = target_address.substr(0, colon_pos);
    const int port = std::stoi(target_address.substr(colon_pos + 1));

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_string.c_str(), &hints, &result) != 0 || result == nullptr) {
        return std::nullopt;
    }

    SocketType sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == kInvalidSocket) {
        freeaddrinfo(result);
        return std::nullopt;
    }

    const int sent = sendto(sock, payload.c_str(), static_cast<int>(payload.size()), 0, result->ai_addr, static_cast<int>(result->ai_addrlen));
    close_socket(sock);
    freeaddrinfo(result);

    return (sent > 0) ? std::make_optional(std::string("OK")) : std::nullopt;
}

std::string NetworkNxAdapter::resolve_target_address(const std::string& target_upf_address) const {
    if (target_upf_address.find(':') != std::string::npos) {
        return target_upf_address;
    }

    const auto it = branch_upf_endpoints_.find(target_upf_address);
    if (it != branch_upf_endpoints_.end()) {
        return it->second;
    }

    return {};
}

std::string NetworkNxAdapter::classify_uplink_packet(const std::string&, const std::string&) {
    if (!ul_classifier_rules_.empty()) {
        return resolve_target_address(ul_classifier_rules_.front().target_upf_address);
    }

    if (!branch_upf_endpoints_.empty()) {
        return branch_upf_endpoints_.begin()->second;
    }
    return "";
}

// Nsmf Adapter Implementation
bool NetworkNsmfAdapter::send_internal_message(const InternalComponentMessage& message) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    // Route message to target component's queue
    if (registered_components_.find(message.target_component) == registered_components_.end()) {
        return false;
    }

    message_queues_[message.target_component].push(message);
    return true;
}

std::optional<InternalComponentMessage> NetworkNsmfAdapter::receive_internal_message(int timeout_ms) {
    // For simplicity, receive from first available queue with timeout
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            for (auto& [component, queue] : message_queues_) {
                if (!queue.empty()) {
                    auto msg = queue.front();
                    queue.pop();
                    return msg;
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() >= timeout_ms) {
            return std::nullopt;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool NetworkNsmfAdapter::register_internal_component(const std::string& component_name) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (registered_components_.find(component_name) != registered_components_.end()) {
        return false;  // Already registered
    }
    registered_components_.insert(component_name);
    message_queues_[component_name] = std::queue<InternalComponentMessage>();
    return true;
}

bool NetworkNsmfAdapter::unregister_internal_component(const std::string& component_name) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (registered_components_.find(component_name) == registered_components_.end()) {
        return false;  // Not registered
    }
    registered_components_.erase(component_name);
    message_queues_.erase(component_name);
    return true;
}

std::vector<std::string> NetworkNsmfAdapter::get_registered_components() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    std::vector<std::string> components;
    for (const auto& comp : registered_components_) {
        components.push_back(comp);
    }
    return components;
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

    const std::string body = format_sbi_event_request_body(service_name, payload);
    const std::string wire = format_http_post_request(remote_host_ + ':' + std::to_string(remote_port_), path_, body);
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
