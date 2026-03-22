#include "upf/protocol/pfcp_wire.hpp"

#include <cstdlib>
#include <cstring>
#include <functional>
#include <sstream>
#include <string>
#include <unordered_set>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace upf::pfcp {

namespace {

int usage_report_field_order(std::uint16_t decoded_inner_type) {
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::UrrId)) {
        return 0;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::MeasurementMethodValue)) {
        return 1;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::ReportingTriggerValue)) {
        return 2;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::Cause)) {
        return 3;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::BytesUl)) {
        return 4;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::BytesDl)) {
        return 5;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::PacketsUl)) {
        return 6;
    }
    if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::PacketsDl)) {
        return 7;
    }
    return -1;
}

}  // namespace

void append_u16(std::vector<std::uint8_t>* buffer, std::uint16_t value) {
    buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void append_u32(std::vector<std::uint8_t>* buffer, std::uint32_t value) {
    buffer->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void append_u64(std::vector<std::uint8_t>* buffer, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer->push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(buffer[offset]) << 8) | buffer[offset + 1]);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    return (static_cast<std::uint32_t>(buffer[offset]) << 24) |
           (static_cast<std::uint32_t>(buffer[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(buffer[offset + 2]) << 8) |
           static_cast<std::uint32_t>(buffer[offset + 3]);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | buffer[offset + i];
    }
    return value;
}

void append_ie(std::vector<std::uint8_t>* buffer, PfcpIeType type, const std::vector<std::uint8_t>& value) {
    append_u16(buffer, static_cast<std::uint16_t>(type));
    append_u16(buffer, static_cast<std::uint16_t>(value.size()));
    buffer->insert(buffer->end(), value.begin(), value.end());
}

void append_ie_string(std::vector<std::uint8_t>* buffer, PfcpIeType type, const std::string& value) {
    append_ie(buffer, type, std::vector<std::uint8_t>(value.begin(), value.end()));
}

void append_ie_u32(std::vector<std::uint8_t>* buffer, PfcpIeType type, std::uint32_t value) {
    std::vector<std::uint8_t> encoded;
    append_u32(&encoded, value);
    append_ie(buffer, type, encoded);
}

void append_ie_u64(std::vector<std::uint8_t>* buffer, PfcpIeType type, std::uint64_t value) {
    std::vector<std::uint8_t> encoded;
    append_u64(&encoded, value);
    append_ie(buffer, type, encoded);
}

std::uint8_t encode_pfcp_cause(PfcpCause cause) {
    switch (cause) {
        case PfcpCause::RequestAccepted:
            return 1;
        case PfcpCause::MandatoryIeMissing:
            return 64;
        case PfcpCause::SessionContextNotFound:
            return 65;
        case PfcpCause::SemanticErrorInTheTft:
            return 73;
        case PfcpCause::InvalidQfi:
            return 74;
        case PfcpCause::InvalidGateStatus:
            return 75;
        case PfcpCause::RuleCreationModificationFailure:
            return 72;
    }
    return 72;
}

PfcpCause decode_pfcp_cause(std::uint8_t code) {
    switch (code) {
        case 1:
            return PfcpCause::RequestAccepted;
        case 64:
            return PfcpCause::MandatoryIeMissing;
        case 65:
            return PfcpCause::SessionContextNotFound;
        case 73:
            return PfcpCause::SemanticErrorInTheTft;
        case 74:
            return PfcpCause::InvalidQfi;
        case 75:
            return PfcpCause::InvalidGateStatus;
        default:
            return PfcpCause::RuleCreationModificationFailure;
    }
}

std::optional<UsageReportCause> decode_usage_report_cause(std::uint8_t code) {
    switch (code) {
        case 1:
            return UsageReportCause::UsageReady;
        case 2:
            return UsageReportCause::ThresholdReached;
        case 3:
            return UsageReportCause::QuotaExhausted;
        default:
            return std::nullopt;
    }
}

std::string default_usage_report_detail(UsageReportCause cause) {
    switch (cause) {
        case UsageReportCause::UsageReady:
            return "usage-ready";
        case UsageReportCause::ThresholdReached:
            return "threshold-reached";
        case UsageReportCause::QuotaExhausted:
            return "quota-exhausted";
        case UsageReportCause::Unknown:
            return "unknown";
    }
    return "unknown";
}

std::vector<std::uint8_t> encode_ipv4_bytes(const std::string& ipv4) {
    std::vector<std::uint8_t> bytes(4, 0);
    in_addr address {};
    if (!ipv4.empty() && inet_pton(AF_INET, ipv4.c_str(), &address) == 1) {
        const auto* raw = reinterpret_cast<const std::uint8_t*>(&address.s_addr);
        bytes.assign(raw, raw + 4);
    }
    return bytes;
}

bool is_valid_ipv4_text(const std::string& ipv4) {
    if (ipv4.empty()) {
        return false;
    }
    in_addr address {};
    return inet_pton(AF_INET, ipv4.c_str(), &address) == 1;
}

std::vector<std::uint8_t> encode_ipv6_bytes(const std::string& ipv6) {
    std::vector<std::uint8_t> bytes;
    in6_addr address {};
    if (!ipv6.empty() && inet_pton(AF_INET6, ipv6.c_str(), &address) == 1) {
        const auto* raw = reinterpret_cast<const std::uint8_t*>(&address.s6_addr);
        bytes.assign(raw, raw + 16);
    }
    return bytes;
}

std::vector<std::uint8_t> encode_mac_bytes(const std::string& mac) {
    std::vector<std::uint8_t> bytes;
    std::size_t start = 0;
    while (start < mac.size()) {
        const std::size_t end = mac.find(':', start);
        const std::string token = mac.substr(start, end == std::string::npos ? std::string::npos : end - start);
        char* parse_end = nullptr;
        const long value = std::strtol(token.c_str(), &parse_end, 16);
        if (parse_end == token.c_str() || *parse_end != '\0' || value < 0 || value > 0xFF) {
            return {};
        }
        bytes.push_back(static_cast<std::uint8_t>(value));
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
    if (bytes.size() != 6) {
        return {};
    }
    return bytes;
}

std::optional<std::uint32_t> parse_teid_value(const std::string& teid) {
    if (teid.empty()) {
        return std::nullopt;
    }
    char* parse_end = nullptr;
    const unsigned long value = std::strtoul(teid.c_str(), &parse_end, 0);
    if (parse_end == teid.c_str() || *parse_end != '\0' || value > 0xFFFFFFFFUL) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

std::string decode_ipv4_bytes(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (bytes.size() < offset + 4) {
        return {};
    }
    char text[INET_ADDRSTRLEN] = {};
    in_addr address {};
    std::memcpy(&address.s_addr, bytes.data() + static_cast<std::ptrdiff_t>(offset), 4);
    if (inet_ntop(AF_INET, &address, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

std::vector<std::uint8_t> encode_node_id_ie_value(const std::string& node_id) {
    std::vector<std::uint8_t> value;
    value.push_back(0x02);
    value.insert(value.end(), node_id.begin(), node_id.end());
    return value;
}

std::vector<std::uint8_t> encode_fseid_ie_value(std::uint64_t seid, const std::string& ipv4) {
    std::vector<std::uint8_t> value;
    value.push_back(0x02);
    append_u64(&value, seid);
    const auto ipv4_bytes = encode_ipv4_bytes(ipv4);
    value.insert(value.end(), ipv4_bytes.begin(), ipv4_bytes.end());
    return value;
}

std::vector<std::uint8_t> encode_fteid_ie_value(std::uint32_t teid, const std::string& ipv4) {
    std::vector<std::uint8_t> value;
    value.push_back(0x01);
    append_u32(&value, teid);
    const auto ipv4_bytes = encode_ipv4_bytes(ipv4);
    value.insert(value.end(), ipv4_bytes.begin(), ipv4_bytes.end());
    return value;
}

std::vector<std::uint8_t> encode_ue_ip_address_ie_value(const std::string& ue_ipv4, const std::string& ue_ipv6) {
    std::vector<std::uint8_t> value;
    std::uint8_t flags = 0;
    const auto ipv4_bytes = encode_ipv4_bytes(ue_ipv4);
    const auto ipv6_bytes = encode_ipv6_bytes(ue_ipv6);
    if (!ue_ipv4.empty()) {
        flags |= 0x02U;
    }
    if (!ue_ipv6.empty()) {
        flags |= 0x01U;
    }
    value.push_back(flags);
    if (!ue_ipv4.empty()) {
        value.insert(value.end(), ipv4_bytes.begin(), ipv4_bytes.end());
    }
    if (!ue_ipv6.empty()) {
        value.insert(value.end(), ipv6_bytes.begin(), ipv6_bytes.end());
    }
    return value;
}

std::vector<std::uint8_t> encode_u32_value(std::uint32_t value) {
    std::vector<std::uint8_t> bytes;
    append_u32(&bytes, value);
    return bytes;
}

std::vector<std::uint8_t> encode_u16_value(std::uint16_t value) {
    std::vector<std::uint8_t> bytes;
    append_u16(&bytes, value);
    return bytes;
}

std::vector<std::uint8_t> encode_u64_value(std::uint64_t value) {
    std::vector<std::uint8_t> bytes;
    append_u64(&bytes, value);
    return bytes;
}

std::vector<std::uint8_t> encode_apply_action_value(const std::string& action) {
    std::uint8_t value = 0;
    if (action == "DROP") {
        value = 0x01U;
    } else if (action == "FORW") {
        value = 0x02U;
    } else if (action == "BUFF") {
        value = 0x04U;
    } else if (action == "NOCP") {
        value = 0x08U;
    }
    return std::vector<std::uint8_t> {value};
}

std::string far_forward_peer_ipv4(const std::string& forward_to) {
    if (forward_to == "internet") {
        return "198.51.100.1";
    }
    if (forward_to == "edge-cache") {
        return "198.51.100.2";
    }
    if (forward_to == "ims") {
        return "198.51.100.3";
    }
    return "198.51.100.254";
}

std::vector<std::uint8_t> encode_grouped_ie_value(PfcpIeType inner_type, const std::vector<std::uint8_t>& inner_value) {
    std::vector<std::uint8_t> grouped;
    append_u16(&grouped, static_cast<std::uint16_t>(inner_type));
    append_u16(&grouped, static_cast<std::uint16_t>(inner_value.size()));
    grouped.insert(grouped.end(), inner_value.begin(), inner_value.end());
    return grouped;
}

std::vector<std::uint8_t> encode_grouped_ie_value(const std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>>& entries) {
    std::vector<std::uint8_t> grouped;
    for (const auto& entry : entries) {
        append_u16(&grouped, static_cast<std::uint16_t>(entry.first));
        append_u16(&grouped, static_cast<std::uint16_t>(entry.second.size()));
        grouped.insert(grouped.end(), entry.second.begin(), entry.second.end());
    }
    return grouped;
}

std::vector<std::uint8_t> encode_outer_header_creation_ie_value(const PfcpFar& far_rule) {
    const std::string tunnel_peer_ipv4 = far_rule.tunnel_peer_ipv4.empty() ? far_forward_peer_ipv4(far_rule.forward_to) : far_rule.tunnel_peer_ipv4;
    const std::uint32_t tunnel_peer_teid = far_rule.tunnel_peer_teid == 0 ? (0x00F00000U + far_rule.id) : far_rule.tunnel_peer_teid;
    std::vector<std::uint8_t> value;
    append_u16(&value, static_cast<std::uint16_t>(far_rule.outer_header_creation_description) << 8);
    append_u32(&value, tunnel_peer_teid);
    const auto ipv4_bytes = encode_ipv4_bytes(tunnel_peer_ipv4);
    value.insert(value.end(), ipv4_bytes.begin(), ipv4_bytes.end());
    return value;
}

std::string pdr_flow_direction_name(std::uint8_t flow_direction) {
    switch (flow_direction) {
        case 0x01U:
            return "out";
        case 0x02U:
            return "in";
        default:
            return "bidirectional";
    }
}

std::string pdr_protocol_name(std::uint8_t protocol_identifier) {
    switch (protocol_identifier) {
        case 6U:
            return "tcp";
        case 17U:
            return "udp";
        default:
            return "ip";
    }
}

bool is_valid_pdr_source_interface(std::uint8_t source_interface) {
    return source_interface <= 0x02U;
}

bool is_valid_pdr_flow_direction(std::uint8_t flow_direction) {
    return flow_direction == 0x01U || flow_direction == 0x02U || flow_direction == 0x03U;
}

bool is_transport_protocol(std::uint8_t protocol_identifier) {
    return protocol_identifier == 6U || protocol_identifier == 17U;
}

bool is_valid_pdr_protocol(std::uint8_t protocol_identifier) {
    return protocol_identifier == 0U || is_transport_protocol(protocol_identifier);
}

bool is_valid_ether_type(std::uint16_t ether_type) {
    return ether_type == 0U || ether_type == 0x0800U || ether_type == 0x86DDU || ether_type == 0x0806U;
}

bool is_valid_apply_action(const std::string& action) {
    return action == "DROP" || action == "FORW" || action == "BUFF" || action == "NOCP";
}

std::string pdr_flow_description(const PfcpPdr& pdr_rule) {
    if (!pdr_rule.flow_description.empty()) {
        return pdr_rule.flow_description;
    }

    std::ostringstream stream;
    stream << "permit " << pdr_flow_direction_name(pdr_rule.flow_direction) << ' ' << pdr_protocol_name(pdr_rule.protocol_identifier) << " from ";
    if (!pdr_rule.ue_ipv4.empty()) {
        stream << pdr_rule.ue_ipv4 << "/32";
    } else {
        stream << "assigned";
    }
    if (pdr_rule.source_port != 0) {
        stream << ' ' << pdr_rule.source_port;
    }
    stream << " to assigned";
    if (pdr_rule.destination_port != 0) {
        stream << ' ' << pdr_rule.destination_port;
    }
    return stream.str();
}

std::string sdf_filter_flow_description(const PfcpPdr::SdfFilterEntry& filter, const std::string& fallback_ue_ipv4) {
    if (!filter.flow_description.empty()) {
        return filter.flow_description;
    }

    std::ostringstream stream;
    stream << "permit " << pdr_flow_direction_name(filter.flow_direction) << ' ' << pdr_protocol_name(filter.protocol_identifier) << " from ";
    if (!fallback_ue_ipv4.empty()) {
        stream << fallback_ue_ipv4 << "/32";
    } else {
        stream << "assigned";
    }
    if (filter.source_port != 0) {
        stream << ' ' << filter.source_port;
        if (filter.source_port_end != 0 && filter.source_port_end != filter.source_port) {
            stream << '-' << filter.source_port_end;
        }
    }
    stream << " to assigned";
    if (filter.destination_port != 0) {
        stream << ' ' << filter.destination_port;
        if (filter.destination_port_end != 0 && filter.destination_port_end != filter.destination_port) {
            stream << '-' << filter.destination_port_end;
        }
    }
    return stream.str();
}

std::vector<PfcpPdr::SdfFilterEntry> build_effective_sdf_filters(const PfcpPdr& pdr_rule) {
    if (!pdr_rule.sdf_filters.empty()) {
        return pdr_rule.sdf_filters;
    }

    PfcpPdr::SdfFilterEntry filter;
    filter.packet_filter_id = pdr_rule.packet_filter_id == 0 ? pdr_rule.id : pdr_rule.packet_filter_id;
    filter.flow_direction = pdr_rule.flow_direction;
    filter.protocol_identifier = pdr_rule.protocol_identifier;
    filter.source_port = pdr_rule.source_port;
    filter.destination_port = pdr_rule.destination_port;
    filter.ether_type = pdr_rule.ether_type;
    filter.flow_description = pdr_rule.flow_description;
    return std::vector<PfcpPdr::SdfFilterEntry> {filter};
}

bool has_explicit_legacy_pdr_filter_fields(const PfcpPdr& pdr_rule) {
    return pdr_rule.packet_filter_id != 0 ||
           pdr_rule.flow_direction != 0x01U ||
           pdr_rule.protocol_identifier != 0 ||
           pdr_rule.source_port != 0 ||
           pdr_rule.destination_port != 0 ||
           pdr_rule.ether_type != 0 ||
           !pdr_rule.flow_description.empty();
}

bool legacy_pdr_fields_match_primary_filter(const PfcpPdr& pdr_rule, const PfcpPdr::SdfFilterEntry& primary_filter) {
    if (pdr_rule.packet_filter_id != 0 && pdr_rule.packet_filter_id != primary_filter.packet_filter_id) {
        return false;
    }
    if (pdr_rule.flow_direction != 0x01U && pdr_rule.flow_direction != primary_filter.flow_direction) {
        return false;
    }
    if (pdr_rule.protocol_identifier != 0 && pdr_rule.protocol_identifier != primary_filter.protocol_identifier) {
        return false;
    }
    if (pdr_rule.source_port != 0 && pdr_rule.source_port != primary_filter.source_port) {
        return false;
    }
    if (pdr_rule.destination_port != 0 && pdr_rule.destination_port != primary_filter.destination_port) {
        return false;
    }
    if (pdr_rule.ether_type != 0 && pdr_rule.ether_type != primary_filter.ether_type) {
        return false;
    }
    if (!pdr_rule.flow_description.empty() && pdr_rule.flow_description != primary_filter.flow_description) {
        return false;
    }
    return true;
}

std::vector<std::uint8_t> encode_sdf_filter_group(const PfcpPdr::SdfFilterEntry& filter, const std::string& fallback_ue_ipv4) {
    const std::string flow_description = sdf_filter_flow_description(filter, fallback_ue_ipv4);
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    entries.push_back({PfcpIeType::PacketFilterId, encode_u32_value(filter.packet_filter_id)});
    entries.push_back({PfcpIeType::FlowDirection, std::vector<std::uint8_t> {filter.flow_direction}});
    entries.push_back({PfcpIeType::FlowDescription, std::vector<std::uint8_t>(flow_description.begin(), flow_description.end())});
    if (filter.protocol_identifier != 0) {
        entries.push_back({PfcpIeType::ProtocolIdentifier, std::vector<std::uint8_t> {filter.protocol_identifier}});
    }
    if (filter.source_port != 0) {
        entries.push_back({PfcpIeType::SourcePort, encode_u16_value(filter.source_port)});
        if (filter.source_port_end != 0 && filter.source_port_end != filter.source_port) {
            entries.push_back({PfcpIeType::SourcePortEnd, encode_u16_value(filter.source_port_end)});
        }
    }
    if (filter.destination_port != 0) {
        entries.push_back({PfcpIeType::DestinationPort, encode_u16_value(filter.destination_port)});
        if (filter.destination_port_end != 0 && filter.destination_port_end != filter.destination_port) {
            entries.push_back({PfcpIeType::DestinationPortEnd, encode_u16_value(filter.destination_port_end)});
        }
    }
    if (filter.ether_type != 0) {
        entries.push_back({PfcpIeType::EtherType, encode_u16_value(filter.ether_type)});
    }
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_recovery_time_stamp_ie_value(std::uint32_t stamp) {
    std::vector<std::uint8_t> value;
    append_u32(&value, stamp);
    return value;
}

std::vector<std::uint8_t> encode_far_ie_value(const PfcpFar& far_rule) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    entries.push_back({PfcpIeType::FarId, encode_u32_value(far_rule.id)});
    entries.push_back({PfcpIeType::ApplyAction, encode_apply_action_value(far_rule.action)});

    if (far_rule.action == "FORW") {
        entries.push_back({PfcpIeType::ForwardingParameters,
                           encode_grouped_ie_value({
                               {PfcpIeType::NetworkInstance, std::vector<std::uint8_t>(far_rule.forward_to.begin(), far_rule.forward_to.end())},
                               {PfcpIeType::OuterHeaderCreation, encode_outer_header_creation_ie_value(far_rule)},
                           })});
    } else if (far_rule.action == "BUFF") {
        entries.push_back({PfcpIeType::BufferingParameters,
                           encode_grouped_ie_value({
                               {PfcpIeType::BufferingDuration, encode_u32_value(far_rule.buffering_duration_ms)},
                           })});
    } else if (far_rule.action == "NOCP") {
        entries.push_back({PfcpIeType::NotifyControlPlane,
                           std::vector<std::uint8_t> {static_cast<std::uint8_t>(far_rule.notify_control_plane ? 0x01U : 0x00U)}});
    }

    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_qer_ie_value(const PfcpQer& qer_rule) {
    return encode_grouped_ie_value({
        {PfcpIeType::QerId, encode_u32_value(qer_rule.id)},
        {PfcpIeType::Qfi, std::vector<std::uint8_t> {qer_rule.qfi}},
        {PfcpIeType::GateStatus, std::vector<std::uint8_t> {static_cast<std::uint8_t>(qer_rule.gate_status == "OPEN" ? 1U : 0U)}},
        {PfcpIeType::GbrUl, encode_u64_value(qer_rule.gbr_ul_kbps)},
        {PfcpIeType::GbrDl, encode_u64_value(qer_rule.gbr_dl_kbps)},
        {PfcpIeType::MbrUl, encode_u64_value(qer_rule.mbr_ul_kbps)},
        {PfcpIeType::MbrDl, encode_u64_value(qer_rule.mbr_dl_kbps)},
    });
}

std::vector<std::uint8_t> encode_urr_ie_value(const PfcpUrr& urr_rule) {
    return encode_grouped_ie_value({
        {PfcpIeType::UrrId, encode_u32_value(urr_rule.id)},
        {PfcpIeType::MeasurementMethodValue, std::vector<std::uint8_t>(urr_rule.measurement_method.begin(), urr_rule.measurement_method.end())},
        {PfcpIeType::ReportingTriggerValue, std::vector<std::uint8_t>(urr_rule.trigger.begin(), urr_rule.trigger.end())},
    });
}

std::vector<std::uint8_t> encode_pdr_ie_value(const PfcpPdr& pdr_rule) {
    const auto filters = build_effective_sdf_filters(pdr_rule);
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> pdi_entries {
        {PfcpIeType::SourceInterface, std::vector<std::uint8_t> {pdr_rule.source_interface}},
        {PfcpIeType::UeIpAddress, encode_ue_ip_address_ie_value(pdr_rule.ue_ipv4, {})},
        {PfcpIeType::ApplicationId, std::vector<std::uint8_t>(pdr_rule.application_id.begin(), pdr_rule.application_id.end())},
    };
    for (const auto& filter : filters) {
        pdi_entries.push_back({PfcpIeType::SdfFilter, encode_sdf_filter_group(filter, pdr_rule.ue_ipv4)});
    }

    return encode_grouped_ie_value({
        {PfcpIeType::PdrId, encode_u32_value(pdr_rule.id)},
        {PfcpIeType::Precedence, encode_u32_value(pdr_rule.precedence)},
        {PfcpIeType::Pdi, encode_grouped_ie_value(pdi_entries)},
        {PfcpIeType::FarId, encode_u32_value(pdr_rule.far_id)},
        {PfcpIeType::QerId, encode_u32_value(pdr_rule.qer_id)},
        {PfcpIeType::UrrId, encode_u32_value(pdr_rule.urr_id)},
    });
}

std::vector<std::uint8_t> encode_user_identity_group(const PfcpSessionRequest& request) {
    return encode_grouped_ie_value({
        {PfcpIeType::Imsi, std::vector<std::uint8_t>(request.imsi.begin(), request.imsi.end())},
        {PfcpIeType::PduSessionId, std::vector<std::uint8_t>(request.pdu_session_id.begin(), request.pdu_session_id.end())},
    });
}

std::vector<std::uint8_t> encode_pdi_group(const PfcpSessionRequest& request, const std::string& local_fseid_ipv4) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    if (const auto teid = parse_teid_value(request.teid); teid.has_value()) {
        entries.push_back({PfcpIeType::SourceInterface, std::vector<std::uint8_t> {0x00}});
        entries.push_back({PfcpIeType::FTeid, encode_fteid_ie_value(*teid, local_fseid_ipv4)});
        entries.push_back({PfcpIeType::UeIpAddress, encode_ue_ip_address_ie_value(request.ue_ipv4, request.ue_ipv6)});
    }
    if (!request.dnn.empty()) {
        entries.push_back({PfcpIeType::NetworkInstance, std::vector<std::uint8_t>(request.dnn.begin(), request.dnn.end())});
    }
    if (!request.ue_mac.empty()) {
        entries.push_back({PfcpIeType::UeMac, encode_mac_bytes(request.ue_mac)});
    }
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_procedure_context_group(const PfcpProcedureContext& procedure) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    if (!procedure.request_id.empty()) {
        entries.push_back({PfcpIeType::RequestId, std::vector<std::uint8_t>(procedure.request_id.begin(), procedure.request_id.end())});
    }

    std::vector<std::uint8_t> timeout_value;
    append_u32(&timeout_value, procedure.timeout_ms);
    entries.push_back({PfcpIeType::TimeoutMs, timeout_value});

    std::vector<std::uint8_t> retries_value;
    append_u32(&retries_value, procedure.max_retries);
    entries.push_back({PfcpIeType::MaxRetries, retries_value});
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_session_profile_group(const PfcpSessionRequest& request) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    if (!request.s_nssai.empty()) {
        entries.push_back({PfcpIeType::Snssai, std::vector<std::uint8_t>(request.s_nssai.begin(), request.s_nssai.end())});
    }
    if (!request.qos_profile.empty()) {
        entries.push_back({PfcpIeType::QosProfile, std::vector<std::uint8_t>(request.qos_profile.begin(), request.qos_profile.end())});
    }
    std::vector<std::uint8_t> access_preferences(1, 0);
    if (request.prefer_n6_ipv6) {
        access_preferences[0] |= 0x01U;
    }
    if (request.prefer_n6_ethernet) {
        access_preferences[0] |= 0x02U;
    }
    entries.push_back({PfcpIeType::AccessPreferences, access_preferences});
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_control_plane_peer_group(const std::string& local_node_id,
                                                          std::uint64_t seid,
                                                          const std::string& local_fseid_ipv4) {
    return encode_grouped_ie_value({
        {PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id)},
        {PfcpIeType::FSeid, encode_fseid_ie_value(seid, local_fseid_ipv4)},
    });
}

std::vector<std::uint8_t> encode_association_context_group(const std::string& local_node_id,
                                                           const std::string& local_fseid_ipv4,
                                                           std::uint32_t recovery_time_stamp) {
    return encode_grouped_ie_value({
        {PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id)},
        {PfcpIeType::FSeid, encode_fseid_ie_value(1, local_fseid_ipv4)},
        {PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(recovery_time_stamp)},
    });
}

std::vector<std::uint8_t> encode_usage_query_context_group(const std::string& imsi,
                                                           const std::string& pdu_session_id,
                                                           const std::vector<std::uint32_t>& urr_ids) {
    (void)imsi;
    (void)pdu_session_id;
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries;
    for (const std::uint32_t urr_id : urr_ids) {
        entries.push_back({PfcpIeType::UrrId, encode_u32_value(urr_id)});
    }
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_usage_report_context_group(std::uint32_t rule_id, const UsageReport& report) {
    std::vector<std::uint8_t> bytes_ul;
    append_u64(&bytes_ul, report.bytes_ul);
    std::vector<std::uint8_t> bytes_dl;
    append_u64(&bytes_dl, report.bytes_dl);
    std::vector<std::uint8_t> packets_ul;
    append_u64(&packets_ul, report.packets_ul);
    std::vector<std::uint8_t> packets_dl;
    append_u64(&packets_dl, report.packets_dl);
    return encode_grouped_ie_value({
        {PfcpIeType::UrrId, encode_u32_value(rule_id)},
        {PfcpIeType::BytesUl, bytes_ul},
        {PfcpIeType::BytesDl, bytes_dl},
        {PfcpIeType::PacketsUl, packets_ul},
        {PfcpIeType::PacketsDl, packets_dl},
    });
}

std::vector<std::uint8_t> encode_capability_context_group(const std::string& local_node_id,
                                                          const std::string& local_fseid_ipv4) {
    std::vector<std::uint8_t> capability_bitmap;
    append_u32(&capability_bitmap, 0x0000000FU);
    return encode_grouped_ie_value({
        {PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id)},
        {PfcpIeType::FSeid, encode_fseid_ie_value(2, local_fseid_ipv4)},
        {PfcpIeType::FeatureBitmap, capability_bitmap},
    });
}

std::vector<std::uint8_t> encode_response_context_group(PfcpCause cause,
                                                        std::uint64_t session_version,
                                                        const std::string& detail,
                                                        std::uint32_t recovery_time_stamp) {
    std::vector<std::uint8_t> cause_value {encode_pfcp_cause(cause)};
    std::vector<std::uint8_t> version_value;
    append_u64(&version_value, session_version);
    (void)detail;
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries {
        {PfcpIeType::Cause, cause_value},
        {PfcpIeType::SessionVersion, version_value},
    };
    if (recovery_time_stamp != 0) {
        std::vector<std::uint8_t> recovery_value;
        append_u32(&recovery_value, recovery_time_stamp);
        entries.push_back({PfcpIeType::RecoveryTimeStamp, recovery_value});
    }
    return encode_grouped_ie_value(entries);
}

std::vector<std::uint8_t> encode_node_feature_context_group(const std::string& local_node_id,
                                                            std::uint32_t feature_bitmap) {
    std::vector<std::uint8_t> bitmap_value;
    append_u32(&bitmap_value, feature_bitmap);
    return encode_grouped_ie_value({
        {PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id)},
        {PfcpIeType::FeatureBitmap, bitmap_value},
    });
}

std::optional<std::vector<std::uint8_t>> decode_grouped_entry(const std::vector<std::uint8_t>& grouped_value,
                                                              PfcpIeType inner_type) {
    std::size_t cursor = 0;
    while (cursor + 4 <= grouped_value.size()) {
        const std::uint16_t decoded_inner_type = read_u16(grouped_value, cursor);
        const std::uint16_t decoded_inner_length = read_u16(grouped_value, cursor + 2);
        cursor += 4;
        if (cursor + decoded_inner_length > grouped_value.size()) {
            return std::nullopt;
        }
        if (decoded_inner_type == static_cast<std::uint16_t>(inner_type)) {
            return std::vector<std::uint8_t>(grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor),
                                             grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor + decoded_inner_length));
        }
        cursor += decoded_inner_length;
    }
    return std::nullopt;
}

PfcpIeType grouped_rule_ie_type(PfcpOperation operation, PfcpIeType flat_type) {
    if (operation == PfcpOperation::Establish) {
        switch (flat_type) {
            case PfcpIeType::Far:
                return PfcpIeType::CreateFar;
            case PfcpIeType::Qer:
                return PfcpIeType::CreateQer;
            case PfcpIeType::Urr:
                return PfcpIeType::CreateUrr;
            case PfcpIeType::Pdr:
                return PfcpIeType::CreatePdr;
            default:
                break;
        }
    }
    if (operation == PfcpOperation::Delete) {
        return remove_grouped_rule_ie_type(flat_type);
    }
    if (operation == PfcpOperation::Modify) {
        switch (flat_type) {
            case PfcpIeType::Far:
                return PfcpIeType::UpdateFar;
            case PfcpIeType::Qer:
                return PfcpIeType::UpdateQer;
            case PfcpIeType::Urr:
                return PfcpIeType::UpdateUrr;
            case PfcpIeType::Pdr:
                return PfcpIeType::UpdatePdr;
            default:
                break;
        }
    }
    return flat_type;
}

PfcpIeType modify_grouped_rule_ie_type(PfcpIeType flat_type, bool exists_in_previous_state) {
    if (exists_in_previous_state) {
        return grouped_rule_ie_type(PfcpOperation::Modify, flat_type);
    }
    return grouped_rule_ie_type(PfcpOperation::Establish, flat_type);
}

PfcpIeType remove_grouped_rule_ie_type(PfcpIeType flat_type) {
    switch (flat_type) {
        case PfcpIeType::Far:
            return PfcpIeType::RemoveFar;
        case PfcpIeType::Qer:
            return PfcpIeType::RemoveQer;
        case PfcpIeType::Urr:
            return PfcpIeType::RemoveUrr;
        case PfcpIeType::Pdr:
            return PfcpIeType::RemovePdr;
        default:
            break;
    }
    return flat_type;
}

PfcpIeType rule_identifier_ie_type(PfcpIeType flat_type) {
    switch (flat_type) {
        case PfcpIeType::Far:
            return PfcpIeType::FarId;
        case PfcpIeType::Qer:
            return PfcpIeType::QerId;
        case PfcpIeType::Urr:
            return PfcpIeType::UrrId;
        case PfcpIeType::Pdr:
            return PfcpIeType::PdrId;
        default:
            break;
    }
    return flat_type;
}

std::vector<std::uint8_t> encode_rule_identifier_only_ie_value(PfcpIeType flat_type, std::uint32_t id) {
    return encode_grouped_ie_value({
        {rule_identifier_ie_type(flat_type), encode_u32_value(id)},
    });
}

bool has_strict_response_context_layout(const std::vector<std::uint8_t>& grouped_value) {
    std::size_t cursor = 0;
    bool saw_cause = false;
    bool saw_session_version = false;
    bool saw_recovery_time_stamp = false;
    int field_index = 0;
    while (cursor + 4 <= grouped_value.size()) {
        const std::uint16_t decoded_inner_type = read_u16(grouped_value, cursor);
        const std::uint16_t decoded_inner_length = read_u16(grouped_value, cursor + 2);
        cursor += 4;
        if (cursor + decoded_inner_length > grouped_value.size()) {
            return false;
        }
        if (field_index == 0 && decoded_inner_type != static_cast<std::uint16_t>(PfcpIeType::Cause)) {
            return false;
        }
        if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::Cause)) {
            if (saw_cause) {
                return false;
            }
            saw_cause = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::SessionVersion)) {
            if (saw_session_version) {
                return false;
            }
            saw_session_version = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::RecoveryTimeStamp)) {
            if (saw_recovery_time_stamp) {
                return false;
            }
            saw_recovery_time_stamp = true;
        } else {
            return false;
        }
        cursor += decoded_inner_length;
        ++field_index;
    }
    return cursor == grouped_value.size() && saw_cause;
}

bool has_strict_usage_report_context_layout(const std::vector<std::uint8_t>& grouped_value) {
    std::size_t cursor = 0;
    bool saw_rule_id = false;
    bool saw_measurement_method = false;
    bool saw_reporting_trigger = false;
    bool saw_cause = false;
    bool saw_bytes_ul = false;
    bool saw_bytes_dl = false;
    bool saw_packets_ul = false;
    bool saw_packets_dl = false;
    int last_field_order = -1;
    while (cursor + 4 <= grouped_value.size()) {
        const std::uint16_t decoded_inner_type = read_u16(grouped_value, cursor);
        const std::uint16_t decoded_inner_length = read_u16(grouped_value, cursor + 2);
        cursor += 4;
        if (cursor + decoded_inner_length > grouped_value.size()) {
            return false;
        }
        const int field_order = usage_report_field_order(decoded_inner_type);
        if (field_order < 0) {
            return false;
        }
        if (field_order == 0 && saw_rule_id) {
            return false;
        }
        if (field_order < last_field_order) {
            return false;
        }
        last_field_order = field_order;
        if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::UrrId)) {
            saw_rule_id = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::MeasurementMethodValue)) {
            if (saw_measurement_method) {
                return false;
            }
            saw_measurement_method = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::ReportingTriggerValue)) {
            if (saw_reporting_trigger) {
                return false;
            }
            saw_reporting_trigger = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::Cause)) {
            if (saw_cause) {
                return false;
            }
            saw_cause = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::BytesUl)) {
            if (saw_bytes_ul) {
                return false;
            }
            saw_bytes_ul = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::BytesDl)) {
            if (saw_bytes_dl) {
                return false;
            }
            saw_bytes_dl = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::PacketsUl)) {
            if (saw_packets_ul) {
                return false;
            }
            saw_packets_ul = true;
        } else if (decoded_inner_type == static_cast<std::uint16_t>(PfcpIeType::PacketsDl)) {
            if (saw_packets_dl) {
                return false;
            }
            saw_packets_dl = true;
        }
        cursor += decoded_inner_length;
    }
    return cursor == grouped_value.size() && saw_rule_id && saw_measurement_method && saw_reporting_trigger && saw_cause && saw_bytes_ul && saw_bytes_dl && saw_packets_ul && saw_packets_dl;
}

PfcpMessageType pfcp_request_message_type(PfcpOperation operation) {
    switch (operation) {
        case PfcpOperation::Establish:
            return PfcpMessageType::SessionEstablishmentRequest;
        case PfcpOperation::Modify:
            return PfcpMessageType::SessionModificationRequest;
        case PfcpOperation::Delete:
            return PfcpMessageType::SessionDeletionRequest;
    }
    return PfcpMessageType::SessionEstablishmentRequest;
}

PfcpMessageType pfcp_response_message_type(PfcpOperation operation) {
    switch (operation) {
        case PfcpOperation::Establish:
            return PfcpMessageType::SessionEstablishmentResponse;
        case PfcpOperation::Modify:
            return PfcpMessageType::SessionModificationResponse;
        case PfcpOperation::Delete:
            return PfcpMessageType::SessionDeletionResponse;
    }
    return PfcpMessageType::SessionEstablishmentResponse;
}

std::uint32_t next_pfcp_sequence(std::uint32_t* sequence_counter) {
    *sequence_counter = (*sequence_counter % 0x00FFFFFFU) + 1U;
    return *sequence_counter;
}

std::uint64_t make_pfcp_seid(const std::string& imsi, const std::string& pdu_session_id) {
    const std::string key = imsi + ":" + pdu_session_id;
    return static_cast<std::uint64_t>(std::hash<std::string> {}(key));
}

std::string encode_association_setup_request_message(const std::string& local_node_id,
                                                     const std::string& local_fseid_ipv4,
                                                     std::uint32_t recovery_time_stamp,
                                                     std::uint32_t sequence) {
    std::vector<std::uint8_t> ies;
    append_ie(&ies, PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id));
    append_ie(&ies, PfcpIeType::FSeid, encode_fseid_ie_value(1, local_fseid_ipv4));
    append_ie(&ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(recovery_time_stamp));
    return encode_pfcp_message(PfcpMessageType::AssociationSetupRequest, false, 0, sequence, ies);
}

std::string encode_capability_exchange_request_message(const std::string& local_node_id,
                                                       const std::string& local_fseid_ipv4,
                                                       std::uint32_t feature_bitmap,
                                                       std::uint32_t sequence) {
    std::vector<std::uint8_t> ies;
    append_ie(&ies, PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id));
    append_ie(&ies, PfcpIeType::FSeid, encode_fseid_ie_value(2, local_fseid_ipv4));
    append_ie_u32(&ies, PfcpIeType::FeatureBitmap, feature_bitmap);
    return encode_pfcp_message(PfcpMessageType::CapabilityExchangeRequest, false, 0, sequence, ies);
}

std::string encode_node_features_request_message(const std::string& local_node_id,
                                                 std::uint32_t feature_bitmap,
                                                 std::uint32_t sequence) {
    std::vector<std::uint8_t> ies;
    append_ie(&ies, PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id));
    append_ie_u32(&ies, PfcpIeType::FeatureBitmap, feature_bitmap);
    return encode_pfcp_message(PfcpMessageType::NodeFeaturesRequest, false, 0, sequence, ies);
}

std::string encode_session_request_message(const PfcpSessionRequest& request,
                                           PfcpOperation operation,
                                           std::uint32_t sequence,
                                           const PfcpRuleSet& previous_rules,
                                           const std::string& local_node_id,
                                           const std::string& local_fseid_ipv4) {
    std::vector<std::uint8_t> ies;
    const std::uint64_t seid = make_pfcp_seid(request.imsi, request.pdu_session_id);

    append_ie_string(&ies, PfcpIeType::Imsi, request.imsi);
    append_ie_string(&ies, PfcpIeType::PduSessionId, request.pdu_session_id);
    if (!request.procedure.request_id.empty()) {
        append_ie_string(&ies, PfcpIeType::RequestId, request.procedure.request_id);
    }
    append_ie_u32(&ies, PfcpIeType::TimeoutMs, request.procedure.timeout_ms);
    append_ie_u32(&ies, PfcpIeType::MaxRetries, request.procedure.max_retries);
    append_ie(&ies, PfcpIeType::NodeId, encode_node_id_ie_value(local_node_id));
    append_ie(&ies, PfcpIeType::FSeid, encode_fseid_ie_value(seid, local_fseid_ipv4));

    if (operation != PfcpOperation::Delete) {
        if (const auto teid = parse_teid_value(request.teid); teid.has_value()) {
            append_ie(&ies, PfcpIeType::SourceInterface, std::vector<std::uint8_t> {0x00U});
            append_ie(&ies, PfcpIeType::FTeid, encode_fteid_ie_value(*teid, local_fseid_ipv4));
            append_ie(&ies, PfcpIeType::UeIpAddress, encode_ue_ip_address_ie_value(request.ue_ipv4, request.ue_ipv6));
        }
        if (!request.ue_mac.empty()) {
            append_ie(&ies, PfcpIeType::UeMac, encode_mac_bytes(request.ue_mac));
        }
        if (!request.dnn.empty()) {
            append_ie_string(&ies, PfcpIeType::NetworkInstance, request.dnn);
        }
        if (!request.s_nssai.empty()) {
            append_ie_string(&ies, PfcpIeType::Snssai, request.s_nssai);
        }
        if (!request.qos_profile.empty()) {
            append_ie_string(&ies, PfcpIeType::QosProfile, request.qos_profile);
        }
        std::uint8_t access_preferences = 0;
        if (request.prefer_n6_ipv6) {
            access_preferences |= 0x01U;
        }
        if (request.prefer_n6_ethernet) {
            access_preferences |= 0x02U;
        }
        append_ie(&ies, PfcpIeType::AccessPreferences, std::vector<std::uint8_t> {access_preferences});
    }

    std::unordered_set<std::uint32_t> previous_far_ids;
    std::unordered_set<std::uint32_t> previous_qer_ids;
    std::unordered_set<std::uint32_t> previous_urr_ids;
    std::unordered_set<std::uint32_t> previous_pdr_ids;
    for (const auto& far_rule : previous_rules.fars) {
        previous_far_ids.insert(far_rule.id);
    }
    for (const auto& qer_rule : previous_rules.qers) {
        previous_qer_ids.insert(qer_rule.id);
    }
    for (const auto& urr_rule : previous_rules.urrs) {
        previous_urr_ids.insert(urr_rule.id);
    }
    for (const auto& pdr_rule : previous_rules.pdrs) {
        previous_pdr_ids.insert(pdr_rule.id);
    }

    for (const auto& far_rule : request.rules.fars) {
        const auto value = encode_far_ie_value(far_rule);
        const PfcpIeType outer_type = operation == PfcpOperation::Modify
            ? modify_grouped_rule_ie_type(PfcpIeType::Far, previous_far_ids.find(far_rule.id) != previous_far_ids.end())
            : grouped_rule_ie_type(operation, PfcpIeType::Far);
        append_ie(&ies, outer_type, value);
    }
    for (const auto& qer_rule : request.rules.qers) {
        const auto value = encode_qer_ie_value(qer_rule);
        const PfcpIeType outer_type = operation == PfcpOperation::Modify
            ? modify_grouped_rule_ie_type(PfcpIeType::Qer, previous_qer_ids.find(qer_rule.id) != previous_qer_ids.end())
            : grouped_rule_ie_type(operation, PfcpIeType::Qer);
        append_ie(&ies, outer_type, value);
    }
    for (const auto& urr_rule : request.rules.urrs) {
        const auto value = encode_urr_ie_value(urr_rule);
        const PfcpIeType outer_type = operation == PfcpOperation::Modify
            ? modify_grouped_rule_ie_type(PfcpIeType::Urr, previous_urr_ids.find(urr_rule.id) != previous_urr_ids.end())
            : grouped_rule_ie_type(operation, PfcpIeType::Urr);
        append_ie(&ies, outer_type, value);
    }
    for (const auto& pdr_rule : request.rules.pdrs) {
        const auto value = encode_pdr_ie_value(pdr_rule);
        const PfcpIeType outer_type = operation == PfcpOperation::Modify
            ? modify_grouped_rule_ie_type(PfcpIeType::Pdr, previous_pdr_ids.find(pdr_rule.id) != previous_pdr_ids.end())
            : grouped_rule_ie_type(operation, PfcpIeType::Pdr);
        append_ie(&ies, outer_type, value);
    }

    if (operation == PfcpOperation::Modify) {
        std::unordered_set<std::uint32_t> current_far_ids;
        std::unordered_set<std::uint32_t> current_qer_ids;
        std::unordered_set<std::uint32_t> current_urr_ids;
        std::unordered_set<std::uint32_t> current_pdr_ids;
        for (const auto& far_rule : request.rules.fars) {
            current_far_ids.insert(far_rule.id);
        }
        for (const auto& qer_rule : request.rules.qers) {
            current_qer_ids.insert(qer_rule.id);
        }
        for (const auto& urr_rule : request.rules.urrs) {
            current_urr_ids.insert(urr_rule.id);
        }
        for (const auto& pdr_rule : request.rules.pdrs) {
            current_pdr_ids.insert(pdr_rule.id);
        }

        for (const auto& far_rule : previous_rules.fars) {
            if (current_far_ids.find(far_rule.id) == current_far_ids.end()) {
                append_ie(&ies,
                          remove_grouped_rule_ie_type(PfcpIeType::Far),
                          encode_rule_identifier_only_ie_value(PfcpIeType::Far, far_rule.id));
            }
        }
        for (const auto& qer_rule : previous_rules.qers) {
            if (current_qer_ids.find(qer_rule.id) == current_qer_ids.end()) {
                append_ie(&ies,
                          remove_grouped_rule_ie_type(PfcpIeType::Qer),
                          encode_rule_identifier_only_ie_value(PfcpIeType::Qer, qer_rule.id));
            }
        }
        for (const auto& urr_rule : previous_rules.urrs) {
            if (current_urr_ids.find(urr_rule.id) == current_urr_ids.end()) {
                append_ie(&ies,
                          remove_grouped_rule_ie_type(PfcpIeType::Urr),
                          encode_rule_identifier_only_ie_value(PfcpIeType::Urr, urr_rule.id));
            }
        }
        for (const auto& pdr_rule : previous_rules.pdrs) {
            if (current_pdr_ids.find(pdr_rule.id) == current_pdr_ids.end()) {
                append_ie(&ies,
                          remove_grouped_rule_ie_type(PfcpIeType::Pdr),
                          encode_rule_identifier_only_ie_value(PfcpIeType::Pdr, pdr_rule.id));
            }
        }
    }

    return encode_pfcp_message(pfcp_request_message_type(operation), true, seid, sequence, ies);
}

std::string encode_pfcp_message(PfcpMessageType message_type,
                                bool has_seid,
                                std::uint64_t seid,
                                std::uint32_t sequence,
                                const std::vector<std::uint8_t>& ies) {
    std::vector<std::uint8_t> buffer;
    const std::uint8_t flags = static_cast<std::uint8_t>(0x20 | (has_seid ? 0x08 : 0x00));
    buffer.push_back(flags);
    buffer.push_back(static_cast<std::uint8_t>(message_type));
    const std::uint16_t message_length = static_cast<std::uint16_t>((has_seid ? 12U : 4U) + ies.size());
    append_u16(&buffer, message_length);
    if (has_seid) {
        append_u64(&buffer, seid);
    }
    buffer.push_back(static_cast<std::uint8_t>((sequence >> 16) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>((sequence >> 8) & 0xFF));
    buffer.push_back(static_cast<std::uint8_t>(sequence & 0xFF));
    buffer.push_back(0x00);
    buffer.insert(buffer.end(), ies.begin(), ies.end());
    return std::string(reinterpret_cast<const char*>(buffer.data()), buffer.size());
}

std::optional<PfcpParsedMessage> decode_pfcp_message(const std::string& payload) {
    const std::vector<std::uint8_t> buffer(payload.begin(), payload.end());
    if (buffer.size() < 8) {
        return std::nullopt;
    }

    const std::uint8_t flags = buffer[0];
    if (((flags >> 5) & 0x07) != 1U) {
        return std::nullopt;
    }

    const bool has_seid = (flags & 0x08U) != 0;
    const std::uint16_t message_length = read_u16(buffer, 2);
    if (buffer.size() != static_cast<std::size_t>(message_length) + 4U) {
        return std::nullopt;
    }

    const std::size_t header_size = has_seid ? 16U : 8U;
    if (buffer.size() < header_size) {
        return std::nullopt;
    }

    PfcpParsedMessage parsed {};
    parsed.message_type = static_cast<PfcpMessageType>(buffer[1]);
    parsed.has_seid = has_seid;
    std::size_t cursor = 4;
    if (has_seid) {
        parsed.seid = read_u64(buffer, cursor);
        cursor += 8;
    }
    parsed.sequence = (static_cast<std::uint32_t>(buffer[cursor]) << 16) |
                      (static_cast<std::uint32_t>(buffer[cursor + 1]) << 8) |
                      static_cast<std::uint32_t>(buffer[cursor + 2]);
    cursor += 4;

    while (cursor + 4 <= buffer.size()) {
        const std::uint16_t ie_type = read_u16(buffer, cursor);
        const std::uint16_t ie_length = read_u16(buffer, cursor + 2);
        cursor += 4;
        if (cursor + ie_length > buffer.size()) {
            return std::nullopt;
        }
        parsed.ies[ie_type].emplace_back(buffer.begin() + static_cast<std::ptrdiff_t>(cursor),
                                         buffer.begin() + static_cast<std::ptrdiff_t>(cursor + ie_length));
        cursor += ie_length;
    }

    if (cursor != buffer.size()) {
        return std::nullopt;
    }

    return parsed;
}

std::string first_ie_string(const PfcpParsedMessage& message, PfcpIeType type) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(type));
    if (it == message.ies.end() || it->second.empty()) {
        return {};
    }
    return std::string(it->second.front().begin(), it->second.front().end());
}

std::optional<std::vector<std::uint8_t>> first_ie_value(const PfcpParsedMessage& message, PfcpIeType type) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(type));
    if (it == message.ies.end() || it->second.empty()) {
        return std::nullopt;
    }
    return it->second.front();
}

std::vector<std::vector<std::uint8_t>> all_ie_values(const PfcpParsedMessage& message, PfcpIeType type) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(type));
    if (it == message.ies.end()) {
        return {};
    }
    return it->second;
}

bool is_valid_node_id_ie(const std::vector<std::uint8_t>& value) {
    return value.size() > 1 && value.front() == 0x02U;
}

bool is_valid_fseid_ie(const std::vector<std::uint8_t>& value) {
    return value.size() == 13 && value.front() == 0x02U && read_u64(value, 1) != 0 && !decode_ipv4_bytes(value, 9).empty();
}

bool is_valid_recovery_time_stamp_ie(const std::vector<std::uint8_t>& value) {
    return value.size() == 4 && read_u32(value, 0) != 0;
}

bool is_valid_feature_bitmap_ie(const std::vector<std::uint8_t>& value) {
    return value.size() == 4 && read_u32(value, 0) != 0;
}

bool has_valid_association_context_response(const PfcpParsedMessage& message) {
    const auto node_id = first_ie_value(message, PfcpIeType::NodeId);
    const auto fseid = first_ie_value(message, PfcpIeType::FSeid);
    const auto recovery_time_stamp = first_ie_value(message, PfcpIeType::RecoveryTimeStamp);
    return node_id.has_value() && fseid.has_value() && recovery_time_stamp.has_value() &&
           is_valid_node_id_ie(*node_id) && is_valid_fseid_ie(*fseid) && is_valid_recovery_time_stamp_ie(*recovery_time_stamp);
}

bool has_valid_capability_context_response(const PfcpParsedMessage& message) {
    const auto node_id = first_ie_value(message, PfcpIeType::NodeId);
    const auto fseid = first_ie_value(message, PfcpIeType::FSeid);
    const auto feature_bitmap = first_ie_value(message, PfcpIeType::FeatureBitmap);
    return node_id.has_value() && fseid.has_value() && feature_bitmap.has_value() &&
           is_valid_node_id_ie(*node_id) && is_valid_fseid_ie(*fseid) && is_valid_feature_bitmap_ie(*feature_bitmap);
}

bool has_valid_node_feature_context_response(const PfcpParsedMessage& message) {
    const auto node_id = first_ie_value(message, PfcpIeType::NodeId);
    const auto feature_bitmap = first_ie_value(message, PfcpIeType::FeatureBitmap);
    return node_id.has_value() && feature_bitmap.has_value() &&
           is_valid_node_id_ie(*node_id) && is_valid_feature_bitmap_ie(*feature_bitmap);
}

std::uint32_t first_ie_u32(const PfcpParsedMessage& message, PfcpIeType type, std::uint32_t fallback) {
    const auto value = first_ie_value(message, type);
    if (!value.has_value() || value->size() != 4) {
        return fallback;
    }
    return read_u32(*value, 0);
}

std::uint64_t first_ie_u64(const PfcpParsedMessage& message, PfcpIeType type, std::uint64_t fallback) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(type));
    if (it == message.ies.end() || it->second.empty()) {
        return fallback;
    }
    const auto& value = it->second.front();
    if (value.size() == 8) {
        return read_u64(value, 0);
    }
    if (value.size() == 4) {
        return read_u32(value, 0);
    }
    return fallback;
}

std::vector<std::string> repeated_ie_strings(const PfcpParsedMessage& message, PfcpIeType type) {
    std::vector<std::string> values;
    const auto it = message.ies.find(static_cast<std::uint16_t>(type));
    if (it == message.ies.end()) {
        return values;
    }
    for (const auto& entry : it->second) {
        values.emplace_back(entry.begin(), entry.end());
    }
    return values;
}

}  // namespace upf::pfcp