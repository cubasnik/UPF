#pragma once

#include "pfcp_usage_report_test_utils.hpp"
#include "upf/protocol/pfcp_wire.hpp"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace test_pfcp_wire {

using upf::pfcp::PfcpIeType;
using upf::pfcp::PfcpMessageType;
using ParsedPfcpMessage = upf::pfcp::PfcpParsedMessage;

using upf::pfcp::all_ie_values;
using upf::pfcp::append_ie;
using upf::pfcp::append_ie_string;
using upf::pfcp::append_ie_u32;
using upf::pfcp::append_ie_u64;
using upf::pfcp::append_u16;
using upf::pfcp::append_u32;
using upf::pfcp::append_u64;
using upf::pfcp::decode_grouped_entry;
using upf::pfcp::decode_ipv4_bytes;
using upf::pfcp::encode_fseid_ie_value;
using upf::pfcp::encode_grouped_ie_value;
using upf::pfcp::encode_node_id_ie_value;
using upf::pfcp::encode_pfcp_message;
using upf::pfcp::encode_recovery_time_stamp_ie_value;
using upf::pfcp::first_ie_string;
using upf::pfcp::first_ie_u32;
using upf::pfcp::first_ie_value;
using upf::pfcp::read_u16;
using upf::pfcp::read_u32;
using upf::pfcp::read_u64;

struct DecodedFar {
    std::uint32_t id {0};
    std::string action;
    std::string forward_to;
    std::uint8_t header_creation_description {0};
    std::string tunnel_peer_ipv4;
    std::uint32_t tunnel_peer_teid {0};
    std::uint32_t buffering_duration_ms {0};
    bool notify_control_plane {false};
};

struct DecodedSdfFilter {
    std::uint32_t packet_filter_id {0};
    std::uint8_t flow_direction {0};
    std::string flow_description;
    std::uint8_t protocol_identifier {0};
    std::uint16_t source_port {0};
    std::uint16_t source_port_end {0};
    std::uint16_t destination_port {0};
    std::uint16_t destination_port_end {0};
    std::uint16_t ether_type {0};
};

struct DecodedQer {
    std::uint32_t id {0};
    std::uint8_t qfi {0};
    std::uint8_t gate_status {0};
    std::uint64_t gbr_ul {0};
    std::uint64_t gbr_dl {0};
    std::uint64_t mbr_ul {0};
    std::uint64_t mbr_dl {0};
};

struct DecodedUrr {
    std::uint32_t id {0};
    std::string method;
    std::string trigger;
};

struct DecodedPdr {
    std::uint32_t id {0};
    std::uint32_t precedence {0};
    std::uint8_t source_interface {0xFFU};
    std::string ue_ipv4;
    std::string application_id;
    std::vector<DecodedSdfFilter> sdf_filters;
    std::uint32_t far_id {0};
    std::uint32_t qer_id {0};
    std::uint32_t urr_id {0};
};

struct DecodedFSeid {
    std::uint64_t seid {0};
    std::string ipv4;
};

struct DecodedFTeid {
    std::uint32_t teid {0};
    std::string ipv4;
};

inline std::optional<ParsedPfcpMessage> decode_pfcp_message(const char* bytes, int recv_len) {
    if (recv_len < 0) {
        return std::nullopt;
    }
    return upf::pfcp::decode_pfcp_message(std::string(bytes, bytes + recv_len));
}

inline std::string encode_pfcp_message(PfcpMessageType message_type,
                                       bool has_seid,
                                       const std::vector<std::uint8_t>& ies,
                                       const std::vector<std::uint8_t>& request_bytes) {
    if (request_bytes.size() < 8) {
        return {};
    }

    const bool request_has_seid = (request_bytes[0] & 0x08U) != 0;
    const std::size_t sequence_offset = request_has_seid ? 12U : 4U;
    if (request_bytes.size() < sequence_offset + 4U) {
        return {};
    }

    std::uint64_t seid = 0;
    if (request_has_seid && request_bytes.size() >= 12U) {
        seid = read_u64(request_bytes, 4);
    }

    const std::uint32_t sequence = (static_cast<std::uint32_t>(request_bytes[sequence_offset]) << 16) |
                                   (static_cast<std::uint32_t>(request_bytes[sequence_offset + 1]) << 8) |
                                   static_cast<std::uint32_t>(request_bytes[sequence_offset + 2]);
    return upf::pfcp::encode_pfcp_message(message_type, has_seid, seid, sequence, ies);
}

inline std::vector<std::uint8_t> encode_grouped_value(const std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>>& entries) {
    return encode_grouped_ie_value(entries);
}

inline std::vector<std::uint8_t> encode_node_id_value(const std::string& node_id) {
    return encode_node_id_ie_value(node_id);
}

inline std::vector<std::uint8_t> encode_fseid_value(std::uint64_t seid, const std::string& ipv4) {
    return encode_fseid_ie_value(seid, ipv4);
}

inline std::vector<std::uint8_t> encode_association_context_response(const std::string& node_id,
                                                                     const std::string& ipv4,
                                                                     std::uint32_t recovery_time_stamp) {
    return encode_grouped_value({
        {PfcpIeType::NodeId, encode_node_id_value(node_id)},
        {PfcpIeType::FSeid, encode_fseid_value(1, ipv4)},
        {PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(recovery_time_stamp)},
    });
}

inline std::vector<std::uint8_t> encode_capability_context_response(const std::string& node_id,
                                                                    const std::string& ipv4,
                                                                    std::uint32_t feature_bitmap) {
    return encode_grouped_value({
        {PfcpIeType::NodeId, encode_node_id_value(node_id)},
        {PfcpIeType::FSeid, encode_fseid_value(2, ipv4)},
        {PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(feature_bitmap)},
    });
}

inline std::vector<std::uint8_t> encode_node_feature_context_response(const std::string& node_id,
                                                                      std::uint32_t feature_bitmap) {
    return encode_grouped_value({
        {PfcpIeType::NodeId, encode_node_id_value(node_id)},
        {PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(feature_bitmap)},
    });
}

template <typename Message>
inline std::optional<std::vector<std::uint8_t>> decode_grouped_ie(const Message& message,
                                                                  PfcpIeType outer_type,
                                                                  PfcpIeType inner_type) {
    return test_pfcp::decode_grouped_ie(message, outer_type, inner_type);
}

template <typename Message>
inline std::vector<std::vector<std::uint8_t>> decode_grouped_ies(const Message& message,
                                                                 PfcpIeType outer_type,
                                                                 PfcpIeType inner_type) {
    return test_pfcp::decode_grouped_ies(message, outer_type, inner_type);
}

inline std::vector<std::vector<std::uint8_t>> decode_grouped_entries(const std::vector<std::uint8_t>& grouped_value,
                                                                     PfcpIeType inner_type) {
    return test_pfcp::find_grouped_entries(grouped_value, inner_type);
}

inline std::optional<std::uint32_t> grouped_rule_identifier(const std::vector<std::uint8_t>& value) {
    for (const PfcpIeType type : {PfcpIeType::PdrId, PfcpIeType::FarId, PfcpIeType::QerId, PfcpIeType::UrrId}) {
        const auto id = decode_grouped_entry(value, type);
        if (id.has_value() && id->size() == 4) {
            return read_u32(*id, 0);
        }
    }
    return std::nullopt;
}

inline bool has_unique_grouped_rule_identifiers(const std::vector<std::vector<std::uint8_t>>& values) {
    std::unordered_set<std::uint32_t> ids;
    for (const auto& value : values) {
        const auto id = grouped_rule_identifier(value);
        if (!id.has_value() || !ids.insert(*id).second) {
            return false;
        }
    }
    return true;
}

inline std::string decode_ipv6_bytes(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    if (bytes.size() < offset + 16) {
        return {};
    }

    char text[INET6_ADDRSTRLEN] = {};
    in6_addr address {};
    std::memcpy(&address.s6_addr, bytes.data() + static_cast<std::ptrdiff_t>(offset), 16);
    if (inet_ntop(AF_INET6, &address, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

inline std::string decode_mac_bytes(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() != 6) {
        return {};
    }

    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) {
            stream << ':';
        }
        stream << std::setw(2) << static_cast<int>(bytes[index]);
    }
    return stream.str();
}

inline std::string decode_ue_ip_address_ie(const std::vector<std::uint8_t>& value, bool want_ipv6) {
    if (value.empty()) {
        return {};
    }

    const std::uint8_t flags = value.front();
    std::size_t offset = 1;
    if (!want_ipv6) {
        return (flags & 0x02U) != 0 && value.size() >= offset + 4U ? decode_ipv4_bytes(value, offset) : std::string();
    }

    if ((flags & 0x02U) != 0) {
        offset += 4;
    }
    return (flags & 0x01U) != 0 && value.size() >= offset + 16U ? decode_ipv6_bytes(value, offset) : std::string();
}

inline DecodedFSeid decode_fseid_ie(const std::vector<std::uint8_t>& value) {
    DecodedFSeid decoded {};
    if (value.size() < 13 || (value[0] & 0x02U) == 0U) {
        return decoded;
    }
    decoded.seid = read_u64(value, 1);
    decoded.ipv4 = decode_ipv4_bytes(value, 9);
    return decoded;
}

inline DecodedFTeid decode_fteid_ie(const std::vector<std::uint8_t>& value) {
    DecodedFTeid decoded {};
    if (value.size() < 9 || value.front() != 0x01U) {
        return decoded;
    }
    decoded.teid = read_u32(value, 1);
    decoded.ipv4 = decode_ipv4_bytes(value, 5);
    return decoded;
}

inline DecodedFar decode_far_ie(const std::vector<std::uint8_t>& value) {
    DecodedFar decoded {};
    const auto id = decode_grouped_entry(value, PfcpIeType::FarId);
    const auto action = decode_grouped_entry(value, PfcpIeType::ApplyAction);
    const auto forwarding = decode_grouped_entry(value, PfcpIeType::ForwardingParameters);
    const auto buffering = decode_grouped_entry(value, PfcpIeType::BufferingParameters);
    const auto buffering_duration = buffering.has_value() ? decode_grouped_entry(*buffering, PfcpIeType::BufferingDuration) : std::nullopt;
    const auto notify_control_plane = decode_grouped_entry(value, PfcpIeType::NotifyControlPlane);
    const auto network_instance = forwarding.has_value() ? decode_grouped_entry(*forwarding, PfcpIeType::NetworkInstance) : std::nullopt;
    const auto outer_header_creation = forwarding.has_value() ? decode_grouped_entry(*forwarding, PfcpIeType::OuterHeaderCreation) : std::nullopt;
    if (!id.has_value() || id->size() != 4 || !action.has_value() || action->size() != 1) {
        return decoded;
    }

    decoded.id = read_u32(*id, 0);
    decoded.action = action->front() == 0x02U ? "FORW" : (action->front() == 0x01U ? "DROP" : (action->front() == 0x04U ? "BUFF" : (action->front() == 0x08U ? "NOCP" : "UNKNOWN")));
    if (decoded.action == "FORW") {
        if (!network_instance.has_value() || !outer_header_creation.has_value() || outer_header_creation->size() < 10) {
            return DecodedFar {};
        }
        decoded.forward_to.assign(network_instance->begin(), network_instance->end());
        decoded.header_creation_description = static_cast<std::uint8_t>(read_u16(*outer_header_creation, 0) >> 8);
        decoded.tunnel_peer_teid = read_u32(*outer_header_creation, 2);
        decoded.tunnel_peer_ipv4 = decode_ipv4_bytes(*outer_header_creation, 6);
    } else if (decoded.action == "BUFF") {
        if (!buffering_duration.has_value() || buffering_duration->size() != 4) {
            return DecodedFar {};
        }
        decoded.buffering_duration_ms = read_u32(*buffering_duration, 0);
    } else if (decoded.action == "NOCP") {
        if (!notify_control_plane.has_value() || notify_control_plane->size() != 1) {
            return DecodedFar {};
        }
        decoded.notify_control_plane = notify_control_plane->front() == 0x01U;
    }
    return decoded;
}

inline DecodedSdfFilter decode_sdf_filter_ie(const std::vector<std::uint8_t>& value) {
    DecodedSdfFilter decoded {};
    const auto packet_filter_id = decode_grouped_entry(value, PfcpIeType::PacketFilterId);
    const auto flow_direction = decode_grouped_entry(value, PfcpIeType::FlowDirection);
    const auto flow_description = decode_grouped_entry(value, PfcpIeType::FlowDescription);
    const auto protocol_identifier = decode_grouped_entry(value, PfcpIeType::ProtocolIdentifier);
    const auto source_port = decode_grouped_entry(value, PfcpIeType::SourcePort);
    const auto source_port_end = decode_grouped_entry(value, PfcpIeType::SourcePortEnd);
    const auto destination_port = decode_grouped_entry(value, PfcpIeType::DestinationPort);
    const auto destination_port_end = decode_grouped_entry(value, PfcpIeType::DestinationPortEnd);
    const auto ether_type = decode_grouped_entry(value, PfcpIeType::EtherType);
    if (!packet_filter_id.has_value() || packet_filter_id->size() != 4 || !flow_direction.has_value() || flow_direction->size() != 1 || !flow_description.has_value() || !protocol_identifier.has_value() || protocol_identifier->size() != 1 || !source_port.has_value() || source_port->size() != 2 || !destination_port.has_value() || destination_port->size() != 2 || !ether_type.has_value() || ether_type->size() != 2) {
        return decoded;
    }

    decoded.packet_filter_id = read_u32(*packet_filter_id, 0);
    decoded.flow_direction = flow_direction->front();
    decoded.flow_description.assign(flow_description->begin(), flow_description->end());
    decoded.protocol_identifier = protocol_identifier->front();
    decoded.source_port = read_u16(*source_port, 0);
    decoded.source_port_end = source_port_end.has_value() && source_port_end->size() == 2 ? read_u16(*source_port_end, 0) : decoded.source_port;
    decoded.destination_port = read_u16(*destination_port, 0);
    decoded.destination_port_end = destination_port_end.has_value() && destination_port_end->size() == 2 ? read_u16(*destination_port_end, 0) : decoded.destination_port;
    decoded.ether_type = read_u16(*ether_type, 0);
    return decoded;
}

inline DecodedQer decode_qer_ie(const std::vector<std::uint8_t>& value) {
    DecodedQer decoded {};
    const auto id = decode_grouped_entry(value, PfcpIeType::QerId);
    const auto qfi = decode_grouped_entry(value, PfcpIeType::Qfi);
    const auto gate_status = decode_grouped_entry(value, PfcpIeType::GateStatus);
    const auto gbr_ul = decode_grouped_entry(value, PfcpIeType::GbrUl);
    const auto gbr_dl = decode_grouped_entry(value, PfcpIeType::GbrDl);
    const auto mbr_ul = decode_grouped_entry(value, PfcpIeType::MbrUl);
    const auto mbr_dl = decode_grouped_entry(value, PfcpIeType::MbrDl);
    if (!id.has_value() || id->size() != 4 || !qfi.has_value() || qfi->size() != 1 || !gate_status.has_value() || gate_status->size() != 1 ||
        !gbr_ul.has_value() || gbr_ul->size() != 8 || !gbr_dl.has_value() || gbr_dl->size() != 8 || !mbr_ul.has_value() || mbr_ul->size() != 8 || !mbr_dl.has_value() || mbr_dl->size() != 8) {
        return decoded;
    }

    decoded.id = read_u32(*id, 0);
    decoded.qfi = qfi->front();
    decoded.gate_status = gate_status->front();
    decoded.gbr_ul = read_u64(*gbr_ul, 0);
    decoded.gbr_dl = read_u64(*gbr_dl, 0);
    decoded.mbr_ul = read_u64(*mbr_ul, 0);
    decoded.mbr_dl = read_u64(*mbr_dl, 0);
    return decoded;
}

inline DecodedUrr decode_urr_ie(const std::vector<std::uint8_t>& value) {
    DecodedUrr decoded {};
    const auto id = decode_grouped_entry(value, PfcpIeType::UrrId);
    const auto method = decode_grouped_entry(value, PfcpIeType::MeasurementMethodValue);
    const auto trigger = decode_grouped_entry(value, PfcpIeType::ReportingTriggerValue);
    if (!id.has_value() || id->size() != 4 || !method.has_value() || !trigger.has_value()) {
        return decoded;
    }
    decoded.id = read_u32(*id, 0);
    decoded.method.assign(method->begin(), method->end());
    decoded.trigger.assign(trigger->begin(), trigger->end());
    return decoded;
}

inline DecodedPdr decode_pdr_ie(const std::vector<std::uint8_t>& value) {
    DecodedPdr decoded {};
    const auto id = decode_grouped_entry(value, PfcpIeType::PdrId);
    const auto precedence = decode_grouped_entry(value, PfcpIeType::Precedence);
    auto pdi = decode_grouped_entry(value, PfcpIeType::Pdi);
    if (!pdi.has_value()) {
        pdi = decode_grouped_entry(value, PfcpIeType::PdiContext);
    }
    const auto source_interface = pdi.has_value() ? decode_grouped_entry(*pdi, PfcpIeType::SourceInterface) : std::nullopt;
    const auto ue_ip = pdi.has_value() ? decode_grouped_entry(*pdi, PfcpIeType::UeIpAddress) : std::nullopt;
    const auto application_id = pdi.has_value() ? decode_grouped_entry(*pdi, PfcpIeType::ApplicationId) : std::nullopt;
    const auto sdf_filter_values = pdi.has_value() ? decode_grouped_entries(*pdi, PfcpIeType::SdfFilter) : std::vector<std::vector<std::uint8_t>> {};
    const auto far_id = decode_grouped_entry(value, PfcpIeType::FarId);
    const auto qer_id = decode_grouped_entry(value, PfcpIeType::QerId);
    const auto urr_id = decode_grouped_entry(value, PfcpIeType::UrrId);
    if (!id.has_value() || id->size() != 4 || !precedence.has_value() || precedence->size() != 4 || !source_interface.has_value() || source_interface->size() != 1 || !ue_ip.has_value() || !application_id.has_value() || sdf_filter_values.empty() || !far_id.has_value() || far_id->size() != 4 || !qer_id.has_value() || qer_id->size() != 4 || !urr_id.has_value() || urr_id->size() != 4) {
        return decoded;
    }

    decoded.id = read_u32(*id, 0);
    decoded.precedence = read_u32(*precedence, 0);
    decoded.source_interface = source_interface->front();
    decoded.ue_ipv4 = decode_ue_ip_address_ie(*ue_ip, false);
    decoded.application_id.assign(application_id->begin(), application_id->end());
    for (const auto& sdf_filter_value : sdf_filter_values) {
        const DecodedSdfFilter filter = decode_sdf_filter_ie(sdf_filter_value);
        if (filter.packet_filter_id == 0) {
            return DecodedPdr {};
        }
        decoded.sdf_filters.push_back(filter);
    }
    decoded.far_id = read_u32(*far_id, 0);
    decoded.qer_id = read_u32(*qer_id, 0);
    decoded.urr_id = read_u32(*urr_id, 0);
    return decoded;
}

}  // namespace test_pfcp_wire