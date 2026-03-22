#include "upf/adapters/console_adapters.hpp"

#include <algorithm>

namespace {

const char* n6_protocol_to_string(upf::N6Protocol protocol) {
    switch (protocol) {
        case upf::N6Protocol::IPv4:
            return "IPv4";
        case upf::N6Protocol::IPv6:
            return "IPv6";
        case upf::N6Protocol::Ethernet:
            return "Ethernet";
    }
    return "Unknown";
}

std::string default_ipv4_destination(const std::string& dnn) {
    if (dnn == "internet") {
        return "8.8.8.8";
    }
    if (dnn == "ims") {
        return "198.18.0.10";
    }
    return "203.0.113.10";
}

std::string default_ipv6_destination(const std::string& dnn) {
    if (dnn == "internet") {
        return "2001:4860:4860::8888";
    }
    if (dnn == "ims") {
        return "2001:db8:1::10";
    }
    return "2001:db8:ffff::10";
}

std::string default_destination_mac(const std::string&) {
    return "02:00:00:00:00:01";
}

std::string normalize_n6_overflow_policy(std::string policy) {
    std::transform(policy.begin(), policy.end(), policy.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return policy == "drop_newest" ? policy : std::string("drop_oldest");
}

upf::N6BufferOverflowPolicy parse_n6_overflow_policy(const std::string& policy) {
    return policy == "drop_newest" ? upf::N6BufferOverflowPolicy::DropNewest : upf::N6BufferOverflowPolicy::DropOldest;
}

std::size_t n6_wire_bytes(const upf::N6Packet& packet) {
    switch (packet.protocol) {
        case upf::N6Protocol::IPv4:
            return packet.payload.size() + 20U;
        case upf::N6Protocol::IPv6:
            return packet.payload.size() + 40U;
        case upf::N6Protocol::Ethernet:
            return packet.payload.size() + 14U;
    }
    return packet.payload.size();
}

std::optional<upf::N6Packet> build_default_n6_packet(const upf::N6SessionContext& session, std::size_t bytes) {
    upf::N6Packet packet {};
    packet.payload.resize(bytes);

    if (session.ipv6_enabled && !session.ue_ipv6.empty()) {
        packet.protocol = upf::N6Protocol::IPv6;
        packet.source_ipv6 = session.ue_ipv6;
        packet.destination_ipv6 = default_ipv6_destination(session.dnn);
        packet.ether_type = 0x86DD;
        return packet;
    }

    if (session.ethernet_enabled && !session.ue_mac.empty()) {
        packet.protocol = upf::N6Protocol::Ethernet;
        packet.source_mac = session.ue_mac;
        packet.destination_mac = default_destination_mac(session.dnn);
        packet.ether_type = 0x0800;
        return packet;
    }

    if (!session.ue_ipv4.empty()) {
        packet.protocol = upf::N6Protocol::IPv4;
        packet.source_ipv4 = session.ue_ipv4;
        packet.destination_ipv4 = default_ipv4_destination(session.dnn);
        packet.ether_type = 0x0800;
        return packet;
    }

    return std::nullopt;
}

std::optional<upf::N6Packet> build_downlink_n6_packet(const upf::N6SessionContext& session, std::size_t bytes) {
    upf::N6Packet packet {};
    packet.payload.resize(bytes);

    if (session.ipv6_enabled && !session.ue_ipv6.empty()) {
        packet.protocol = upf::N6Protocol::IPv6;
        packet.source_ipv6 = default_ipv6_destination(session.dnn);
        packet.destination_ipv6 = session.ue_ipv6;
        packet.ether_type = 0x86DD;
        return packet;
    }

    if (session.ethernet_enabled && !session.ue_mac.empty()) {
        packet.protocol = upf::N6Protocol::Ethernet;
        packet.source_mac = default_destination_mac(session.dnn);
        packet.destination_mac = session.ue_mac;
        packet.ether_type = 0x0800;
        return packet;
    }

    if (!session.ue_ipv4.empty()) {
        packet.protocol = upf::N6Protocol::IPv4;
        packet.source_ipv4 = default_ipv4_destination(session.dnn);
        packet.destination_ipv4 = session.ue_ipv4;
        packet.ether_type = 0x0800;
        return packet;
    }

    return std::nullopt;
}

upf::UsageReport build_usage_report_from_rules(const upf::PfcpRuleSet& rules) {
    upf::UsageReport report;
    for (const auto& urr : rules.urrs) {
        upf::UsageReportEntry entry;
        entry.urr_id = urr.id;
        entry.measurement_method = urr.measurement_method;
        entry.reporting_trigger = urr.trigger;
        if (urr.trigger == "ON_THRESHOLD") {
            entry.report_cause = upf::UsageReportCause::ThresholdReached;
            entry.detail = "threshold-reached";
            entry.threshold_value = 4096;
            entry.bytes_ul = 6;
            entry.bytes_dl = 13;
            entry.packets_ul = 0;
            entry.packets_dl = 1;
        } else if (urr.trigger == "ON_QUOTA") {
            entry.report_cause = upf::UsageReportCause::QuotaExhausted;
            entry.detail = "quota-exhausted";
            entry.quota_value = 8192;
            entry.bytes_ul = 8;
            entry.bytes_dl = 5;
            entry.packets_ul = 2;
            entry.packets_dl = 1;
        } else {
            entry.report_cause = upf::UsageReportCause::UsageReady;
            entry.detail = "usage-ready";
            entry.bytes_ul = 4;
            entry.bytes_dl = 7;
            entry.packets_ul = 1;
            entry.packets_dl = 1;
        }
        report.bytes_ul += entry.bytes_ul;
        report.bytes_dl += entry.bytes_dl;
        report.packets_ul += entry.packets_ul;
        report.packets_dl += entry.packets_dl;
        report.urr_reports.push_back(entry);
    }
    return report;
}

upf::UsageReport filter_usage_report(const upf::UsageReport& report, const std::vector<std::uint32_t>& urr_ids) {
    if (urr_ids.empty()) {
        return report;
    }

    std::unordered_set<std::uint32_t> allowed_ids(urr_ids.begin(), urr_ids.end());
    upf::UsageReport filtered;
    for (const auto& entry : report.urr_reports) {
        if (allowed_ids.find(entry.urr_id) == allowed_ids.end()) {
            continue;
        }
        filtered.urr_reports.push_back(entry);
        filtered.bytes_ul += entry.bytes_ul;
        filtered.bytes_dl += entry.bytes_dl;
        filtered.packets_ul += entry.packets_ul;
        filtered.packets_dl += entry.packets_dl;
    }
    return filtered;
}

}  // namespace

namespace upf {

bool ConsoleN3Adapter::receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::cout << "[N3] UL packet imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
}

bool ConsoleN3Adapter::send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::cout << "[N3] DL packet imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
}

bool ConsoleN3Adapter::create_tunnel(const N3TunnelContext& context) {
    std::cout << "[N3] Create tunnel TEID=" << context.teid << " imsi=" << context.imsi 
              << " gnb_ip=" << context.gnb_ip << "\n";
    return true;
}

bool ConsoleN3Adapter::delete_tunnel(std::uint32_t teid) {
    std::cout << "[N3] Delete tunnel TEID=" << teid << "\n";
    return true;
}

bool ConsoleN3Adapter::update_tunnel_qos_flows(std::uint32_t teid, const std::vector<QosFlowMapping>& qos_flows) {
    std::cout << "[N3] Update tunnel TEID=" << teid << " QoS flows=" << qos_flows.size() << "\n";
    return true;
}

std::optional<N3TunnelContext> ConsoleN3Adapter::get_tunnel(std::uint32_t teid) const {
    std::cout << "[N3] Get tunnel TEID=" << teid << " (console adapter returns nullopt)\n";
    return std::nullopt;
}

bool ConsoleN3Adapter::process_gtp_u_packet(const GtpUPacket& packet) {
    std::cout << "[N3] Process GTP-U packet TEID=" << packet.header.teid 
              << " payload_size=" << packet.payload.size() << "\n";
    return true;
}

std::optional<GtpUPacket> ConsoleN3Adapter::send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) {
    std::cout << "[N3] Send GTP-U packet TEID=" << teid << " payload_size=" << payload.size() << "\n";
    GtpUPacket packet {};
    packet.header.version = GtpVersion::V1;
    packet.header.protocol_type = true;
    packet.header.packet_type = GtpPacketType::Data;
    packet.header.teid = teid;
    packet.header.message_length = static_cast<std::uint16_t>(payload.size());
    packet.payload = payload;
    return packet;
}

bool ConsoleN3Adapter::start_listening(std::uint16_t port) {
    std::cout << "[N3] Start listening on port " << port << "\n";
    return true;
}

bool ConsoleN3Adapter::stop_listening() {
    std::cout << "[N3] Stop listening\n";
    return true;
}

bool ConsoleN3Adapter::is_listening() const {
    return false;
}

std::size_t ConsoleN3Adapter::get_active_tunnels() const {
    return 0;
}

UsageReport ConsoleN3Adapter::get_tunnel_usage(std::uint32_t teid) {
    std::cout << "[N3] Get tunnel usage TEID=" << teid << "\n";
    return UsageReport{};
}

PfcpSessionResponse ConsoleN4Adapter::apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) {
    if (!request.procedure.request_id.empty()) {
        const auto replay_it = replay_cache_.find(request.procedure.request_id);
        if (replay_it != replay_cache_.end()) {
            PfcpSessionResponse replayed = replay_it->second;
            replayed.idempotent_replay = true;
            return replayed;
        }
    }

    const PfcpSessionResponse validation = validate_request(request, operation);
    if (!validation.success) {
        return validation;
    }

    const std::string key = key_of(request.imsi, request.pdu_session_id);
    const bool exists = usage_reports_.find(key) != usage_reports_.end();

    if ((operation == PfcpOperation::Modify || operation == PfcpOperation::Delete) && !exists) {
        return PfcpSessionResponse {false, PfcpCause::SessionContextNotFound, 0, false, "PFCP session context not found"};
    }
    if (operation == PfcpOperation::Establish && exists) {
        return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, "PFCP session already exists"};
    }

    ++version_;
    session_versions_[key] = version_;

    if (operation == PfcpOperation::Delete) {
        usage_reports_.erase(key);
        session_versions_.erase(key);
    } else {
        usage_reports_[key] = build_usage_report_from_rules(request.rules);
    }

    PfcpSessionResponse response {};
    response.success = true;
    response.cause = PfcpCause::RequestAccepted;
    response.session_version = version_;
    response.detail = "PFCP applied";

    if (!request.procedure.request_id.empty()) {
        replay_cache_[request.procedure.request_id] = response;
    }

    return response;
}

std::optional<UsageReport> ConsoleN4Adapter::query_usage_report(const std::string& imsi,
                                                                const std::string& pdu_session_id,
                                                                const std::vector<std::uint32_t>& urr_ids) {
    const auto it = usage_reports_.find(key_of(imsi, pdu_session_id));
    if (it == usage_reports_.end()) {
        return std::nullopt;
    }
    return filter_usage_report(it->second, urr_ids);
}

bool ConsoleN4Adapter::send_heartbeat() {
    return heartbeat_ok_;
}

void ConsoleN4Adapter::set_heartbeat_ok(bool value) {
    heartbeat_ok_ = value;
}

std::string ConsoleN4Adapter::key_of(const std::string& imsi, const std::string& pdu_session_id) const {
    return imsi + "|" + pdu_session_id;
}

PfcpSessionResponse ConsoleN4Adapter::validate_request(const PfcpSessionRequest& request, PfcpOperation operation) const {
    if (request.imsi.empty() || request.pdu_session_id.empty()) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing mandatory IMSI or PDU session ID"};
    }

    if (operation != PfcpOperation::Delete && (request.teid.empty() || request.ue_ipv4.empty())) {
        return PfcpSessionResponse {false, PfcpCause::MandatoryIeMissing, 0, false, "Missing mandatory TEID or UE IPv4"};
    }

    if (request.rules.qers.empty() || request.rules.pdrs.empty()) {
        return PfcpSessionResponse {true, PfcpCause::RequestAccepted, 0, false, "Default PFCP rule path"};
    }

    std::unordered_set<std::uint32_t> far_ids;
    std::unordered_set<std::uint32_t> qer_ids;
    std::unordered_set<std::uint32_t> urr_ids;
    std::unordered_set<std::uint8_t> qfi_set;

    for (const PfcpFar& far : request.rules.fars) {
        far_ids.insert(far.id);
    }
    for (const PfcpQer& qer : request.rules.qers) {
        if (qer.qfi == 0 || qer.qfi > 63 || qfi_set.find(qer.qfi) != qfi_set.end()) {
            return PfcpSessionResponse {false, PfcpCause::InvalidQfi, 0, false, "Invalid or duplicate QFI"};
        }
        if (!is_valid_gate_status(qer.gate_status)) {
            return PfcpSessionResponse {false, PfcpCause::InvalidGateStatus, 0, false, "Invalid gate status"};
        }
        if ((qer.gbr_ul_kbps > qer.mbr_ul_kbps && qer.mbr_ul_kbps != 0) ||
            (qer.gbr_dl_kbps > qer.mbr_dl_kbps && qer.mbr_dl_kbps != 0)) {
            return PfcpSessionResponse {false, PfcpCause::SemanticErrorInTheTft, 0, false, "GBR cannot exceed MBR"};
        }
        qfi_set.insert(qer.qfi);
        qer_ids.insert(qer.id);
    }
    for (const PfcpUrr& urr : request.rules.urrs) {
        urr_ids.insert(urr.id);
    }

    for (const PfcpPdr& pdr : request.rules.pdrs) {
        if (pdr.far_id != 0 && far_ids.find(pdr.far_id) == far_ids.end()) {
            return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, "PDR references missing FAR"};
        }
        if (pdr.qer_id != 0 && qer_ids.find(pdr.qer_id) == qer_ids.end()) {
            return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, "PDR references missing QER"};
        }
        if (pdr.urr_id != 0 && urr_ids.find(pdr.urr_id) == urr_ids.end()) {
            return PfcpSessionResponse {false, PfcpCause::RuleCreationModificationFailure, 0, false, "PDR references missing URR"};
        }
    }

    return PfcpSessionResponse {true, PfcpCause::RequestAccepted, 0, false, "Validated"};
}

bool ConsoleN4Adapter::is_valid_gate_status(const std::string& gate_status) {
    return gate_status == "OPEN" || gate_status == "CLOSED" || gate_status == "BLOCKED";
}

ConsoleN6Adapter::ConsoleN6Adapter(std::size_t downlink_buffer_capacity, std::string downlink_overflow_policy)
    : downlink_overflow_policy_(normalize_n6_overflow_policy(std::move(downlink_overflow_policy)))
    , downlink_overflow_policy_enum_(parse_n6_overflow_policy(downlink_overflow_policy_))
    , downlink_buffer_(downlink_buffer_capacity) {}

bool ConsoleN6Adapter::register_session(const N6SessionContext& context) {
    if (context.imsi.empty() || context.pdu_session_id.empty() || context.dnn.empty()) {
        return false;
    }
    if (context.ue_ipv4.empty() && context.ue_ipv6.empty() && context.ue_mac.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    sessions_[key_of(context.imsi, context.pdu_session_id)] = context;
    return true;
}

bool ConsoleN6Adapter::update_session(const N6SessionContext& context) {
    if (context.imsi.empty() || context.pdu_session_id.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const std::string key = key_of(context.imsi, context.pdu_session_id);
    if (sessions_.find(key) == sessions_.end()) {
        return false;
    }
    sessions_[key] = context;
    return true;
}

bool ConsoleN6Adapter::remove_session(const std::string& imsi, const std::string& pdu_session_id) {
    const std::string key = key_of(imsi, pdu_session_id);
    downlink_buffer_.clear_session(key);
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.erase(key) > 0;
}

std::optional<N6SessionContext> ConsoleN6Adapter::get_session(const std::string& imsi, const std::string& pdu_session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = sessions_.find(key_of(imsi, pdu_session_id));
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ConsoleN6Adapter::forward_packet(const std::string& imsi, const std::string& pdu_session_id, const N6Packet& packet) {
    const auto session = get_session(imsi, pdu_session_id);
    if (!session.has_value()) {
        return false;
    }

    N6Packet outbound = packet;
    if (outbound.protocol == N6Protocol::IPv4) {
        if (outbound.source_ipv4.empty()) {
            outbound.source_ipv4 = session->ue_ipv4;
        }
        if (outbound.destination_ipv4.empty()) {
            outbound.destination_ipv4 = default_ipv4_destination(session->dnn);
        }
        if (outbound.source_ipv4.empty() || outbound.destination_ipv4.empty()) {
            return false;
        }
        outbound.ether_type = 0x0800;
    } else if (outbound.protocol == N6Protocol::IPv6) {
        if (outbound.source_ipv6.empty()) {
            outbound.source_ipv6 = session->ue_ipv6;
        }
        if (outbound.destination_ipv6.empty()) {
            outbound.destination_ipv6 = default_ipv6_destination(session->dnn);
        }
        if (outbound.source_ipv6.empty() || outbound.destination_ipv6.empty()) {
            return false;
        }
        outbound.ether_type = 0x86DD;
    } else {
        if (outbound.source_mac.empty()) {
            outbound.source_mac = session->ue_mac;
        }
        if (outbound.destination_mac.empty()) {
            outbound.destination_mac = default_destination_mac(session->dnn);
        }
        if (outbound.source_mac.empty() || outbound.destination_mac.empty()) {
            return false;
        }
        if (outbound.ether_type == 0) {
            outbound.ether_type = 0x0800;
        }
    }

    N6ForwardRecord record {};
    record.imsi = imsi;
    record.pdu_session_id = pdu_session_id;
    record.dnn = session->dnn;
    record.direction = N6TrafficDirection::Uplink;
    record.packet = outbound;
    record.wire_bytes = n6_wire_bytes(outbound);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        history_.push_back(record);
    }

    std::cout << "[N6] protocol=" << n6_protocol_to_string(outbound.protocol)
              << " imsi=" << imsi
              << " pdu=" << pdu_session_id
              << " dnn=" << session->dnn
              << " bytes=" << record.wire_bytes
              << " payload=" << outbound.payload.size() << "\n";
    return true;
}

std::optional<N6Packet> ConsoleN6Adapter::receive_from_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    const auto session = get_session(imsi, pdu_session_id);
    if (!session.has_value()) {
        return std::nullopt;
    }

    const auto packet = downlink_buffer_.dequeue(key_of(imsi, pdu_session_id));
    if (!packet.has_value()) {
        return std::nullopt;
    }

    N6ForwardRecord record {};
    record.imsi = imsi;
    record.pdu_session_id = pdu_session_id;
    record.dnn = session->dnn;
    record.direction = N6TrafficDirection::Downlink;
    record.packet = *packet;
    record.wire_bytes = n6_wire_bytes(*packet);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        history_.push_back(record);
    }

    std::cout << "[N6] downlink protocol=" << n6_protocol_to_string(packet->protocol)
              << " imsi=" << imsi
              << " pdu=" << pdu_session_id
              << " dnn=" << session->dnn
              << " bytes=" << record.wire_bytes
              << " payload=" << packet->payload.size() << "\n";
    return packet;
}

bool ConsoleN6Adapter::forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    const auto session = get_session(imsi, pdu_session_id);
    if (!session.has_value()) {
        return false;
    }

    const auto uplink_packet = build_default_n6_packet(*session, bytes);
    const auto downlink_packet = build_downlink_n6_packet(*session, bytes);
    if (!uplink_packet.has_value() || !downlink_packet.has_value()) {
        return false;
    }

    if (!forward_packet(imsi, pdu_session_id, *uplink_packet)) {
        return false;
    }

    downlink_buffer_.enqueue(key_of(imsi, pdu_session_id), *downlink_packet, downlink_overflow_policy_enum_);
    return true;
}

std::vector<N6ForwardRecord> ConsoleN6Adapter::get_forward_history() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return history_;
}

N6BufferStatus ConsoleN6Adapter::get_buffer_status() const {
    const auto stats = downlink_buffer_.stats();
    N6BufferStatus status {};
    status.per_session_capacity = downlink_buffer_.capacity();
    status.overflow_policy = downlink_overflow_policy_enum_;
    status.enqueued_packets = stats.enqueued_packets;
    status.dequeued_packets = stats.dequeued_packets;
    status.dropped_packets = stats.dropped_packets;
    status.buffered_packets = stats.buffered_packets;
    status.active_sessions = stats.active_sessions;
    status.dropped_overflow_oldest = stats.dropped_overflow_oldest;
    status.dropped_overflow_newest = stats.dropped_overflow_newest;
    status.dropped_session_removed = stats.dropped_session_removed;
    status.rejected_by_policy = stats.rejected_by_policy;
    return status;
}

std::size_t ConsoleN6Adapter::buffered_packets_for_session(const std::string& imsi, const std::string& pdu_session_id) const {
    return downlink_buffer_.buffered_packets(key_of(imsi, pdu_session_id));
}

N6SessionBufferCounters ConsoleN6Adapter::buffer_counters_for_session(const std::string& imsi, const std::string& pdu_session_id) const {
    const auto stats = downlink_buffer_.session_stats(key_of(imsi, pdu_session_id));
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

std::string ConsoleN6Adapter::key_of(const std::string& imsi, const std::string& pdu_session_id) const {
    return imsi + "|" + pdu_session_id;
}

bool ConsoleN9Adapter::forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    if (!enabled_) {
        return false;
    }
    std::cout << "[N9] branch-forward imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
}

bool ConsoleN9Adapter::is_enabled() const {
    return enabled_;
}

void ConsoleN9Adapter::set_enabled(bool enabled) {
    enabled_ = enabled;
}

bool ConsoleSbiAdapter::publish_event(const std::string& service_name, const std::string& payload) {
    std::cout << "[SBI] service=" << service_name << " payload=" << payload << "\n";
    return true;
}

}  // namespace upf
