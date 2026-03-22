#include "upf/upf.hpp"
#include "upf/modules/observability.hpp"

#include <cstdlib>
#include <ctime>

namespace upf {

namespace {

struct ResolvedSteering {
    std::string anchor_upf;
    std::string n19_endpoint;
    std::string nx_endpoint;
    std::string nsmf_component;
    bool mirror_to_n9 {false};
};

std::optional<std::uint32_t> parse_n3_teid(const std::string& teid) {
    if (teid.empty()) {
        return 0U;
    }

    char* end = nullptr;
    const unsigned long parsed = std::strtoul(teid.c_str(), &end, 0);
    if (end == teid.c_str() || *end != '\0' || parsed > 0xFFFFFFFFUL) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(parsed);
}

std::optional<N3TunnelContext> to_n3_tunnel_context(const PfcpSessionRequest& request) {
    const auto teid = parse_n3_teid(request.teid);
    if (!teid.has_value()) {
        return std::nullopt;
    }

    N3TunnelContext tunnel {};
    tunnel.teid = *teid;
    tunnel.ue_ip = request.ue_ipv4;
    tunnel.gnb_ip = "127.0.0.1";
    tunnel.imsi = request.imsi;
    tunnel.pdu_session_id = request.pdu_session_id;
    return tunnel;
}

N6SessionContext to_n6_session_context(const SessionContext& context) {
    N6SessionContext n6 {};
    n6.imsi = context.imsi;
    n6.pdu_session_id = context.pdu_session_id;
    n6.dnn = context.dnn;
    n6.ue_ipv4 = context.ue_ipv4;
    n6.ue_ipv6 = context.ue_ipv6;
    n6.ue_mac = context.ue_mac;
    n6.ipv6_enabled = context.n6_ipv6_enabled;
    n6.ethernet_enabled = context.n6_ethernet_enabled;
    return n6;
}

N6SessionBufferSnapshot to_n6_session_buffer_snapshot(const SessionContext& context, const N6SessionBufferCounters& counters) {
    N6SessionBufferSnapshot snapshot {};
    snapshot.imsi = context.imsi;
    snapshot.pdu_session_id = context.pdu_session_id;
    snapshot.dnn = context.dnn;
    snapshot.last_updated_utc = context.last_updated_utc;
    snapshot.ipv6_enabled = context.n6_ipv6_enabled;
    snapshot.ethernet_enabled = context.n6_ethernet_enabled;
    snapshot.enqueued_packets = counters.enqueued_packets;
    snapshot.dequeued_packets = counters.dequeued_packets;
    snapshot.dropped_packets = counters.dropped_packets;
    snapshot.dropped_overflow_oldest = counters.dropped_overflow_oldest;
    snapshot.dropped_overflow_newest = counters.dropped_overflow_newest;
    snapshot.dropped_session_removed = counters.dropped_session_removed;
    snapshot.rejected_by_policy = counters.rejected_by_policy;
    snapshot.buffered_packets = counters.buffered_packets;
    return snapshot;
}

std::string extract_prefixed_endpoint(const std::string& anchor_upf, const char* prefix) {
    const std::string full_prefix(prefix);
    if (anchor_upf.rfind(full_prefix, 0) != 0) {
        return {};
    }
    return anchor_upf.substr(full_prefix.size());
}

std::string select_nsmf_component(const PfcpSessionRequest& request) {
    if (!request.rules.steering.nsmf_component.empty()) {
        return request.rules.steering.nsmf_component;
    }

    const std::string explicit_component = extract_prefixed_endpoint(request.rules.anchor_upf, "nsmf:");
    if (!explicit_component.empty()) {
        return explicit_component;
    }
    if (request.dnn == "distributed" || request.dnn == "edge-distributed") {
        return "DU-UP";
    }
    return {};
}

ResolvedSteering resolve_steering(const PfcpSessionRequest& request) {
    ResolvedSteering resolved {};
    resolved.anchor_upf = request.rules.anchor_upf;
    resolved.nsmf_component = select_nsmf_component(request);

    switch (request.rules.steering.mode) {
        case SteeringMode::N19Local:
            resolved.n19_endpoint = request.rules.steering.target_endpoint;
            break;
        case SteeringMode::NxBranch:
            resolved.nx_endpoint = request.rules.steering.target_endpoint;
            break;
        case SteeringMode::Default:
            break;
    }

    resolved.mirror_to_n9 = request.rules.steering.mirror_to_n9;

    // Backward compatibility for legacy anchor_upf prefixes.
    if (resolved.n19_endpoint.empty()) {
        resolved.n19_endpoint = extract_prefixed_endpoint(request.rules.anchor_upf, "n19:");
    }
    if (resolved.nx_endpoint.empty()) {
        resolved.nx_endpoint = extract_prefixed_endpoint(request.rules.anchor_upf, "nx:");
    }

    return resolved;
}

std::string now_utc() {
    std::time_t t = std::time(nullptr);
    char buf[32] {};
#if defined(_WIN32)
    std::tm tm_value {};
    gmtime_s(&tm_value, &t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_value);
#else
    std::tm* tm_value = std::gmtime(&t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm_value);
#endif
    return std::string(buf);
}

PfcpRuleSet build_default_rules(const PfcpSessionRequest& request, bool modify_mode) {
    PfcpRuleSet rules {};
    rules.steering = request.rules.steering;
    rules.anchor_upf = request.rules.anchor_upf.empty() ? "upf-anchor-1" : request.rules.anchor_upf;

    PfcpPdr pdr {};
    pdr.id = 1;
    pdr.precedence = modify_mode ? 300 : 200;
    pdr.source_interface = 0x00U;
    pdr.ue_ipv4 = request.ue_ipv4;
    pdr.application_id = modify_mode ? "edge-cache-sync" : "web-browsing";
    pdr.packet_filter_id = 100 + pdr.id;
    pdr.flow_direction = 0x01U;
    pdr.protocol_identifier = 17U;
    pdr.source_port = 2152;
    pdr.destination_port = modify_mode ? 8080 : 2152;
    pdr.ether_type = 0x0800U;
    pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {100 + pdr.id, 0x01U, 17U, 2152, 2152, static_cast<std::uint16_t>(modify_mode ? 8080 : 2152), static_cast<std::uint16_t>(modify_mode ? 8080 : 2152), 0x0800U, {}});
    pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {200 + pdr.id, 0x02U, 6U, 3000, 3010, 443, 445, 0x0800U, modify_mode ? "permit in tcp from 10.0.0.0/24 3000-3010 to assigned 443-445" : "permit in tcp from assigned 3000-3010 to assigned 443-445"});
    pdr.far_id = 1;
    pdr.qer_id = 1;
    pdr.urr_id = 1;
    rules.pdrs.push_back(pdr);

    PfcpFar far {};
    far.id = 1;
    far.action = "FORW";
    far.forward_to = request.dnn;
    far.outer_header_creation_description = 0x01U;
    far.tunnel_peer_ipv4 = request.dnn == "internet" ? "198.51.100.1" : (request.dnn == "edge-cache" ? "198.51.100.2" : "198.51.100.254");
    far.tunnel_peer_teid = 0x00F00000U + far.id;
    rules.fars.push_back(far);

    PfcpUrr urr {};
    urr.id = 1;
    urr.measurement_method = "VOLUME";
    urr.trigger = "PERIODIC";
    rules.urrs.push_back(urr);

    PfcpQer qer {};
    qer.id = 1;
    qer.gate_status = modify_mode ? "CLOSED" : "OPEN";
    qer.gbr_ul_kbps = modify_mode ? 70000 : 50000;
    qer.gbr_dl_kbps = modify_mode ? 70000 : 50000;
    qer.mbr_ul_kbps = modify_mode ? 120000 : 100000;
    qer.mbr_dl_kbps = modify_mode ? 120000 : 100000;
    qer.qfi = 9;
    rules.qers.push_back(qer);

    return rules;
}

PfcpSessionRequest with_default_rules(const PfcpSessionRequest& request, bool modify_mode) {
    PfcpSessionRequest out = request;
    if (out.rules.pdrs.empty() && out.rules.qers.empty()) {
        out.rules = build_default_rules(request, modify_mode);
    }
    if (out.procedure.request_id.empty()) {
        out.procedure.request_id = (modify_mode ? "modify|" : "establish|") + request.imsi + "|" + request.pdu_session_id;
    }
    return out;
}

}  // namespace

const char* to_string(UpfState state) {
    switch (state) {
        case UpfState::Idle:
            return "IDLE";
        case UpfState::Initializing:
            return "INITIALIZING";
        case UpfState::Running:
            return "RUNNING";
        case UpfState::Degraded:
            return "DEGRADED";
        case UpfState::Stopped:
            return "STOPPED";
    }
    return "UNKNOWN";
}

const char* to_string(PfcpCause cause) {
    switch (cause) {
        case PfcpCause::RequestAccepted:
            return "RequestAccepted";
        case PfcpCause::MandatoryIeMissing:
            return "MandatoryIeMissing";
        case PfcpCause::SessionContextNotFound:
            return "SessionContextNotFound";
        case PfcpCause::RuleCreationModificationFailure:
            return "RuleCreationModificationFailure";
        case PfcpCause::SemanticErrorInTheTft:
            return "SemanticErrorInTheTft";
        case PfcpCause::InvalidQfi:
            return "InvalidQfi";
        case PfcpCause::InvalidGateStatus:
            return "InvalidGateStatus";
    }
    return "UnknownPfcpCause";
}

const char* to_string(UsageReportCause cause) {
    switch (cause) {
        case UsageReportCause::UsageReady:
            return "UsageReady";
        case UsageReportCause::ThresholdReached:
            return "ThresholdReached";
        case UsageReportCause::QuotaExhausted:
            return "QuotaExhausted";
        case UsageReportCause::Unknown:
            return "Unknown";
    }
    return "UnknownUsageReportCause";
}

const char* to_string(N6BufferOverflowPolicy policy) {
    switch (policy) {
        case N6BufferOverflowPolicy::DropOldest:
            return "drop_oldest";
        case N6BufferOverflowPolicy::DropNewest:
            return "drop_newest";
    }
    return "unknown";
}

const char* to_string(N6BufferDropReason reason) {
    switch (reason) {
        case N6BufferDropReason::None:
            return "none";
        case N6BufferDropReason::OverflowDropOldest:
            return "overflow_drop_oldest";
        case N6BufferDropReason::OverflowDropNewest:
            return "overflow_drop_newest";
        case N6BufferDropReason::SessionRemoved:
            return "session_removed";
        case N6BufferDropReason::UnknownSession:
            return "unknown_session";
    }
    return "unknown";
}

UpfNode::UpfNode(IN4Interface& n4, ISbiInterface& sbi, UpfPeerInterfaces peers)
    : n4_(n4), sbi_(sbi), peers_(peers) {}

bool UpfNode::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UpfState::Running) {
        return false;
    }
    state_ = UpfState::Running;
    ++stats_.starts;
    if (peers_.nsmf != nullptr) {
        peers_.nsmf->register_internal_component("UPF-CTRL");
    }
    return true;
}

bool UpfNode::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UpfState::Stopped) {
        return false;
    }
    state_ = UpfState::Stopped;
    ++stats_.stops;
    if (peers_.nsmf != nullptr) {
        peers_.nsmf->unregister_internal_component("UPF-CTRL");
    }
    return true;
}

bool UpfNode::set_degraded() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != UpfState::Running) {
        return false;
    }
    state_ = UpfState::Degraded;
    return true;
}

bool UpfNode::recover() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != UpfState::Degraded) {
        return false;
    }
    state_ = UpfState::Running;
    return true;
}

void UpfNode::tick() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return;
    }
    ++stats_.ticks;
    ++stats_.n4_heartbeats;
    if (!n4_.send_heartbeat()) {
        ++stats_.n4_heartbeat_failures;
        state_ = UpfState::Degraded;
        return;
    }
    if (state_ == UpfState::Degraded) {
        state_ = UpfState::Running;
    }
}

bool UpfNode::establish_session(const PfcpSessionRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return false;
    }

    const PfcpSessionRequest request_to_send = with_default_rules(request, false);
    const ResolvedSteering steering = resolve_steering(request_to_send);
    const PfcpSessionResponse response = n4_.apply_pfcp(request_to_send, PfcpOperation::Establish);
    ++stats_.n4_messages;
    if (!response.success) {
        return false;
    }

    SessionContext context {};
    context.imsi = request.imsi;
    context.pdu_session_id = request.pdu_session_id;
    context.teid = request.teid;
    context.ue_ipv4 = request.ue_ipv4;
    context.ue_ipv6 = request.ue_ipv6;
    context.ue_mac = request.ue_mac;
    context.dnn = request.dnn;
    context.s_nssai = request.s_nssai;
    context.anchor_upf = steering.anchor_upf;
    context.n19_endpoint = steering.n19_endpoint;
    context.nx_endpoint = steering.nx_endpoint;
    context.nsmf_component = steering.nsmf_component;
    context.n6_ipv6_enabled = request.prefer_n6_ipv6 && !request.ue_ipv6.empty();
    context.n6_ethernet_enabled = request.prefer_n6_ethernet && !request.ue_mac.empty();
    context.mirror_to_n9 = steering.mirror_to_n9;
    context.active = true;
    context.last_updated_utc = now_utc();

    if (!sessions_.create(context)) {
        return false;
    }

    if (peers_.n6 != nullptr && !peers_.n6->register_session(to_n6_session_context(context))) {
        sessions_.remove(context.imsi, context.pdu_session_id);
        return false;
    }

    if (peers_.n3 != nullptr) {
        const auto tunnel = to_n3_tunnel_context(request);
        if (!tunnel.has_value() || !peers_.n3->create_tunnel(*tunnel)) {
            if (peers_.n6 != nullptr) {
                peers_.n6->remove_session(context.imsi, context.pdu_session_id);
            }
            sessions_.remove(context.imsi, context.pdu_session_id);
            return false;
        }
    }

    if (peers_.nsmf != nullptr && !context.nsmf_component.empty()) {
        InternalComponentMessage message {};
        message.source_component = "UPF-CTRL";
        message.target_component = context.nsmf_component;
        message.message_type = "SESSION_ESTABLISH";
        message.payload = context.imsi + "|" + context.pdu_session_id;
        message.timestamp_ms = static_cast<std::uint64_t>(std::time(nullptr));
        if (peers_.nsmf->send_internal_message(message)) {
            ++stats_.nsmf_messages;
        }
    }

    ++stats_.session_establishes;
    return true;
}

bool UpfNode::modify_session(const PfcpSessionRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return false;
    }

    auto context_opt = sessions_.find(request.imsi, request.pdu_session_id);
    if (!context_opt.has_value()) {
        return false;
    }

    const PfcpSessionRequest request_to_send = with_default_rules(request, true);
    const ResolvedSteering steering = resolve_steering(request_to_send);
    const PfcpSessionResponse response = n4_.apply_pfcp(request_to_send, PfcpOperation::Modify);
    ++stats_.n4_messages;
    if (!response.success) {
        return false;
    }

    SessionContext context = *context_opt;
    context.teid = request.teid;
    context.ue_ipv4 = request.ue_ipv4;
    context.ue_ipv6 = request.ue_ipv6;
    context.ue_mac = request.ue_mac;
    context.dnn = request.dnn;
    context.s_nssai = request.s_nssai;
    context.anchor_upf = steering.anchor_upf;
    context.n19_endpoint = steering.n19_endpoint;
    context.nx_endpoint = steering.nx_endpoint;
    context.nsmf_component = steering.nsmf_component;
    context.n6_ipv6_enabled = request.prefer_n6_ipv6 && !request.ue_ipv6.empty();
    context.n6_ethernet_enabled = request.prefer_n6_ethernet && !request.ue_mac.empty();
    context.mirror_to_n9 = steering.mirror_to_n9;
    context.last_updated_utc = now_utc();

    if (!sessions_.modify(context)) {
        return false;
    }

    if (peers_.n6 != nullptr && !peers_.n6->update_session(to_n6_session_context(context))) {
        sessions_.modify(*context_opt);
        return false;
    }

    if (peers_.n3 != nullptr &&
        (context_opt->teid != context.teid || context_opt->ue_ipv4 != context.ue_ipv4)) {
        const auto tunnel = to_n3_tunnel_context(request);
        if (!tunnel.has_value()) {
            if (peers_.n6 != nullptr) {
                peers_.n6->update_session(to_n6_session_context(*context_opt));
            }
            sessions_.modify(*context_opt);
            return false;
        }

        if (!peers_.n3->create_tunnel(*tunnel)) {
            if (peers_.n6 != nullptr) {
                peers_.n6->update_session(to_n6_session_context(*context_opt));
            }
            sessions_.modify(*context_opt);
            return false;
        }

        const auto previous_teid = parse_n3_teid(context_opt->teid);
        if (!previous_teid.has_value()) {
            peers_.n3->delete_tunnel(tunnel->teid);
            if (peers_.n6 != nullptr) {
                peers_.n6->update_session(to_n6_session_context(*context_opt));
            }
            sessions_.modify(*context_opt);
            return false;
        }

        if (*previous_teid != 0 && *previous_teid != tunnel->teid && !peers_.n3->delete_tunnel(*previous_teid)) {
            peers_.n3->delete_tunnel(tunnel->teid);
            if (peers_.n6 != nullptr) {
                peers_.n6->update_session(to_n6_session_context(*context_opt));
            }
            sessions_.modify(*context_opt);
            return false;
        }
    }

    if (peers_.nsmf != nullptr && !context.nsmf_component.empty()) {
        InternalComponentMessage message {};
        message.source_component = "UPF-CTRL";
        message.target_component = context.nsmf_component;
        message.message_type = "SESSION_MODIFY";
        message.payload = context.imsi + "|" + context.pdu_session_id;
        message.timestamp_ms = static_cast<std::uint64_t>(std::time(nullptr));
        if (peers_.nsmf->send_internal_message(message)) {
            ++stats_.nsmf_messages;
        }
    }

    ++stats_.session_modifies;
    return true;
}

bool UpfNode::release_session(const std::string& imsi, const std::string& pdu_session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return false;
    }

    auto context_opt = sessions_.find(imsi, pdu_session_id);
    if (!context_opt.has_value()) {
        return false;
    }

    PfcpSessionRequest request {};
    request.imsi = context_opt->imsi;
    request.pdu_session_id = context_opt->pdu_session_id;
    request.teid = context_opt->teid;
    request.ue_ipv4 = context_opt->ue_ipv4;
    request.dnn = context_opt->dnn;
    request.s_nssai = context_opt->s_nssai;
    request.procedure.request_id = "delete|" + imsi + "|" + pdu_session_id;

    const PfcpSessionResponse response = n4_.apply_pfcp(request, PfcpOperation::Delete);
    ++stats_.n4_messages;
    if (!response.success) {
        return false;
    }

    bool n3_removed = true;
    if (peers_.n3 != nullptr && !context_opt->teid.empty()) {
        const auto teid = parse_n3_teid(context_opt->teid);
        if (!teid.has_value()) {
            n3_removed = false;
        } else {
            n3_removed = peers_.n3->delete_tunnel(*teid);
        }
    }

    const bool n6_removed = peers_.n6 == nullptr || peers_.n6->remove_session(imsi, pdu_session_id);
    const bool session_removed = sessions_.remove(imsi, pdu_session_id);

    if (peers_.nsmf != nullptr && !context_opt->nsmf_component.empty()) {
        InternalComponentMessage message {};
        message.source_component = "UPF-CTRL";
        message.target_component = context_opt->nsmf_component;
        message.message_type = "SESSION_RELEASE";
        message.payload = context_opt->imsi + "|" + context_opt->pdu_session_id;
        message.timestamp_ms = static_cast<std::uint64_t>(std::time(nullptr));
        if (peers_.nsmf->send_internal_message(message)) {
            ++stats_.nsmf_messages;
        }
    }

    if (!session_removed || !n3_removed || !n6_removed) {
        return false;
    }

    ++stats_.session_releases;
    return true;
}

bool UpfNode::process_uplink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto context_opt = sessions_.find(imsi, pdu_session_id);
    if (!is_operational() || !context_opt.has_value()) {
        return false;
    }
    const SessionContext& context = *context_opt;

    if (peers_.n3 != nullptr && !peers_.n3->receive_uplink_packet(imsi, pdu_session_id, bytes)) {
        return false;
    }
    ++stats_.n3_packets_rx;

    if (!context.nx_endpoint.empty() && peers_.nx != nullptr && peers_.nx->is_enabled()) {
        if (!peers_.nx->forward_uplink_classified(imsi, pdu_session_id, context.nx_endpoint, bytes)) {
            return false;
        }
        ++stats_.nx_forwards;
    }

    if (!context.n19_endpoint.empty() && peers_.n19 != nullptr && peers_.n19->is_enabled()) {
        if (!peers_.n19->forward_to_local_upf(imsi, pdu_session_id, context.n19_endpoint, bytes)) {
            return false;
        }
        ++stats_.n19_forwards;
    } else {
        if (peers_.n6 == nullptr || !peers_.n6->forward_to_data_network(imsi, pdu_session_id, bytes)) {
            return false;
        }
        ++stats_.n6_forwards;
    }

    if ((context.mirror_to_n9 || context.nx_endpoint.empty()) && peers_.n9 != nullptr && peers_.n9->is_enabled()) {
        if (!peers_.n9->forward_to_branch_upf(imsi, pdu_session_id, bytes / 2U)) {
            return false;
        }
        ++stats_.n9_forwards;
    }

    return true;
}

bool UpfNode::process_downlink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto context = sessions_.find(imsi, pdu_session_id);
    if (!is_operational() || !context.has_value()) {
        return false;
    }

    if (peers_.n6 == nullptr) {
        return false;
    }

    const auto packet = peers_.n6->receive_from_data_network(imsi, pdu_session_id, bytes);
    if (!packet.has_value()) {
        return false;
    }

    if (peers_.n3 == nullptr) {
        return false;
    }

    bool downlink_sent = false;
    const auto teid = parse_n3_teid(context->teid);
    if (teid.has_value() && peers_.n3->send_gtp_u_packet(*teid, packet->payload).has_value()) {
        downlink_sent = true;
    }

    if (!downlink_sent && !peers_.n3->send_downlink_packet(imsi, pdu_session_id, packet->payload.size())) {
        return false;
    }

    ++stats_.n3_packets_tx;
    return true;
}

std::optional<SessionContext> UpfNode::find_session(const std::string& imsi, const std::string& pdu_session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.find(imsi, pdu_session_id);
}

std::vector<SessionContext> UpfNode::list_sessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.list();
}

std::optional<N6SessionBufferSnapshot> UpfNode::inspect_n6_session(const std::string& imsi, const std::string& pdu_session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto context = sessions_.find(imsi, pdu_session_id);
    if (!context.has_value() || peers_.n6 == nullptr) {
        return std::nullopt;
    }
    return to_n6_session_buffer_snapshot(*context, peers_.n6->buffer_counters_for_session(imsi, pdu_session_id));
}

bool UpfNode::notify_sbi(const std::string& service_name, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return false;
    }

    UpfStatusSnapshot snapshot {};
    snapshot.state = state_;
    snapshot.active_sessions = sessions_.size();
    snapshot.stats = stats_;
    if (peers_.n6 != nullptr) {
        snapshot.n6_buffer = peers_.n6->get_buffer_status();
    }

    if (!sbi_.publish_event(service_name, format_sbi_event_payload_json(payload, snapshot))) {
        return false;
    }

    ++stats_.sbi_notifications;
    return true;
}

UpfStatusSnapshot UpfNode::status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    UpfStatusSnapshot snapshot {};
    snapshot.state = state_;
    snapshot.active_sessions = sessions_.size();
    snapshot.stats = stats_;
    if (peers_.n6 != nullptr) {
        snapshot.n6_buffer = peers_.n6->get_buffer_status();
    }
    return snapshot;
}

void UpfNode::clear_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = UpfStats {};
}

bool UpfNode::is_operational() const {
    return state_ == UpfState::Running || state_ == UpfState::Degraded;
}

}  // namespace upf
