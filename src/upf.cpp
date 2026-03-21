#include "upf/upf.hpp"

#include <ctime>

namespace upf {

namespace {

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
    rules.anchor_upf = "upf-anchor-1";

    PfcpPdr pdr {};
    pdr.id = 1;
    pdr.precedence = modify_mode ? 300 : 200;
    pdr.ue_ipv4 = request.ue_ipv4;
    pdr.far_id = 1;
    pdr.qer_id = 1;
    pdr.urr_id = 1;
    rules.pdrs.push_back(pdr);

    PfcpFar far {};
    far.id = 1;
    far.action = "FORW";
    far.forward_to = request.dnn;
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

UpfNode::UpfNode(IN4Interface& n4, ISbiInterface& sbi, UpfPeerInterfaces peers)
    : n4_(n4), sbi_(sbi), peers_(peers) {}

bool UpfNode::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UpfState::Running) {
        return false;
    }
    state_ = UpfState::Running;
    ++stats_.starts;
    return true;
}

bool UpfNode::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == UpfState::Stopped) {
        return false;
    }
    state_ = UpfState::Stopped;
    ++stats_.stops;
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
    context.dnn = request.dnn;
    context.s_nssai = request.s_nssai;
    context.active = true;
    context.last_updated_utc = now_utc();

    if (!sessions_.create(context)) {
        return false;
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
    const PfcpSessionResponse response = n4_.apply_pfcp(request_to_send, PfcpOperation::Modify);
    ++stats_.n4_messages;
    if (!response.success) {
        return false;
    }

    SessionContext context = *context_opt;
    context.teid = request.teid;
    context.ue_ipv4 = request.ue_ipv4;
    context.dnn = request.dnn;
    context.s_nssai = request.s_nssai;
    context.last_updated_utc = now_utc();

    if (!sessions_.modify(context)) {
        return false;
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

    if (!sessions_.remove(imsi, pdu_session_id)) {
        return false;
    }

    ++stats_.session_releases;
    return true;
}

bool UpfNode::process_uplink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational() || !sessions_.find(imsi, pdu_session_id).has_value()) {
        return false;
    }

    if (peers_.n3 != nullptr && !peers_.n3->receive_uplink_packet(imsi, pdu_session_id, bytes)) {
        return false;
    }
    ++stats_.n3_packets_rx;

    if (peers_.n6 == nullptr || !peers_.n6->forward_to_data_network(imsi, pdu_session_id, bytes)) {
        return false;
    }
    ++stats_.n6_forwards;

    if (peers_.n9 != nullptr && peers_.n9->is_enabled()) {
        if (!peers_.n9->forward_to_branch_upf(imsi, pdu_session_id, bytes / 2U)) {
            return false;
        }
        ++stats_.n9_forwards;
    }

    return true;
}

bool UpfNode::process_downlink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational() || !sessions_.find(imsi, pdu_session_id).has_value()) {
        return false;
    }

    if (peers_.n3 == nullptr || !peers_.n3->send_downlink_packet(imsi, pdu_session_id, bytes)) {
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

bool UpfNode::notify_sbi(const std::string& service_name, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_operational()) {
        return false;
    }

    if (!sbi_.publish_event(service_name, payload)) {
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
