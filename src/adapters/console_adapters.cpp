#include "upf/adapters/console_adapters.hpp"

#include <algorithm>

namespace upf {

bool ConsoleN3Adapter::receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::cout << "[N3] UL packet imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
}

bool ConsoleN3Adapter::send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::cout << "[N3] DL packet imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
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
        usage_reports_[key] = UsageReport {};
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

std::optional<UsageReport> ConsoleN4Adapter::query_usage_report(const std::string& imsi, const std::string& pdu_session_id) {
    const auto it = usage_reports_.find(key_of(imsi, pdu_session_id));
    if (it == usage_reports_.end()) {
        return std::nullopt;
    }
    return it->second;
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

bool ConsoleN6Adapter::forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) {
    std::cout << "[N6] forward imsi=" << imsi << " pdu=" << pdu_session_id << " bytes=" << bytes << "\n";
    return true;
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
