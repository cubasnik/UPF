#include <cstdlib>

#include "upf/adapters/console_adapters.hpp"

int main() {
    upf::ConsoleN4Adapter n4;

    upf::PfcpSessionRequest req {};
    req.imsi = "001010000000001";
    req.pdu_session_id = "7";
    req.teid = "0x700";
    req.ue_ipv4 = "10.7.0.2";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.procedure.request_id = "req-1";

    upf::PfcpFar far {};
    far.id = 1;
    far.action = "FORW";
    far.forward_to = "internet";
    req.rules.fars.push_back(far);

    upf::PfcpUrr urr {};
    urr.id = 1;
    urr.measurement_method = "VOLUME";
    urr.trigger = "PERIODIC";
    req.rules.urrs.push_back(urr);

    upf::PfcpQer qer {};
    qer.id = 1;
    qer.qfi = 9;
    qer.gate_status = "OPEN";
    qer.gbr_ul_kbps = 100;
    qer.gbr_dl_kbps = 100;
    qer.mbr_ul_kbps = 200;
    qer.mbr_dl_kbps = 200;
    req.rules.qers.push_back(qer);

    upf::PfcpPdr pdr {};
    pdr.id = 1;
    pdr.far_id = 1;
    pdr.qer_id = 1;
    pdr.urr_id = 1;
    pdr.ue_ipv4 = req.ue_ipv4;
    req.rules.pdrs.push_back(pdr);

    const auto established = n4.apply_pfcp(req, upf::PfcpOperation::Establish);
    if (!established.success || established.cause != upf::PfcpCause::RequestAccepted) {
        return EXIT_FAILURE;
    }

    const auto replayed = n4.apply_pfcp(req, upf::PfcpOperation::Establish);
    if (!replayed.success || !replayed.idempotent_replay) {
        return EXIT_FAILURE;
    }

    const auto report = n4.query_usage_report(req.imsi, req.pdu_session_id);
    if (!report.has_value()) {
        return EXIT_FAILURE;
    }

    req.procedure.request_id = "req-2";
    const auto deleted = n4.apply_pfcp(req, upf::PfcpOperation::Delete);
    if (!deleted.success) {
        return EXIT_FAILURE;
    }

    const auto missing = n4.query_usage_report(req.imsi, req.pdu_session_id);
    if (missing.has_value()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid = req;
    invalid.procedure.request_id = "req-invalid";
    invalid.rules.qers[0].qfi = 0;
    const auto invalid_result = n4.apply_pfcp(invalid, upf::PfcpOperation::Establish);
    if (invalid_result.success || invalid_result.cause != upf::PfcpCause::InvalidQfi) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
