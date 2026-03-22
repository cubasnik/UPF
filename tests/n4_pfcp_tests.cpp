#include <cstdlib>

#include "upf/adapters/console_adapters.hpp"

int main() {
    upf::ConsoleN4Adapter n4;

    upf::PfcpSessionRequest req {};
    req.imsi = "250200000000001";
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
    far.outer_header_creation_description = 0x01U;
    far.tunnel_peer_ipv4 = "203.0.113.10";
    far.tunnel_peer_teid = 0x0A0B0C01U;
    req.rules.fars.push_back(far);

    upf::PfcpUrr urr {};
    urr.id = 1;
    urr.measurement_method = "VOLUME";
    urr.trigger = "PERIODIC";
    req.rules.urrs.push_back(urr);

    upf::PfcpUrr quota_urr {};
    quota_urr.id = 3;
    quota_urr.measurement_method = "VOLUME";
    quota_urr.trigger = "ON_QUOTA";
    req.rules.urrs.push_back(quota_urr);

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
    pdr.source_interface = 0x00U;
    pdr.packet_filter_id = 101;
    pdr.flow_direction = 0x01U;
    pdr.protocol_identifier = 17U;
    pdr.source_port = 2152;
    pdr.destination_port = 8080;
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
    if (!report.has_value() || report->urr_reports.size() != 2 || report->bytes_ul != 12 || report->bytes_dl != 12 || report->packets_ul != 3 || report->packets_dl != 2) {
        return EXIT_FAILURE;
    }
    const auto scoped_report = n4.query_usage_report(req.imsi, req.pdu_session_id, std::vector<std::uint32_t> {1});
    if (!scoped_report.has_value() || scoped_report->urr_reports.size() != 1 || scoped_report->urr_reports[0].urr_id != 1 ||
        scoped_report->urr_reports[0].measurement_method != "VOLUME" || scoped_report->urr_reports[0].reporting_trigger != "PERIODIC" ||
        scoped_report->urr_reports[0].report_cause != upf::UsageReportCause::UsageReady || scoped_report->urr_reports[0].detail != "usage-ready") {
        return EXIT_FAILURE;
    }
    const auto quota_report = n4.query_usage_report(req.imsi, req.pdu_session_id, std::vector<std::uint32_t> {3});
    if (!quota_report.has_value() || quota_report->urr_reports.size() != 1 || quota_report->urr_reports[0].urr_id != 3 ||
        quota_report->urr_reports[0].measurement_method != "VOLUME" || quota_report->urr_reports[0].reporting_trigger != "ON_QUOTA" ||
        quota_report->urr_reports[0].report_cause != upf::UsageReportCause::QuotaExhausted || quota_report->urr_reports[0].detail != "quota-exhausted" ||
        quota_report->urr_reports[0].threshold_value.has_value() || !quota_report->urr_reports[0].quota_value.has_value() || *quota_report->urr_reports[0].quota_value != 8192 ||
        quota_report->bytes_ul != 8 || quota_report->bytes_dl != 5 || quota_report->packets_ul != 2 || quota_report->packets_dl != 1) {
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
