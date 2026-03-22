#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pfcp_test_wire.hpp"
#include "pfcp_usage_report_test_utils.hpp"
#include "upf/adapters/network_adapters.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

#if defined(_WIN32)
using SocketType = SOCKET;
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
#else
using SocketType = int;
constexpr SocketType kInvalidSocket = -1;
#endif

using namespace test_pfcp_wire;

struct MockServerState {
    bool saw_association_setup {false};
    bool saw_capability_exchange {false};
    bool saw_node_features {false};
    bool saw_recovery_time_stamp {false};
    bool saw_node_id {false};
    bool saw_fseid {false};
    bool saw_grouped_contexts {false};
    bool saw_binary_rules {false};
    int retry_request_count {0};
};

void close_socket(SocketType sock) {
#if defined(_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

bool init_stack() {
#if defined(_WIN32)
    WSADATA data {};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
}

std::vector<std::uint8_t> encode_response_context(std::uint64_t session_version,
                                                  const std::string& detail,
                                                  std::uint32_t recovery_time_stamp = 0) {
    return test_pfcp::encode_response_context(1,
                                              detail,
                                              session_version,
                                              recovery_time_stamp == 0 ? std::optional<std::uint32_t> {} : std::optional<std::uint32_t> {recovery_time_stamp});
}

void run_udp_mock_server(int port, MockServerState* state) {
    if (!init_stack()) {
        return;
    }

    SocketType sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
        return;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));

    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(sock);
        return;
    }

#if defined(_WIN32)
    const DWORD timeout = static_cast<DWORD>(250);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    timeval tv {};
    tv.tv_sec = 0;
    tv.tv_usec = 250000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    int idle_polls = 0;
    for (int i = 0; i < 32 && idle_polls < 8; ++i) {
        char buffer[4096] {};
        sockaddr_in peer {};
        socklen_t peer_len = sizeof(peer);
        const int recv_len = recvfrom(sock, buffer, static_cast<int>(sizeof(buffer)), 0, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (recv_len <= 0) {
            ++idle_polls;
            continue;
        }
        idle_polls = 0;

        const auto request = decode_pfcp_message(buffer, recv_len);
        if (!request.has_value()) {
            continue;
        }

        std::vector<std::uint8_t> response_ies;
        PfcpMessageType response_type = PfcpMessageType::HeartbeatResponse;

        if (request->message_type == PfcpMessageType::AssociationSetupRequest) {
            const auto node_id = first_ie_value(*request, PfcpIeType::NodeId);
            const auto fseid_ie = first_ie_value(*request, PfcpIeType::FSeid);
            const auto recovery_ie = first_ie_value(*request, PfcpIeType::RecoveryTimeStamp);
            state->saw_association_setup = node_id.has_value() && fseid_ie.has_value() && recovery_ie.has_value();
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(1, "associated"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FSeid, encode_fseid_value(1, "127.0.0.2"));
            append_ie(&response_ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(1));
            response_type = PfcpMessageType::AssociationSetupResponse;
        } else if (request->message_type == PfcpMessageType::CapabilityExchangeRequest) {
            const auto node_id = first_ie_value(*request, PfcpIeType::NodeId);
            const auto fseid_ie = first_ie_value(*request, PfcpIeType::FSeid);
            const auto feature_bitmap = first_ie_value(*request, PfcpIeType::FeatureBitmap);
            state->saw_capability_exchange = node_id.has_value() && fseid_ie.has_value() && feature_bitmap.has_value();
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(2, "capabilities-ok"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2"));
            append_ie(&response_ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x0000000FU));
            response_type = PfcpMessageType::CapabilityExchangeResponse;
        } else if (request->message_type == PfcpMessageType::NodeFeaturesRequest) {
            const auto node_id = first_ie_value(*request, PfcpIeType::NodeId);
            const auto feature_bitmap = first_ie_value(*request, PfcpIeType::FeatureBitmap);
            state->saw_node_features = node_id.has_value() && feature_bitmap.has_value();
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(3, "node-features-ok"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x00000007U));
            response_type = PfcpMessageType::NodeFeaturesResponse;
        } else if (request->message_type == PfcpMessageType::HeartbeatRequest) {
            std::uint32_t recovery_time_stamp = 1;
            const auto recovery_ie = first_ie_value(*request, PfcpIeType::RecoveryTimeStamp);
            state->saw_recovery_time_stamp = recovery_ie.has_value() && recovery_ie->size() == 4 && read_u32(*recovery_ie, 0) != 0;
            if (recovery_ie.has_value() && recovery_ie->size() == 4) {
                recovery_time_stamp = read_u32(*recovery_ie, 0);
            }
            append_ie(&response_ies,
                      PfcpIeType::ResponseContext,
                      encode_response_context(recovery_time_stamp, "heartbeat-ok", recovery_time_stamp));
            response_type = PfcpMessageType::HeartbeatResponse;
        } else if (request->message_type == PfcpMessageType::SessionReportRequest) {
            const auto pdu_session_id = first_ie_value(*request, PfcpIeType::PduSessionId);
            const auto requested_rule_ids = request->ies.count(static_cast<std::uint16_t>(PfcpIeType::UsageQueryContext)) != 0
                ? decode_grouped_ies(*request, PfcpIeType::UsageQueryContext, PfcpIeType::UrrId)
                : std::vector<std::vector<std::uint8_t>> {};
            state->saw_grouped_contexts = state->saw_grouped_contexts && pdu_session_id.has_value();
            bool request_rule_1 = requested_rule_ids.empty();
            bool request_rule_2 = requested_rule_ids.empty();
            bool request_rule_3 = requested_rule_ids.empty();
            for (const auto& requested_rule_id : requested_rule_ids) {
                if (requested_rule_id.size() != 4) {
                    continue;
                }
                const std::uint32_t rule_id = read_u32(requested_rule_id, 0);
                request_rule_1 = request_rule_1 || rule_id == 1;
                request_rule_2 = request_rule_2 || rule_id == 2;
                request_rule_3 = request_rule_3 || rule_id == 3;
            }
            if (request_rule_1) {
                const auto usage_context_1 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                    1,
                    "VOLUME",
                    "PERIODIC",
                    1,
                    std::string("ul-volume-ready"),
                    std::nullopt,
                    std::nullopt,
                    4,
                    7,
                    1,
                    1,
                });
                append_ie(&response_ies, PfcpIeType::UsageReportContext, usage_context_1);
            }
            if (request_rule_2) {
                const auto usage_context_2 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                    2,
                    "DURATION",
                    "ON_THRESHOLD",
                    2,
                    std::string("dl-threshold-reached"),
                    4096,
                    std::nullopt,
                    6,
                    13,
                    0,
                    1,
                });
                append_ie(&response_ies, PfcpIeType::UsageReportContext, usage_context_2);
            }
            if (request_rule_3) {
                const auto usage_context_3 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                    3,
                    "VOLUME",
                    "ON_QUOTA",
                    3,
                    std::string("quota-exhausted"),
                    std::nullopt,
                    8192,
                    8,
                    5,
                    2,
                    1,
                });
                append_ie(&response_ies, PfcpIeType::UsageReportContext, usage_context_3);
            }
            response_type = PfcpMessageType::SessionReportResponse;
        } else {
            const auto node_id = first_ie_value(*request, PfcpIeType::NodeId);
            const auto fseid_ie = first_ie_value(*request, PfcpIeType::FSeid);
            state->saw_node_id = node_id.has_value() && !node_id->empty() && node_id->front() == 0x02U;

            if (fseid_ie.has_value()) {
                const DecodedFSeid fseid = decode_fseid_ie(*fseid_ie);
                state->saw_fseid = fseid.seid != 0 && fseid.ipv4 == "127.0.0.1";
            }

            const auto grouped_imsi = first_ie_value(*request, PfcpIeType::Imsi);
            const auto grouped_pdu = first_ie_value(*request, PfcpIeType::PduSessionId);
            const auto grouped_request_id = first_ie_value(*request, PfcpIeType::RequestId);
            const auto grouped_timeout = first_ie_value(*request, PfcpIeType::TimeoutMs);
            const auto grouped_source_interface = first_ie_value(*request, PfcpIeType::SourceInterface);
            const auto grouped_fteid = first_ie_value(*request, PfcpIeType::FTeid);
            const auto grouped_ue_ip = first_ie_value(*request, PfcpIeType::UeIpAddress);
            const auto grouped_ue_mac = first_ie_value(*request, PfcpIeType::UeMac);
            const auto grouped_network_instance = first_ie_value(*request, PfcpIeType::NetworkInstance);
            const auto grouped_snssai = first_ie_value(*request, PfcpIeType::Snssai);
            const auto grouped_qos = first_ie_value(*request, PfcpIeType::QosProfile);
            const auto grouped_access_preferences = first_ie_value(*request, PfcpIeType::AccessPreferences);
            const DecodedFTeid fteid = grouped_fteid.has_value() ? decode_fteid_ie(*grouped_fteid) : DecodedFTeid {};
            state->saw_grouped_contexts = grouped_imsi.has_value() &&
                                          grouped_pdu.has_value() &&
                                          grouped_request_id.has_value() &&
                                          grouped_timeout.has_value() &&
                                          grouped_source_interface.has_value() &&
                                          grouped_fteid.has_value() &&
                                          grouped_ue_ip.has_value() &&
                                          grouped_ue_mac.has_value() &&
                                          grouped_network_instance.has_value() &&
                                          grouped_snssai.has_value() &&
                                          grouped_qos.has_value() &&
                                          grouped_access_preferences.has_value() &&
                                          grouped_source_interface->size() == 1 &&
                                          grouped_source_interface->front() == 0x00U &&
                                          fteid.teid == 0x1100U &&
                                          fteid.ipv4 == "127.0.0.1" &&
                                          decode_ue_ip_address_ie(*grouped_ue_ip, false) == "10.11.0.2" &&
                                          decode_ue_ip_address_ie(*grouped_ue_ip, true) == "2001:db8:11::2" &&
                                          decode_mac_bytes(*grouped_ue_mac) == "02:11:22:33:44:55" &&
                                          std::string(grouped_network_instance->begin(), grouped_network_instance->end()) == "internet" &&
                                          std::string(grouped_snssai->begin(), grouped_snssai->end()) == "1-010203" &&
                                          std::string(grouped_qos->begin(), grouped_qos->end()) == "gold" &&
                                          grouped_access_preferences->size() == 1 &&
                                          grouped_access_preferences->front() == 0x03U;

            const auto far_ies = decode_grouped_ies(*request, PfcpIeType::CreateFar, PfcpIeType::Far);
            const auto qer_ie = decode_grouped_ie(*request, PfcpIeType::CreateQer, PfcpIeType::Qer);
            const auto pdr_ies = decode_grouped_ies(*request, PfcpIeType::CreatePdr, PfcpIeType::Pdr);
            if (far_ies.size() == 3 && has_unique_grouped_rule_identifiers(far_ies) && qer_ie.has_value() && pdr_ies.size() == 3 && has_unique_grouped_rule_identifiers(pdr_ies)) {
                const DecodedQer qer = decode_qer_ie(*qer_ie);
                bool saw_forw_far = false;
                bool saw_buff_far = false;
                bool saw_nocp_far = false;
                for (const auto& far_ie : far_ies) {
                    const DecodedFar far_decoded = decode_far_ie(far_ie);
                    saw_forw_far = saw_forw_far || (far_decoded.id == 1 &&
                                                   far_decoded.action == "FORW" &&
                                                   far_decoded.forward_to == "internet" &&
                                                   far_decoded.header_creation_description == 0x01U &&
                                                   far_decoded.tunnel_peer_ipv4 == "203.0.113.10" &&
                                                   far_decoded.tunnel_peer_teid == 0x0A0B0C01U);
                    saw_buff_far = saw_buff_far || (far_decoded.id == 2 &&
                                                   far_decoded.action == "BUFF" &&
                                                   far_decoded.buffering_duration_ms == 250U);
                    saw_nocp_far = saw_nocp_far || (far_decoded.id == 3 &&
                                                   far_decoded.action == "NOCP" &&
                                                   far_decoded.notify_control_plane);
                }

                bool saw_pdr1 = false;
                bool saw_pdr2 = false;
                bool saw_pdr3 = false;
                for (const auto& pdr_ie : pdr_ies) {
                    const DecodedPdr pdr = decode_pdr_ie(pdr_ie);
                    const bool saw_primary_filter = pdr.sdf_filters.size() >= 1 &&
                                                    pdr.sdf_filters[0].packet_filter_id == 101 &&
                                                    pdr.sdf_filters[0].flow_direction == 0x01U &&
                                                    pdr.sdf_filters[0].flow_description == "permit out udp from 10.11.0.2/32 2152 to assigned 8080" &&
                                                    pdr.sdf_filters[0].protocol_identifier == 17U &&
                                                    pdr.sdf_filters[0].source_port == 2152 &&
                                                    pdr.sdf_filters[0].source_port_end == 2152 &&
                                                    pdr.sdf_filters[0].destination_port == 8080 &&
                                                    pdr.sdf_filters[0].destination_port_end == 8080 &&
                                                    pdr.sdf_filters[0].ether_type == 0x0800U;
                    const bool saw_secondary_filter = pdr.sdf_filters.size() >= 2 &&
                                                      pdr.sdf_filters[1].packet_filter_id == 102 &&
                                                      pdr.sdf_filters[1].flow_direction == 0x02U &&
                                                      pdr.sdf_filters[1].flow_description == "permit in tcp from 10.11.0.2/32 3000-3010 to assigned 443-445" &&
                                                      pdr.sdf_filters[1].protocol_identifier == 6U &&
                                                      pdr.sdf_filters[1].source_port == 3000 &&
                                                      pdr.sdf_filters[1].source_port_end == 3010 &&
                                                      pdr.sdf_filters[1].destination_port == 443 &&
                                                      pdr.sdf_filters[1].destination_port_end == 445 &&
                                                      pdr.sdf_filters[1].ether_type == 0x0800U;

                    saw_pdr1 = saw_pdr1 || (pdr.id == 1 &&
                                            pdr.source_interface == 0x00U &&
                                            pdr.ue_ipv4 == "10.11.0.2" &&
                                            pdr.application_id == "web-browsing" &&
                                            saw_primary_filter &&
                                            saw_secondary_filter &&
                                            pdr.far_id == 1 &&
                                            pdr.qer_id == 1);
                    saw_pdr2 = saw_pdr2 || (pdr.id == 2 &&
                                            pdr.application_id == "buffered-video" &&
                                            pdr.sdf_filters.size() == 1 &&
                                            pdr.sdf_filters[0].packet_filter_id == 201 &&
                                            pdr.sdf_filters[0].protocol_identifier == 17U &&
                                            pdr.sdf_filters[0].source_port == 6000 &&
                                            pdr.sdf_filters[0].source_port_end == 6010 &&
                                            pdr.sdf_filters[0].destination_port == 7000 &&
                                            pdr.sdf_filters[0].destination_port_end == 7010 &&
                                            pdr.far_id == 2);
                    saw_pdr3 = saw_pdr3 || (pdr.id == 3 &&
                                            pdr.application_id == "control-plane-mirror" &&
                                            pdr.sdf_filters.size() == 1 &&
                                            pdr.sdf_filters[0].packet_filter_id == 301 &&
                                            pdr.sdf_filters[0].protocol_identifier == 6U &&
                                            pdr.sdf_filters[0].source_port == 9443 &&
                                            pdr.sdf_filters[0].source_port_end == 9443 &&
                                            pdr.sdf_filters[0].destination_port == 9443 &&
                                            pdr.sdf_filters[0].destination_port_end == 9443 &&
                                            pdr.far_id == 3);
                }

                state->saw_binary_rules = saw_forw_far &&
                                          saw_buff_far &&
                                          saw_nocp_far &&
                                          qer.id == 1 &&
                                          qer.qfi == 9 &&
                                          qer.gate_status == 1 &&
                                          saw_pdr1 &&
                                          saw_pdr2 &&
                                          saw_pdr3;
            }

            if (grouped_request_id.has_value() && std::string(grouped_request_id->begin(), grouped_request_id->end()) == "req-retry") {
                state->retry_request_count++;
                if (state->retry_request_count < 3) {
                    continue;
                }
            }

            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(42, "applied"));
            append_ie_string(&response_ies, PfcpIeType::NodeId, std::string("\x02", 1) + "smf-test-peer");
            append_ie(&response_ies, PfcpIeType::FSeid, std::vector<std::uint8_t> {0x02, 0, 0, 0, 0, 0, 0, 0, 42, 127, 0, 0, 2});
            response_type = PfcpMessageType::SessionEstablishmentResponse;
        }

        const std::string response = encode_pfcp_message(response_type,
                                                         request->has_seid,
                                                         response_ies,
                                                         std::vector<std::uint8_t>(buffer, buffer + recv_len));
        sendto(sock, response.data(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
}

}  // namespace

int main() {
    constexpr int kPort = 39005;
    MockServerState state;
    std::thread server(run_udp_mock_server, kPort, &state);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkN4Adapter n4("127.0.0.1", kPort, 500, "upf-test-node");

    if (!n4.send_heartbeat()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto usage = n4.query_usage_report("001", "1");
    if (!usage.has_value() || usage->bytes_ul != 18 || usage->bytes_dl != 25 || usage->packets_ul != 3 || usage->packets_dl != 3 || usage->urr_reports.size() != 3) {
        server.join();
        return EXIT_FAILURE;
    }
    if (usage->urr_reports[0].urr_id != 1 || usage->urr_reports[0].measurement_method != "VOLUME" || usage->urr_reports[0].reporting_trigger != "PERIODIC" ||
        usage->urr_reports[0].report_cause != upf::UsageReportCause::UsageReady || usage->urr_reports[0].detail != "usage-ready" || usage->urr_reports[1].urr_id != 2 ||
        usage->urr_reports[1].measurement_method != "DURATION" || usage->urr_reports[1].reporting_trigger != "ON_THRESHOLD" ||
        usage->urr_reports[1].report_cause != upf::UsageReportCause::ThresholdReached || usage->urr_reports[1].detail != "threshold-reached" ||
        usage->urr_reports[1].threshold_value.has_value() || usage->urr_reports[1].quota_value.has_value() ||
        usage->urr_reports[2].urr_id != 3 || usage->urr_reports[2].measurement_method != "VOLUME" || usage->urr_reports[2].reporting_trigger != "ON_QUOTA" ||
        usage->urr_reports[2].report_cause != upf::UsageReportCause::QuotaExhausted || usage->urr_reports[2].detail != "quota-exhausted" ||
        usage->urr_reports[2].threshold_value.has_value() || usage->urr_reports[2].quota_value.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto scoped_usage = n4.query_usage_report("001", "1", std::vector<std::uint32_t> {2});
    if (!scoped_usage.has_value() || scoped_usage->bytes_ul != 6 || scoped_usage->bytes_dl != 13 || scoped_usage->packets_ul != 0 || scoped_usage->packets_dl != 1 ||
        scoped_usage->urr_reports.size() != 1 || scoped_usage->urr_reports[0].urr_id != 2 || scoped_usage->urr_reports[0].measurement_method != "DURATION" ||
        scoped_usage->urr_reports[0].reporting_trigger != "ON_THRESHOLD" || scoped_usage->urr_reports[0].report_cause != upf::UsageReportCause::ThresholdReached ||
        scoped_usage->urr_reports[0].detail != "threshold-reached" || scoped_usage->urr_reports[0].threshold_value.has_value() ||
        scoped_usage->urr_reports[0].quota_value.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto quota_usage = n4.query_usage_report("001", "1", std::vector<std::uint32_t> {3});
    if (!quota_usage.has_value() || quota_usage->bytes_ul != 8 || quota_usage->bytes_dl != 5 || quota_usage->packets_ul != 2 || quota_usage->packets_dl != 1 ||
        quota_usage->urr_reports.size() != 1 || quota_usage->urr_reports[0].urr_id != 3 || quota_usage->urr_reports[0].measurement_method != "VOLUME" ||
        quota_usage->urr_reports[0].reporting_trigger != "ON_QUOTA" || quota_usage->urr_reports[0].report_cause != upf::UsageReportCause::QuotaExhausted ||
        quota_usage->urr_reports[0].detail != "quota-exhausted" || quota_usage->urr_reports[0].threshold_value.has_value() ||
        quota_usage->urr_reports[0].quota_value.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest req {};
    req.imsi = "250200123456789";
    req.pdu_session_id = "11";
    req.teid = "0x1100";
    req.ue_ipv4 = "10.11.0.2";
    req.ue_ipv6 = "2001:db8:11::2";
    req.ue_mac = "02:11:22:33:44:55";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.qos_profile = "gold";
    req.prefer_n6_ipv6 = true;
    req.prefer_n6_ethernet = true;
    req.procedure.request_id = "req-retry";
    req.procedure.timeout_ms = 120;
    req.procedure.max_retries = 2;

    upf::PfcpFar far_rule {};
    far_rule.id = 1;
    far_rule.action = "FORW";
    far_rule.forward_to = "internet";
    far_rule.outer_header_creation_description = 0x01U;
    far_rule.tunnel_peer_ipv4 = "203.0.113.10";
    far_rule.tunnel_peer_teid = 0x0A0B0C01U;
    req.rules.fars.push_back(far_rule);

    upf::PfcpFar buffering_far {};
    buffering_far.id = 2;
    buffering_far.action = "BUFF";
    buffering_far.buffering_duration_ms = 250;
    req.rules.fars.push_back(buffering_far);

    upf::PfcpFar nocp_far {};
    nocp_far.id = 3;
    nocp_far.action = "NOCP";
    nocp_far.notify_control_plane = true;
    req.rules.fars.push_back(nocp_far);

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
    pdr.precedence = 200;
    pdr.source_interface = 0x00U;
    pdr.packet_filter_id = 101;
    pdr.application_id = "web-browsing";
    pdr.flow_direction = 0x01U;
    pdr.protocol_identifier = 17U;
    pdr.source_port = 2152;
    pdr.destination_port = 8080;
    pdr.ether_type = 0x0800U;
    pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {101, 0x01U, 17U, 2152, 2152, 8080, 8080, 0x0800U, "permit out udp from 10.11.0.2/32 2152 to assigned 8080"});
    pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {102, 0x02U, 6U, 3000, 3010, 443, 445, 0x0800U, "permit in tcp from 10.11.0.2/32 3000-3010 to assigned 443-445"});
    pdr.far_id = 1;
    pdr.qer_id = 1;
    pdr.urr_id = 1;
    pdr.ue_ipv4 = req.ue_ipv4;
    req.rules.pdrs.push_back(pdr);

    upf::PfcpPdr buffered_pdr {};
    buffered_pdr.id = 2;
    buffered_pdr.precedence = 180;
    buffered_pdr.source_interface = 0x00U;
    buffered_pdr.ue_ipv4 = req.ue_ipv4;
    buffered_pdr.application_id = "buffered-video";
    buffered_pdr.packet_filter_id = 201;
    buffered_pdr.flow_direction = 0x01U;
    buffered_pdr.protocol_identifier = 17U;
    buffered_pdr.source_port = 6000;
    buffered_pdr.destination_port = 7000;
    buffered_pdr.ether_type = 0x0800U;
    buffered_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {201, 0x01U, 17U, 6000, 6010, 7000, 7010, 0x0800U, "permit out udp from 10.11.0.2/32 6000-6010 to assigned 7000-7010"});
    buffered_pdr.far_id = 2;
    buffered_pdr.qer_id = 1;
    buffered_pdr.urr_id = 1;
    req.rules.pdrs.push_back(buffered_pdr);

    upf::PfcpPdr nocp_pdr {};
    nocp_pdr.id = 3;
    nocp_pdr.precedence = 160;
    nocp_pdr.source_interface = 0x00U;
    nocp_pdr.ue_ipv4 = req.ue_ipv4;
    nocp_pdr.application_id = "control-plane-mirror";
    nocp_pdr.packet_filter_id = 301;
    nocp_pdr.flow_direction = 0x02U;
    nocp_pdr.protocol_identifier = 6U;
    nocp_pdr.source_port = 9443;
    nocp_pdr.destination_port = 9443;
    nocp_pdr.ether_type = 0x0800U;
    nocp_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {301, 0x02U, 6U, 9443, 9443, 9443, 9443, 0x0800U, "permit in tcp from 10.11.0.2/32 9443 to assigned 9443"});
    nocp_pdr.far_id = 3;
    nocp_pdr.qer_id = 1;
    nocp_pdr.urr_id = 1;
    req.rules.pdrs.push_back(nocp_pdr);

    const auto response = n4.apply_pfcp(req, upf::PfcpOperation::Establish);
    if (!response.success || response.cause != upf::PfcpCause::RequestAccepted || response.session_version != 42 || response.detail != "PFCP request accepted") {
        server.join();
        return EXIT_FAILURE;
    }

    if (!state.saw_association_setup || !state.saw_capability_exchange || !state.saw_node_features || !state.saw_recovery_time_stamp || !state.saw_node_id || !state.saw_fseid || !state.saw_grouped_contexts || !state.saw_binary_rules || state.retry_request_count < 3) {
        server.join();
        return EXIT_FAILURE;
    }

    server.join();
    return EXIT_SUCCESS;
}
