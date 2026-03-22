#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "pfcp_test_wire.hpp"
#include "pfcp_usage_report_test_utils.hpp"
#include "upf/adapters/network_adapters.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
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

std::vector<std::uint8_t> encode_response_context(std::uint64_t session_version, const std::string& detail) {
    return test_pfcp::encode_response_context(1, detail, session_version);
}

std::vector<std::uint8_t> encode_response_context_bad_order(const std::string& detail) {
    return test_pfcp::encode_response_context_bad_order(1, detail);
}

std::vector<std::uint8_t> encode_response_context_duplicate_cause(const std::string& detail) {
    return test_pfcp::encode_response_context_duplicate_cause(1, detail);
}

std::vector<std::uint8_t> encode_association_context_response(bool include_recovery_time_stamp) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries {
        {PfcpIeType::NodeId, encode_node_id_value("smf-peer")},
        {PfcpIeType::FSeid, encode_fseid_value(1, "127.0.0.2")},
    };
    if (include_recovery_time_stamp) {
        std::vector<std::uint8_t> recovery_value;
        append_u32(&recovery_value, 1);
        entries.push_back({PfcpIeType::RecoveryTimeStamp, recovery_value});
    }
    return encode_grouped_value(entries);
}

std::vector<std::uint8_t> encode_capability_context_response(bool include_feature_bitmap) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries {
        {PfcpIeType::NodeId, encode_node_id_value("smf-peer")},
        {PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2")},
    };
    if (include_feature_bitmap) {
        std::vector<std::uint8_t> bitmap_value;
        append_u32(&bitmap_value, 0x0000000FU);
        entries.push_back({PfcpIeType::FeatureBitmap, bitmap_value});
    }
    return encode_grouped_value(entries);
}

std::vector<std::uint8_t> encode_node_feature_context_response(bool include_feature_bitmap) {
    std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>> entries {
        {PfcpIeType::NodeId, encode_node_id_value("smf-peer")},
    };
    if (include_feature_bitmap) {
        std::vector<std::uint8_t> bitmap_value;
        append_u32(&bitmap_value, 0x00000007U);
        entries.push_back({PfcpIeType::FeatureBitmap, bitmap_value});
    }
    return encode_grouped_value(entries);
}

std::optional<std::vector<std::uint8_t>> first_grouped_entry(const std::vector<std::uint8_t>& grouped_value, PfcpIeType type) {
    return test_pfcp::find_grouped_entry(grouped_value, type);
}

std::vector<std::vector<std::uint8_t>> all_grouped_entries(const std::vector<std::uint8_t>& grouped_value, PfcpIeType type) {
    return test_pfcp::find_grouped_entries(grouped_value, type);
}

struct ParsedRequest {
    PfcpMessageType message_type {PfcpMessageType::AssociationSetupRequest};
    bool has_seid {false};
    std::uint64_t seid {0};
    std::uint32_t sequence {0};
    std::string request_id;
    std::string pdu_session_id;
    std::vector<std::uint32_t> requested_rule_ids;
};

enum class BootstrapResponseMode {
    Normal,
    MissingAssociationContext,
    MissingAssociationRecoveryTimeStamp,
    MissingCapabilityFeatureBitmap,
    MissingNodeFeatureBitmap,
};

struct MockServerState {
    int session_response_count {0};
    BootstrapResponseMode bootstrap_response_mode {BootstrapResponseMode::Normal};
};

std::optional<ParsedRequest> decode_request(const char* bytes, int recv_len) {
    if (recv_len < 8) {
        return std::nullopt;
    }
    const std::vector<std::uint8_t> buffer(bytes, bytes + recv_len);
    const bool has_seid = (buffer[0] & 0x08U) != 0;
    const std::size_t header_size = has_seid ? 16U : 8U;
    if (buffer.size() < header_size || buffer.size() != static_cast<std::size_t>(read_u16(buffer, 2)) + 4U) {
        return std::nullopt;
    }
    ParsedRequest parsed {};
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
        if (ie_type == static_cast<std::uint16_t>(PfcpIeType::RequestId)) {
            parsed.request_id.assign(buffer.begin() + static_cast<std::ptrdiff_t>(cursor),
                                     buffer.begin() + static_cast<std::ptrdiff_t>(cursor + ie_length));
        } else if (ie_type == static_cast<std::uint16_t>(PfcpIeType::PduSessionId)) {
            parsed.pdu_session_id.assign(buffer.begin() + static_cast<std::ptrdiff_t>(cursor),
                                         buffer.begin() + static_cast<std::ptrdiff_t>(cursor + ie_length));
        } else if (ie_type == static_cast<std::uint16_t>(PfcpIeType::UsageQueryContext)) {
            const std::vector<std::uint8_t> grouped(buffer.begin() + static_cast<std::ptrdiff_t>(cursor),
                                                    buffer.begin() + static_cast<std::ptrdiff_t>(cursor + ie_length));
            for (const auto& rule_id : all_grouped_entries(grouped, PfcpIeType::UrrId)) {
                if (rule_id.size() == 4) {
                    parsed.requested_rule_ids.push_back(read_u32(rule_id, 0));
                }
            }
        }
        cursor += ie_length;
    }
    return parsed;
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

        const auto request = decode_request(buffer, recv_len);
        if (!request.has_value()) {
            continue;
        }

        std::vector<std::uint8_t> ies;
        PfcpMessageType response_type = PfcpMessageType::AssociationSetupResponse;
        bool has_seid = false;
        std::uint64_t seid = 0;
        std::uint32_t sequence = request->sequence;

        if (request->message_type == PfcpMessageType::AssociationSetupRequest) {
            response_type = PfcpMessageType::AssociationSetupResponse;
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(1, "ok"));
            if (state->bootstrap_response_mode != BootstrapResponseMode::MissingAssociationContext) {
                append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
                append_ie(&ies, PfcpIeType::FSeid, encode_fseid_value(1, "127.0.0.2"));
                if (state->bootstrap_response_mode != BootstrapResponseMode::MissingAssociationRecoveryTimeStamp) {
                    append_ie(&ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(1));
                }
            }
        } else if (request->message_type == PfcpMessageType::CapabilityExchangeRequest) {
            response_type = PfcpMessageType::CapabilityExchangeResponse;
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(2, "ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&ies, PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2"));
            if (state->bootstrap_response_mode != BootstrapResponseMode::MissingCapabilityFeatureBitmap) {
                append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x0000000FU));
            }
        } else if (request->message_type == PfcpMessageType::NodeFeaturesRequest) {
            response_type = PfcpMessageType::NodeFeaturesResponse;
            append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(3, "ok"));
            append_ie(&ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            if (state->bootstrap_response_mode != BootstrapResponseMode::MissingNodeFeatureBitmap) {
                append_ie(&ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x00000007U));
            }
        } else if (request->message_type == PfcpMessageType::SessionEstablishmentRequest) {
            response_type = PfcpMessageType::SessionEstablishmentResponse;
            has_seid = true;
            seid = request->seid;
            if (request->request_id == "bad-response-order") {
                append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context_bad_order("bad-order"));
            } else if (request->request_id == "duplicate-response-cause") {
                append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context_duplicate_cause("duplicate-cause"));
            } else {
                append_ie(&ies, PfcpIeType::ResponseContext, encode_response_context(1, "ok"));
                state->session_response_count++;
                if (state->session_response_count == 1) {
                    sequence = request->sequence + 1U;
                } else if (state->session_response_count == 2) {
                    seid = request->seid + 1U;
                } else {
                    response_type = PfcpMessageType::SessionModificationResponse;
                }
            }
        } else if (request->message_type == PfcpMessageType::SessionReportRequest) {
            response_type = PfcpMessageType::SessionReportResponse;
            has_seid = true;
            seid = request->seid;
            const bool scoped_request_for_rule_1_only = request->pdu_session_id == "94" && request->requested_rule_ids.size() == 1 && request->requested_rule_ids[0] == 1;
            const bool unknown_usage_cause = request->pdu_session_id == "95";
            const bool duplicate_usage_measurement = request->pdu_session_id == "96";
            const bool invalid_usage_order = request->pdu_session_id == "97";
            const bool duplicate_usage_bytes_ul = request->pdu_session_id == "98";
            std::vector<std::uint8_t> usage_context_1;
            if (invalid_usage_order) {
                append_ie(&usage_context_1, PfcpIeType::UrrId, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x01});
                append_ie(&usage_context_1, PfcpIeType::Cause, std::vector<std::uint8_t> {1});
                append_ie(&usage_context_1, PfcpIeType::MeasurementMethodValue, std::vector<std::uint8_t> {'V', 'O', 'L', 'U', 'M', 'E'});
                append_ie(&usage_context_1, PfcpIeType::ReportingTriggerValue, std::vector<std::uint8_t> {'P', 'E', 'R', 'I', 'O', 'D', 'I', 'C'});
                append_ie(&usage_context_1, PfcpIeType::BytesUl, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04});
                append_ie(&usage_context_1, PfcpIeType::BytesDl, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07});
                append_ie(&usage_context_1, PfcpIeType::PacketsUl, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
                append_ie(&usage_context_1, PfcpIeType::PacketsDl, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
            } else if (duplicate_usage_measurement) {
                usage_context_1 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                    1,
                    "VOLUME",
                    "PERIODIC",
                    1,
                    std::string("usage-1"),
                    std::nullopt,
                    std::nullopt,
                    4,
                    7,
                    1,
                    1,
                });
                append_ie(&usage_context_1, PfcpIeType::MeasurementMethodValue, std::vector<std::uint8_t> {'D', 'U', 'P'});
            } else {
                usage_context_1 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                    1,
                    "VOLUME",
                    "PERIODIC",
                    static_cast<std::uint8_t>(unknown_usage_cause ? 0x7F : 1),
                    std::string("usage-1"),
                    std::nullopt,
                    std::nullopt,
                    4,
                    7,
                    1,
                    1,
                });
                if (duplicate_usage_bytes_ul) {
                    append_ie(&usage_context_1, PfcpIeType::BytesUl, std::vector<std::uint8_t> {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09});
                }
            }
            append_ie(&ies, PfcpIeType::UsageReportContext, usage_context_1);
            const auto usage_context_2 = test_pfcp::encode_usage_report_context(test_pfcp::UsageReportContextSpec {
                scoped_request_for_rule_1_only ? 2U : 1U,
                "DURATION",
                "ON_THRESHOLD",
                2,
                std::string("usage-2"),
                4096,
                std::nullopt,
                6,
                13,
                0,
                1,
            });
            if (!unknown_usage_cause && !duplicate_usage_measurement && !invalid_usage_order && !duplicate_usage_bytes_ul) {
                append_ie(&ies, PfcpIeType::UsageReportContext, usage_context_2);
            }
        } else {
            continue;
        }

        const std::string response = (request->message_type == PfcpMessageType::AssociationSetupRequest ||
                                      request->message_type == PfcpMessageType::CapabilityExchangeRequest ||
                                      request->message_type == PfcpMessageType::NodeFeaturesRequest)
            ? encode_pfcp_message(response_type,
                                  has_seid,
                                  ies,
                                  std::vector<std::uint8_t>(buffer, buffer + recv_len))
            : encode_pfcp_message(response_type, has_seid, seid, sequence, ies);
        sendto(sock, response.data(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
}

upf::PfcpSessionRequest make_request(const std::string& request_id) {
    upf::PfcpSessionRequest request {};
    request.imsi = "250200999999999";
    request.pdu_session_id = request_id == "bad-seid" ? "92" : (request_id == "bad-type" ? "93" : "91");
    request.teid = "0x9100";
    request.ue_ipv4 = "10.91.0.2";
    request.ue_ipv6 = "2001:db8:91::2";
    request.ue_mac = "02:91:00:00:00:02";
    request.dnn = "internet";
    request.s_nssai = "1-010203";
    request.qos_profile = "gold";
    request.prefer_n6_ipv6 = true;
    request.prefer_n6_ethernet = true;
    request.procedure.request_id = request_id;

    upf::PfcpFar far_rule {};
    far_rule.id = 1;
    far_rule.action = "FORW";
    far_rule.forward_to = "internet";
    far_rule.outer_header_creation_description = 0x01U;
    far_rule.tunnel_peer_ipv4 = "203.0.113.30";
    far_rule.tunnel_peer_teid = 0x0A0B0C03U;
    request.rules.fars.push_back(far_rule);

    upf::PfcpUrr urr_rule {};
    urr_rule.id = 1;
    urr_rule.measurement_method = "VOLUME";
    urr_rule.trigger = "PERIODIC";
    request.rules.urrs.push_back(urr_rule);

    upf::PfcpQer qer_rule {};
    qer_rule.id = 1;
    qer_rule.qfi = 9;
    qer_rule.gate_status = "OPEN";
    qer_rule.gbr_ul_kbps = 100;
    qer_rule.gbr_dl_kbps = 100;
    qer_rule.mbr_ul_kbps = 200;
    qer_rule.mbr_dl_kbps = 200;
    request.rules.qers.push_back(qer_rule);

    upf::PfcpPdr pdr_rule {};
    pdr_rule.id = 1;
    pdr_rule.precedence = 200;
    pdr_rule.source_interface = 0x00U;
    pdr_rule.ue_ipv4 = request.ue_ipv4;
    pdr_rule.application_id = "web-browsing";
    pdr_rule.packet_filter_id = 101;
    pdr_rule.flow_direction = 0x01U;
    pdr_rule.protocol_identifier = 17U;
    pdr_rule.source_port = 2152;
    pdr_rule.destination_port = 8080;
    pdr_rule.ether_type = 0x0800U;
    pdr_rule.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {101, 0x01U, 17U, 2152, 2152, 8080, 8080, 0x0800U, "permit out udp from 10.91.0.2/32 2152 to assigned 8080"});
    pdr_rule.far_id = 1;
    pdr_rule.qer_id = 1;
    pdr_rule.urr_id = 1;
    request.rules.pdrs.push_back(pdr_rule);
    return request;
}

}  // namespace

int main() {
    constexpr int kPort = 39007;
    const auto expect_bootstrap_failure = [](int port, BootstrapResponseMode mode) {
        MockServerState bootstrap_state;
        bootstrap_state.bootstrap_response_mode = mode;
        std::thread bootstrap_server(run_udp_mock_server, port, &bootstrap_state);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));

        upf::NetworkN4Adapter bootstrap_n4("127.0.0.1", port, 500, "upf-test-node");
        const auto response = bootstrap_n4.apply_pfcp(make_request("bootstrap-failure"), upf::PfcpOperation::Establish);
        bootstrap_server.join();
        return !response.success && response.detail == "PFCP association setup failed";
    };

    if (!expect_bootstrap_failure(kPort + 1, BootstrapResponseMode::MissingAssociationContext) ||
        !expect_bootstrap_failure(kPort + 2, BootstrapResponseMode::MissingAssociationRecoveryTimeStamp) ||
        !expect_bootstrap_failure(kPort + 3, BootstrapResponseMode::MissingCapabilityFeatureBitmap) ||
        !expect_bootstrap_failure(kPort + 4, BootstrapResponseMode::MissingNodeFeatureBitmap)) {
        return EXIT_FAILURE;
    }

    MockServerState state;
    std::thread server(run_udp_mock_server, kPort, &state);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkN4Adapter n4("127.0.0.1", kPort, 500, "upf-test-node");

    const auto bad_sequence = n4.apply_pfcp(make_request("bad-sequence"), upf::PfcpOperation::Establish);
    if (bad_sequence.success || bad_sequence.detail != "Unexpected PFCP sequence") {
        server.join();
        return EXIT_FAILURE;
    }

    const auto bad_seid = n4.apply_pfcp(make_request("bad-seid"), upf::PfcpOperation::Establish);
    if (bad_seid.success || bad_seid.detail != "Unexpected PFCP SEID") {
        server.join();
        return EXIT_FAILURE;
    }

    const auto bad_type = n4.apply_pfcp(make_request("bad-type"), upf::PfcpOperation::Establish);
    if (bad_type.success || bad_type.detail != "Unexpected PFCP message type") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest missing_profile = make_request("missing-profile");
    missing_profile.dnn.clear();
    const auto missing_profile_response = n4.apply_pfcp(missing_profile, upf::PfcpOperation::Establish);
    if (missing_profile_response.success || missing_profile_response.detail != "Missing session profile IE") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest missing_identity = make_request("missing-identity");
    missing_identity.ue_ipv4.clear();
    missing_identity.ue_ipv6.clear();
    missing_identity.ue_mac.clear();
    const auto missing_identity_response = n4.apply_pfcp(missing_identity, upf::PfcpOperation::Establish);
    if (missing_identity_response.success || missing_identity_response.detail != "Missing UE access identity") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_teid = make_request("invalid-teid");
    invalid_teid.teid = "not-a-teid";
    const auto invalid_teid_response = n4.apply_pfcp(invalid_teid, upf::PfcpOperation::Establish);
    if (invalid_teid_response.success || invalid_teid_response.detail != "Invalid TEID") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_ipv6 = make_request("invalid-ipv6");
    invalid_ipv6.ue_ipv6 = "bad::ipv6::addr";
    const auto invalid_ipv6_response = n4.apply_pfcp(invalid_ipv6, upf::PfcpOperation::Establish);
    if (invalid_ipv6_response.success || invalid_ipv6_response.detail != "Invalid UE IPv6") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_mac = make_request("invalid-mac");
    invalid_mac.ue_mac = "02:91:00:00:ZZ:02";
    const auto invalid_mac_response = n4.apply_pfcp(invalid_mac, upf::PfcpOperation::Establish);
    if (invalid_mac_response.success || invalid_mac_response.detail != "Invalid UE MAC") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_tunnel_peer_ip = make_request("invalid-tunnel-peer-ip");
    invalid_tunnel_peer_ip.rules.fars[0].tunnel_peer_ipv4 = "bad-ipv4";
    const auto invalid_tunnel_peer_ip_response = n4.apply_pfcp(invalid_tunnel_peer_ip, upf::PfcpOperation::Establish);
    if (invalid_tunnel_peer_ip_response.success || invalid_tunnel_peer_ip_response.detail != "Invalid FAR tunnel peer IPv4") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest missing_tunnel_peer_ip = make_request("missing-tunnel-peer-ip");
    missing_tunnel_peer_ip.rules.fars[0].tunnel_peer_ipv4.clear();
    const auto missing_tunnel_peer_ip_response = n4.apply_pfcp(missing_tunnel_peer_ip, upf::PfcpOperation::Establish);
    if (missing_tunnel_peer_ip_response.success || missing_tunnel_peer_ip_response.detail != "Invalid FAR tunnel peer IPv4") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_tunnel_peer_teid = make_request("invalid-tunnel-peer-teid");
    invalid_tunnel_peer_teid.rules.fars[0].tunnel_peer_teid = 0;
    const auto invalid_tunnel_peer_teid_response = n4.apply_pfcp(invalid_tunnel_peer_teid, upf::PfcpOperation::Establish);
    if (invalid_tunnel_peer_teid_response.success || invalid_tunnel_peer_teid_response.detail != "Invalid FAR tunnel peer TEID") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_protocol = make_request("invalid-protocol");
    invalid_protocol.rules.pdrs[0].protocol_identifier = 1;
    invalid_protocol.rules.pdrs[0].sdf_filters[0].protocol_identifier = 1;
    const auto invalid_protocol_response = n4.apply_pfcp(invalid_protocol, upf::PfcpOperation::Establish);
    if (invalid_protocol_response.success || invalid_protocol_response.detail != "Invalid PDR protocol identifier") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_port_protocol = make_request("invalid-port-protocol");
    invalid_port_protocol.rules.pdrs[0].protocol_identifier = 0;
    invalid_port_protocol.rules.pdrs[0].sdf_filters[0].protocol_identifier = 0;
    const auto invalid_port_protocol_response = n4.apply_pfcp(invalid_port_protocol, upf::PfcpOperation::Establish);
    if (invalid_port_protocol_response.success || invalid_port_protocol_response.detail != "PDR ports require TCP or UDP protocol") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_ether_type = make_request("invalid-ether-type");
    invalid_ether_type.rules.pdrs[0].ether_type = 0x1234U;
    invalid_ether_type.rules.pdrs[0].sdf_filters[0].ether_type = 0x1234U;
    const auto invalid_ether_type_response = n4.apply_pfcp(invalid_ether_type, upf::PfcpOperation::Establish);
    if (invalid_ether_type_response.success || invalid_ether_type_response.detail != "Invalid PDR ether type") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_precedence = make_request("invalid-precedence");
    invalid_precedence.rules.pdrs[0].precedence = 0;
    const auto invalid_precedence_response = n4.apply_pfcp(invalid_precedence, upf::PfcpOperation::Establish);
    if (invalid_precedence_response.success || invalid_precedence_response.detail != "Invalid PDR precedence") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest duplicate_precedence = make_request("duplicate-precedence");
    upf::PfcpPdr duplicate_precedence_pdr = duplicate_precedence.rules.pdrs.front();
    duplicate_precedence_pdr.id = 2;
    duplicate_precedence_pdr.packet_filter_id = 102;
    duplicate_precedence_pdr.sdf_filters[0].packet_filter_id = 102;
    duplicate_precedence_pdr.sdf_filters[0].destination_port = 8081;
    duplicate_precedence_pdr.sdf_filters[0].destination_port_end = 8081;
    duplicate_precedence_pdr.destination_port = 8081;
    duplicate_precedence_pdr.flow_description = "permit out udp from 10.91.0.2/32 2152 to assigned 8081";
    duplicate_precedence_pdr.sdf_filters[0].flow_description = duplicate_precedence_pdr.flow_description;
    duplicate_precedence.rules.pdrs.push_back(duplicate_precedence_pdr);
    const auto duplicate_precedence_response = n4.apply_pfcp(duplicate_precedence, upf::PfcpOperation::Establish);
    if (duplicate_precedence_response.success || duplicate_precedence_response.detail != "Duplicate PDR precedence") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_source_port_range = make_request("invalid-source-port-range");
    invalid_source_port_range.rules.pdrs[0].source_port = 4000;
    invalid_source_port_range.rules.pdrs[0].sdf_filters[0].source_port = 4000;
    invalid_source_port_range.rules.pdrs[0].sdf_filters[0].source_port_end = 3999;
    const auto invalid_source_port_range_response = n4.apply_pfcp(invalid_source_port_range, upf::PfcpOperation::Establish);
    if (invalid_source_port_range_response.success || invalid_source_port_range_response.detail != "Invalid PDR source port range") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_destination_port_range = make_request("invalid-destination-port-range");
    invalid_destination_port_range.rules.pdrs[0].destination_port = 9000;
    invalid_destination_port_range.rules.pdrs[0].sdf_filters[0].destination_port = 9000;
    invalid_destination_port_range.rules.pdrs[0].sdf_filters[0].destination_port_end = 8999;
    const auto invalid_destination_port_range_response = n4.apply_pfcp(invalid_destination_port_range, upf::PfcpOperation::Establish);
    if (invalid_destination_port_range_response.success || invalid_destination_port_range_response.detail != "Invalid PDR destination port range") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest conflicting_legacy_structured = make_request("conflicting-legacy-structured");
    conflicting_legacy_structured.rules.pdrs[0].packet_filter_id = 999;
    const auto conflicting_legacy_structured_response = n4.apply_pfcp(conflicting_legacy_structured, upf::PfcpOperation::Establish);
    if (conflicting_legacy_structured_response.success || conflicting_legacy_structured_response.detail != "Conflicting legacy and structured PDR filter fields") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest duplicate_far_id = make_request("duplicate-far-id");
    duplicate_far_id.rules.fars.push_back(duplicate_far_id.rules.fars.front());
    const auto duplicate_far_id_response = n4.apply_pfcp(duplicate_far_id, upf::PfcpOperation::Establish);
    if (duplicate_far_id_response.success || duplicate_far_id_response.detail != "Duplicate FAR ID") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest duplicate_pdr_id = make_request("duplicate-pdr-id");
    duplicate_pdr_id.rules.pdrs.push_back(duplicate_pdr_id.rules.pdrs.front());
    const auto duplicate_pdr_id_response = n4.apply_pfcp(duplicate_pdr_id, upf::PfcpOperation::Establish);
    if (duplicate_pdr_id_response.success || duplicate_pdr_id_response.detail != "Duplicate PDR ID") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_buffer_far = make_request("invalid-buffer-far");
    invalid_buffer_far.rules.fars[0].action = "BUFF";
    invalid_buffer_far.rules.fars[0].forward_to.clear();
    invalid_buffer_far.rules.fars[0].tunnel_peer_ipv4.clear();
    invalid_buffer_far.rules.fars[0].tunnel_peer_teid = 0;
    const auto invalid_buffer_far_response = n4.apply_pfcp(invalid_buffer_far, upf::PfcpOperation::Establish);
    if (invalid_buffer_far_response.success || invalid_buffer_far_response.detail != "Invalid FAR buffering duration") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_nocp_far = make_request("invalid-nocp-far");
    invalid_nocp_far.rules.fars[0].action = "NOCP";
    invalid_nocp_far.rules.fars[0].forward_to.clear();
    invalid_nocp_far.rules.fars[0].tunnel_peer_ipv4.clear();
    invalid_nocp_far.rules.fars[0].tunnel_peer_teid = 0;
    const auto invalid_nocp_far_response = n4.apply_pfcp(invalid_nocp_far, upf::PfcpOperation::Establish);
    if (invalid_nocp_far_response.success || invalid_nocp_far_response.detail != "Invalid FAR notify control plane flag") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest invalid_drop_far = make_request("invalid-drop-far");
    invalid_drop_far.rules.fars[0].action = "DROP";
    const auto invalid_drop_far_response = n4.apply_pfcp(invalid_drop_far, upf::PfcpOperation::Establish);
    if (invalid_drop_far_response.success || invalid_drop_far_response.detail != "DROP FAR must not carry forwarding, buffering, or notification parameters") {
        server.join();
        return EXIT_FAILURE;
    }

    const auto bad_response_order = n4.apply_pfcp(make_request("bad-response-order"), upf::PfcpOperation::Establish);
    if (bad_response_order.success || bad_response_order.detail != "Invalid PFCP response context") {
        server.join();
        return EXIT_FAILURE;
    }

    const auto duplicate_response_cause = n4.apply_pfcp(make_request("duplicate-response-cause"), upf::PfcpOperation::Establish);
    if (duplicate_response_cause.success || duplicate_response_cause.detail != "Invalid PFCP response context") {
        server.join();
        return EXIT_FAILURE;
    }

    const auto duplicate_usage_report = n4.query_usage_report("250200999999999", "91");
    if (duplicate_usage_report.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto scoped_usage_with_unexpected_urr = n4.query_usage_report("250200999999999", "94", std::vector<std::uint32_t> {1});
    if (scoped_usage_with_unexpected_urr.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto unknown_usage_cause = n4.query_usage_report("250200999999999", "95");
    if (unknown_usage_cause.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto duplicate_usage_measurement = n4.query_usage_report("250200999999999", "96");
    if (duplicate_usage_measurement.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto invalid_usage_order = n4.query_usage_report("250200999999999", "97");
    if (invalid_usage_order.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    const auto duplicate_usage_bytes_ul = n4.query_usage_report("250200999999999", "98");
    if (duplicate_usage_bytes_ul.has_value()) {
        server.join();
        return EXIT_FAILURE;
    }

    server.join();
    return EXIT_SUCCESS;
}