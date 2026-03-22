#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
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
    bool saw_establish_message {false};
    bool saw_modify_message {false};
    bool saw_delete_message {false};
    bool saw_grouped_session_context {false};
    bool saw_modify_grouped_rules {false};
    bool saw_modify_rule_replacement {false};
    bool saw_delete_without_rules {false};
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

std::vector<std::uint8_t> encode_response_context(std::uint64_t session_version, const std::string& detail) {
    std::vector<std::uint8_t> grouped;
    (void)detail;
    append_ie(&grouped, PfcpIeType::Cause, std::vector<std::uint8_t> {1});
    append_ie_u32(&grouped, PfcpIeType::SessionVersion, static_cast<std::uint32_t>(session_version));
    return grouped;
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
    for (int i = 0; i < 24 && idle_polls < 8; ++i) {
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
        PfcpMessageType response_type = PfcpMessageType::SessionEstablishmentResponse;

        if (request->message_type == PfcpMessageType::AssociationSetupRequest) {
            state->saw_association_setup = first_ie_value(*request, PfcpIeType::NodeId).has_value() &&
                                           first_ie_value(*request, PfcpIeType::FSeid).has_value() &&
                                           first_ie_value(*request, PfcpIeType::RecoveryTimeStamp).has_value();
            response_type = PfcpMessageType::AssociationSetupResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(99, "associated"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FSeid, encode_fseid_value(1, "127.0.0.2"));
            append_ie(&response_ies, PfcpIeType::RecoveryTimeStamp, encode_recovery_time_stamp_ie_value(1));
        } else if (request->message_type == PfcpMessageType::CapabilityExchangeRequest) {
            state->saw_capability_exchange = first_ie_value(*request, PfcpIeType::NodeId).has_value() &&
                                            first_ie_value(*request, PfcpIeType::FSeid).has_value() &&
                                            first_ie_value(*request, PfcpIeType::FeatureBitmap).has_value();
            response_type = PfcpMessageType::CapabilityExchangeResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(100, "capabilities-ok"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FSeid, encode_fseid_value(2, "127.0.0.2"));
            append_ie(&response_ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x0000000FU));
        } else if (request->message_type == PfcpMessageType::NodeFeaturesRequest) {
            state->saw_node_features = first_ie_value(*request, PfcpIeType::NodeId).has_value() &&
                                       first_ie_value(*request, PfcpIeType::FeatureBitmap).has_value();
            response_type = PfcpMessageType::NodeFeaturesResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(101, "node-features-ok"));
            append_ie(&response_ies, PfcpIeType::NodeId, encode_node_id_value("smf-peer"));
            append_ie(&response_ies, PfcpIeType::FeatureBitmap, upf::pfcp::encode_u32_value(0x00000007U));
        } else if (request->message_type == PfcpMessageType::SessionEstablishmentRequest) {
            state->saw_establish_message = true;
            const auto source_interface = first_ie_value(*request, PfcpIeType::SourceInterface);
            const auto fteid = first_ie_value(*request, PfcpIeType::FTeid);
            const auto ue_ip = first_ie_value(*request, PfcpIeType::UeIpAddress);
            const auto ue_mac = first_ie_value(*request, PfcpIeType::UeMac);
            const auto network_instance = first_ie_value(*request, PfcpIeType::NetworkInstance);
            const auto snssai = first_ie_value(*request, PfcpIeType::Snssai);
            const auto qos = first_ie_value(*request, PfcpIeType::QosProfile);
            const auto access_preferences = first_ie_value(*request, PfcpIeType::AccessPreferences);
            const DecodedFTeid decoded_fteid = fteid.has_value() ? decode_fteid_ie(*fteid) : DecodedFTeid {};
            state->saw_grouped_session_context = first_ie_value(*request, PfcpIeType::Imsi).has_value() &&
                                                first_ie_value(*request, PfcpIeType::PduSessionId).has_value() &&
                                                first_ie_value(*request, PfcpIeType::RequestId).has_value() &&
                                                first_ie_value(*request, PfcpIeType::NodeId).has_value() &&
                                                first_ie_value(*request, PfcpIeType::FSeid).has_value() &&
                                                source_interface.has_value() &&
                                                source_interface->size() == 1 &&
                                                source_interface->front() == 0x00U &&
                                                fteid.has_value() &&
                                                decoded_fteid.teid == 0x1700U &&
                                                decoded_fteid.ipv4 == "127.0.0.1" &&
                                                ue_ip.has_value() &&
                                                decode_ue_ip_address_ie(*ue_ip, false) == "10.17.0.2" &&
                                                decode_ue_ip_address_ie(*ue_ip, true) == "2001:db8:17::2" &&
                                                ue_mac.has_value() &&
                                                decode_mac_bytes(*ue_mac) == "02:17:00:00:00:02" &&
                                                network_instance.has_value() &&
                                                std::string(network_instance->begin(), network_instance->end()) == "internet" &&
                                                snssai.has_value() &&
                                                std::string(snssai->begin(), snssai->end()) == "1-010203" &&
                                                qos.has_value() &&
                                                std::string(qos->begin(), qos->end()) == "gold" &&
                                                access_preferences.has_value() &&
                                                access_preferences->size() == 1 &&
                                                access_preferences->front() == 0x03U;
            response_type = PfcpMessageType::SessionEstablishmentResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(200, "established"));
        } else if (request->message_type == PfcpMessageType::SessionModificationRequest) {
            state->saw_modify_message = true;
            const auto update_far_ies = decode_grouped_ies(*request, PfcpIeType::UpdateFar, PfcpIeType::Far);
            const auto create_far_ies = decode_grouped_ies(*request, PfcpIeType::CreateFar, PfcpIeType::Far);
            const auto remove_far_ies = decode_grouped_ies(*request, PfcpIeType::RemoveFar, PfcpIeType::Far);
            const auto update_qer_ies = decode_grouped_ies(*request, PfcpIeType::UpdateQer, PfcpIeType::Qer);
            const auto create_qer_ies = decode_grouped_ies(*request, PfcpIeType::CreateQer, PfcpIeType::Qer);
            const auto remove_qer_ies = decode_grouped_ies(*request, PfcpIeType::RemoveQer, PfcpIeType::Qer);
            const auto update_urr_ies = decode_grouped_ies(*request, PfcpIeType::UpdateUrr, PfcpIeType::Urr);
            const auto create_urr_ies = decode_grouped_ies(*request, PfcpIeType::CreateUrr, PfcpIeType::Urr);
            const auto remove_urr_ies = decode_grouped_ies(*request, PfcpIeType::RemoveUrr, PfcpIeType::Urr);
            const auto update_pdr_ies = decode_grouped_ies(*request, PfcpIeType::UpdatePdr, PfcpIeType::Pdr);
            const auto create_pdr_ies = decode_grouped_ies(*request, PfcpIeType::CreatePdr, PfcpIeType::Pdr);
            const auto remove_pdr_ies = decode_grouped_ies(*request, PfcpIeType::RemovePdr, PfcpIeType::Pdr);
            if (update_far_ies.size() == 1 && create_far_ies.size() == 2 && remove_far_ies.size() == 2 &&
                create_qer_ies.size() == 1 && remove_qer_ies.size() == 1 && update_qer_ies.empty() &&
                create_urr_ies.size() == 1 && remove_urr_ies.size() == 1 && update_urr_ies.empty() &&
                update_pdr_ies.size() == 1 && create_pdr_ies.size() == 2 && remove_pdr_ies.size() == 2 &&
                has_unique_grouped_rule_identifiers(update_far_ies) &&
                has_unique_grouped_rule_identifiers(create_far_ies) &&
                has_unique_grouped_rule_identifiers(remove_far_ies) &&
                has_unique_grouped_rule_identifiers(create_qer_ies) &&
                has_unique_grouped_rule_identifiers(remove_qer_ies) &&
                has_unique_grouped_rule_identifiers(create_urr_ies) &&
                has_unique_grouped_rule_identifiers(remove_urr_ies) &&
                has_unique_grouped_rule_identifiers(update_pdr_ies) &&
                has_unique_grouped_rule_identifiers(create_pdr_ies) &&
                has_unique_grouped_rule_identifiers(remove_pdr_ies)) {
                const DecodedQer qer_decoded = decode_qer_ie(create_qer_ies.front());
                const DecodedUrr urr_decoded = decode_urr_ie(create_urr_ies.front());
                bool saw_updated_far = false;
                bool saw_created_buff_far = false;
                bool saw_created_drop_far = false;
                for (const auto& far_ie : update_far_ies) {
                    const DecodedFar far_decoded = decode_far_ie(far_ie);
                    saw_updated_far = saw_updated_far || (far_decoded.id == 1 &&
                                                          far_decoded.action == "FORW" &&
                                                          far_decoded.forward_to == "edge-cache" &&
                                                          far_decoded.header_creation_description == 0x01U &&
                                                          far_decoded.tunnel_peer_ipv4 == "203.0.113.20" &&
                                                          far_decoded.tunnel_peer_teid == 0x0A0B0C02U);
                }
                for (const auto& far_ie : create_far_ies) {
                    const DecodedFar far_decoded = decode_far_ie(far_ie);
                    saw_created_buff_far = saw_created_buff_far || (far_decoded.id == 4 &&
                                                                    far_decoded.action == "BUFF" &&
                                                                    far_decoded.buffering_duration_ms == 750U);
                    saw_created_drop_far = saw_created_drop_far || (far_decoded.id == 5 &&
                                                                    far_decoded.action == "DROP");
                }
                bool saw_removed_far_2 = false;
                bool saw_removed_far_3 = false;
                for (const auto& far_ie : remove_far_ies) {
                    const auto rule_identifier = decode_grouped_entry(far_ie, PfcpIeType::FarId);
                    if (!rule_identifier.has_value() || rule_identifier->size() != 4) {
                        continue;
                    }
                    const std::uint32_t id = read_u32(*rule_identifier, 0);
                    saw_removed_far_2 = saw_removed_far_2 || id == 2;
                    saw_removed_far_3 = saw_removed_far_3 || id == 3;
                }

                bool saw_removed_qer_1 = false;
                for (const auto& qer_ie : remove_qer_ies) {
                    const auto rule_identifier = decode_grouped_entry(qer_ie, PfcpIeType::QerId);
                    if (!rule_identifier.has_value() || rule_identifier->size() != 4) {
                        continue;
                    }
                    saw_removed_qer_1 = saw_removed_qer_1 || read_u32(*rule_identifier, 0) == 1;
                }

                bool saw_removed_urr_1 = false;
                for (const auto& urr_ie : remove_urr_ies) {
                    const auto rule_identifier = decode_grouped_entry(urr_ie, PfcpIeType::UrrId);
                    if (!rule_identifier.has_value() || rule_identifier->size() != 4) {
                        continue;
                    }
                    saw_removed_urr_1 = saw_removed_urr_1 || read_u32(*rule_identifier, 0) == 1;
                }

                bool saw_updated_pdr = false;
                for (const auto& pdr_ie : update_pdr_ies) {
                    const DecodedPdr pdr_decoded = decode_pdr_ie(pdr_ie);
                    const bool saw_primary_filter = pdr_decoded.sdf_filters.size() >= 1 &&
                                                    pdr_decoded.sdf_filters[0].packet_filter_id == 101 &&
                                                    pdr_decoded.sdf_filters[0].flow_direction == 0x01U &&
                                                    pdr_decoded.sdf_filters[0].flow_description == "permit out tcp from 10.17.0.2/32 4000 to assigned 443" &&
                                                    pdr_decoded.sdf_filters[0].protocol_identifier == 6U &&
                                                    pdr_decoded.sdf_filters[0].source_port == 4000 &&
                                                    pdr_decoded.sdf_filters[0].source_port_end == 4000 &&
                                                    pdr_decoded.sdf_filters[0].destination_port == 443 &&
                                                    pdr_decoded.sdf_filters[0].destination_port_end == 443 &&
                                                    pdr_decoded.sdf_filters[0].ether_type == 0x0800U;
                    const bool saw_secondary_filter = pdr_decoded.sdf_filters.size() >= 2 &&
                                                      pdr_decoded.sdf_filters[1].packet_filter_id == 202 &&
                                                      pdr_decoded.sdf_filters[1].flow_direction == 0x02U &&
                                                      pdr_decoded.sdf_filters[1].flow_description == "permit in udp from 10.17.0.2/32 5000-5010 to assigned 9000-9010" &&
                                                      pdr_decoded.sdf_filters[1].protocol_identifier == 17U &&
                                                      pdr_decoded.sdf_filters[1].source_port == 5000 &&
                                                      pdr_decoded.sdf_filters[1].source_port_end == 5010 &&
                                                      pdr_decoded.sdf_filters[1].destination_port == 9000 &&
                                                      pdr_decoded.sdf_filters[1].destination_port_end == 9010 &&
                                                      pdr_decoded.sdf_filters[1].ether_type == 0x0800U;
                    saw_updated_pdr = saw_updated_pdr || (pdr_decoded.id == 1 &&
                                                          pdr_decoded.precedence == 350 &&
                                                          pdr_decoded.source_interface == 0x00U &&
                                                          pdr_decoded.ue_ipv4 == "10.17.0.2" &&
                                                          pdr_decoded.application_id == "edge-cache-sync" &&
                                                          saw_primary_filter &&
                                                          saw_secondary_filter &&
                                                          pdr_decoded.far_id == 1 &&
                                                          pdr_decoded.qer_id == 2 &&
                                                          pdr_decoded.urr_id == 2);
                }

                bool saw_created_pdr4 = false;
                bool saw_created_pdr5 = false;
                for (const auto& pdr_ie : create_pdr_ies) {
                    const DecodedPdr pdr_decoded = decode_pdr_ie(pdr_ie);
                    saw_created_pdr4 = saw_created_pdr4 || (pdr_decoded.id == 4 &&
                                                            pdr_decoded.application_id == "buffered-video-replacement" &&
                                                            pdr_decoded.sdf_filters.size() == 1 &&
                                                            pdr_decoded.sdf_filters[0].packet_filter_id == 401 &&
                                                            pdr_decoded.sdf_filters[0].source_port == 6000 &&
                                                            pdr_decoded.sdf_filters[0].source_port_end == 6020 &&
                                                            pdr_decoded.sdf_filters[0].destination_port == 7000 &&
                                                            pdr_decoded.sdf_filters[0].destination_port_end == 7020 &&
                                                            pdr_decoded.far_id == 4 &&
                                                            pdr_decoded.qer_id == 2 &&
                                                            pdr_decoded.urr_id == 2);
                    saw_created_pdr5 = saw_created_pdr5 || (pdr_decoded.id == 5 &&
                                                            pdr_decoded.application_id == "discard-flow" &&
                                                            pdr_decoded.sdf_filters.size() == 1 &&
                                                            pdr_decoded.sdf_filters[0].packet_filter_id == 501 &&
                                                            pdr_decoded.sdf_filters[0].protocol_identifier == 6U &&
                                                            pdr_decoded.sdf_filters[0].source_port == 9443 &&
                                                            pdr_decoded.sdf_filters[0].destination_port == 9443 &&
                                                            pdr_decoded.far_id == 5 &&
                                                            pdr_decoded.qer_id == 2 &&
                                                            pdr_decoded.urr_id == 2);
                }
                bool saw_removed_pdr_2 = false;
                bool saw_removed_pdr_3 = false;
                for (const auto& pdr_ie : remove_pdr_ies) {
                    const auto rule_identifier = decode_grouped_entry(pdr_ie, PfcpIeType::PdrId);
                    if (!rule_identifier.has_value() || rule_identifier->size() != 4) {
                        continue;
                    }
                    const std::uint32_t id = read_u32(*rule_identifier, 0);
                    saw_removed_pdr_2 = saw_removed_pdr_2 || id == 2;
                    saw_removed_pdr_3 = saw_removed_pdr_3 || id == 3;
                }

                state->saw_modify_grouped_rules = saw_updated_far &&
                                                                                                    qer_decoded.id == 2 &&
                                                                                                    qer_decoded.qfi == 7 &&
                                                                                                    qer_decoded.gate_status == 0 &&
                                                                                                    qer_decoded.gbr_ul == 80 &&
                                                                                                    qer_decoded.gbr_dl == 120 &&
                                                                                                    qer_decoded.mbr_ul == 160 &&
                                                                                                    qer_decoded.mbr_dl == 240 &&
                                                                                                    urr_decoded.id == 2 &&
                                                                                                    urr_decoded.method == "DURATION" &&
                                                                                                    urr_decoded.trigger == "ON_THRESHOLD" &&
                                                  saw_updated_pdr;
                state->saw_modify_rule_replacement = saw_created_buff_far &&
                                                    saw_created_drop_far &&
                                                    saw_removed_far_2 &&
                                                    saw_removed_far_3 &&
                                                                                                        saw_removed_qer_1 &&
                                                                                                        saw_removed_urr_1 &&
                                                    saw_created_pdr4 &&
                                                    saw_created_pdr5 &&
                                                    saw_removed_pdr_2 &&
                                                    saw_removed_pdr_3;
            }
            response_type = PfcpMessageType::SessionModificationResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(201, "modified"));
        } else if (request->message_type == PfcpMessageType::SessionDeletionRequest) {
            state->saw_delete_message = true;
            state->saw_delete_without_rules =
                !first_ie_value(*request, PfcpIeType::CreateFar).has_value() &&
                !first_ie_value(*request, PfcpIeType::CreateQer).has_value() &&
                !first_ie_value(*request, PfcpIeType::CreateUrr).has_value() &&
                !first_ie_value(*request, PfcpIeType::CreatePdr).has_value() &&
                !first_ie_value(*request, PfcpIeType::UpdateFar).has_value() &&
                !first_ie_value(*request, PfcpIeType::UpdateQer).has_value() &&
                !first_ie_value(*request, PfcpIeType::UpdateUrr).has_value() &&
                !first_ie_value(*request, PfcpIeType::UpdatePdr).has_value() &&
                !first_ie_value(*request, PfcpIeType::Far).has_value() &&
                !first_ie_value(*request, PfcpIeType::Qer).has_value() &&
                !first_ie_value(*request, PfcpIeType::Urr).has_value() &&
                !first_ie_value(*request, PfcpIeType::Pdr).has_value();
            response_type = PfcpMessageType::SessionDeletionResponse;
            append_ie(&response_ies, PfcpIeType::ResponseContext, encode_response_context(202, "deleted"));
        } else {
            continue;
        }

        const std::string response = encode_pfcp_message(response_type,
                                                         request->has_seid,
                                                         response_ies,
                                                         std::vector<std::uint8_t>(buffer, buffer + recv_len));
        sendto(sock, response.data(), static_cast<int>(response.size()), 0, reinterpret_cast<sockaddr*>(&peer), peer_len);
    }

    close_socket(sock);
}

upf::PfcpSessionRequest make_request() {
    upf::PfcpSessionRequest request {};
    request.imsi = "250200000000777";
    request.pdu_session_id = "17";
    request.teid = "0x1700";
    request.ue_ipv4 = "10.17.0.2";
    request.ue_ipv6 = "2001:db8:17::2";
    request.ue_mac = "02:17:00:00:00:02";
    request.dnn = "internet";
    request.s_nssai = "1-010203";
    request.qos_profile = "gold";
    request.prefer_n6_ipv6 = true;
    request.prefer_n6_ethernet = true;

    upf::PfcpFar far_rule {};
    far_rule.id = 1;
    far_rule.action = "FORW";
    far_rule.forward_to = "internet";
    far_rule.outer_header_creation_description = 0x01U;
    far_rule.tunnel_peer_ipv4 = "203.0.113.10";
    far_rule.tunnel_peer_teid = 0x0A0B0C01U;
    request.rules.fars.push_back(far_rule);

    upf::PfcpFar buffering_far {};
    buffering_far.id = 2;
    buffering_far.action = "BUFF";
    buffering_far.buffering_duration_ms = 250;
    request.rules.fars.push_back(buffering_far);

    upf::PfcpFar nocp_far {};
    nocp_far.id = 3;
    nocp_far.action = "NOCP";
    nocp_far.notify_control_plane = true;
    request.rules.fars.push_back(nocp_far);

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
    pdr_rule.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {101, 0x01U, 17U, 2152, 2152, 8080, 8080, 0x0800U, "permit out udp from 10.17.0.2/32 2152 to assigned 8080"});
    pdr_rule.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {202, 0x02U, 17U, 5000, 5010, 9000, 9010, 0x0800U, "permit in udp from 10.17.0.2/32 5000-5010 to assigned 9000-9010"});
    pdr_rule.far_id = 1;
    pdr_rule.qer_id = 1;
    pdr_rule.urr_id = 1;
    request.rules.pdrs.push_back(pdr_rule);

    upf::PfcpPdr buffered_pdr {};
    buffered_pdr.id = 2;
    buffered_pdr.precedence = 180;
    buffered_pdr.source_interface = 0x00U;
    buffered_pdr.ue_ipv4 = request.ue_ipv4;
    buffered_pdr.application_id = "buffered-video";
    buffered_pdr.packet_filter_id = 201;
    buffered_pdr.flow_direction = 0x01U;
    buffered_pdr.protocol_identifier = 17U;
    buffered_pdr.source_port = 6000;
    buffered_pdr.destination_port = 7000;
    buffered_pdr.ether_type = 0x0800U;
    buffered_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {201, 0x01U, 17U, 6000, 6010, 7000, 7010, 0x0800U, "permit out udp from 10.17.0.2/32 6000-6010 to assigned 7000-7010"});
    buffered_pdr.far_id = 2;
    buffered_pdr.qer_id = 1;
    buffered_pdr.urr_id = 1;
    request.rules.pdrs.push_back(buffered_pdr);

    upf::PfcpPdr nocp_pdr {};
    nocp_pdr.id = 3;
    nocp_pdr.precedence = 160;
    nocp_pdr.source_interface = 0x00U;
    nocp_pdr.ue_ipv4 = request.ue_ipv4;
    nocp_pdr.application_id = "control-plane-mirror";
    nocp_pdr.packet_filter_id = 301;
    nocp_pdr.flow_direction = 0x02U;
    nocp_pdr.protocol_identifier = 6U;
    nocp_pdr.source_port = 9443;
    nocp_pdr.destination_port = 9443;
    nocp_pdr.ether_type = 0x0800U;
    nocp_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {301, 0x02U, 6U, 9443, 9443, 9443, 9443, 0x0800U, "permit in tcp from 10.17.0.2/32 9443 to assigned 9443"});
    nocp_pdr.far_id = 3;
    nocp_pdr.qer_id = 1;
    nocp_pdr.urr_id = 1;
    request.rules.pdrs.push_back(nocp_pdr);

    return request;
}

}  // namespace

int main() {
    constexpr int kPort = 39006;
    MockServerState state;
    std::thread server(run_udp_mock_server, kPort, &state);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkN4Adapter n4("127.0.0.1", kPort, 300, "upf-test-node");

    upf::PfcpSessionRequest establish_request = make_request();
    establish_request.procedure.request_id = "req-establish";
    const auto established = n4.apply_pfcp(establish_request, upf::PfcpOperation::Establish);
    if (!established.success || established.session_version != 200 || established.detail != "PFCP request accepted") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest modify_request = establish_request;
    modify_request.procedure.request_id = "req-modify";
    modify_request.rules.fars[0].forward_to = "edge-cache";
    modify_request.rules.fars[0].tunnel_peer_ipv4 = "203.0.113.20";
    modify_request.rules.fars[0].tunnel_peer_teid = 0x0A0B0C02U;
    modify_request.rules.fars.erase(modify_request.rules.fars.begin() + 1, modify_request.rules.fars.end());
    upf::PfcpFar replacement_buffer_far {};
    replacement_buffer_far.id = 4;
    replacement_buffer_far.action = "BUFF";
    replacement_buffer_far.buffering_duration_ms = 750;
    modify_request.rules.fars.push_back(replacement_buffer_far);
    upf::PfcpFar replacement_drop_far {};
    replacement_drop_far.id = 5;
    replacement_drop_far.action = "DROP";
    modify_request.rules.fars.push_back(replacement_drop_far);
    modify_request.rules.urrs[0].trigger = "ON_THRESHOLD";
    modify_request.rules.qers.clear();
    upf::PfcpQer replacement_qer {};
    replacement_qer.id = 2;
    replacement_qer.qfi = 7;
    replacement_qer.gate_status = "CLOSED";
    replacement_qer.gbr_ul_kbps = 80;
    replacement_qer.gbr_dl_kbps = 120;
    replacement_qer.mbr_ul_kbps = 160;
    replacement_qer.mbr_dl_kbps = 240;
    modify_request.rules.qers.push_back(replacement_qer);
    modify_request.rules.urrs.clear();
    upf::PfcpUrr replacement_urr {};
    replacement_urr.id = 2;
    replacement_urr.measurement_method = "DURATION";
    replacement_urr.trigger = "ON_THRESHOLD";
    modify_request.rules.urrs.push_back(replacement_urr);
    modify_request.rules.pdrs[0].precedence = 350;
    modify_request.rules.pdrs[0].application_id = "edge-cache-sync";
    modify_request.rules.pdrs[0].protocol_identifier = 6U;
    modify_request.rules.pdrs[0].source_port = 4000;
    modify_request.rules.pdrs[0].destination_port = 443;
    modify_request.rules.pdrs[0].qer_id = 2;
    modify_request.rules.pdrs[0].urr_id = 2;
    modify_request.rules.pdrs[0].sdf_filters[0] = upf::PfcpPdr::SdfFilterEntry {101, 0x01U, 6U, 4000, 4000, 443, 443, 0x0800U, "permit out tcp from 10.17.0.2/32 4000 to assigned 443"};
    modify_request.rules.pdrs[0].sdf_filters[1] = upf::PfcpPdr::SdfFilterEntry {202, 0x02U, 17U, 5000, 5010, 9000, 9010, 0x0800U, "permit in udp from 10.17.0.2/32 5000-5010 to assigned 9000-9010"};
    modify_request.rules.pdrs.erase(modify_request.rules.pdrs.begin() + 1, modify_request.rules.pdrs.end());
    upf::PfcpPdr replacement_buffered_pdr {};
    replacement_buffered_pdr.id = 4;
    replacement_buffered_pdr.precedence = 180;
    replacement_buffered_pdr.source_interface = 0x00U;
    replacement_buffered_pdr.ue_ipv4 = modify_request.ue_ipv4;
    replacement_buffered_pdr.application_id = "buffered-video-replacement";
    replacement_buffered_pdr.packet_filter_id = 401;
    replacement_buffered_pdr.flow_direction = 0x01U;
    replacement_buffered_pdr.protocol_identifier = 17U;
    replacement_buffered_pdr.source_port = 6000;
    replacement_buffered_pdr.destination_port = 7000;
    replacement_buffered_pdr.ether_type = 0x0800U;
    replacement_buffered_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {401, 0x01U, 17U, 6000, 6020, 7000, 7020, 0x0800U, "permit out udp from 10.17.0.2/32 6000-6020 to assigned 7000-7020"});
    replacement_buffered_pdr.far_id = 4;
    replacement_buffered_pdr.qer_id = 2;
    replacement_buffered_pdr.urr_id = 2;
    modify_request.rules.pdrs.push_back(replacement_buffered_pdr);
    upf::PfcpPdr replacement_drop_pdr {};
    replacement_drop_pdr.id = 5;
    replacement_drop_pdr.precedence = 160;
    replacement_drop_pdr.source_interface = 0x00U;
    replacement_drop_pdr.ue_ipv4 = modify_request.ue_ipv4;
    replacement_drop_pdr.application_id = "discard-flow";
    replacement_drop_pdr.packet_filter_id = 501;
    replacement_drop_pdr.flow_direction = 0x02U;
    replacement_drop_pdr.protocol_identifier = 6U;
    replacement_drop_pdr.source_port = 9443;
    replacement_drop_pdr.destination_port = 9443;
    replacement_drop_pdr.ether_type = 0x0800U;
    replacement_drop_pdr.sdf_filters.push_back(upf::PfcpPdr::SdfFilterEntry {501, 0x02U, 6U, 9443, 9443, 9443, 9443, 0x0800U, "permit in tcp from 10.17.0.2/32 9443 to assigned 9443"});
    replacement_drop_pdr.far_id = 5;
    replacement_drop_pdr.qer_id = 2;
    replacement_drop_pdr.urr_id = 2;
    modify_request.rules.pdrs.push_back(replacement_drop_pdr);
    const auto modified = n4.apply_pfcp(modify_request, upf::PfcpOperation::Modify);
    if (!modified.success || modified.session_version != 201 || modified.detail != "PFCP request accepted") {
        server.join();
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest delete_request {};
    delete_request.imsi = establish_request.imsi;
    delete_request.pdu_session_id = establish_request.pdu_session_id;
    delete_request.procedure.request_id = "req-delete";
    const auto deleted = n4.apply_pfcp(delete_request, upf::PfcpOperation::Delete);
    if (!deleted.success || deleted.session_version != 202 || deleted.detail != "PFCP request accepted") {
        server.join();
        return EXIT_FAILURE;
    }

    if (!state.saw_association_setup || !state.saw_capability_exchange || !state.saw_node_features || !state.saw_establish_message || !state.saw_modify_message || !state.saw_delete_message ||
        !state.saw_grouped_session_context ||
        !state.saw_modify_grouped_rules || !state.saw_modify_rule_replacement || !state.saw_delete_without_rules) {
        server.join();
        return EXIT_FAILURE;
    }

    server.join();
    return EXIT_SUCCESS;
}