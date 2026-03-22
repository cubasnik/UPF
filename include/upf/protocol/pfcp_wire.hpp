#pragma once

#include "upf/interfaces.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace upf::pfcp {

enum class PfcpMessageType : std::uint8_t {
    AssociationSetupRequest = 5,
    AssociationSetupResponse = 6,
    CapabilityExchangeRequest = 7,
    CapabilityExchangeResponse = 8,
    NodeFeaturesRequest = 9,
    NodeFeaturesResponse = 10,
    HeartbeatRequest = 1,
    HeartbeatResponse = 2,
    SessionEstablishmentRequest = 50,
    SessionEstablishmentResponse = 51,
    SessionModificationRequest = 52,
    SessionModificationResponse = 53,
    SessionDeletionRequest = 54,
    SessionDeletionResponse = 55,
    SessionReportRequest = 56,
    SessionReportResponse = 57,
};

enum class PfcpIeType : std::uint16_t {
    Imsi = 0x0101,
    PduSessionId = 0x0102,
    Teid = 0x0103,
    UeIpv4 = 0x0104,
    RequestId = 0x0105,
    TimeoutMs = 0x0106,
    MaxRetries = 0x0107,
    Cause = 19,
    SessionVersion = 0x0109,
    Detail = 0x010A,
    BytesUl = 0x010B,
    BytesDl = 0x010C,
    PacketsUl = 0x010D,
    PacketsDl = 0x010E,
    NodeId = 60,
    Far = 0x0110,
    Qer = 0x0111,
    Urr = 0x0112,
    Pdr = 0x0113,
    FSeid = 57,
    RecoveryTimeStamp = 96,
    UeIpv6 = 0x0116,
    UeMac = 0x0117,
    Dnn = 0x0118,
    Snssai = 0x0119,
    QosProfile = 0x011A,
    AccessPreferences = 0x011B,
    FTeid = 21,
    NetworkInstance = 22,
    UeIpAddress = 93,
    SourceInterface = 20,
    CreateFar = 3,
    CreateQer = 7,
    CreateUrr = 6,
    CreatePdr = 1,
    UpdateFar = 10,
    UpdateQer = 14,
    UpdateUrr = 13,
    UpdatePdr = 9,
    RemoveFar = 16,
    RemoveQer = 18,
    RemoveUrr = 17,
    RemovePdr = 15,
    UserIdentity = 0x0130,
    AccessTunnel = 0x0131,
    ProcedureContext = 0x0132,
    ControlPlanePeer = 0x0133,
    AssociationContext = 0x0134,
    UsageQueryContext = 77,
    UsageReportContext = 80,
    CapabilityContext = 0x0137,
    ResponseContext = 0x0138,
    FeatureBitmap = 0x0139,
    NodeFeatureContext = 0x013A,
    SessionProfileContext = 0x013B,
    Pdi = 2,
    PdiContext = 0x013C,
    RuleIdentifier = 0x0140,
    ApplyAction = 44,
    ForwardingParameters = 4,
    Qfi = 124,
    QfiValue = 124,
    GateStatus = 25,
    GateStatusValue = 25,
    GbrUl = 0x0145,
    GbrDl = 0x0146,
    MbrUl = 0x0147,
    MbrDl = 0x0148,
    MeasurementMethodValue = 62,
    ReportingTriggerValue = 63,
    Precedence = 29,
    PrecedenceValue = 29,
    PdrId = 56,
    UrrId = 81,
    FarId = 108,
    QerId = 109,
    LinkedFarId = 108,
    LinkedQerId = 109,
    LinkedUrrId = 81,
    OuterHeaderCreation = 84,
    HeaderCreationDescription = 0x0150,
    TunnelPeerAddress = 0x0151,
    TunnelPeerTeid = 0x0152,
    PacketFilterId = 0x0153,
    FlowDescription = 0x0154,
    SdfFilter = 0x0155,
    ProtocolIdentifier = 0x0156,
    SourcePort = 0x0157,
    DestinationPort = 0x0158,
    FlowDirection = 0x0159,
    ApplicationId = 0x015A,
    EtherType = 0x015B,
    SourcePortEnd = 0x015C,
    DestinationPortEnd = 0x015D,
    BufferingParameters = 0x015E,
    BufferingDuration = 0x015F,
    NotifyControlPlane = 0x0160,
    ThresholdValue = 0x0161,
    QuotaValue = 0x0162,
};

struct PfcpParsedMessage {
    PfcpMessageType message_type {PfcpMessageType::HeartbeatRequest};
    bool has_seid {false};
    std::uint64_t seid {0};
    std::uint32_t sequence {0};
    std::unordered_map<std::uint16_t, std::vector<std::vector<std::uint8_t>>> ies;
};

void append_u16(std::vector<std::uint8_t>* buffer, std::uint16_t value);
void append_u32(std::vector<std::uint8_t>* buffer, std::uint32_t value);
void append_u64(std::vector<std::uint8_t>* buffer, std::uint64_t value);
std::uint16_t read_u16(const std::vector<std::uint8_t>& buffer, std::size_t offset);
std::uint32_t read_u32(const std::vector<std::uint8_t>& buffer, std::size_t offset);
std::uint64_t read_u64(const std::vector<std::uint8_t>& buffer, std::size_t offset);

void append_ie(std::vector<std::uint8_t>* buffer, PfcpIeType type, const std::vector<std::uint8_t>& value);
void append_ie_string(std::vector<std::uint8_t>* buffer, PfcpIeType type, const std::string& value);
void append_ie_u32(std::vector<std::uint8_t>* buffer, PfcpIeType type, std::uint32_t value);
void append_ie_u64(std::vector<std::uint8_t>* buffer, PfcpIeType type, std::uint64_t value);

std::uint8_t encode_pfcp_cause(PfcpCause cause);
PfcpCause decode_pfcp_cause(std::uint8_t code);
std::optional<UsageReportCause> decode_usage_report_cause(std::uint8_t code);
std::string default_usage_report_detail(UsageReportCause cause);

std::vector<std::uint8_t> encode_ipv4_bytes(const std::string& ipv4);
bool is_valid_ipv4_text(const std::string& ipv4);
std::vector<std::uint8_t> encode_ipv6_bytes(const std::string& ipv6);
std::vector<std::uint8_t> encode_mac_bytes(const std::string& mac);
std::optional<std::uint32_t> parse_teid_value(const std::string& teid);
std::string decode_ipv4_bytes(const std::vector<std::uint8_t>& bytes, std::size_t offset);

std::vector<std::uint8_t> encode_node_id_ie_value(const std::string& node_id);
std::vector<std::uint8_t> encode_fseid_ie_value(std::uint64_t seid, const std::string& ipv4);
std::vector<std::uint8_t> encode_fteid_ie_value(std::uint32_t teid, const std::string& ipv4);
std::vector<std::uint8_t> encode_ue_ip_address_ie_value(const std::string& ue_ipv4, const std::string& ue_ipv6);
std::vector<std::uint8_t> encode_u32_value(std::uint32_t value);
std::vector<std::uint8_t> encode_u16_value(std::uint16_t value);
std::vector<std::uint8_t> encode_u64_value(std::uint64_t value);
std::vector<std::uint8_t> encode_apply_action_value(const std::string& action);
std::string far_forward_peer_ipv4(const std::string& forward_to);
std::vector<std::uint8_t> encode_outer_header_creation_ie_value(const PfcpFar& far_rule);

std::string pdr_flow_direction_name(std::uint8_t flow_direction);
std::string pdr_protocol_name(std::uint8_t protocol_identifier);
bool is_valid_pdr_source_interface(std::uint8_t source_interface);
bool is_valid_pdr_flow_direction(std::uint8_t flow_direction);
bool is_transport_protocol(std::uint8_t protocol_identifier);
bool is_valid_pdr_protocol(std::uint8_t protocol_identifier);
bool is_valid_ether_type(std::uint16_t ether_type);
bool is_valid_apply_action(const std::string& action);
std::string pdr_flow_description(const PfcpPdr& pdr_rule);
std::string sdf_filter_flow_description(const PfcpPdr::SdfFilterEntry& filter, const std::string& fallback_ue_ipv4);
std::vector<PfcpPdr::SdfFilterEntry> build_effective_sdf_filters(const PfcpPdr& pdr_rule);
bool has_explicit_legacy_pdr_filter_fields(const PfcpPdr& pdr_rule);
bool legacy_pdr_fields_match_primary_filter(const PfcpPdr& pdr_rule, const PfcpPdr::SdfFilterEntry& primary_filter);

std::vector<std::uint8_t> encode_sdf_filter_group(const PfcpPdr::SdfFilterEntry& filter, const std::string& fallback_ue_ipv4);
std::vector<std::uint8_t> encode_recovery_time_stamp_ie_value(std::uint32_t stamp);
std::vector<std::uint8_t> encode_far_ie_value(const PfcpFar& far_rule);
std::vector<std::uint8_t> encode_qer_ie_value(const PfcpQer& qer_rule);
std::vector<std::uint8_t> encode_urr_ie_value(const PfcpUrr& urr_rule);
std::vector<std::uint8_t> encode_pdr_ie_value(const PfcpPdr& pdr_rule);
std::vector<std::uint8_t> encode_grouped_ie_value(PfcpIeType inner_type, const std::vector<std::uint8_t>& inner_value);
std::vector<std::uint8_t> encode_grouped_ie_value(const std::vector<std::pair<PfcpIeType, std::vector<std::uint8_t>>>& entries);
std::vector<std::uint8_t> encode_user_identity_group(const PfcpSessionRequest& request);
std::vector<std::uint8_t> encode_pdi_group(const PfcpSessionRequest& request, const std::string& local_fseid_ipv4);
std::vector<std::uint8_t> encode_procedure_context_group(const PfcpProcedureContext& procedure);
std::vector<std::uint8_t> encode_session_profile_group(const PfcpSessionRequest& request);
std::vector<std::uint8_t> encode_control_plane_peer_group(const std::string& local_node_id,
                                                          std::uint64_t seid,
                                                          const std::string& local_fseid_ipv4);
std::vector<std::uint8_t> encode_association_context_group(const std::string& local_node_id,
                                                           const std::string& local_fseid_ipv4,
                                                           std::uint32_t recovery_time_stamp);
std::vector<std::uint8_t> encode_usage_query_context_group(const std::string& imsi,
                                                           const std::string& pdu_session_id,
                                                           const std::vector<std::uint32_t>& urr_ids);
std::vector<std::uint8_t> encode_usage_report_context_group(std::uint32_t rule_id, const UsageReport& report);
std::vector<std::uint8_t> encode_capability_context_group(const std::string& local_node_id,
                                                          const std::string& local_fseid_ipv4);
std::vector<std::uint8_t> encode_response_context_group(PfcpCause cause,
                                                        std::uint64_t session_version,
                                                        const std::string& detail,
                                                        std::uint32_t recovery_time_stamp = 0);
std::vector<std::uint8_t> encode_node_feature_context_group(const std::string& local_node_id,
                                                            std::uint32_t feature_bitmap);

std::optional<std::vector<std::uint8_t>> decode_grouped_entry(const std::vector<std::uint8_t>& grouped_value,
                                                              PfcpIeType inner_type);
PfcpIeType grouped_rule_ie_type(PfcpOperation operation, PfcpIeType flat_type);
PfcpIeType modify_grouped_rule_ie_type(PfcpIeType flat_type, bool exists_in_previous_state);
PfcpIeType remove_grouped_rule_ie_type(PfcpIeType flat_type);
PfcpIeType rule_identifier_ie_type(PfcpIeType flat_type);
std::vector<std::uint8_t> encode_rule_identifier_only_ie_value(PfcpIeType flat_type, std::uint32_t id);
bool has_strict_response_context_layout(const std::vector<std::uint8_t>& grouped_value);
bool has_strict_usage_report_context_layout(const std::vector<std::uint8_t>& grouped_value);
PfcpMessageType pfcp_request_message_type(PfcpOperation operation);
PfcpMessageType pfcp_response_message_type(PfcpOperation operation);
std::uint32_t next_pfcp_sequence(std::uint32_t* sequence_counter);
std::uint64_t make_pfcp_seid(const std::string& imsi, const std::string& pdu_session_id);
std::string encode_association_setup_request_message(const std::string& local_node_id,
                                                     const std::string& local_fseid_ipv4,
                                                     std::uint32_t recovery_time_stamp,
                                                     std::uint32_t sequence);
std::string encode_capability_exchange_request_message(const std::string& local_node_id,
                                                       const std::string& local_fseid_ipv4,
                                                       std::uint32_t feature_bitmap,
                                                       std::uint32_t sequence);
std::string encode_node_features_request_message(const std::string& local_node_id,
                                                 std::uint32_t feature_bitmap,
                                                 std::uint32_t sequence);
std::string encode_session_request_message(const PfcpSessionRequest& request,
                                           PfcpOperation operation,
                                           std::uint32_t sequence,
                                           const PfcpRuleSet& previous_rules,
                                           const std::string& local_node_id,
                                           const std::string& local_fseid_ipv4);

std::string encode_pfcp_message(PfcpMessageType message_type,
                                bool has_seid,
                                std::uint64_t seid,
                                std::uint32_t sequence,
                                const std::vector<std::uint8_t>& ies);
std::optional<PfcpParsedMessage> decode_pfcp_message(const std::string& payload);
std::string first_ie_string(const PfcpParsedMessage& message, PfcpIeType type);
std::optional<std::vector<std::uint8_t>> first_ie_value(const PfcpParsedMessage& message, PfcpIeType type);
std::vector<std::vector<std::uint8_t>> all_ie_values(const PfcpParsedMessage& message, PfcpIeType type);
bool is_valid_node_id_ie(const std::vector<std::uint8_t>& value);
bool is_valid_fseid_ie(const std::vector<std::uint8_t>& value);
bool is_valid_recovery_time_stamp_ie(const std::vector<std::uint8_t>& value);
bool is_valid_feature_bitmap_ie(const std::vector<std::uint8_t>& value);
bool has_valid_association_context_response(const PfcpParsedMessage& message);
bool has_valid_capability_context_response(const PfcpParsedMessage& message);
bool has_valid_node_feature_context_response(const PfcpParsedMessage& message);
std::uint32_t first_ie_u32(const PfcpParsedMessage& message, PfcpIeType type, std::uint32_t fallback);
std::uint64_t first_ie_u64(const PfcpParsedMessage& message, PfcpIeType type, std::uint64_t fallback);
std::vector<std::string> repeated_ie_strings(const PfcpParsedMessage& message, PfcpIeType type);

}  // namespace upf::pfcp