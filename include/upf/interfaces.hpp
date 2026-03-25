#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace upf {

enum class UpfState {
    Idle,
    Initializing,
    Running,
    Degraded,
    Stopped,
};

struct SessionContext {
    std::string imsi;
    std::string pdu_session_id;
    std::string teid;
    std::string ue_ipv4;
    std::string ue_ipv6;
    std::string ue_mac;
    std::string dnn;
    std::string s_nssai;
    std::string anchor_upf;
    std::string n19_endpoint;
    std::string nx_endpoint;
    std::string nsmf_component;
    bool n6_ipv6_enabled {false};
    bool n6_ethernet_enabled {false};
    bool mirror_to_n9 {false};
    bool active {true};
    std::string last_updated_utc;
};

struct UpfStats {
    std::size_t starts {0};
    std::size_t stops {0};
    std::size_t ticks {0};
    std::size_t session_establishes {0};
    std::size_t session_modifies {0};
    std::size_t session_releases {0};
    std::size_t n3_packets_rx {0};
    std::size_t n3_packets_tx {0};
    std::size_t n4_messages {0};
    std::size_t n4_heartbeats {0};
    std::size_t n4_heartbeat_failures {0};
    std::size_t n6_forwards {0};
    std::size_t n9_forwards {0};
    std::size_t n19_forwards {0};
    std::size_t nx_forwards {0};
    std::size_t nsmf_messages {0};
    std::size_t sbi_notifications {0};
};

enum class N6BufferOverflowPolicy {
    DropOldest,
    DropNewest,
};

enum class N6BufferDropReason {
    None,
    OverflowDropOldest,
    OverflowDropNewest,
    SessionRemoved,
    UnknownSession,
};

struct N6BufferStatus {
    std::size_t per_session_capacity {0};
    N6BufferOverflowPolicy overflow_policy {N6BufferOverflowPolicy::DropOldest};
    std::size_t enqueued_packets {0};
    std::size_t dequeued_packets {0};
    std::size_t dropped_packets {0};
    std::size_t buffered_packets {0};
    std::size_t active_sessions {0};
    std::size_t dropped_overflow_oldest {0};
    std::size_t dropped_overflow_newest {0};
    std::size_t dropped_session_removed {0};
    std::size_t dropped_unknown_session {0};
    std::size_t rejected_by_policy {0};
};

struct N6SessionBufferSnapshot {
    std::string imsi;
    std::string pdu_session_id;
    std::string dnn;
    std::string last_updated_utc;
    bool ipv6_enabled {false};
    bool ethernet_enabled {false};
    std::size_t enqueued_packets {0};
    std::size_t dequeued_packets {0};
    std::size_t dropped_packets {0};
    std::size_t dropped_overflow_oldest {0};
    std::size_t dropped_overflow_newest {0};
    std::size_t dropped_session_removed {0};
    std::size_t rejected_by_policy {0};
    std::size_t buffered_packets {0};
};

struct N6SessionBufferCounters {
    std::size_t enqueued_packets {0};
    std::size_t dequeued_packets {0};
    std::size_t dropped_packets {0};
    std::size_t dropped_overflow_oldest {0};
    std::size_t dropped_overflow_newest {0};
    std::size_t dropped_session_removed {0};
    std::size_t rejected_by_policy {0};
    std::size_t buffered_packets {0};
};

struct UpfStatusSnapshot {
    UpfState state {UpfState::Idle};
    std::size_t active_sessions {0};
    UpfStats stats {};
    std::optional<N6BufferStatus> n6_buffer;
    bool is_running = false;
};

enum class PfcpOperation {
    Establish,
    Modify,
    Delete,
};

enum class PfcpCause {
    RequestAccepted,
    MandatoryIeMissing,
    SessionContextNotFound,
    RuleCreationModificationFailure,
    SemanticErrorInTheTft,
    InvalidQfi,
    InvalidGateStatus,
};

enum class UsageReportCause {
    UsageReady,
    ThresholdReached,
    QuotaExhausted,
    Unknown,
};

struct PfcpPdr {
    struct SdfFilterEntry {
        std::uint32_t packet_filter_id {0};
        std::uint8_t flow_direction {0x01U};
        std::uint8_t protocol_identifier {0};
        std::uint16_t source_port {0};
        std::uint16_t source_port_end {0};
        std::uint16_t destination_port {0};
        std::uint16_t destination_port_end {0};
        std::uint16_t ether_type {0};
        std::string flow_description;
    };

    std::uint32_t id {0};
    std::uint32_t precedence {0};
    std::uint8_t source_interface {0x00U};
    std::string ue_ipv4;
    std::string application_id;
    std::uint32_t packet_filter_id {0};
    std::uint8_t flow_direction {0x01U};
    std::uint8_t protocol_identifier {0};
    std::uint16_t source_port {0};
    std::uint16_t destination_port {0};
    std::uint16_t ether_type {0};
    std::string flow_description;
    std::vector<SdfFilterEntry> sdf_filters;
    std::uint32_t far_id {0};
    std::uint32_t qer_id {0};
    std::uint32_t urr_id {0};
};

struct PfcpFar {
    std::uint32_t id {0};
    std::string action;
    std::string forward_to;
    std::uint8_t outer_header_creation_description {0x01U};
    std::string tunnel_peer_ipv4;
    std::uint32_t tunnel_peer_teid {0};
    std::uint32_t buffering_duration_ms {0};
    bool notify_control_plane {false};
};

struct PfcpUrr {
    std::uint32_t id {0};
    std::string measurement_method;
    std::string trigger;
};

struct PfcpQer {
    std::uint32_t id {0};
    std::string gate_status {"OPEN"};
    std::uint64_t gbr_ul_kbps {0};
    std::uint64_t gbr_dl_kbps {0};
    std::uint64_t mbr_ul_kbps {0};
    std::uint64_t mbr_dl_kbps {0};
    std::uint8_t qfi {0};
};

enum class SteeringMode {
    Default,
    N19Local,
    NxBranch,
};

struct SteeringPolicy {
    SteeringMode mode {SteeringMode::Default};
    std::string target_endpoint;
    std::string nsmf_component;
    bool mirror_to_n9 {false};
};

struct PfcpRuleSet {
    std::vector<PfcpPdr> pdrs;
    std::vector<PfcpFar> fars;
    std::vector<PfcpUrr> urrs;
    std::vector<PfcpQer> qers;
    SteeringPolicy steering {};
    std::string anchor_upf;
};

struct PfcpProcedureContext {
    std::string request_id;
    std::uint32_t timeout_ms {300};
    std::uint32_t max_retries {2};
};

struct PfcpSessionRequest {
    std::string imsi;
    std::string pdu_session_id;
    std::string teid;
    std::string ue_ipv4;
    std::string ue_ipv6;
    std::string ue_mac;
    std::string dnn;
    std::string s_nssai;
    std::string qos_profile;
    bool prefer_n6_ipv6 {false};
    bool prefer_n6_ethernet {false};
    PfcpProcedureContext procedure {};
    PfcpRuleSet rules {};
};

struct PfcpSessionResponse {
    bool success {false};
    PfcpCause cause {PfcpCause::RuleCreationModificationFailure};
    std::uint64_t session_version {0};
    bool idempotent_replay {false};
    std::string detail;
};

struct UsageReportEntry {
    std::uint32_t urr_id {0};
    std::string measurement_method;
    std::string reporting_trigger;
    UsageReportCause report_cause {UsageReportCause::UsageReady};
    std::string detail;
    std::optional<std::uint64_t> threshold_value;
    std::optional<std::uint64_t> quota_value;
    std::uint64_t bytes_ul {0};
    std::uint64_t bytes_dl {0};
    std::uint64_t packets_ul {0};
    std::uint64_t packets_dl {0};
};

struct UsageReport {
    std::uint64_t bytes_ul {0};
    std::uint64_t bytes_dl {0};
    std::uint64_t packets_ul {0};
    std::uint64_t packets_dl {0};
    std::vector<UsageReportEntry> urr_reports;
};

enum class N6TrafficDirection {
    Uplink,
    Downlink,
};

enum class N6Protocol {
    IPv4,
    IPv6,
    Ethernet,
};

struct N6SessionContext {
    std::string imsi;
    std::string pdu_session_id;
    std::string dnn;
    std::string ue_ipv4;
    std::string ue_ipv6;
    std::string ue_mac;
    bool ipv6_enabled {false};
    bool ethernet_enabled {false};
};

struct N6Packet {
    N6Protocol protocol {N6Protocol::IPv4};
    std::string source_ipv4;
    std::string destination_ipv4;
    std::string source_ipv6;
    std::string destination_ipv6;
    std::string source_mac;
    std::string destination_mac;
    std::uint16_t ether_type {0};
    std::vector<std::uint8_t> payload;
};

struct N6ForwardRecord {
    std::string imsi;
    std::string pdu_session_id;
    std::string dnn;
    N6TrafficDirection direction {N6TrafficDirection::Uplink};
    N6Packet packet;
    std::size_t wire_bytes {0};
};

// GTP-U Protocol structures (3GPP TS 29.281)
enum class GtpVersion {
    V1 = 1,
    V2 = 2,
};

enum class GtpPacketType {
    Data = 0xFF,  // T-PDU (G-PDU)
    SignalingResponse = 1,
    SignalingRequest = 2,
};

enum class GtpMessageType {
    EchoRequest = 1,
    EchoResponse = 2,
    ErrorIndication = 26,
    SupportedExtensionHeadersNotification = 31,
};

struct GtpUHeader {
    GtpVersion version {GtpVersion::V1};
    bool protocol_type {true};  // 1 = GTP, 0 = GTP'
    bool extension_headers_flag {false};
    bool sequence_flag {false};
    bool pn_flag {false};  // PN (N-PDU Number) flag
    GtpPacketType packet_type {GtpPacketType::Data};
    std::uint16_t message_length {0};
    std::uint32_t teid {0};  // Tunnel Endpoint Identifier
    std::uint16_t sequence_number {0};
    std::uint8_t n_pdu_number {0};
    std::uint8_t next_extension_header_type {0};
};

struct GtpUPacket {
    GtpUHeader header;
    std::vector<std::uint8_t> payload;
    std::string source_ip;
    std::string dest_ip;
    std::uint16_t source_port {2152};
    std::uint16_t dest_port {2152};
};

// QoS Flow to GTP Tunnel mapping
struct QosFlowMapping {
    std::uint8_t qfi {0};  // QoS Flow Identifier (0-63)
    std::uint32_t teid {0};  // Mapped TEID
    std::string ue_ip;
    std::uint64_t gbr_ul_kbps {0};  // Guaranteed Bit Rate Uplink
    std::uint64_t gbr_dl_kbps {0};  // Guaranteed Bit Rate Downlink
    std::uint64_t mbr_ul_kbps {0};  // Maximum Bit Rate Uplink
    std::uint64_t mbr_dl_kbps {0};  // Maximum Bit Rate Downlink
    std::uint32_t precedence {0};
};

// N3 GTP-U Tunnel context
struct N3TunnelContext {
    std::uint32_t teid {0};
    std::string ue_ip;
    std::string gnb_ip;
    std::uint16_t gnb_port {2152};
    std::string imsi;
    std::string pdu_session_id;
    std::vector<QosFlowMapping> qos_flows;
    bool active {true};
    std::uint64_t packets_ul {0};
    std::uint64_t packets_dl {0};
    std::uint64_t bytes_ul {0};
    std::uint64_t bytes_dl {0};
};

class IN3Interface {
public:
    virtual ~IN3Interface() = default;
    
    // Legacy packet-based methods
    virtual bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    
    // GTP-U tunnel management
    virtual bool create_tunnel(const N3TunnelContext& context) = 0;
    virtual bool delete_tunnel(std::uint32_t teid) = 0;
    virtual bool update_tunnel_qos_flows(std::uint32_t teid, const std::vector<QosFlowMapping>& qos_flows) = 0;
    virtual std::optional<N3TunnelContext> get_tunnel(std::uint32_t teid) const = 0;
    
    // GTP-U packet processing
    virtual bool process_gtp_u_packet(const GtpUPacket& packet) = 0;
    virtual std::optional<GtpUPacket> send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) = 0;
    
    // Server functions
    virtual bool start_listening(std::uint16_t port = 2152) = 0;
    virtual bool stop_listening() = 0;
    virtual bool is_listening() const = 0;
    
    // Statistics
    virtual std::size_t get_active_tunnels() const = 0;
    virtual UsageReport get_tunnel_usage(std::uint32_t teid) = 0;
};

class IN4Interface {
public:
    virtual ~IN4Interface() = default;
    virtual PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) = 0;
    virtual std::optional<UsageReport> query_usage_report(const std::string& imsi,
                                                          const std::string& pdu_session_id,
                                                          const std::vector<std::uint32_t>& urr_ids = {}) = 0;
    virtual bool send_heartbeat() = 0;
};

class IN6Interface {
public:
    virtual ~IN6Interface() = default;
    virtual bool register_session(const N6SessionContext& context) = 0;
    virtual bool update_session(const N6SessionContext& context) = 0;
    virtual bool remove_session(const std::string& imsi, const std::string& pdu_session_id) = 0;
    virtual std::optional<N6SessionContext> get_session(const std::string& imsi, const std::string& pdu_session_id) const = 0;
    virtual bool forward_packet(const std::string& imsi, const std::string& pdu_session_id, const N6Packet& packet) = 0;
    virtual std::optional<N6Packet> receive_from_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual std::vector<N6ForwardRecord> get_forward_history() const = 0;
    virtual N6BufferStatus get_buffer_status() const = 0;
    virtual std::size_t buffered_packets_for_session(const std::string& imsi, const std::string& pdu_session_id) const = 0;
    virtual N6SessionBufferCounters buffer_counters_for_session(const std::string& imsi, const std::string& pdu_session_id) const = 0;
};

class IN9Interface {
public:
    virtual ~IN9Interface() = default;
    virtual bool forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool is_enabled() const = 0;
};

// N19: GTP-U interface to another UPF (local data center / regional traffic)
// Used for multi-vendor deployments, local traffic within same data center/region
class IN19Interface {
public:
    virtual ~IN19Interface() = default;
    virtual bool forward_to_local_upf(const std::string& imsi, const std::string& pdu_session_id, 
                                     const std::string& target_upf_address, std::size_t bytes) = 0;
    virtual bool is_enabled() const = 0;
    virtual std::string get_local_upf_endpoint() const = 0;
};

// Nx: GTP-U interface for UL-CL (Uplink Classifier) and Branching Point scenarios
// Used in UL-CL and I-UPF branching deployments
struct UplinkClassifierRule {
    std::uint32_t id {0};
    std::string ue_subnet;
    std::string target_upf_address;
    std::uint32_t precedence {0};
};

class INxInterface {
public:
    virtual ~INxInterface() = default;
    virtual bool forward_uplink_classified(const std::string& imsi, const std::string& pdu_session_id, 
                                          const std::string& target_upf_address, std::size_t bytes) = 0;
    virtual bool set_uplink_classifier_rules(const std::vector<UplinkClassifierRule>& rules) = 0;
    virtual bool add_branch_upf_endpoint(const std::string& upf_id, const std::string& address) = 0;
    virtual bool is_enabled() const = 0;
};

// Nsmf: Internal interface for distributed UPF components
// Used when UPF is split between CU-UP and DU-UP or other internal components
struct InternalComponentMessage {
    std::string source_component;
    std::string target_component;
    std::string message_type;
    std::string payload;
    std::uint64_t timestamp_ms {0};
};

class INsmfInterface {
public:
    virtual ~INsmfInterface() = default;
    virtual bool send_internal_message(const InternalComponentMessage& message) = 0;
    virtual std::optional<InternalComponentMessage> receive_internal_message(int timeout_ms = 100) = 0;
    virtual bool register_internal_component(const std::string& component_name) = 0;
    virtual bool unregister_internal_component(const std::string& component_name) = 0;
    virtual std::vector<std::string> get_registered_components() const = 0;
};

class ISbiInterface {
public:
    virtual ~ISbiInterface() = default;
    virtual bool publish_event(const std::string& service_name, const std::string& payload) = 0;
};

struct UpfPeerInterfaces {
    IN3Interface* n3 {nullptr};
    IN4Interface* n4 {nullptr};
    IN6Interface* n6 {nullptr};
    IN9Interface* n9 {nullptr};
    IN19Interface* n19 {nullptr};
    INxInterface* nx {nullptr};
    INsmfInterface* nsmf {nullptr};
    ISbiInterface* sbi {nullptr};
};

class IUpfNode {
public:
    virtual ~IUpfNode() = default;

    virtual bool start() = 0;
    virtual bool stop() = 0;
    virtual bool set_degraded() = 0;
    virtual bool recover() = 0;
    virtual void tick() = 0;

    virtual bool establish_session(const PfcpSessionRequest& request) = 0;
    virtual bool modify_session(const PfcpSessionRequest& request) = 0;
    virtual bool release_session(const std::string& imsi, const std::string& pdu_session_id) = 0;

    virtual bool process_uplink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool process_downlink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;

    virtual std::optional<SessionContext> find_session(const std::string& imsi, const std::string& pdu_session_id) const = 0;
    virtual std::vector<SessionContext> list_sessions() const = 0;
    virtual std::optional<N6SessionBufferSnapshot> inspect_n6_session(const std::string& imsi, const std::string& pdu_session_id) const = 0;

    virtual bool notify_sbi(const std::string& service_name, const std::string& payload) = 0;
    virtual UpfStatusSnapshot status() const = 0;
    virtual void clear_stats() = 0;
};

const char* to_string(UpfState state);
const char* to_string(PfcpCause cause);
const char* to_string(UsageReportCause cause);
const char* to_string(N6BufferOverflowPolicy policy);
const char* to_string(N6BufferDropReason reason);

}  // namespace upf
