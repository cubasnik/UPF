#pragma once

#include "upf/interfaces.hpp"
#include "upf/modules/n6_packet_buffer.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace upf {

class NetworkN3Adapter final : public IN3Interface {
public:
    struct ControlPlaneStats {
        std::uint64_t echo_requests_rx {0};
        std::uint64_t echo_responses_tx {0};
        std::uint64_t supported_ext_headers_notifications_rx {0};
        std::uint64_t error_indications_rx {0};
        std::uint64_t other_signaling_rx {0};
    };

    NetworkN3Adapter(std::uint16_t listen_port = 2152, int max_workers = 4);
    ~NetworkN3Adapter();

    // Legacy packet-based methods
    bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    
    // GTP-U tunnel management
    bool create_tunnel(const N3TunnelContext& context) override;
    bool delete_tunnel(std::uint32_t teid) override;
    bool update_tunnel_qos_flows(std::uint32_t teid, const std::vector<QosFlowMapping>& qos_flows) override;
    std::optional<N3TunnelContext> get_tunnel(std::uint32_t teid) const override;
    
    // GTP-U packet processing
    bool process_gtp_u_packet(const GtpUPacket& packet) override;
    std::optional<GtpUPacket> send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) override;
    
    // Server functions
    bool start_listening(std::uint16_t port = 2152) override;
    bool stop_listening() override;
    bool is_listening() const override;
    
    // Statistics
    std::size_t get_active_tunnels() const override;
    UsageReport get_tunnel_usage(std::uint32_t teid) override;
    ControlPlaneStats get_control_plane_stats() const;

private:
    // GTP-U packet encoding/decoding
    std::vector<std::uint8_t> encode_gtp_u_header(const GtpUHeader& header);
    std::optional<GtpUHeader> decode_gtp_u_header(const std::vector<std::uint8_t>& data);
    std::size_t gtp_u_optional_part_size(const GtpUHeader& header) const;
    std::optional<std::size_t> decode_gtp_u_header_size(const std::vector<std::uint8_t>& data) const;
    
    // Socket management
    void udp_listener_thread();
    bool send_raw_udp(const std::string& dest_ip, std::uint16_t dest_port, const std::vector<std::uint8_t>& data);
    
    // TEID to tunnel mapping
    std::unordered_map<std::uint32_t, N3TunnelContext> tunnels_;
    std::unordered_map<std::string, std::uint32_t> session_to_teid_;  // "imsi:pdu_session_id" -> teid
    
    mutable std::recursive_mutex tunnel_mutex_;
    
    std::uint16_t listen_port_ {2152};
    std::atomic<bool> listening_ {false};
    std::unique_ptr<std::thread> listener_thread_;
    
    std::queue<GtpUPacket> packet_queue_;
    std::mutex queue_mutex_;

    mutable std::mutex control_plane_stats_mutex_;
    ControlPlaneStats control_plane_stats_;
    
    std::uint32_t next_teid_ {1};
};

class NetworkN4Adapter final : public IN4Interface {
public:
    NetworkN4Adapter(std::string remote_host = "127.0.0.1", int remote_port = 8805, int timeout_ms = 300, std::string local_node_id = "upf-1");

    PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) override;
    std::optional<UsageReport> query_usage_report(const std::string& imsi,
                                                  const std::string& pdu_session_id,
                                                  const std::vector<std::uint32_t>& urr_ids = {}) override;
    bool send_heartbeat() override;

private:
    struct PfcpSessionState {
        PfcpRuleSet rules;
        UsageReport usage;
        std::uint64_t version {0};
    };

    std::string session_key(const std::string& imsi, const std::string& pdu_session_id) const;
    PfcpSessionResponse validate_request(const PfcpSessionRequest& request, PfcpOperation operation) const;
    bool validate_rule_references(const PfcpRuleSet& rules, std::string* failure_detail) const;
    bool validate_rule_parameters(const PfcpRuleSet& rules, std::string* failure_detail) const;
    std::vector<PfcpPdr::SdfFilterEntry> effective_sdf_filters(const PfcpPdr& pdr) const;
    bool validate_qers(const std::vector<PfcpQer>& qers, PfcpCause* failure_cause) const;
    bool is_valid_gate_status(const std::string& gate_status) const;
    bool ensure_association();
    bool ensure_capabilities();
    bool ensure_node_features();
    PfcpSessionResponse parse_wire_response(const std::string& response_text,
                                           std::uint8_t expected_message_type,
                                           std::uint32_t expected_sequence,
                                           bool expect_seid,
                                           std::uint64_t expected_seid) const;
    std::optional<std::string> send_udp_request(const std::string& payload, int timeout_ms, int max_attempts) const;

    std::string remote_host_;
    int remote_port_ {8805};
    int timeout_ms_ {300};
    std::string local_node_id_;
    std::string local_fseid_ipv4_ {"127.0.0.1"};
    std::uint32_t recovery_time_stamp_ {0};
    mutable std::mutex state_mutex_;
    std::unordered_map<std::string, PfcpSessionState> sessions_;
    std::unordered_map<std::string, PfcpSessionResponse> replay_cache_;
    std::uint64_t version_counter_ {0};
    std::uint32_t sequence_counter_ {0};
    mutable bool association_established_ {false};
    mutable bool capabilities_exchanged_ {false};
    mutable bool node_features_exchanged_ {false};
};

class NetworkN6Adapter final : public IN6Interface {
public:
    NetworkN6Adapter(std::string remote_host = "127.0.0.1",
                     int remote_port = 30000,
                     std::string bind_endpoint = "0.0.0.0:30000",
                     int downlink_wait_timeout_ms = 250,
                     std::size_t downlink_buffer_capacity = 16,
                     std::string downlink_overflow_policy = "drop_oldest");
    ~NetworkN6Adapter();

    bool register_session(const N6SessionContext& context) override;
    bool update_session(const N6SessionContext& context) override;
    bool remove_session(const std::string& imsi, const std::string& pdu_session_id) override;
    std::optional<N6SessionContext> get_session(const std::string& imsi, const std::string& pdu_session_id) const override;
    bool forward_packet(const std::string& imsi, const std::string& pdu_session_id, const N6Packet& packet) override;
    std::optional<N6Packet> receive_from_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    std::vector<N6ForwardRecord> get_forward_history() const override;
    N6BufferStatus get_buffer_status() const override;
    std::size_t buffered_packets_for_session(const std::string& imsi, const std::string& pdu_session_id) const override;
    N6SessionBufferCounters buffer_counters_for_session(const std::string& imsi, const std::string& pdu_session_id) const override;

private:
    std::string session_key(const std::string& imsi, const std::string& pdu_session_id) const;
    bool validate_session_context(const N6SessionContext& context) const;
    bool finalize_packet(const N6SessionContext& session, N6Packet* packet) const;
    std::optional<N6Packet> build_default_packet(const N6SessionContext& session, std::size_t bytes) const;
    std::size_t calculate_wire_bytes(const N6Packet& packet) const;
    std::string encode_packet(const std::string& imsi, const std::string& pdu_session_id, const std::string& dnn, const N6Packet& packet) const;
    bool send_payload(const std::string& payload) const;
    void downlink_listener_thread();
    bool parse_downlink_wire_payload(const std::string& payload, std::string* out_session_key, N6Packet* out_packet) const;
    void stop_listener();

    std::string remote_host_;
    int remote_port_ {30000};
    std::string bind_endpoint_;
    int downlink_wait_timeout_ms_ {250};
    std::string downlink_overflow_policy_ {"drop_oldest"};
    N6BufferOverflowPolicy downlink_overflow_policy_enum_ {N6BufferOverflowPolicy::DropOldest};
    mutable std::mutex state_mutex_;
    std::unordered_map<std::string, N6SessionContext> sessions_;
    std::vector<N6ForwardRecord> history_;
    N6PacketBuffer downlink_buffer_;
    std::atomic<std::size_t> unknown_session_drop_count_ {0};
    std::atomic<bool> listening_ {false};
    std::unique_ptr<std::thread> listener_thread_;
};

class NetworkN9Adapter final : public IN9Interface {
public:
    explicit NetworkN9Adapter(bool enabled = true) : enabled_(enabled) {}

    bool forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool is_enabled() const override;

private:
    bool enabled_ {true};
};

class NetworkN19Adapter final : public IN19Interface {
public:
    explicit NetworkN19Adapter(std::string local_upf_endpoint = "127.0.0.1:2152", bool enabled = true);

    bool forward_to_local_upf(const std::string& imsi, const std::string& pdu_session_id, 
                             const std::string& target_upf_address, std::size_t bytes) override;
    bool is_enabled() const override;
    std::string get_local_upf_endpoint() const override;

private:
    std::optional<std::string> send_gtp_packet(const std::string& target_address, 
                                              const std::string& payload) const;

    std::string local_upf_endpoint_;
    bool enabled_ {true};
};

class NetworkNxAdapter final : public INxInterface {
public:
    explicit NetworkNxAdapter(bool enabled = true) : enabled_(enabled) {}

    bool forward_uplink_classified(const std::string& imsi, const std::string& pdu_session_id, 
                                  const std::string& target_upf_address, std::size_t bytes) override;
    bool set_uplink_classifier_rules(const std::vector<UplinkClassifierRule>& rules) override;
    bool add_branch_upf_endpoint(const std::string& upf_id, const std::string& address) override;
    bool is_enabled() const override;

private:
    std::optional<std::string> send_gtp_packet(const std::string& target_address, 
                                              const std::string& payload) const;
    std::string resolve_target_address(const std::string& target_upf_address) const;
    std::string classify_uplink_packet(const std::string& imsi, const std::string& pdu_session_id);

    std::vector<UplinkClassifierRule> ul_classifier_rules_;
    std::unordered_map<std::string, std::string> branch_upf_endpoints_;  // upf_id -> address
    bool enabled_ {true};
};

class NetworkNsmfAdapter final : public INsmfInterface {
public:
    NetworkNsmfAdapter() = default;

    bool send_internal_message(const InternalComponentMessage& message) override;
    std::optional<InternalComponentMessage> receive_internal_message(int timeout_ms = 100) override;
    bool register_internal_component(const std::string& component_name) override;
    bool unregister_internal_component(const std::string& component_name) override;
    std::vector<std::string> get_registered_components() const override;

private:
    std::unordered_map<std::string, std::queue<InternalComponentMessage>> message_queues_;
    std::unordered_set<std::string> registered_components_;
    mutable std::mutex queue_mutex_;
};

class NetworkSbiAdapter final : public ISbiInterface {
public:
    NetworkSbiAdapter(std::string remote_host = "127.0.0.1", int remote_port = 8080, std::string path = "/nupf-event-exposure/v1/events", int timeout_ms = 500);

    bool publish_event(const std::string& service_name, const std::string& payload) override;

private:
    std::string remote_host_;
    int remote_port_ {8080};
    std::string path_ {"/nupf-event-exposure/v1/events"};
    int timeout_ms_ {500};
};

}  // namespace upf
