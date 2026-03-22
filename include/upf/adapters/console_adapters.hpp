#pragma once

#include "upf/modules/n6_packet_buffer.hpp"

#include <cstddef>
#include <iostream>
#include <mutex>
#include <unordered_set>
#include <string>
#include <unordered_map>
#include <vector>

#include "upf/interfaces.hpp"

namespace upf {

class ConsoleN3Adapter final : public IN3Interface {
public:
    bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    
    bool create_tunnel(const N3TunnelContext& context) override;
    bool delete_tunnel(std::uint32_t teid) override;
    bool update_tunnel_qos_flows(std::uint32_t teid, const std::vector<QosFlowMapping>& qos_flows) override;
    std::optional<N3TunnelContext> get_tunnel(std::uint32_t teid) const override;
    
    bool process_gtp_u_packet(const GtpUPacket& packet) override;
    std::optional<GtpUPacket> send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) override;
    
    bool start_listening(std::uint16_t port = 2152) override;
    bool stop_listening() override;
    bool is_listening() const override;
    
    std::size_t get_active_tunnels() const override;
    UsageReport get_tunnel_usage(std::uint32_t teid) override;
};

class ConsoleN4Adapter final : public IN4Interface {
public:
    PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) override;
    std::optional<UsageReport> query_usage_report(const std::string& imsi,
                                                  const std::string& pdu_session_id,
                                                  const std::vector<std::uint32_t>& urr_ids = {}) override;
    bool send_heartbeat() override;
    void set_heartbeat_ok(bool value);

private:
    PfcpSessionResponse validate_request(const PfcpSessionRequest& request, PfcpOperation operation) const;
    static bool is_valid_gate_status(const std::string& gate_status);
    std::string key_of(const std::string& imsi, const std::string& pdu_session_id) const;

    bool heartbeat_ok_ {true};
    std::uint64_t version_ {0};
    std::unordered_map<std::string, UsageReport> usage_reports_;
    std::unordered_map<std::string, std::uint64_t> session_versions_;
    std::unordered_map<std::string, PfcpSessionResponse> replay_cache_;
};

class ConsoleN6Adapter final : public IN6Interface {
public:
    explicit ConsoleN6Adapter(std::size_t downlink_buffer_capacity = 16,
                              std::string downlink_overflow_policy = "drop_oldest");

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
    std::string key_of(const std::string& imsi, const std::string& pdu_session_id) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, N6SessionContext> sessions_;
    std::vector<N6ForwardRecord> history_;
    std::string downlink_overflow_policy_ {"drop_oldest"};
    N6BufferOverflowPolicy downlink_overflow_policy_enum_ {N6BufferOverflowPolicy::DropOldest};
    N6PacketBuffer downlink_buffer_;
};

class ConsoleN9Adapter final : public IN9Interface {
public:
    explicit ConsoleN9Adapter(bool enabled = true) : enabled_(enabled) {}

    bool forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool is_enabled() const override;
    void set_enabled(bool enabled);

private:
    bool enabled_ {true};
};

class ConsoleSbiAdapter final : public ISbiInterface {
public:
    bool publish_event(const std::string& service_name, const std::string& payload) override;
};

}  // namespace upf
