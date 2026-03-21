#pragma once

#include "upf/interfaces.hpp"

namespace upf {

class NetworkN3Adapter final : public IN3Interface {
public:
    bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
};

class NetworkN4Adapter final : public IN4Interface {
public:
    NetworkN4Adapter(std::string remote_host = "127.0.0.1", int remote_port = 8805, int timeout_ms = 300);

    PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) override;
    std::optional<UsageReport> query_usage_report(const std::string& imsi, const std::string& pdu_session_id) override;
    bool send_heartbeat() override;

private:
    std::optional<std::string> send_udp_request(const std::string& payload) const;

    std::string remote_host_;
    int remote_port_ {8805};
    int timeout_ms_ {300};
};

class NetworkN6Adapter final : public IN6Interface {
public:
    bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
};

class NetworkN9Adapter final : public IN9Interface {
public:
    explicit NetworkN9Adapter(bool enabled = true) : enabled_(enabled) {}

    bool forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool is_enabled() const override;

private:
    bool enabled_ {true};
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
