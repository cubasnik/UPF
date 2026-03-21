#pragma once

#include <iostream>
#include <unordered_set>
#include <string>
#include <unordered_map>

#include "upf/interfaces.hpp"

namespace upf {

class ConsoleN3Adapter final : public IN3Interface {
public:
    bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
};

class ConsoleN4Adapter final : public IN4Interface {
public:
    PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) override;
    std::optional<UsageReport> query_usage_report(const std::string& imsi, const std::string& pdu_session_id) override;
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
    bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
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
