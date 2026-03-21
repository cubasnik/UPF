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
    std::string dnn;
    std::string s_nssai;
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
    std::size_t sbi_notifications {0};
};

struct UpfStatusSnapshot {
    UpfState state {UpfState::Idle};
    std::size_t active_sessions {0};
    UpfStats stats {};
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

struct PfcpPdr {
    std::uint32_t id {0};
    std::uint32_t precedence {0};
    std::string ue_ipv4;
    std::uint32_t far_id {0};
    std::uint32_t qer_id {0};
    std::uint32_t urr_id {0};
};

struct PfcpFar {
    std::uint32_t id {0};
    std::string action;
    std::string forward_to;
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

struct PfcpRuleSet {
    std::vector<PfcpPdr> pdrs;
    std::vector<PfcpFar> fars;
    std::vector<PfcpUrr> urrs;
    std::vector<PfcpQer> qers;
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
    std::string dnn;
    std::string s_nssai;
    std::string qos_profile;
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

struct UsageReport {
    std::uint64_t bytes_ul {0};
    std::uint64_t bytes_dl {0};
    std::uint64_t packets_ul {0};
    std::uint64_t packets_dl {0};
};

class IN3Interface {
public:
    virtual ~IN3Interface() = default;
    virtual bool receive_uplink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool send_downlink_packet(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
};

class IN4Interface {
public:
    virtual ~IN4Interface() = default;
    virtual PfcpSessionResponse apply_pfcp(const PfcpSessionRequest& request, PfcpOperation operation) = 0;
    virtual std::optional<UsageReport> query_usage_report(const std::string& imsi, const std::string& pdu_session_id) = 0;
    virtual bool send_heartbeat() = 0;
};

class IN6Interface {
public:
    virtual ~IN6Interface() = default;
    virtual bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
};

class IN9Interface {
public:
    virtual ~IN9Interface() = default;
    virtual bool forward_to_branch_upf(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) = 0;
    virtual bool is_enabled() const = 0;
};

class ISbiInterface {
public:
    virtual ~ISbiInterface() = default;
    virtual bool publish_event(const std::string& service_name, const std::string& payload) = 0;
};

struct UpfPeerInterfaces {
    IN3Interface* n3 {nullptr};
    IN6Interface* n6 {nullptr};
    IN9Interface* n9 {nullptr};
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

    virtual bool notify_sbi(const std::string& service_name, const std::string& payload) = 0;
    virtual UpfStatusSnapshot status() const = 0;
    virtual void clear_stats() = 0;
};

const char* to_string(UpfState state);
const char* to_string(PfcpCause cause);

}  // namespace upf
