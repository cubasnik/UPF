#include <algorithm>
#include <cstdlib>
#include <unordered_map>
#include <vector>

#include "upf/interfaces.hpp"
#include "upf/upf.hpp"

namespace {

class TestN3 final : public upf::IN3Interface {
public:
    bool receive_uplink_packet(const std::string&, const std::string&, std::size_t) override {
        if (uplink_should_fail) {
            return false;
        }
        ++uplink_rx;
        return true;
    }

    bool send_downlink_packet(const std::string&, const std::string&, std::size_t) override {
        if (downlink_should_fail) {
            return false;
        }
        ++downlink_tx;
        return true;
    }

    bool create_tunnel(const upf::N3TunnelContext& context) override {
        if (create_should_fail) {
            return false;
        }
        last_teid = context.teid;
        ++tunnels_created;
        return true;
    }

    bool delete_tunnel(std::uint32_t teid) override {
        if (delete_should_fail) {
            return false;
        }
        deleted_teid = teid;
        ++tunnels_deleted;
        return true;
    }

    bool update_tunnel_qos_flows(std::uint32_t, const std::vector<upf::QosFlowMapping>&) override { return true; }
    std::optional<upf::N3TunnelContext> get_tunnel(std::uint32_t) const override { return std::nullopt; }
    bool process_gtp_u_packet(const upf::GtpUPacket&) override { return true; }
    std::optional<upf::GtpUPacket> send_gtp_u_packet(std::uint32_t teid, const std::vector<std::uint8_t>& payload) override {
        if (gtp_downlink_should_fail) {
            return std::nullopt;
        }
        upf::GtpUPacket packet {};
        packet.header.version = upf::GtpVersion::V1;
        packet.header.protocol_type = true;
        packet.header.packet_type = upf::GtpPacketType::Data;
        packet.header.teid = teid;
        packet.header.message_length = static_cast<std::uint16_t>(payload.size());
        packet.payload = payload;
        last_gtp_teid = teid;
        last_gtp_payload = payload;
        ++gtp_downlink_tx;
        return packet;
    }
    bool start_listening(std::uint16_t = 2152) override { return true; }
    bool stop_listening() override { return true; }
    bool is_listening() const override { return false; }
    std::size_t get_active_tunnels() const override { return 0; }
    upf::UsageReport get_tunnel_usage(std::uint32_t) override { return upf::UsageReport {}; }

    int uplink_rx {0};
    int downlink_tx {0};
    int tunnels_created {0};
    int tunnels_deleted {0};
    std::uint32_t last_teid {0};
    std::uint32_t deleted_teid {0};
    int gtp_downlink_tx {0};
    std::uint32_t last_gtp_teid {0};
    std::vector<std::uint8_t> last_gtp_payload;
    bool uplink_should_fail {false};
    bool downlink_should_fail {false};
    bool gtp_downlink_should_fail {false};
    bool create_should_fail {false};
    bool delete_should_fail {false};
};

class TestN4 final : public upf::IN4Interface {
public:
    upf::PfcpSessionResponse apply_pfcp(const upf::PfcpSessionRequest&, upf::PfcpOperation) override {
        ++messages;
        return upf::PfcpSessionResponse {true, upf::PfcpCause::RequestAccepted, 1, false, "ok"};
    }

    std::optional<upf::UsageReport> query_usage_report(const std::string&, const std::string&, const std::vector<std::uint32_t>& = {}) override {
        return upf::UsageReport {};
    }

    bool send_heartbeat() override {
        return true;
    }

    int messages {0};
};

class TestN6 final : public upf::IN6Interface {
public:
    bool register_session(const upf::N6SessionContext& context) override {
        sessions[context.imsi + "|" + context.pdu_session_id] = context;
        ++registered;
        return true;
    }

    bool update_session(const upf::N6SessionContext& context) override {
        sessions[context.imsi + "|" + context.pdu_session_id] = context;
        ++updated;
        return true;
    }

    bool remove_session(const std::string& imsi, const std::string& pdu_session_id) override {
        sessions.erase(imsi + "|" + pdu_session_id);
        ++removed;
        return true;
    }

    std::optional<upf::N6SessionContext> get_session(const std::string& imsi, const std::string& pdu_session_id) const override {
        const auto it = sessions.find(imsi + "|" + pdu_session_id);
        if (it == sessions.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    bool forward_packet(const std::string& imsi, const std::string& pdu_session_id, const upf::N6Packet& packet) override {
        upf::N6ForwardRecord record {};
        record.imsi = imsi;
        record.pdu_session_id = pdu_session_id;
        record.direction = upf::N6TrafficDirection::Uplink;
        record.packet = packet;
        record.wire_bytes = packet.payload.size();
        history.push_back(record);
        return true;
    }

    std::optional<upf::N6Packet> receive_from_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override {
        const auto it = sessions.find(imsi + "|" + pdu_session_id);
        if (it == sessions.end()) {
            return std::nullopt;
        }
        upf::N6Packet packet {};
        packet.protocol = it->second.ipv6_enabled ? upf::N6Protocol::IPv6 : (it->second.ethernet_enabled ? upf::N6Protocol::Ethernet : upf::N6Protocol::IPv4);
        packet.payload.reserve(bytes);
        for (std::size_t index = 0; index < bytes; ++index) {
            packet.payload.push_back(static_cast<std::uint8_t>((index * 37U + 11U) & 0xFFU));
        }
        upf::N6ForwardRecord record {};
        record.imsi = imsi;
        record.pdu_session_id = pdu_session_id;
        record.direction = upf::N6TrafficDirection::Downlink;
        record.packet = packet;
        record.wire_bytes = packet.payload.size();
        history.push_back(record);
        ++received_downlink;
        return packet;
    }

    bool forward_to_data_network(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override {
        if (forward_to_data_network_should_fail) {
            return false;
        }
        const auto it = sessions.find(imsi + "|" + pdu_session_id);
        if (it == sessions.end()) {
            return false;
        }
        upf::N6Packet packet {};
        packet.protocol = it->second.ipv6_enabled ? upf::N6Protocol::IPv6 : (it->second.ethernet_enabled ? upf::N6Protocol::Ethernet : upf::N6Protocol::IPv4);
        packet.payload.resize(bytes);
        upf::N6ForwardRecord record {};
        record.imsi = imsi;
        record.pdu_session_id = pdu_session_id;
        record.direction = upf::N6TrafficDirection::Uplink;
        record.packet = packet;
        record.wire_bytes = packet.payload.size();
        history.push_back(record);
        forwarded_bytes += bytes;
        ++forwards;
        return true;
    }

    std::vector<upf::N6ForwardRecord> get_forward_history() const override {
        return history;
    }

    upf::N6BufferStatus get_buffer_status() const override {
        return buffer_status;
    }

    std::size_t buffered_packets_for_session(const std::string&, const std::string&) const override {
        return buffer_status.buffered_packets;
    }

    upf::N6SessionBufferCounters buffer_counters_for_session(const std::string&, const std::string&) const override {
        return upf::N6SessionBufferCounters {0, 0, 0, 0, 0, 0, 0, buffer_status.buffered_packets};
    }

    std::unordered_map<std::string, upf::N6SessionContext> sessions;
    std::vector<upf::N6ForwardRecord> history;
    upf::N6BufferStatus buffer_status {};
    int registered {0};
    int updated {0};
    int removed {0};
    int received_downlink {0};
    int forwards {0};
    std::size_t forwarded_bytes {0};
    bool forward_to_data_network_should_fail {false};
};

class TestN9 final : public upf::IN9Interface {
public:
    bool forward_to_branch_upf(const std::string&, const std::string&, std::size_t bytes) override {
        if (forward_should_fail) {
            return false;
        }
        forwarded_bytes += bytes;
        ++forwards;
        return true;
    }

    bool is_enabled() const override {
        return true;
    }

    int forwards {0};
    std::size_t forwarded_bytes {0};
    bool forward_should_fail {false};
};

class TestN19 final : public upf::IN19Interface {
public:
    bool forward_to_local_upf(const std::string&, const std::string&, const std::string& target_upf_address, std::size_t bytes) override {
        if (forward_should_fail) {
            return false;
        }
        last_target = target_upf_address;
        forwarded_bytes += bytes;
        ++forwards;
        return true;
    }

    bool is_enabled() const override {
        return enabled;
    }

    std::string get_local_upf_endpoint() const override {
        return "127.0.0.1:2152";
    }

    bool enabled {true};
    int forwards {0};
    std::size_t forwarded_bytes {0};
    std::string last_target;
    bool forward_should_fail {false};
};

class TestNx final : public upf::INxInterface {
public:
    bool forward_uplink_classified(const std::string&, const std::string&, const std::string& target_upf_address, std::size_t bytes) override {
        if (forward_should_fail) {
            return false;
        }
        last_target = target_upf_address;
        forwarded_bytes += bytes;
        ++forwards;
        return true;
    }

    bool set_uplink_classifier_rules(const std::vector<upf::UplinkClassifierRule>&) override {
        return true;
    }

    bool add_branch_upf_endpoint(const std::string&, const std::string&) override {
        return true;
    }

    bool is_enabled() const override {
        return enabled;
    }

    bool enabled {true};
    int forwards {0};
    std::size_t forwarded_bytes {0};
    std::string last_target;
    bool forward_should_fail {false};
};

class TestNsmf final : public upf::INsmfInterface {
public:
    bool send_internal_message(const upf::InternalComponentMessage& message) override {
        if (std::find(components.begin(), components.end(), message.target_component) == components.end()) {
            return false;
        }
        messages.push_back(message);
        return true;
    }

    std::optional<upf::InternalComponentMessage> receive_internal_message(int = 100) override {
        return std::nullopt;
    }

    bool register_internal_component(const std::string& component_name) override {
        if (std::find(components.begin(), components.end(), component_name) != components.end()) {
            return false;
        }
        components.push_back(component_name);
        return true;
    }

    bool unregister_internal_component(const std::string& component_name) override {
        const auto it = std::find(components.begin(), components.end(), component_name);
        if (it == components.end()) {
            return false;
        }
        components.erase(it);
        return true;
    }

    std::vector<std::string> get_registered_components() const override {
        return components;
    }

    std::vector<std::string> components;
    std::vector<upf::InternalComponentMessage> messages;
};

class TestSbi final : public upf::ISbiInterface {
public:
    bool publish_event(const std::string&, const std::string&) override {
        return true;
    }
};

}  // namespace

int main() {
    TestN3 n3;
    TestN4 n4;
    TestN6 n6;
    TestN9 n9;
    TestN19 n19;
    TestNx nx;
    TestNsmf nsmf;
    TestSbi sbi;

    nsmf.register_internal_component("DU-UP");

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;
    peers.n19 = &n19;
    peers.nx = &nx;
    peers.nsmf = &nsmf;

    upf::UpfNode node(n4, sbi, peers);
    if (!node.start()) {
        return EXIT_FAILURE;
    }

    const auto registered = nsmf.get_registered_components();
    if (std::find(registered.begin(), registered.end(), "UPF-CTRL") == registered.end()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest branch_req {};
    branch_req.imsi = "250200123456789";
    branch_req.pdu_session_id = "12";
    branch_req.teid = "0x1200";
    branch_req.ue_ipv4 = "10.12.0.2";
    branch_req.dnn = "distributed";
    branch_req.s_nssai = "1-010203";
    branch_req.rules.steering.mode = upf::SteeringMode::NxBranch;
    branch_req.rules.steering.target_endpoint = "branch-a:2152";
    branch_req.rules.steering.nsmf_component = "DU-UP";
    branch_req.rules.steering.mirror_to_n9 = true;
    branch_req.rules.anchor_upf = "policy:nx";

    if (!node.establish_session(branch_req)) {
        return EXIT_FAILURE;
    }
    if (n6.registered != 1) {
        return EXIT_FAILURE;
    }
    const auto branch_n6 = n6.get_session(branch_req.imsi, branch_req.pdu_session_id);
    if (!branch_n6.has_value() || branch_n6->ue_ipv4 != branch_req.ue_ipv4) {
        return EXIT_FAILURE;
    }
    if (n3.tunnels_created != 1 || n3.last_teid != 0x1200) {
        return EXIT_FAILURE;
    }
    if (nsmf.messages.empty() || nsmf.messages.back().message_type != "SESSION_ESTABLISH") {
        return EXIT_FAILURE;
    }

    if (!node.process_uplink(branch_req.imsi, branch_req.pdu_session_id, 1000)) {
        return EXIT_FAILURE;
    }
    if (!node.process_downlink(branch_req.imsi, branch_req.pdu_session_id, 400)) {
        return EXIT_FAILURE;
    }
    if (nx.forwards != 1 || nx.last_target != "branch-a:2152") {
        return EXIT_FAILURE;
    }
    if (n6.forwards != 1) {
        return EXIT_FAILURE;
    }
    if (n9.forwards != 1) {
        return EXIT_FAILURE;
    }
    if (n6.received_downlink != 1) {
        return EXIT_FAILURE;
    }
    if (n3.gtp_downlink_tx != 1 || n3.last_gtp_teid != 0x1200 || n3.last_gtp_payload.size() != 400) {
        return EXIT_FAILURE;
    }
    std::vector<std::uint8_t> expected_downlink_payload;
    expected_downlink_payload.reserve(400);
    for (std::size_t index = 0; index < 400; ++index) {
        expected_downlink_payload.push_back(static_cast<std::uint8_t>((index * 37U + 11U) & 0xFFU));
    }
    if (n3.last_gtp_payload != expected_downlink_payload) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest modify_req = branch_req;
    modify_req.teid = "0x12A0";
    modify_req.ue_ipv4 = "10.12.0.20";
    modify_req.rules.steering.mode = upf::SteeringMode::N19Local;
    modify_req.rules.steering.target_endpoint = "regional-upf:2152";
    modify_req.rules.steering.mirror_to_n9 = false;
    modify_req.rules.steering.nsmf_component = "DU-UP";
    modify_req.rules.anchor_upf = "policy:n19";
    modify_req.ue_ipv6 = "2001:db8:12::20";
    modify_req.prefer_n6_ipv6 = true;
    if (!node.modify_session(modify_req)) {
        return EXIT_FAILURE;
    }
    if (n6.updated != 1) {
        return EXIT_FAILURE;
    }
    const auto modified_n6 = n6.get_session(modify_req.imsi, modify_req.pdu_session_id);
    if (!modified_n6.has_value() || modified_n6->ue_ipv6 != modify_req.ue_ipv6 || !modified_n6->ipv6_enabled) {
        return EXIT_FAILURE;
    }
    if (n3.tunnels_created != 2 || n3.tunnels_deleted != 1 || n3.last_teid != 0x12A0 || n3.deleted_teid != 0x1200) {
        return EXIT_FAILURE;
    }
    if (nsmf.messages.empty() || nsmf.messages.back().message_type != "SESSION_MODIFY") {
        return EXIT_FAILURE;
    }

    const auto modified_ctx = node.find_session(modify_req.imsi, modify_req.pdu_session_id);
    if (!modified_ctx.has_value() ||
        modified_ctx->n19_endpoint != "regional-upf:2152" ||
        !modified_ctx->nx_endpoint.empty() ||
        modified_ctx->mirror_to_n9) {
        return EXIT_FAILURE;
    }

    if (!node.process_uplink(modify_req.imsi, modify_req.pdu_session_id, 700)) {
        return EXIT_FAILURE;
    }
    if (n19.forwards != 1 || n19.last_target != "regional-upf:2152") {
        return EXIT_FAILURE;
    }
    if (nx.forwards != 1) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest local_req {};
    local_req.imsi = "250200123456790";
    local_req.pdu_session_id = "13";
    local_req.teid = "0x1300";
    local_req.ue_ipv4 = "10.13.0.2";
    local_req.dnn = "enterprise";
    local_req.s_nssai = "1-010203";
    local_req.rules.anchor_upf = "n19:regional-upf:2152";
    local_req.ue_mac = "02:11:22:33:44:55";
    local_req.prefer_n6_ethernet = true;

    if (!node.establish_session(local_req)) {
        return EXIT_FAILURE;
    }
    const auto local_n6 = n6.get_session(local_req.imsi, local_req.pdu_session_id);
    if (!local_n6.has_value() || local_n6->ue_mac != local_req.ue_mac || !local_n6->ethernet_enabled) {
        return EXIT_FAILURE;
    }
    if (!node.process_uplink(local_req.imsi, local_req.pdu_session_id, 2000)) {
        return EXIT_FAILURE;
    }
    if (n19.forwards != 2 || n19.last_target != "regional-upf:2152") {
        return EXIT_FAILURE;
    }
    if (n6.forwards != 1) {
        return EXIT_FAILURE;
    }

    if (!node.release_session(branch_req.imsi, branch_req.pdu_session_id)) {
        return EXIT_FAILURE;
    }
    if (n6.removed != 1) {
        return EXIT_FAILURE;
    }
    if (n3.tunnels_deleted != 2 || n3.deleted_teid != 0x12A0) {
        return EXIT_FAILURE;
    }
    if (nsmf.messages.back().message_type != "SESSION_RELEASE") {
        return EXIT_FAILURE;
    }

    TestN3 failing_n3;
    failing_n3.create_should_fail = true;
    TestN4 failing_n4;
    TestN6 failing_n6;
    TestSbi failing_sbi;
    upf::UpfPeerInterfaces failing_peers {};
    failing_peers.n3 = &failing_n3;
    failing_peers.n6 = &failing_n6;

    upf::UpfNode failing_node(failing_n4, failing_sbi, failing_peers);
    if (!failing_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest failing_req {};
    failing_req.imsi = "250200123456799";
    failing_req.pdu_session_id = "99";
    failing_req.teid = "0x9900";
    failing_req.ue_ipv4 = "10.99.0.2";
    failing_req.dnn = "internet";
    failing_req.s_nssai = "1-010203";
    failing_req.qos_profile = "default";

    if (failing_node.establish_session(failing_req)) {
        return EXIT_FAILURE;
    }
    if (failing_node.find_session(failing_req.imsi, failing_req.pdu_session_id).has_value()) {
        return EXIT_FAILURE;
    }
    if (failing_n6.get_session(failing_req.imsi, failing_req.pdu_session_id).has_value()) {
        return EXIT_FAILURE;
    }
    if (failing_n6.registered != 1 || failing_n6.removed != 1) {
        return EXIT_FAILURE;
    }

    if (!failing_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 failing_release_n3;
    TestN4 failing_release_n4;
    TestN6 failing_release_n6;
    TestSbi failing_release_sbi;
    upf::UpfPeerInterfaces failing_release_peers {};
    failing_release_peers.n3 = &failing_release_n3;
    failing_release_peers.n6 = &failing_release_n6;

    upf::UpfNode failing_release_node(failing_release_n4, failing_release_sbi, failing_release_peers);
    if (!failing_release_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest failing_release_req {};
    failing_release_req.imsi = "250200123456798";
    failing_release_req.pdu_session_id = "98";
    failing_release_req.teid = "0x9800";
    failing_release_req.ue_ipv4 = "10.98.0.2";
    failing_release_req.dnn = "internet";
    failing_release_req.s_nssai = "1-010203";
    failing_release_req.qos_profile = "default";

    if (!failing_release_node.establish_session(failing_release_req)) {
        return EXIT_FAILURE;
    }

    failing_release_n3.delete_should_fail = true;
    if (failing_release_node.release_session(failing_release_req.imsi, failing_release_req.pdu_session_id)) {
        return EXIT_FAILURE;
    }
    if (failing_release_node.find_session(failing_release_req.imsi, failing_release_req.pdu_session_id).has_value()) {
        return EXIT_FAILURE;
    }
    if (failing_release_n6.get_session(failing_release_req.imsi, failing_release_req.pdu_session_id).has_value()) {
        return EXIT_FAILURE;
    }
    if (failing_release_n6.removed != 1) {
        return EXIT_FAILURE;
    }

    if (!failing_release_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 nx_fail_n3;
    TestN4 nx_fail_n4;
    TestN6 nx_fail_n6;
    TestN9 nx_fail_n9;
    TestN19 nx_fail_n19;
    TestNx nx_fail_nx;
    TestSbi nx_fail_sbi;
    upf::UpfPeerInterfaces nx_fail_peers {};
    nx_fail_peers.n3 = &nx_fail_n3;
    nx_fail_peers.n6 = &nx_fail_n6;
    nx_fail_peers.n9 = &nx_fail_n9;
    nx_fail_peers.n19 = &nx_fail_n19;
    nx_fail_peers.nx = &nx_fail_nx;

    upf::UpfNode nx_fail_node(nx_fail_n4, nx_fail_sbi, nx_fail_peers);
    if (!nx_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest nx_fail_req = branch_req;
    nx_fail_req.imsi = "250200123456791";
    nx_fail_req.pdu_session_id = "14";
    nx_fail_req.teid = "0x1400";
    nx_fail_nx.forward_should_fail = true;
    if (!nx_fail_node.establish_session(nx_fail_req)) {
        return EXIT_FAILURE;
    }
    if (nx_fail_node.process_uplink(nx_fail_req.imsi, nx_fail_req.pdu_session_id, 321)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot nx_fail_snapshot = nx_fail_node.status();
    if (nx_fail_n3.uplink_rx != 1 || nx_fail_nx.forwards != 0 || nx_fail_n19.forwards != 0 || nx_fail_n6.forwards != 0 || nx_fail_n9.forwards != 0) {
        return EXIT_FAILURE;
    }
    if (nx_fail_snapshot.stats.n3_packets_rx != 1 || nx_fail_snapshot.stats.nx_forwards != 0 || nx_fail_snapshot.stats.n19_forwards != 0 || nx_fail_snapshot.stats.n6_forwards != 0 || nx_fail_snapshot.stats.n9_forwards != 0) {
        return EXIT_FAILURE;
    }
    if (!nx_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 n19_fail_n3;
    TestN4 n19_fail_n4;
    TestN6 n19_fail_n6;
    TestN9 n19_fail_n9;
    TestN19 n19_fail_n19;
    TestNx n19_fail_nx;
    TestSbi n19_fail_sbi;
    upf::UpfPeerInterfaces n19_fail_peers {};
    n19_fail_peers.n3 = &n19_fail_n3;
    n19_fail_peers.n6 = &n19_fail_n6;
    n19_fail_peers.n9 = &n19_fail_n9;
    n19_fail_peers.n19 = &n19_fail_n19;
    n19_fail_peers.nx = &n19_fail_nx;

    upf::UpfNode n19_fail_node(n19_fail_n4, n19_fail_sbi, n19_fail_peers);
    if (!n19_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest n19_fail_req = local_req;
    n19_fail_req.imsi = "250200123456792";
    n19_fail_req.pdu_session_id = "15";
    n19_fail_req.teid = "0x1500";
    n19_fail_n19.forward_should_fail = true;
    if (!n19_fail_node.establish_session(n19_fail_req)) {
        return EXIT_FAILURE;
    }
    if (n19_fail_node.process_uplink(n19_fail_req.imsi, n19_fail_req.pdu_session_id, 654)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot n19_fail_snapshot = n19_fail_node.status();
    if (n19_fail_n3.uplink_rx != 1 || n19_fail_n19.forwards != 0 || n19_fail_n6.forwards != 0 || n19_fail_n9.forwards != 0) {
        return EXIT_FAILURE;
    }
    if (n19_fail_snapshot.stats.n3_packets_rx != 1 || n19_fail_snapshot.stats.n19_forwards != 0 || n19_fail_snapshot.stats.n6_forwards != 0 || n19_fail_snapshot.stats.n9_forwards != 0) {
        return EXIT_FAILURE;
    }
    if (!n19_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 n6_fail_n3;
    TestN4 n6_fail_n4;
    TestN6 n6_fail_n6;
    TestN9 n6_fail_n9;
    TestN19 n6_fail_n19;
    TestNx n6_fail_nx;
    TestSbi n6_fail_sbi;
    upf::UpfPeerInterfaces n6_fail_peers {};
    n6_fail_peers.n3 = &n6_fail_n3;
    n6_fail_peers.n6 = &n6_fail_n6;
    n6_fail_peers.n9 = &n6_fail_n9;
    n6_fail_peers.n19 = &n6_fail_n19;
    n6_fail_peers.nx = &n6_fail_nx;

    upf::UpfNode n6_fail_node(n6_fail_n4, n6_fail_sbi, n6_fail_peers);
    if (!n6_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest n6_fail_req {};
    n6_fail_req.imsi = "250200123456793";
    n6_fail_req.pdu_session_id = "16";
    n6_fail_req.teid = "0x1600";
    n6_fail_req.ue_ipv4 = "10.16.0.2";
    n6_fail_req.dnn = "internet";
    n6_fail_req.s_nssai = "1-010203";
    n6_fail_req.qos_profile = "default";
    n6_fail_n6.forward_to_data_network_should_fail = true;
    if (!n6_fail_node.establish_session(n6_fail_req)) {
        return EXIT_FAILURE;
    }
    if (n6_fail_node.process_uplink(n6_fail_req.imsi, n6_fail_req.pdu_session_id, 777)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot n6_fail_snapshot = n6_fail_node.status();
    if (n6_fail_n3.uplink_rx != 1 || n6_fail_n6.forwards != 0 || n6_fail_n9.forwards != 0 || n6_fail_n19.forwards != 0 || n6_fail_nx.forwards != 0) {
        return EXIT_FAILURE;
    }
    if (n6_fail_snapshot.stats.n3_packets_rx != 1 || n6_fail_snapshot.stats.n6_forwards != 0 || n6_fail_snapshot.stats.n9_forwards != 0 || n6_fail_snapshot.stats.n19_forwards != 0 || n6_fail_snapshot.stats.nx_forwards != 0) {
        return EXIT_FAILURE;
    }
    if (!n6_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 n9_fail_n3;
    TestN4 n9_fail_n4;
    TestN6 n9_fail_n6;
    TestN9 n9_fail_n9;
    TestN19 n9_fail_n19;
    TestNx n9_fail_nx;
    TestSbi n9_fail_sbi;
    upf::UpfPeerInterfaces n9_fail_peers {};
    n9_fail_peers.n3 = &n9_fail_n3;
    n9_fail_peers.n6 = &n9_fail_n6;
    n9_fail_peers.n9 = &n9_fail_n9;
    n9_fail_peers.n19 = &n9_fail_n19;
    n9_fail_peers.nx = &n9_fail_nx;

    upf::UpfNode n9_fail_node(n9_fail_n4, n9_fail_sbi, n9_fail_peers);
    if (!n9_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest n9_fail_req {};
    n9_fail_req.imsi = "250200123456794";
    n9_fail_req.pdu_session_id = "17";
    n9_fail_req.teid = "0x1700";
    n9_fail_req.ue_ipv4 = "10.17.0.2";
    n9_fail_req.dnn = "internet";
    n9_fail_req.s_nssai = "1-010203";
    n9_fail_req.qos_profile = "default";
    n9_fail_n9.forward_should_fail = true;
    if (!n9_fail_node.establish_session(n9_fail_req)) {
        return EXIT_FAILURE;
    }
    if (n9_fail_node.process_uplink(n9_fail_req.imsi, n9_fail_req.pdu_session_id, 888)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot n9_fail_snapshot = n9_fail_node.status();
    if (n9_fail_n3.uplink_rx != 1 || n9_fail_n6.forwards != 1 || n9_fail_n9.forwards != 0 || n9_fail_n19.forwards != 0 || n9_fail_nx.forwards != 0) {
        return EXIT_FAILURE;
    }
    if (n9_fail_snapshot.stats.n3_packets_rx != 1 || n9_fail_snapshot.stats.n6_forwards != 1 || n9_fail_snapshot.stats.n9_forwards != 0 || n9_fail_snapshot.stats.n19_forwards != 0 || n9_fail_snapshot.stats.nx_forwards != 0) {
        return EXIT_FAILURE;
    }
    if (!n9_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 uplink_n3_fail_n3;
    TestN4 uplink_n3_fail_n4;
    TestN6 uplink_n3_fail_n6;
    TestN9 uplink_n3_fail_n9;
    TestN19 uplink_n3_fail_n19;
    TestNx uplink_n3_fail_nx;
    TestSbi uplink_n3_fail_sbi;
    upf::UpfPeerInterfaces uplink_n3_fail_peers {};
    uplink_n3_fail_peers.n3 = &uplink_n3_fail_n3;
    uplink_n3_fail_peers.n6 = &uplink_n3_fail_n6;
    uplink_n3_fail_peers.n9 = &uplink_n3_fail_n9;
    uplink_n3_fail_peers.n19 = &uplink_n3_fail_n19;
    uplink_n3_fail_peers.nx = &uplink_n3_fail_nx;

    upf::UpfNode uplink_n3_fail_node(uplink_n3_fail_n4, uplink_n3_fail_sbi, uplink_n3_fail_peers);
    if (!uplink_n3_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest uplink_n3_fail_req {};
    uplink_n3_fail_req.imsi = "250200123456795";
    uplink_n3_fail_req.pdu_session_id = "18";
    uplink_n3_fail_req.teid = "0x1800";
    uplink_n3_fail_req.ue_ipv4 = "10.18.0.2";
    uplink_n3_fail_req.dnn = "internet";
    uplink_n3_fail_req.s_nssai = "1-010203";
    uplink_n3_fail_req.qos_profile = "default";
    uplink_n3_fail_n3.uplink_should_fail = true;
    if (!uplink_n3_fail_node.establish_session(uplink_n3_fail_req)) {
        return EXIT_FAILURE;
    }
    if (uplink_n3_fail_node.process_uplink(uplink_n3_fail_req.imsi, uplink_n3_fail_req.pdu_session_id, 999)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot uplink_n3_fail_snapshot = uplink_n3_fail_node.status();
    if (uplink_n3_fail_n3.uplink_rx != 0 || uplink_n3_fail_n6.forwards != 0 || uplink_n3_fail_n9.forwards != 0 || uplink_n3_fail_n19.forwards != 0 || uplink_n3_fail_nx.forwards != 0) {
        return EXIT_FAILURE;
    }
    if (uplink_n3_fail_snapshot.stats.n3_packets_rx != 0 || uplink_n3_fail_snapshot.stats.n6_forwards != 0 || uplink_n3_fail_snapshot.stats.n9_forwards != 0 || uplink_n3_fail_snapshot.stats.n19_forwards != 0 || uplink_n3_fail_snapshot.stats.nx_forwards != 0) {
        return EXIT_FAILURE;
    }
    if (!uplink_n3_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    TestN3 downlink_fail_n3;
    TestN4 downlink_fail_n4;
    TestN6 downlink_fail_n6;
    TestSbi downlink_fail_sbi;
    upf::UpfPeerInterfaces downlink_fail_peers {};
    downlink_fail_peers.n3 = &downlink_fail_n3;
    downlink_fail_peers.n6 = &downlink_fail_n6;

    upf::UpfNode downlink_fail_node(downlink_fail_n4, downlink_fail_sbi, downlink_fail_peers);
    if (!downlink_fail_node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest downlink_fail_req {};
    downlink_fail_req.imsi = "250200123456796";
    downlink_fail_req.pdu_session_id = "19";
    downlink_fail_req.teid = "0x1900";
    downlink_fail_req.ue_ipv4 = "10.19.0.2";
    downlink_fail_req.dnn = "internet";
    downlink_fail_req.s_nssai = "1-010203";
    downlink_fail_req.qos_profile = "default";
    downlink_fail_n3.gtp_downlink_should_fail = true;
    downlink_fail_n3.downlink_should_fail = true;
    if (!downlink_fail_node.establish_session(downlink_fail_req)) {
        return EXIT_FAILURE;
    }
    if (downlink_fail_node.process_downlink(downlink_fail_req.imsi, downlink_fail_req.pdu_session_id, 222)) {
        return EXIT_FAILURE;
    }
    const upf::UpfStatusSnapshot downlink_fail_snapshot = downlink_fail_node.status();
    if (downlink_fail_n6.received_downlink != 1 || downlink_fail_n3.gtp_downlink_tx != 0 || downlink_fail_n3.downlink_tx != 0) {
        return EXIT_FAILURE;
    }
    if (downlink_fail_snapshot.stats.n3_packets_tx != 0) {
        return EXIT_FAILURE;
    }
    if (!downlink_fail_node.stop()) {
        return EXIT_FAILURE;
    }

    const upf::UpfStatusSnapshot snapshot = node.status();
    if (snapshot.stats.nx_forwards != 1 || snapshot.stats.n19_forwards != 2 || snapshot.stats.nsmf_messages < 3 || !snapshot.n6_buffer.has_value()) {
        return EXIT_FAILURE;
    }
    if (n6.history.size() < 2 ||
        n6.history[0].direction != upf::N6TrafficDirection::Uplink ||
        n6.history[1].direction != upf::N6TrafficDirection::Downlink) {
        return EXIT_FAILURE;
    }

    if (!node.stop()) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}