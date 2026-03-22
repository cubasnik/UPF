#include <cstdlib>
#include <unordered_map>
#include <vector>

#include "upf/interfaces.hpp"
#include "upf/upf.hpp"

namespace {

class TestN3 final : public upf::IN3Interface {
public:
    bool receive_uplink_packet(const std::string&, const std::string&, std::size_t) override {
        ++uplink_rx;
        return true;
    }

    bool send_downlink_packet(const std::string&, const std::string&, std::size_t) override {
        ++downlink_tx;
        return true;
    }

    bool create_tunnel(const upf::N3TunnelContext&) override { return true; }
    bool delete_tunnel(std::uint32_t) override { return true; }
    bool update_tunnel_qos_flows(std::uint32_t, const std::vector<upf::QosFlowMapping>&) override { return true; }
    std::optional<upf::N3TunnelContext> get_tunnel(std::uint32_t) const override { return std::nullopt; }
    bool process_gtp_u_packet(const upf::GtpUPacket&) override { return true; }
    std::optional<upf::GtpUPacket> send_gtp_u_packet(std::uint32_t, const std::vector<std::uint8_t>&) override { return std::nullopt; }
    bool start_listening(std::uint16_t = 2152) override { return true; }
    bool stop_listening() override { return true; }
    bool is_listening() const override { return false; }
    std::size_t get_active_tunnels() const override { return 0; }
    upf::UsageReport get_tunnel_usage(std::uint32_t) override { return upf::UsageReport{}; }

    int uplink_rx {0};
    int downlink_tx {0};
};

class TestN4 final : public upf::IN4Interface {
public:
    upf::PfcpSessionResponse apply_pfcp(const upf::PfcpSessionRequest&, upf::PfcpOperation) override {
        return upf::PfcpSessionResponse {true, upf::PfcpCause::RequestAccepted, 1, false, "ok"};
    }

    std::optional<upf::UsageReport> query_usage_report(const std::string&, const std::string&, const std::vector<std::uint32_t>& = {}) override {
        return upf::UsageReport {};
    }

    bool send_heartbeat() override {
        return true;
    }
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
        packet.payload.resize(bytes);
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
        ++forwarded;
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
    int forwarded {0};
};

class TestN9 final : public upf::IN9Interface {
public:
    bool forward_to_branch_upf(const std::string&, const std::string&, std::size_t) override {
        ++forwarded;
        return true;
    }

    bool is_enabled() const override {
        return true;
    }

    int forwarded {0};
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
    TestSbi sbi;

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;

    upf::UpfNode node(n4, sbi, peers);
    node.start();

    upf::PfcpSessionRequest req {};
    req.imsi = "250200123456789";
    req.pdu_session_id = "9";
    req.teid = "0x900";
    req.ue_ipv4 = "10.9.0.2";
    req.dnn = "internet";
    req.s_nssai = "1-010203";

    if (!node.establish_session(req)) {
        return EXIT_FAILURE;
    }
    if (n6.registered != 1) {
        return EXIT_FAILURE;
    }
    const auto n6_session = n6.get_session(req.imsi, req.pdu_session_id);
    if (!n6_session.has_value() || n6_session->ue_ipv4 != req.ue_ipv4 || n6_session->dnn != req.dnn) {
        return EXIT_FAILURE;
    }

    if (!node.process_uplink(req.imsi, req.pdu_session_id, 1000)) {
        return EXIT_FAILURE;
    }
    if (!node.process_downlink(req.imsi, req.pdu_session_id, 1000)) {
        return EXIT_FAILURE;
    }

    if (n3.uplink_rx != 1 || n3.downlink_tx != 1) {
        return EXIT_FAILURE;
    }
    if (n6.forwarded != 1 || n9.forwarded != 1) {
        return EXIT_FAILURE;
    }
    if (n6.received_downlink != 1) {
        return EXIT_FAILURE;
    }
    if (n6.history.size() != 2 ||
        n6.history[0].direction != upf::N6TrafficDirection::Uplink ||
        n6.history[1].direction != upf::N6TrafficDirection::Downlink) {
        return EXIT_FAILURE;
    }

    if (!node.status().n6_buffer.has_value()) {
        return EXIT_FAILURE;
    }

    if (!node.release_session(req.imsi, req.pdu_session_id)) {
        return EXIT_FAILURE;
    }
    if (n6.removed != 1) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
