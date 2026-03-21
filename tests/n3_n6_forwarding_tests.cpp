#include <cstdlib>

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

    int uplink_rx {0};
    int downlink_tx {0};
};

class TestN4 final : public upf::IN4Interface {
public:
    upf::PfcpSessionResponse apply_pfcp(const upf::PfcpSessionRequest&, upf::PfcpOperation) override {
        return upf::PfcpSessionResponse {true, upf::PfcpCause::RequestAccepted, 1, false, "ok"};
    }

    std::optional<upf::UsageReport> query_usage_report(const std::string&, const std::string&) override {
        return upf::UsageReport {};
    }

    bool send_heartbeat() override {
        return true;
    }
};

class TestN6 final : public upf::IN6Interface {
public:
    bool forward_to_data_network(const std::string&, const std::string&, std::size_t) override {
        ++forwarded;
        return true;
    }

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
    req.imsi = "001010123456789";
    req.pdu_session_id = "9";
    req.teid = "0x900";
    req.ue_ipv4 = "10.9.0.2";
    req.dnn = "internet";
    req.s_nssai = "1-010203";

    if (!node.establish_session(req)) {
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

    return EXIT_SUCCESS;
}
