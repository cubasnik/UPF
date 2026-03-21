#include <iostream>

#include "upf/adapters/console_adapters.hpp"
#include "upf/cli.hpp"
#include "upf/config/runtime_config.hpp"
#include "upf/upf.hpp"

int main() {
    upf::RuntimeConfig cfg = upf::load_runtime_config("config/upf-config.yaml");
    upf::UpfCli cli(cfg);

    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6;
    upf::ConsoleN9Adapter n9(cfg.enable_n9);
    upf::ConsoleSbiAdapter sbi;

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;

    upf::UpfNode node(n4, sbi, peers);
    node.start();

    upf::PfcpSessionRequest request {};
    request.imsi = "001010123456789";
    request.pdu_session_id = "10";
    request.teid = "0x1001";
    request.ue_ipv4 = "10.10.0.2";
    request.dnn = "internet";
    request.s_nssai = "1-010203";
    request.qos_profile = "default";

    node.establish_session(request);
    node.process_uplink(request.imsi, request.pdu_session_id, 1500);
    node.process_downlink(request.imsi, request.pdu_session_id, 1200);
    node.notify_sbi("nupf-event-exposure", "session-up");
    node.tick();

    const auto status = node.status();
    std::cout << "UPF state=" << upf::to_string(status.state)
              << " active_sessions=" << status.active_sessions
              << " n4_messages=" << status.stats.n4_messages
              << "\n";

    std::cout << cli.execute("show running") << "\n";

    node.release_session(request.imsi, request.pdu_session_id);
    node.stop();
    return 0;
}
