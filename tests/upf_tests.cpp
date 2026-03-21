#include <cstdlib>

#include "upf/adapters/console_adapters.hpp"
#include "upf/upf.hpp"

int main() {
    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6;
    upf::ConsoleN9Adapter n9(true);
    upf::ConsoleSbiAdapter sbi;

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;

    upf::UpfNode node(n4, sbi, peers);
    if (!node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest req {};
    req.imsi = "001010123456789";
    req.pdu_session_id = "5";
    req.teid = "0x111";
    req.ue_ipv4 = "10.0.0.10";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.qos_profile = "default";

    if (!node.establish_session(req)) {
        return EXIT_FAILURE;
    }
    if (!node.modify_session(req)) {
        return EXIT_FAILURE;
    }
    if (!node.release_session(req.imsi, req.pdu_session_id)) {
        return EXIT_FAILURE;
    }

    node.stop();
    return EXIT_SUCCESS;
}
