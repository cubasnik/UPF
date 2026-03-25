#include <cstdlib>
#include <string>
#include "upf/adapters/console_adapters.hpp"
#include "upf/node.hpp"

int main() {
    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6;
    upf::ConsoleN9Adapter n9(true);
    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;
    upf::UpfNode node(n4, *(upf::ISbiInterface*)nullptr, peers); // Sbi не нужен для сессий
    if (!node.start()) return EXIT_FAILURE;
    upf::PfcpSessionRequest req {};
    req.imsi = "250200123456789";
    req.pdu_session_id = "5";
    req.teid = "0x111";
    req.ue_ipv4 = "10.0.0.10";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.qos_profile = "default";
    if (!node.establish_session(req)) return EXIT_FAILURE;
    if (!node.process_uplink(req.imsi, req.pdu_session_id, 256)) return EXIT_FAILURE;
    if (!node.process_downlink(req.imsi, req.pdu_session_id, 256)) return EXIT_FAILURE;
    upf::SessionRequest sreq;
    sreq.imsi = req.imsi;
    sreq.pdu_session_id = static_cast<uint32_t>(std::stoul(req.pdu_session_id));
    // Остальные поля не обязательны для modify_session в этом тесте
    if (!node.modify_session(sreq)) return EXIT_FAILURE;
    if (!node.release_session(req.imsi, static_cast<uint32_t>(std::stoul(req.pdu_session_id)))) return EXIT_FAILURE;
    node.stop();
    return EXIT_SUCCESS;
}
