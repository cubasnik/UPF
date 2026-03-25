
#include <cstdlib>
#include <string>

#include "upf/adapters/console_adapters.hpp"
#include "upf/cli.hpp"
#include "upf/node.hpp"
#include "upf/interfaces.hpp"

int main() {
    upf::RuntimeConfig cfg {};
    upf::UpfCli cli(cfg);

    if (cli.execute("set n6_remote_port not-a-number") != "ERR: invalid value for n6_remote_port") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_buffer_capacity -5") != "ERR: invalid value for n6_buffer_capacity") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set enable_n9 maybe") != "ERR: invalid value for enable_n9") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_default_protocol gre") != "ERR: invalid value for n6_default_protocol") {
        return EXIT_FAILURE;
    }

    if (cli.execute("set node_id upf-test") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_remote_host 192.0.2.10") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_remote_port 31000") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_default_protocol ipv6") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_downlink_wait_timeout_ms 650") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_buffer_capacity 24") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("set n6_buffer_overflow_policy drop_oldest") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("commit") != "OK") {
        return EXIT_FAILURE;
    }

    const std::string running = cli.execute("show running");
    if (running.find("upf-test") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_remote=192.0.2.10:31000") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_protocol=ipv6") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_downlink_wait_ms=650") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_buffer_capacity=24") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_buffer_policy=drop_oldest") == std::string::npos) {
        return EXIT_FAILURE;
    }
    if (running.find("n6_remote=192.0.2.10:31000") == std::string::npos ||
        running.find("n6_protocol=ipv6") == std::string::npos ||
        running.find("n6_buffer_capacity=24") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string running_json = cli.execute("show running json");
    if (running_json.find("\"schema\":\"upf.runtime-config.v1\"") == std::string::npos ||
        running_json.find("\"node_id\":\"upf-test\"") == std::string::npos ||
        running_json.find("\"n6_remote_host\":\"192.0.2.10\"") == std::string::npos ||
        running_json.find("\"n6_buffer_policy\":\"drop_oldest\"") == std::string::npos) {
        return EXIT_FAILURE;
    }

    if (cli.execute("show mode").find("operational") == std::string::npos) {
        return EXIT_FAILURE;
    }

    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6(1, "drop_newest");
    upf::ConsoleN9Adapter n9;
    upf::ConsoleSbiAdapter sbi;

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;

    upf::UpfNode node(n4, sbi, peers);
    if (!node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest request {};
    request.imsi = "250200123456789";
    request.pdu_session_id = "7";
    request.teid = "0x700";
    request.ue_ipv4 = "10.7.0.2";
    request.dnn = "internet";
    request.s_nssai = "1-010203";

    if (!node.establish_session(request)) {
        return EXIT_FAILURE;
    }
    if (!node.process_uplink(request.imsi, request.pdu_session_id, 128)) {
        return EXIT_FAILURE;
    }
    if (!node.process_uplink(request.imsi, request.pdu_session_id, 256)) {
        return EXIT_FAILURE;
    }

    upf::UpfCli live_cli(cfg, &node);
    const std::string live_status = live_cli.execute("show status");
    if (live_status.find("state=RUNNING") == std::string::npos ||
        live_status.find("active_sessions=1") == std::string::npos ||
        live_status.find("n6_forwards=2") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string live_status_json = live_cli.execute("show status json");
    if (live_status_json.find("\"schema\":\"upf.status.v1\"") == std::string::npos ||
        live_status_json.find("\"state\":\"RUNNING\"") == std::string::npos ||
        live_status_json.find("\"active_sessions\":1") == std::string::npos ||
        live_status_json.find("\"n6_forwards\":2") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string live_buffer = live_cli.execute("show n6-buffer");
    if (live_buffer.find("capacity=1") == std::string::npos ||
        live_buffer.find("overflow_policy=drop_newest") == std::string::npos ||
        live_buffer.find("rejected_by_policy=1") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string live_buffer_json = live_cli.execute("show n6-buffer json");
    if (live_buffer_json.find("\"schema\":\"upf.n6-buffer.v1\"") == std::string::npos ||
        live_buffer_json.find("\"capacity\":1") == std::string::npos ||
        live_buffer_json.find("\"overflow_policy\":\"drop_newest\"") == std::string::npos ||
        live_buffer_json.find("\"rejected_by_policy\":1") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string session_buffer = live_cli.execute("show n6-buffer session 250200123456789 7");
    if (session_buffer.find("imsi=250200123456789") == std::string::npos ||
        session_buffer.find("pdu=7") == std::string::npos ||
        session_buffer.find("enqueued=1") == std::string::npos ||
        session_buffer.find("dequeued=0") == std::string::npos ||
        session_buffer.find("dropped=1") == std::string::npos ||
        session_buffer.find("dropped_oldest=0") == std::string::npos ||
        session_buffer.find("dropped_newest=1") == std::string::npos ||
        session_buffer.find("dropped_session_removed=0") == std::string::npos ||
        session_buffer.find("rejected_by_policy=1") == std::string::npos ||
        session_buffer.find("buffered=1") == std::string::npos) {
        return EXIT_FAILURE;
    }

    const std::string session_buffer_json = live_cli.execute("show n6-buffer session 250200123456789 7 json");
    if (session_buffer_json.find("\"schema\":\"upf.n6-session.v1\"") == std::string::npos ||
        session_buffer_json.find("\"imsi\":\"250200123456789\"") == std::string::npos ||
        session_buffer_json.find("\"pdu\":\"7\"") == std::string::npos ||
        session_buffer_json.find("\"enqueued\":1") == std::string::npos ||
        session_buffer_json.find("\"dropped_newest\":1") == std::string::npos ||
        session_buffer_json.find("\"rejected_by_policy\":1") == std::string::npos ||
        session_buffer_json.find("\"buffered\":1") == std::string::npos) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
