// n3_network_transport_test_dl.cpp
#include <chrono>
#include <thread>
#include <vector>
#include "upf/adapters/network_adapters.hpp"

// ...helpers from original file (send_udp_datagram, etc.)...
// ...copy or #include them as needed...

int main() {
    constexpr int kListenPort = 39252;
    constexpr int kCapturePort = 39253;
    constexpr std::uint32_t kTeid = 0xABC;
    upf::NetworkN3Adapter n3;
    upf::N3TunnelContext tunnel {};
    tunnel.teid = kTeid;
    tunnel.ue_ip = "10.20.0.2";
    tunnel.gnb_ip = "127.0.0.1";
    tunnel.gnb_port = kCapturePort;
    tunnel.imsi = "250200999999999";
    tunnel.pdu_session_id = "20";
    n3.create_tunnel(tunnel);
    n3.start_listening(static_cast<std::uint16_t>(kListenPort));
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    // ...DL packet/capture tests only...
    // ...copy relevant code from original main()...
    n3.stop_listening();
    return 0;
}
