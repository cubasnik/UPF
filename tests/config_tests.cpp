#include <cstdlib>

#include "upf/config/runtime_config.hpp"
#include "upf/upf.hpp"

int main() {
    const upf::RuntimeConfig cfg = upf::load_runtime_config("config/upf-config.yaml");
    if (cfg.node_id != "upf-1") {
        return EXIT_FAILURE;
    }
    if (!cfg.enable_n9) {
        return EXIT_FAILURE;
    }
    if (cfg.n6_remote_host != "127.0.0.1") {
        return EXIT_FAILURE;
    }
    if (cfg.n6_remote_port != 30001) {
        return EXIT_FAILURE;
    }
    if (cfg.n6_default_protocol != "ipv4") {
        return EXIT_FAILURE;
    }
    if (cfg.n6_downlink_wait_timeout_ms != 500) {
        return EXIT_FAILURE;
    }
    if (cfg.n6_buffer_capacity != 16) {
        return EXIT_FAILURE;
    }
    if (cfg.n6_buffer_overflow_policy != "drop_oldest") {
        return EXIT_FAILURE;
    }
    if (cfg.heartbeat_interval_ms != 1000) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
