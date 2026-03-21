#include <cstdlib>

#include "upf/config/runtime_config.hpp"

int main() {
    const upf::RuntimeConfig cfg = upf::load_runtime_config("config/upf-config.yaml");
    if (cfg.node_id != "upf-1") {
        return EXIT_FAILURE;
    }
    if (!cfg.enable_n9) {
        return EXIT_FAILURE;
    }
    if (cfg.heartbeat_interval_ms != 1000) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
