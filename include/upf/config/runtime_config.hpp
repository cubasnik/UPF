#pragma once

#include <string>

namespace upf {

struct RuntimeConfig {
    std::string node_id {"upf-1"};
    std::string n3_bind {"0.0.0.0:2152"};
    std::string n4_bind {"0.0.0.0:8805"};
    std::string n6_bind {"0.0.0.0:30000"};
    std::string n4_remote_host {"127.0.0.1"};
    int n4_remote_port {8805};
    int n4_timeout_ms {300};
    std::string sbi_host {"127.0.0.1"};
    int sbi_port {8080};
    std::string sbi_path {"/nupf-event-exposure/v1/events"};
    int sbi_timeout_ms {500};
    bool enable_n9 {true};
    bool strict_pfcp {true};
    int heartbeat_interval_ms {1000};
};

RuntimeConfig load_runtime_config(const std::string& path);

}  // namespace upf
