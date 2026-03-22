#include "upf/config/runtime_config.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string>

namespace upf {

namespace {

std::string trim(std::string value) {
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(), value.end());
    return value;
}

std::string unquote(std::string value) {
    value = trim(value);
    if (!value.empty() && value.back() == ',') {
        value.pop_back();
    }
    value = trim(value);
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        return value.substr(1, value.size() - 2);
    }
    return value;
}

bool parse_bool(const std::string& value, bool fallback) {
    if (value == "true" || value == "1") {
        return true;
    }
    if (value == "false" || value == "0") {
        return false;
    }
    return fallback;
}

int parse_int(const std::string& value, int fallback) {
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

void apply_key_value(RuntimeConfig& cfg, const std::string& raw_key, const std::string& raw_value) {
    std::string key = trim(raw_key);
    key.erase(std::remove(key.begin(), key.end(), '"'), key.end());

    const std::string value = unquote(raw_value);

    if (key == "node_id") {
        cfg.node_id = value;
    } else if (key == "n3_bind") {
        cfg.n3_bind = value;
    } else if (key == "n4_bind") {
        cfg.n4_bind = value;
    } else if (key == "n6_bind") {
        cfg.n6_bind = value;
    } else if (key == "n6_remote_host") {
        cfg.n6_remote_host = value;
    } else if (key == "n6_remote_port") {
        cfg.n6_remote_port = parse_int(value, cfg.n6_remote_port);
    } else if (key == "n6_default_protocol") {
        cfg.n6_default_protocol = value;
    } else if (key == "n6_downlink_wait_timeout_ms") {
        cfg.n6_downlink_wait_timeout_ms = parse_int(value, cfg.n6_downlink_wait_timeout_ms);
    } else if (key == "n6_buffer_capacity") {
        cfg.n6_buffer_capacity = static_cast<std::size_t>(std::max(1, parse_int(value, static_cast<int>(cfg.n6_buffer_capacity))));
    } else if (key == "n6_buffer_overflow_policy") {
        cfg.n6_buffer_overflow_policy = value;
    } else if (key == "enable_n9") {
        cfg.enable_n9 = parse_bool(value, cfg.enable_n9);
    } else if (key == "strict_pfcp") {
        cfg.strict_pfcp = parse_bool(value, cfg.strict_pfcp);
    } else if (key == "n4_remote_host") {
        cfg.n4_remote_host = value;
    } else if (key == "n4_remote_port") {
        cfg.n4_remote_port = parse_int(value, cfg.n4_remote_port);
    } else if (key == "n4_timeout_ms") {
        cfg.n4_timeout_ms = parse_int(value, cfg.n4_timeout_ms);
    } else if (key == "sbi_host") {
        cfg.sbi_host = value;
    } else if (key == "sbi_port") {
        cfg.sbi_port = parse_int(value, cfg.sbi_port);
    } else if (key == "sbi_path") {
        cfg.sbi_path = value;
    } else if (key == "sbi_timeout_ms") {
        cfg.sbi_timeout_ms = parse_int(value, cfg.sbi_timeout_ms);
    } else if (key == "heartbeat_interval_ms") {
        cfg.heartbeat_interval_ms = parse_int(value, cfg.heartbeat_interval_ms);
    }
}

}  // namespace

RuntimeConfig load_runtime_config(const std::string& path) {
    RuntimeConfig cfg {};

    std::ifstream input(path);
    if (!input.is_open()) {
        return cfg;
    }

    std::string line;
    while (std::getline(input, line)) {
        const std::string cleaned = trim(line);
        if (cleaned.empty() || cleaned[0] == '#') {
            continue;
        }

        const std::size_t pos = cleaned.find(':');
        if (pos == std::string::npos) {
            continue;
        }

        const std::string key = cleaned.substr(0, pos);
        const std::string value = cleaned.substr(pos + 1);
        apply_key_value(cfg, key, value);
    }

    return cfg;
}

}  // namespace upf
