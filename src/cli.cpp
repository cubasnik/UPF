#include "upf/cli.hpp"
#include "upf/modules/observability.hpp"

#include <limits>
#include <optional>
#include <sstream>
#include <string>

namespace upf {

namespace {

std::optional<int> parse_int_strict(const std::string& value, int minimum, int maximum) {
    if (value.empty()) {
        return std::nullopt;
    }

    std::size_t parsed_chars = 0;
    int parsed = 0;
    try {
        parsed = std::stoi(value, &parsed_chars);
    } catch (...) {
        return std::nullopt;
    }

    if (parsed_chars != value.size() || parsed < minimum || parsed > maximum) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<bool> parse_bool_strict(const std::string& value) {
    if (value == "true" || value == "1") {
        return true;
    }
    if (value == "false" || value == "0") {
        return false;
    }
    return std::nullopt;
}

bool is_valid_n6_protocol(const std::string& value) {
    return value == "ipv4" || value == "ipv6" || value == "ethernet";
}

bool is_valid_n6_buffer_policy(const std::string& value) {
    return value == "drop_oldest" || value == "drop_newest";
}

}  // namespace

UpfCli::UpfCli(RuntimeConfig base, const IUpfNode* live_node)
    : running_(std::move(base)), candidate_(running_), live_node_(live_node) {}

std::string UpfCli::execute(const std::string& command_line) {
    std::istringstream stream(command_line);
    std::string command;
    stream >> command;

    if (command == "set") {
        std::string key;
        std::string value;
        std::string error;
        stream >> key >> value;
        if (key.empty() || value.empty()) {
            return "ERR: usage set <key> <value>";
        }
        if (set_value(key, value, &error)) {
            return "OK";
        }
        return error.empty() ? "ERR: unknown key" : error;
    }

    if (command == "commit") {
        running_ = candidate_;
        return "OK";
    }

    if (command == "discard") {
        candidate_ = running_;
        return "OK";
    }

    if (command == "show") {
        std::string what;
        std::string format;
        stream >> what;
        stream >> format;
        if (what == "running") {
            return format == "json" ? format_runtime_config_json(running_) : format_runtime_config_text(running_);
        }
        if (what == "candidate") {
            return format == "json" ? format_runtime_config_json(candidate_) : format_runtime_config_text(candidate_);
        }
        if (what == "mode") {
            return "mode=operational";
        }
        if (what == "status") {
            if (live_node_ == nullptr) {
                return "ERR: live status unavailable";
            }
            return format == "json" ? format_upf_status_json(live_node_->status()) : format_upf_status_text(live_node_->status());
        }
        if (what == "n6-buffer") {
            const std::string scope = format;
            if (scope == "session") {
                std::string imsi;
                std::string pdu_session_id;
                std::string session_format;
                stream >> imsi >> pdu_session_id;
                stream >> session_format;
                if (live_node_ == nullptr) {
                    return "ERR: live status unavailable";
                }
                const auto session = live_node_->inspect_n6_session(imsi, pdu_session_id);
                if (!session.has_value()) {
                    return "ERR: session unavailable";
                }
                return session_format == "json" ? format_n6_session_json(*session) : format_n6_session_text(*session);
            }
            if (live_node_ == nullptr) {
                return "ERR: live status unavailable";
            }
            const auto snapshot = live_node_->status();
            if (!snapshot.n6_buffer.has_value()) {
                return "ERR: n6 buffer unavailable";
            }
            return format == "json" ? format_n6_buffer_status_json(*snapshot.n6_buffer) : format_n6_buffer_status_text(*snapshot.n6_buffer);
        }
        return "ERR: unknown show";
    }

    return "ERR: unknown command";
}

const RuntimeConfig& UpfCli::running() const {
    return running_;
}

bool UpfCli::set_value(const std::string& key, const std::string& value, std::string* error) {
    if (key == "node_id") {
        candidate_.node_id = value;
        return true;
    }
    if (key == "n3_bind") {
        candidate_.n3_bind = value;
        return true;
    }
    if (key == "n4_bind") {
        candidate_.n4_bind = value;
        return true;
    }
    if (key == "n6_bind") {
        candidate_.n6_bind = value;
        return true;
    }
    if (key == "n6_remote_host") {
        candidate_.n6_remote_host = value;
        return true;
    }
    if (key == "n6_remote_port") {
        const auto parsed = parse_int_strict(value, 1, 65535);
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for n6_remote_port";
            }
            return false;
        }
        candidate_.n6_remote_port = *parsed;
        return true;
    }
    if (key == "n6_default_protocol") {
        if (!is_valid_n6_protocol(value)) {
            if (error != nullptr) {
                *error = "ERR: invalid value for n6_default_protocol";
            }
            return false;
        }
        candidate_.n6_default_protocol = value;
        return true;
    }
    if (key == "n6_downlink_wait_timeout_ms") {
        const auto parsed = parse_int_strict(value, 0, std::numeric_limits<int>::max());
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for n6_downlink_wait_timeout_ms";
            }
            return false;
        }
        candidate_.n6_downlink_wait_timeout_ms = *parsed;
        return true;
    }
    if (key == "n6_buffer_capacity") {
        const auto parsed = parse_int_strict(value, 1, std::numeric_limits<int>::max());
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for n6_buffer_capacity";
            }
            return false;
        }
        candidate_.n6_buffer_capacity = static_cast<std::size_t>(*parsed);
        return true;
    }
    if (key == "n6_buffer_overflow_policy") {
        if (!is_valid_n6_buffer_policy(value)) {
            if (error != nullptr) {
                *error = "ERR: invalid value for n6_buffer_overflow_policy";
            }
            return false;
        }
        candidate_.n6_buffer_overflow_policy = value;
        return true;
    }
    if (key == "enable_n9") {
        const auto parsed = parse_bool_strict(value);
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for enable_n9";
            }
            return false;
        }
        candidate_.enable_n9 = *parsed;
        return true;
    }
    if (key == "strict_pfcp") {
        const auto parsed = parse_bool_strict(value);
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for strict_pfcp";
            }
            return false;
        }
        candidate_.strict_pfcp = *parsed;
        return true;
    }
    if (key == "heartbeat_interval_ms") {
        const auto parsed = parse_int_strict(value, 0, std::numeric_limits<int>::max());
        if (!parsed.has_value()) {
            if (error != nullptr) {
                *error = "ERR: invalid value for heartbeat_interval_ms";
            }
            return false;
        }
        candidate_.heartbeat_interval_ms = *parsed;
        return true;
    }
    return false;
}

}  // namespace upf
