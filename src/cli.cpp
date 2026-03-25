    constexpr const char* color_ok = "\033[32m";    // green
    constexpr const char* color_err = "\033[31m";   // red
    constexpr const char* color_cmd = "\033[32m";   // green (help)
    constexpr const char* color_desc = "\033[0m";   // white/default (help)
    constexpr const char* color_key = "\033[33m";   // yellow (show)
    constexpr const char* color_val = "\033[0m";    // white/default (show)
    constexpr const char* color_reset = "\033[0m";
#include "upf/cli.hpp"
#include "upf/modules/observability.hpp"

namespace upf {
// Минимальная заглушка Impl для UpfCli
struct UpfCli::Impl {};

// ... rest of the file ...


#include <limits>
#include <optional>
#include <sstream>
#include <string>



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


UpfCli::UpfCli(const RuntimeConfig& config)
    : running_(config), candidate_(running_), live_node_(nullptr) {}

UpfCli::UpfCli(const RuntimeConfig& config, UpfNode* node)
    : running_(config), candidate_(running_), live_node_(node) {}

std::string UpfCli::execute(const std::string& command_line) {

    std::istringstream stream(command_line);
    std::string command;
    stream >> command;

    if (command.empty()) {
        return "";
    }
    if (command == "help") {
        constexpr const char* cmd_color = "\033[32m"; // green
        constexpr const char* desc_color = "\033[0m"; // white/default
        std::ostringstream oss;
        oss << "Available commands:\n";
        oss << "  " << cmd_color << "set <key> <value>" << desc_color << "      Set a configuration parameter\n";
        oss << "  " << cmd_color << "commit" << desc_color << "                 Apply changes (make candidate config active)\n";
        oss << "  " << cmd_color << "discard" << desc_color << "                Discard unsaved changes (reset candidate to running)\n";
        oss << "  " << cmd_color << "show running" << desc_color << "           Show current (active) configuration\n";
        oss << "  " << cmd_color << "show candidate" << desc_color << "         Show candidate configuration\n";
        oss << "  " << cmd_color << "show running json" << desc_color << "      Show current configuration in JSON format\n";
        oss << "  " << cmd_color << "show candidate json" << desc_color << "    Show candidate configuration in JSON format\n";
        oss << "  " << cmd_color << "show mode" << desc_color << "              Show mode (mode=operational)\n";
        oss << "  " << cmd_color << "exit, quit" << desc_color << "             Exit REPL\n";
        oss << "  " << cmd_color << "help" << desc_color << "                   Show this help message";
        return oss.str();
    }

    if (command == "set") {
        std::string key;
        std::string value;
        std::string error;
        stream >> key >> value;
        if (key.empty() || value.empty()) {
            return std::string(color_err) + "ERR: usage set <key> <value>" + color_reset;
        }
        if (set_value(key, value, &error)) {
            return std::string(color_ok) + "OK" + color_reset;
        }
        return std::string(color_err) + (error.empty() ? "ERR: unknown key" : error) + color_reset;
    }

    if (command == "commit") {
        running_ = candidate_;
        return std::string(color_ok) + "OK" + color_reset;
    }

    if (command == "discard") {
        candidate_ = running_;
        return std::string(color_ok) + "OK" + color_reset;
    }

    if (command == "show") {
        std::string what;
        std::string format;
        stream >> what;
        stream >> format;
        if (what == "running") {
            if (format == "json") {
                return format_runtime_config_json(running_);
            } else {
                std::ostringstream oss;
                oss << color_key << "node_id" << color_val << " = " << running_.node_id << "\n";
                oss << color_key << "n3" << color_val << " = " << running_.n3_bind << "\n";
                oss << color_key << "n4" << color_val << " = " << running_.n4_bind << "\n";
                oss << color_key << "n6" << color_val << " = " << running_.n6_bind << "\n";
                oss << color_key << "n6_remote" << color_val << " = " << running_.n6_remote_host << ":" << running_.n6_remote_port << "\n";
                oss << color_key << "n6_protocol" << color_val << " = " << running_.n6_default_protocol << "\n";
                oss << color_key << "n6_downlink_wait_ms" << color_val << " = " << running_.n6_downlink_wait_timeout_ms << "\n";
                oss << color_key << "n6_buffer_capacity" << color_val << " = " << running_.n6_buffer_capacity << "\n";
                oss << color_key << "n6_buffer_policy" << color_val << " = " << running_.n6_buffer_overflow_policy << "\n";
                return oss.str();
            }
        }
        if (what == "candidate") {
            if (format == "json") {
                return upf::format_runtime_config_json(candidate_);
            } else {
                std::ostringstream oss;
                oss << color_key << "node_id" << color_val << " = " << candidate_.node_id << "\n";
                oss << color_key << "n3" << color_val << " = " << candidate_.n3_bind << "\n";
                oss << color_key << "n4" << color_val << " = " << candidate_.n4_bind << "\n";
                oss << color_key << "n6" << color_val << " = " << candidate_.n6_bind << "\n";
                oss << color_key << "n6_remote" << color_val << " = " << candidate_.n6_remote_host << ":" << candidate_.n6_remote_port << "\n";
                oss << color_key << "n6_protocol" << color_val << " = " << candidate_.n6_default_protocol << "\n";
                oss << color_key << "n6_downlink_wait_ms" << color_val << " = " << candidate_.n6_downlink_wait_timeout_ms << "\n";
                oss << color_key << "n6_buffer_capacity" << color_val << " = " << candidate_.n6_buffer_capacity << "\n";
                oss << color_key << "n6_buffer_policy" << color_val << " = " << candidate_.n6_buffer_overflow_policy << "\n";
                return oss.str();
            }
        }
        if (what == "mode") {
            return "mode=operational";
        }
        if (what == "status") {
            if (live_node_ == nullptr) {
                return "ERR: live status unavailable";
            }
            return format == "json" ? upf::format_upf_status_json(live_node_->status()) : upf::format_upf_status_text(live_node_->status());
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
                return session_format == "json" ? upf::format_n6_session_json(*session) : upf::format_n6_session_text(*session);
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
        return std::string(color_err) + "ERR: unknown show" + color_reset;
    }

    return std::string(color_err) + "ERR: unknown command" + color_reset;
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
