#include "upf/cli.hpp"

#include <sstream>
#include <string>

namespace upf {

UpfCli::UpfCli(RuntimeConfig base)
    : running_(std::move(base)), candidate_(running_) {}

std::string UpfCli::execute(const std::string& command_line) {
    std::istringstream stream(command_line);
    std::string command;
    stream >> command;

    if (command == "set") {
        std::string key;
        std::string value;
        stream >> key >> value;
        if (key.empty() || value.empty()) {
            return "ERR: usage set <key> <value>";
        }
        return set_value(key, value) ? "OK" : "ERR: unknown key";
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
        stream >> what;
        if (what == "running") {
            return "node_id=" + running_.node_id + " n3=" + running_.n3_bind + " n4=" + running_.n4_bind;
        }
        if (what == "candidate") {
            return "node_id=" + candidate_.node_id + " n3=" + candidate_.n3_bind + " n4=" + candidate_.n4_bind;
        }
        if (what == "mode") {
            return "mode=operational";
        }
        return "ERR: unknown show";
    }

    return "ERR: unknown command";
}

const RuntimeConfig& UpfCli::running() const {
    return running_;
}

bool UpfCli::set_value(const std::string& key, const std::string& value) {
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
    if (key == "enable_n9") {
        candidate_.enable_n9 = (value == "true" || value == "1");
        return true;
    }
    if (key == "strict_pfcp") {
        candidate_.strict_pfcp = (value == "true" || value == "1");
        return true;
    }
    if (key == "heartbeat_interval_ms") {
        candidate_.heartbeat_interval_ms = std::stoi(value);
        return true;
    }
    return false;
}

}  // namespace upf
