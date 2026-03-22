#pragma once

#include <string>

#include "upf/config/runtime_config.hpp"
#include "upf/interfaces.hpp"

namespace upf {

class UpfCli {
public:
    explicit UpfCli(RuntimeConfig base, const IUpfNode* live_node = nullptr);

    std::string execute(const std::string& command_line);
    const RuntimeConfig& running() const;

private:
    bool set_value(const std::string& key, const std::string& value, std::string* error = nullptr);

    RuntimeConfig running_;
    RuntimeConfig candidate_;
    const IUpfNode* live_node_ {nullptr};
};

}  // namespace upf
