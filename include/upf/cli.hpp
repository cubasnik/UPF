#pragma once

#include <string>

#include "upf/config/runtime_config.hpp"

namespace upf {

class UpfCli {
public:
    explicit UpfCli(RuntimeConfig base);

    std::string execute(const std::string& command_line);
    const RuntimeConfig& running() const;

private:
    bool set_value(const std::string& key, const std::string& value);

    RuntimeConfig running_;
    RuntimeConfig candidate_;
};

}  // namespace upf
