#pragma once

#include "upf/node.hpp"
#include "upf/config/runtime_config.hpp"
#include <string>
#include <memory>

namespace upf {

class UpfCli {
public:
    UpfCli(const RuntimeConfig& config, UpfNode* node);
    ~UpfCli();
    
    bool run();
    void process_command(const std::string& command);
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace upf