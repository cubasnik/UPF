#pragma once

#include "upf/node.hpp"
#include "upf/config/runtime_config.hpp"
#include "upf/modules/observability.hpp"
#include <string>
#include <memory>

namespace upf {

class UpfCli {
public:
    // ...existing code...
    // Возвращает текущую конфигурацию
    const RuntimeConfig& running() const;
    // Устанавливает значение параметра
    bool set_value(const std::string& key, const std::string& value, std::string* error);

public:
    UpfCli(const RuntimeConfig& config);
    UpfCli(const RuntimeConfig& config, UpfNode* node);
    ~UpfCli();

    bool run();
    void process_command(const std::string& command);

    // Добавлено для тестов
    std::string execute(const std::string& command);

private:
    RuntimeConfig running_;
    RuntimeConfig candidate_;
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
    UpfNode* live_node_ = nullptr;
};

} // namespace upf