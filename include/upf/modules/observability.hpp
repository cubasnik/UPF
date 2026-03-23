#pragma once

#include "upf/config/runtime_config.hpp"
#include <string>
#include <chrono>

namespace upf {

// Классы для observability
class MetricsCollector {
public:
    MetricsCollector(const RuntimeConfig& config);
    void record_packet(const std::string& interface, size_t bytes);
    void record_session_event(const std::string& event);
    void print_metrics() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

// Другие классы observability...

} // namespace upf