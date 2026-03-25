
#pragma once
#include "upf/config/runtime_config.hpp"
#include "upf/upf.hpp"
#include <memory>
#include "upf/interfaces.hpp"
#include <string>
#include <chrono>

namespace upf {

std::string format_runtime_config_text(const RuntimeConfig& cfg);
std::string format_runtime_config_json(const RuntimeConfig& cfg);
std::string format_n6_session_text(const N6SessionBufferSnapshot& session);
std::string format_n6_session_json(const N6SessionBufferSnapshot& session);

std::string format_upf_status_text(const UpfStatusSnapshot& snapshot);
std::string format_upf_status_json(const UpfStatusSnapshot& snapshot);
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

std::string format_n6_buffer_status_text(const N6BufferStatus& status);
std::string format_n6_buffer_status_json(const N6BufferStatus& status);

} // namespace upf