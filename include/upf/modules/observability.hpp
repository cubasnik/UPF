#pragma once

#include <string>

#include "upf/config/runtime_config.hpp"
#include "upf/interfaces.hpp"
#include "upf/modules/transport_serialization.hpp"

namespace upf {

std::string json_escape(const std::string& value);

std::string format_runtime_config_text(const RuntimeConfig& cfg);
std::string format_runtime_config_json(const RuntimeConfig& cfg);

std::string format_upf_status_text(const UpfStatusSnapshot& snapshot);
std::string format_upf_status_json(const UpfStatusSnapshot& snapshot);

std::string format_n6_buffer_status_text(const N6BufferStatus& status);
std::string format_n6_buffer_status_json(const N6BufferStatus& status);

std::string format_n6_session_text(const N6SessionBufferSnapshot& session);
std::string format_n6_session_json(const N6SessionBufferSnapshot& session);

std::string format_sbi_event_payload_json(const std::string& message, const UpfStatusSnapshot& snapshot);

}  // namespace upf