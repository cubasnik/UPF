#pragma once

#include <string>

#include "upf/interfaces.hpp"

namespace upf {

constexpr const char* kRuntimeConfigSchema = "upf.runtime-config.v1";
constexpr const char* kUpfStatusSchema = "upf.status.v1";
constexpr const char* kN6BufferStatusSchema = "upf.n6-buffer.v1";
constexpr const char* kN6SessionSchema = "upf.n6-session.v1";
constexpr const char* kPresetsSchema = "upf.presets.v1";
constexpr const char* kTargetSchema = "upf.target.v1";
constexpr const char* kToolCommandSchema = "upf.tool-command.v1";
constexpr const char* kMatrixSchema = "upf.matrix.v1";
constexpr const char* kMatrixToolCommandSchema = "upf.matrix-tool-command.v1";
constexpr const char* kCompareSchema = "upf.compare.v1";
constexpr const char* kCompareToolCommandSchema = "upf.compare-tool-command.v1";
constexpr const char* kSbiEventSchema = "upf.sbi-event.v1";
constexpr const char* kSbiEnvelopeSchema = "upf.sbi-envelope.v1";

std::string format_schema_json(const char* schema);
std::string coerce_json_value(const std::string& payload);
std::string format_sbi_event_request_body(const std::string& service_name, const std::string& payload);
std::string format_http_post_request(const std::string& host, const std::string& path, const std::string& body);

std::string format_pfcp_default_response_detail(PfcpCause cause);
std::string format_pfcp_operation(PfcpOperation operation);


namespace modules {

class TransportSerialization {
public:
	static std::vector<uint8_t> serialize(const std::string& data);
	static std::string deserialize(const std::vector<uint8_t>& data);
};

} // namespace modules
}  // namespace upf