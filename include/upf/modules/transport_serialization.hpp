#pragma once

#include <string>

#include "upf/interfaces.hpp"

namespace upf {

constexpr const char* kRuntimeConfigSchema = "upf.runtime-config.v1";
constexpr const char* kUpfStatusSchema = "upf.status.v1";
constexpr const char* kN6BufferStatusSchema = "upf.n6-buffer.v1";
constexpr const char* kN6SessionSchema = "upf.n6-session.v1";
constexpr const char* kDemoPresetsSchema = "upf.demo-presets.v1";
constexpr const char* kDemoTargetSchema = "upf.demo-target.v1";
constexpr const char* kDemoToolCommandSchema = "upf.demo-tool-command.v1";
constexpr const char* kDemoMatrixSchema = "upf.demo-matrix.v1";
constexpr const char* kDemoMatrixToolCommandSchema = "upf.demo-matrix-tool-command.v1";
constexpr const char* kDemoCompareSchema = "upf.demo-compare.v1";
constexpr const char* kDemoCompareToolCommandSchema = "upf.demo-compare-tool-command.v1";
constexpr const char* kSbiEventSchema = "upf.sbi-event.v1";
constexpr const char* kSbiEnvelopeSchema = "upf.sbi-envelope.v1";

std::string format_schema_json(const char* schema);
std::string coerce_json_value(const std::string& payload);
std::string format_sbi_event_request_body(const std::string& service_name, const std::string& payload);
std::string format_http_post_request(const std::string& host, const std::string& path, const std::string& body);

std::string format_pfcp_default_response_detail(PfcpCause cause);
std::string format_pfcp_operation(PfcpOperation operation);

}  // namespace upf