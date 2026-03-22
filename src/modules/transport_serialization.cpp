#include "upf/modules/transport_serialization.hpp"

#include <cctype>
#include <sstream>

#include "upf/modules/observability.hpp"

namespace upf {

std::string format_schema_json(const char* schema) {
    return std::string{"\"schema\":\""} + schema + "\"";
}

std::string coerce_json_value(const std::string& payload) {
    const std::size_t first = payload.find_first_not_of(" \t\r\n");
    if (first != std::string::npos) {
        const char lead = payload[first];
        if (lead == '{' || lead == '[' || lead == '"' || lead == '-' || std::isdigit(static_cast<unsigned char>(lead)) ||
            lead == 't' || lead == 'f' || lead == 'n') {
            return payload;
        }
    }
    return '"' + json_escape(payload) + '"';
}

std::string format_sbi_event_request_body(const std::string& service_name, const std::string& payload) {
    return std::string{"{"}
        + "\"service\":\"" + json_escape(service_name) + "\","
    + format_schema_json(kSbiEnvelopeSchema) + ','
        + "\"payload\":" + coerce_json_value(payload)
        + '}';
}

std::string format_http_post_request(const std::string& host, const std::string& path, const std::string& body) {
    std::ostringstream request;
    request << "POST " << path << " HTTP/1.1\r\n"
            << "Host: " << host << "\r\n"
            << "Connection: Upgrade, HTTP2-Settings\r\n"
            << "Upgrade: h2c\r\n"
            << "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n\r\n"
            << body;
    return request.str();
}

std::string format_pfcp_default_response_detail(PfcpCause cause) {
    return cause == PfcpCause::RequestAccepted ? "PFCP request accepted" : "PFCP request failed";
}

std::string format_pfcp_operation(PfcpOperation operation) {
    switch (operation) {
        case PfcpOperation::Establish:
            return "ESTABLISH";
        case PfcpOperation::Modify:
            return "MODIFY";
        case PfcpOperation::Delete:
            return "DELETE";
    }
    return "UNKNOWN";
}

}  // namespace upf