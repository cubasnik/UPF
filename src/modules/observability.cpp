#include "upf/modules/observability.hpp"

#include <sstream>

namespace upf {

std::string json_escape(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (const char ch : value) {
        switch (ch) {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped.push_back(ch);
                break;
        }
    }
    return escaped;
}

std::string format_runtime_config_text(const RuntimeConfig& cfg) {
    return "node_id=" + cfg.node_id +
           " n3=" + cfg.n3_bind +
           " n4=" + cfg.n4_bind +
           " n6=" + cfg.n6_bind +
           " n6_remote=" + cfg.n6_remote_host + ":" + std::to_string(cfg.n6_remote_port) +
           " n6_protocol=" + cfg.n6_default_protocol +
           " n6_downlink_wait_ms=" + std::to_string(cfg.n6_downlink_wait_timeout_ms) +
           " n6_buffer_capacity=" + std::to_string(cfg.n6_buffer_capacity) +
           " n6_buffer_policy=" + cfg.n6_buffer_overflow_policy;
}

std::string format_runtime_config_json(const RuntimeConfig& cfg) {
    std::ostringstream output;
    output << '{'
           << format_schema_json(kRuntimeConfigSchema) << ','
           << "\"node_id\":\"" << json_escape(cfg.node_id) << "\"," 
           << "\"n3\":\"" << json_escape(cfg.n3_bind) << "\"," 
           << "\"n4\":\"" << json_escape(cfg.n4_bind) << "\"," 
           << "\"n6\":\"" << json_escape(cfg.n6_bind) << "\"," 
           << "\"n6_remote_host\":\"" << json_escape(cfg.n6_remote_host) << "\"," 
           << "\"n6_remote_port\":" << cfg.n6_remote_port << ','
           << "\"n6_protocol\":\"" << json_escape(cfg.n6_default_protocol) << "\"," 
           << "\"n6_downlink_wait_ms\":" << cfg.n6_downlink_wait_timeout_ms << ','
           << "\"n6_buffer_capacity\":" << cfg.n6_buffer_capacity << ','
           << "\"n6_buffer_policy\":\"" << json_escape(cfg.n6_buffer_overflow_policy) << "\""
           << '}';
    return output.str();
}

std::string format_upf_status_text(const UpfStatusSnapshot& snapshot) {
    return std::string("state=") + to_string(snapshot.state) +
           " active_sessions=" + std::to_string(snapshot.active_sessions) +
           " n4_messages=" + std::to_string(snapshot.stats.n4_messages) +
           " n6_forwards=" + std::to_string(snapshot.stats.n6_forwards) +
           " n3_rx=" + std::to_string(snapshot.stats.n3_packets_rx) +
           " n3_tx=" + std::to_string(snapshot.stats.n3_packets_tx);
}

std::string format_upf_status_json(const UpfStatusSnapshot& snapshot) {
    std::ostringstream output;
    output << '{'
           << format_schema_json(kUpfStatusSchema) << ','
           << "\"state\":\"" << to_string(snapshot.state) << "\"," 
           << "\"active_sessions\":" << snapshot.active_sessions << ','
           << "\"n4_messages\":" << snapshot.stats.n4_messages << ','
           << "\"n6_forwards\":" << snapshot.stats.n6_forwards << ','
           << "\"n3_rx\":" << snapshot.stats.n3_packets_rx << ','
           << "\"n3_tx\":" << snapshot.stats.n3_packets_tx
           << '}';
    return output.str();
}

std::string format_n6_buffer_status_text(const N6BufferStatus& status) {
    return std::string("capacity=") + std::to_string(status.per_session_capacity) +
           " overflow_policy=" + to_string(status.overflow_policy) +
           " enqueued=" + std::to_string(status.enqueued_packets) +
           " dequeued=" + std::to_string(status.dequeued_packets) +
           " buffered=" + std::to_string(status.buffered_packets) +
           " active_sessions=" + std::to_string(status.active_sessions) +
           " dropped=" + std::to_string(status.dropped_packets) +
           " dropped_oldest=" + std::to_string(status.dropped_overflow_oldest) +
           " dropped_newest=" + std::to_string(status.dropped_overflow_newest) +
           " dropped_session_removed=" + std::to_string(status.dropped_session_removed) +
           " dropped_unknown_session=" + std::to_string(status.dropped_unknown_session) +
           " rejected_by_policy=" + std::to_string(status.rejected_by_policy);
}

std::string format_n6_buffer_status_json(const N6BufferStatus& status) {
    std::ostringstream output;
    output << '{'
           << format_schema_json(kN6BufferStatusSchema) << ','
           << "\"capacity\":" << status.per_session_capacity << ','
           << "\"overflow_policy\":\"" << to_string(status.overflow_policy) << "\"," 
           << "\"enqueued\":" << status.enqueued_packets << ','
           << "\"dequeued\":" << status.dequeued_packets << ','
           << "\"buffered\":" << status.buffered_packets << ','
           << "\"active_sessions\":" << status.active_sessions << ','
           << "\"dropped\":" << status.dropped_packets << ','
           << "\"dropped_oldest\":" << status.dropped_overflow_oldest << ','
           << "\"dropped_newest\":" << status.dropped_overflow_newest << ','
           << "\"dropped_session_removed\":" << status.dropped_session_removed << ','
           << "\"dropped_unknown_session\":" << status.dropped_unknown_session << ','
           << "\"rejected_by_policy\":" << status.rejected_by_policy
           << '}';
    return output.str();
}

std::string format_n6_session_text(const N6SessionBufferSnapshot& session) {
    return "imsi=" + session.imsi +
           " pdu=" + session.pdu_session_id +
           " dnn=" + session.dnn +
           " enqueued=" + std::to_string(session.enqueued_packets) +
           " dequeued=" + std::to_string(session.dequeued_packets) +
           " dropped=" + std::to_string(session.dropped_packets) +
           " dropped_oldest=" + std::to_string(session.dropped_overflow_oldest) +
           " dropped_newest=" + std::to_string(session.dropped_overflow_newest) +
           " dropped_session_removed=" + std::to_string(session.dropped_session_removed) +
           " rejected_by_policy=" + std::to_string(session.rejected_by_policy) +
           " buffered=" + std::to_string(session.buffered_packets) +
           " ipv6_enabled=" + std::string(session.ipv6_enabled ? "true" : "false") +
           " ethernet_enabled=" + std::string(session.ethernet_enabled ? "true" : "false") +
           " last_updated=" + session.last_updated_utc;
}

std::string format_n6_session_json(const N6SessionBufferSnapshot& session) {
    std::ostringstream output;
    output << '{'
           << format_schema_json(kN6SessionSchema) << ','
           << "\"imsi\":\"" << json_escape(session.imsi) << "\"," 
           << "\"pdu\":\"" << json_escape(session.pdu_session_id) << "\"," 
           << "\"dnn\":\"" << json_escape(session.dnn) << "\"," 
           << "\"enqueued\":" << session.enqueued_packets << ','
           << "\"dequeued\":" << session.dequeued_packets << ','
           << "\"dropped\":" << session.dropped_packets << ','
           << "\"dropped_oldest\":" << session.dropped_overflow_oldest << ','
           << "\"dropped_newest\":" << session.dropped_overflow_newest << ','
           << "\"dropped_session_removed\":" << session.dropped_session_removed << ','
           << "\"rejected_by_policy\":" << session.rejected_by_policy << ','
           << "\"buffered\":" << session.buffered_packets << ','
           << "\"ipv6_enabled\":" << (session.ipv6_enabled ? "true" : "false") << ','
           << "\"ethernet_enabled\":" << (session.ethernet_enabled ? "true" : "false") << ','
           << "\"last_updated\":\"" << json_escape(session.last_updated_utc) << "\""
           << '}';
    return output.str();
}

std::string format_sbi_event_payload_json(const std::string& message, const UpfStatusSnapshot& snapshot) {
    std::ostringstream output;
    output << '{'
           << format_schema_json(kSbiEventSchema) << ','
           << "\"message\":\"" << json_escape(message) << "\"," 
           << "\"status\":" << format_upf_status_json(snapshot);
    if (snapshot.n6_buffer.has_value()) {
        output << ",\"n6_buffer\":" << format_n6_buffer_status_json(*snapshot.n6_buffer);
    }
    output << '}';
    return output.str();
}

}  // namespace upf