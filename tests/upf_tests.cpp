#include <cstdlib>

#include <string>

#include "upf/adapters/console_adapters.hpp"
#include "upf/upf.hpp"

namespace {

std::size_t skip_ws(const std::string& text, std::size_t pos) {
    while (pos < text.size() && (text[pos] == ' ' || text[pos] == '\n' || text[pos] == '\r' || text[pos] == '\t')) {
        ++pos;
    }
    return pos;
}

std::string extract_json_string_field(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\":";
    const std::size_t marker_pos = json.find(marker);
    if (marker_pos == std::string::npos) {
        return {};
    }
    std::size_t cursor = skip_ws(json, marker_pos + marker.size());
    if (cursor >= json.size() || json[cursor] != '"') {
        return {};
    }
    ++cursor;
    std::string value;
    bool escaped = false;
    while (cursor < json.size()) {
        const char ch = json[cursor++];
        if (escaped) {
            value.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            return value;
        }
        value.push_back(ch);
    }
    return {};
}

std::string extract_json_object_field(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\":";
    const std::size_t marker_pos = json.find(marker);
    if (marker_pos == std::string::npos) {
        return {};
    }
    std::size_t cursor = skip_ws(json, marker_pos + marker.size());
    if (cursor >= json.size() || json[cursor] != '{') {
        return {};
    }
    const std::size_t start = cursor;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    while (cursor < json.size()) {
        const char ch = json[cursor++];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            in_string = !in_string;
            continue;
        }
        if (in_string) {
            continue;
        }
        if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                return json.substr(start, cursor - start);
            }
        }
    }
    return {};
}

class RecordingSbi final : public upf::ISbiInterface {
public:
    bool publish_event(const std::string& service_name, const std::string& payload) override {
        last_service = service_name;
        last_payload = payload;
        ++publish_count;
        return true;
    }

    std::string last_service;
    std::string last_payload;
    int publish_count {0};
};

}  // namespace

int main() {
    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6;
    upf::ConsoleN9Adapter n9(true);
    RecordingSbi sbi;

    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;

    upf::UpfNode node(n4, sbi, peers);
    if (!node.start()) {
        return EXIT_FAILURE;
    }

    upf::PfcpSessionRequest req {};
    req.imsi = "250200123456789";
    req.pdu_session_id = "5";
    req.teid = "0x111";
    req.ue_ipv4 = "10.0.0.10";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.qos_profile = "default";

    if (!node.establish_session(req)) {
        return EXIT_FAILURE;
    }
    if (!node.process_uplink(req.imsi, req.pdu_session_id, 256)) {
        return EXIT_FAILURE;
    }
    if (!node.process_downlink(req.imsi, req.pdu_session_id, 256)) {
        return EXIT_FAILURE;
    }
    if (!node.modify_session(req)) {
        return EXIT_FAILURE;
    }

    const auto snapshot = node.status();
    if (!snapshot.n6_buffer.has_value()) {
        return EXIT_FAILURE;
    }

    if (!node.notify_sbi("nupf-event-exposure", "session-up")) {
        return EXIT_FAILURE;
    }
    const std::string status_json = extract_json_object_field(sbi.last_payload, "status");
    const std::string n6_buffer_json = extract_json_object_field(sbi.last_payload, "n6_buffer");
    if (sbi.publish_count != 1 ||
        sbi.last_service != "nupf-event-exposure" ||
        extract_json_string_field(sbi.last_payload, "schema") != "upf.sbi-event.v1" ||
        extract_json_string_field(sbi.last_payload, "message") != "session-up" ||
        status_json.empty() ||
        extract_json_string_field(status_json, "schema") != "upf.status.v1" ||
        extract_json_string_field(status_json, "state") != "RUNNING" ||
        n6_buffer_json.empty() ||
        extract_json_string_field(n6_buffer_json, "schema") != "upf.n6-buffer.v1" ||
        extract_json_string_field(n6_buffer_json, "overflow_policy") != "drop_oldest") {
        return EXIT_FAILURE;
    }

    if (!node.release_session(req.imsi, req.pdu_session_id)) {
        return EXIT_FAILURE;
    }

    node.stop();
    return EXIT_SUCCESS;
}
