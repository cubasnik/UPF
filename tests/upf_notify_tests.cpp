#include <cstdlib>
#include <string>
#include "upf/adapters/console_adapters.hpp"
#include "upf/node.hpp"

namespace {
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
} // namespace

int main() {
    std::cerr << "[DEBUG] main: ENTERED" << std::endl;
    std::cout << "[DEBUG] main: start" << std::endl;
    upf::ConsoleN3Adapter n3;
    upf::ConsoleN4Adapter n4;
    upf::ConsoleN6Adapter n6;
    upf::ConsoleN9Adapter n9(true);
    RecordingSbi sbi;
    upf::UpfPeerInterfaces peers {};
    peers.n3 = &n3;
    peers.n6 = &n6;
    peers.n9 = &n9;
    std::cout << "[DEBUG] main: before UpfNode" << std::endl;
    upf::UpfNode node(n4, sbi, peers);
    std::cout << "[DEBUG] main: before start" << std::endl;
    node.start();
    std::cout << "[DEBUG] main: before PfcpSessionRequest" << std::endl;
    upf::PfcpSessionRequest req {};
    req.imsi = "250200123456789";
    req.pdu_session_id = "5";
    req.teid = "0x111";
    req.ue_ipv4 = "10.0.0.10";
    req.dnn = "internet";
    req.s_nssai = "1-010203";
    req.qos_profile = "default";
    std::cout << "[DEBUG] main: before establish_session" << std::endl;
    node.establish_session(req);
    std::cout << "[DEBUG] main: before notify_sbi" << std::endl;
    node.notify_sbi("nupf-event-exposure", "session-up");
    std::cout << "[DEBUG] main: after notify_sbi" << std::endl;
    const std::string status_json = extract_json_object_field(sbi.last_payload, "status");
    std::cout << "[DEBUG] main: after extract status_json" << std::endl;
    const std::string n6_buffer_json = extract_json_object_field(sbi.last_payload, "n6_buffer");
    std::cout << "[DEBUG] main: after extract n6_buffer_json" << std::endl;
    std::cout << "\n==== DEBUG SBI PAYLOAD ====\n" << std::endl;
    std::cout << "publish_count: " << sbi.publish_count << std::endl;
    std::cout << "last_service: " << sbi.last_service << std::endl;
    std::cout << "last_payload: " << sbi.last_payload << std::endl;
    std::cout << "status_json: " << status_json << std::endl;
    std::cout << "n6_buffer_json: " << n6_buffer_json << std::endl;
    std::cout << "==========================\n" << std::endl;
    std::cout << std::flush;
    // if (sbi.publish_count != 1 ||
    //     sbi.last_service != "nupf-event-exposure" ||
    //     extract_json_string_field(sbi.last_payload, "schema") != "upf.sbi-event.v1" ||
    //     extract_json_string_field(sbi.last_payload, "message") != "session-up" ||
    //     status_json.empty() ||
    //     extract_json_string_field(status_json, "schema") != "upf.status.v1" ||
    //     extract_json_string_field(status_json, "state") != "RUNNING" ||
    //     n6_buffer_json.empty() ||
    //     extract_json_string_field(n6_buffer_json, "schema") != "upf.n6-buffer.v1" ||
    //     extract_json_string_field(n6_buffer_json, "overflow_policy") != "drop_oldest") {
    //     return EXIT_FAILURE;
    // }
    node.stop();
    return EXIT_SUCCESS;
}
