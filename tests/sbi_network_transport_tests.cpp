#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

#include "upf/adapters/network_adapters.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

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

std::string extract_http_body(const std::string& request) {
    const std::size_t split = request.find("\r\n\r\n");
    if (split == std::string::npos) {
        return {};
    }
    return request.substr(split + 4);
}

#if defined(_WIN32)
using SocketType = SOCKET;
constexpr SocketType kInvalidSocket = INVALID_SOCKET;
#else
using SocketType = int;
constexpr SocketType kInvalidSocket = -1;
#endif

void close_socket(SocketType sock) {
#if defined(_WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

struct CaptureState {
    std::mutex mutex;
    std::string request;
};

bool init_stack() {
#if defined(_WIN32)
    WSADATA data {};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
#else
    return true;
#endif
}

void run_tcp_mock_server(int port, CaptureState* capture) {
    if (!init_stack()) {
        return;
    }

    SocketType server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == kInvalidSocket) {
        return;
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<unsigned short>(port));

    if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_socket(server);
        return;
    }

    if (listen(server, 1) != 0) {
        close_socket(server);
        return;
    }

    sockaddr_in client_addr {};
    socklen_t client_len = sizeof(client_addr);
    SocketType client = accept(server, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
    if (client == kInvalidSocket) {
        close_socket(server);
        return;
    }

    char buffer[1024] {};
    const int received = recv(client, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
    if (received > 0 && capture != nullptr) {
        std::lock_guard<std::mutex> lock(capture->mutex);
        capture->request.assign(buffer, buffer + received);
    }
    const char response[] = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n";
    send(client, response, static_cast<int>(std::strlen(response)), 0);

    close_socket(client);
    close_socket(server);
}

}  // namespace

int main() {
    constexpr int kPort = 39006;
    CaptureState capture;
    std::thread server(run_tcp_mock_server, kPort, &capture);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    upf::NetworkSbiAdapter sbi("127.0.0.1", kPort, "/nupf-event-exposure/v1/events", 500);
    const bool ok = sbi.publish_event("nupf-event-exposure",
                                      "{\"schema\":\"upf.sbi-event.v1\",\"message\":\"session-up\",\"status\":{\"schema\":\"upf.status.v1\",\"state\":\"RUNNING\"}}");

    server.join();
    if (!ok) {
        return EXIT_FAILURE;
    }

    std::string request;
    {
        std::lock_guard<std::mutex> lock(capture.mutex);
        request = capture.request;
    }

    const std::string body = extract_http_body(request);
    const std::string payload = extract_json_object_field(body, "payload");
    const std::string status = extract_json_object_field(payload, "status");
    if (request.find("POST /nupf-event-exposure/v1/events HTTP/1.1") == std::string::npos ||
        extract_json_string_field(body, "service") != "nupf-event-exposure" ||
        extract_json_string_field(body, "schema") != "upf.sbi-envelope.v1" ||
        payload.empty() ||
        extract_json_string_field(payload, "schema") != "upf.sbi-event.v1" ||
        extract_json_string_field(payload, "message") != "session-up" ||
        status.empty() ||
        extract_json_string_field(status, "schema") != "upf.status.v1" ||
        extract_json_string_field(status, "state") != "RUNNING") {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
