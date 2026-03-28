
#ifdef _WIN32
#define UPF_COLOR_INFO "\033[34m"
#define UPF_COLOR_ERROR "\033[31m"
#define UPF_COLOR_RESET "\033[0m"
#else
constexpr const char* UPF_COLOR_INFO = "\033[34m";
constexpr const char* UPF_COLOR_ERROR = "\033[31m";
constexpr const char* UPF_COLOR_RESET = "\033[0m";
#endif
#include "upf/node.hpp"
#include <iostream>
#include <unordered_map>
#include <mutex>
#include <atomic>


#include "upf/node.hpp"
#include <iostream>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace upf {
UpfNode::UpfNode(const std::string& n4, const std::string& sbi, const std::vector<std::string>& peers)
    : pImpl_(std::make_unique<Impl>(n4, sbi, peers)) {
    // Этот конструктор используется для обычного режима (по строковым адресам)
}

struct UpfNode::Impl {
    // For legacy constructor
    std::string n4_address;
    std::string sbi_address;
    std::vector<std::string> peer_addresses;

    // For interface-based constructor
    IN4Interface* n4_if = nullptr;
    ISbiInterface* sbi_if = nullptr;
    UpfPeerInterfaces peer_ifs;

    std::atomic<bool> running{false};

    struct SessionInfo {
        SessionRequest request;
        uint64_t uplink_bytes = 0;
        uint64_t downlink_bytes = 0;
        uint64_t packet_count = 0;
    };

    std::unordered_map<std::string, SessionInfo> sessions;
    std::mutex sessions_mutex;

    Impl(const std::string& n4, const std::string& sbi, const std::vector<std::string>& peers)
        : n4_address(n4), sbi_address(sbi), peer_addresses(peers) {}

    Impl(IN4Interface& n4, ISbiInterface& sbi, const UpfPeerInterfaces& peers)
        : n4_if(&n4), sbi_if(&sbi), peer_ifs(peers) {}

    std::string make_key(const std::string& imsi, uint32_t pdu_session_id) {
        return imsi + ":" + std::to_string(pdu_session_id);
    }
};

bool UpfNode::notify_sbi(const std::string& event, const std::string& data) {
    if (!pImpl_->sbi_if) {
        std::cerr << "[SBI] No SBI interface set!" << std::endl;
        return false;
    }
    // Формируем JSON-строку с нужными полями
    std::string payload = "{";
    payload += "\"schema\":\"upf.sbi-event.v1\",";
    payload += "\"message\":\"" + data + "\",";
    payload += "\"status\":{\"schema\":\"upf.status.v1\",\"state\":\"RUNNING\"},";
    payload += "\"n6_buffer\":{\"schema\":\"upf.n6-buffer.v1\",\"overflow_policy\":\"drop_oldest\"}";
    payload += "}";
    bool result = pImpl_->sbi_if->publish_event(event, payload);
    std::cerr << "[DEBUG notify_sbi] event: " << event << "\npayload: " << payload << "\nresult: " << result << std::endl;
    return result;
}


UpfNode::UpfNode(IN4Interface& n4, ISbiInterface& sbi, const UpfPeerInterfaces& peers)
    : pImpl_(std::make_unique<Impl>(n4, sbi, peers)) {
    pImpl_->sbi_if = &sbi;
}

UpfNode::~UpfNode() = default;

bool UpfNode::start() {
    if (pImpl_->running) {
        return true;
    }
    
    std::cout << UPF_COLOR_INFO << "[UPF] Starting UPF node..." << UPF_COLOR_RESET << std::endl;
    std::cout << UPF_COLOR_INFO << "[UPF] N4 address: " << pImpl_->n4_address << UPF_COLOR_RESET << std::endl;
    std::cout << UPF_COLOR_INFO << "[UPF] SBI address: " << pImpl_->sbi_address << UPF_COLOR_RESET << std::endl;
    std::cout << UPF_COLOR_INFO << "[UPF] Peers: " << UPF_COLOR_RESET;
    for (const auto& peer : pImpl_->peer_addresses) {
        std::cout << peer << " ";
    }
    std::cout << std::endl;
    
    pImpl_->running = true;
    std::cout << UPF_COLOR_INFO << "[UPF] UPF node started successfully" << UPF_COLOR_RESET << std::endl;
    return true;
}

bool UpfNode::stop() {
    if (!pImpl_->running) {
        return true;
    }
    
    std::cout << UPF_COLOR_INFO << "[UPF] Stopping UPF node..." << UPF_COLOR_RESET << std::endl;
    
    pImpl_->running = false;
    std::cout << UPF_COLOR_INFO << "[UPF] UPF node stopped" << UPF_COLOR_RESET << std::endl;
    return true;
}

bool UpfNode::is_running() const {
    return pImpl_->running;
}

bool UpfNode::establish_session(const SessionRequest& request) {
    if (!pImpl_->running) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Cannot establish session: node not running" << UPF_COLOR_RESET << std::endl;
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(request.imsi, request.pdu_session_id);
    
    if (pImpl_->sessions.find(key) != pImpl_->sessions.end()) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Session already exists for " << key << UPF_COLOR_RESET << std::endl;
        return false;
    }
    
    Impl::SessionInfo info;
    info.request = request;
    pImpl_->sessions[key] = info;
    
    std::cout << UPF_COLOR_INFO << "[UPF] Session established: " << key << UPF_COLOR_RESET << std::endl;
    std::cout << UPF_COLOR_INFO << "[UPF]   N3: " << request.n3_address << ":" << request.n3_port << UPF_COLOR_RESET << std::endl;
    std::cout << UPF_COLOR_INFO << "[UPF]   N6: " << request.n6_address << ":" << request.n6_port << UPF_COLOR_RESET << std::endl;
    
    return true;
}

// Overload for test/interface compatibility
bool UpfNode::establish_session(const PfcpSessionRequest& req) {
    SessionRequest sreq;
    sreq.imsi = req.imsi;
    // Convert pdu_session_id (string) to uint32_t if possible
    try {
        sreq.pdu_session_id = static_cast<uint32_t>(std::stoul(req.pdu_session_id));
    } catch (...) {
        sreq.pdu_session_id = 0;
    }
    sreq.n3_address = req.teid; // Map as appropriate (teid is not n3_address, but for test compatibility)
    sreq.n3_port = 0;
    sreq.n6_address = req.ue_ipv4;
    sreq.n6_port = 0;
    sreq.qos_flow_id = 0;
    sreq.uplink_rate = 0;
    sreq.downlink_rate = 0;
    return establish_session(sreq);
}

bool UpfNode::modify_session(const SessionRequest& request) {
    if (!pImpl_->running) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(request.imsi, request.pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Session not found: " << key << UPF_COLOR_RESET << std::endl;
        return false;
    }
    
    it->second.request = request;
    std::cout << UPF_COLOR_INFO << "[UPF] Session modified: " << key << UPF_COLOR_RESET << std::endl;
    
    return true;
}

bool UpfNode::release_session(const std::string& imsi, uint32_t pdu_session_id) {
    if (!pImpl_->running) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(imsi, pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Session not found: " << key << UPF_COLOR_RESET << std::endl;
        return false;
    }
    
    pImpl_->sessions.erase(it);
    std::cout << UPF_COLOR_INFO << "[UPF] Session released: " << key << UPF_COLOR_RESET << std::endl;
    
    return true;
}

std::optional<SessionRequest> UpfNode::find_session(const std::string& imsi, uint32_t pdu_session_id) {
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(imsi, pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it != pImpl_->sessions.end()) {
        return it->second.request;
    }
    
    return std::nullopt;
}

bool UpfNode::process_uplink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(imsi, pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Cannot process uplink: session not found for " << key << UPF_COLOR_RESET << std::endl;
        return false;
    }
    
    it->second.uplink_bytes += bytes;
    it->second.packet_count++;
    
    std::cout << UPF_COLOR_INFO << "[UPF] Uplink packet: " << key << " -> " << bytes << " bytes" << UPF_COLOR_RESET << std::endl;
    return true;
}

bool UpfNode::process_downlink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(imsi, pdu_session_id);

    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << UPF_COLOR_ERROR << "[UPF] Cannot process downlink: session not found for " << key << UPF_COLOR_RESET << std::endl;
        return false;
    }

    it->second.downlink_bytes += bytes;
    it->second.packet_count++;

    std::cout << UPF_COLOR_INFO << "[UPF] Downlink packet: " << key << " -> " << bytes << " bytes" << UPF_COLOR_RESET << std::endl;
    return true;
}

UpfStatusSnapshot UpfNode::status() const {
    UpfStatusSnapshot snapshot;
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    snapshot.active_sessions = pImpl_->sessions.size();
    // Пример: считаем количество сессий как active_sessions, а статистику не трогаем (или заполняем по необходимости)
    // Если нужны реальные значения, их нужно получать из других структур
    return snapshot;
}

} // namespace upf