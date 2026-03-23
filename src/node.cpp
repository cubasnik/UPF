#include "upf/node.hpp"
#include <iostream>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace upf {

struct UpfNode::Impl {
    std::string n4_address;
    std::string sbi_address;
    std::vector<std::string> peer_addresses;
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
    
    std::string make_key(const std::string& imsi, uint32_t pdu_session_id) {
        return imsi + ":" + std::to_string(pdu_session_id);
    }
};

UpfNode::UpfNode(const std::string& n4_address, 
                 const std::string& sbi_address,
                 const std::vector<std::string>& peer_addresses)
    : pImpl_(std::make_unique<Impl>(n4_address, sbi_address, peer_addresses)) {
}

UpfNode::~UpfNode() = default;

bool UpfNode::start() {
    if (pImpl_->running) {
        return true;
    }
    
    std::cout << "[UPF] Starting UPF node..." << std::endl;
    std::cout << "[UPF] N4 address: " << pImpl_->n4_address << std::endl;
    std::cout << "[UPF] SBI address: " << pImpl_->sbi_address << std::endl;
    std::cout << "[UPF] Peers: ";
    for (const auto& peer : pImpl_->peer_addresses) {
        std::cout << peer << " ";
    }
    std::cout << std::endl;
    
    // TODO: Инициализация сетевых интерфейсов
    // TODO: Запуск потоков обработки
    
    pImpl_->running = true;
    std::cout << "[UPF] UPF node started successfully" << std::endl;
    return true;
}

bool UpfNode::stop() {
    if (!pImpl_->running) {
        return true;
    }
    
    std::cout << "[UPF] Stopping UPF node..." << std::endl;
    
    // TODO: Остановка потоков
    // TODO: Закрытие соединений
    
    pImpl_->running = false;
    std::cout << "[UPF] UPF node stopped" << std::endl;
    return true;
}

bool UpfNode::is_running() const {
    return pImpl_->running;
}

bool UpfNode::establish_session(const SessionRequest& request) {
    if (!pImpl_->running) {
        std::cerr << "[UPF] Cannot establish session: node not running" << std::endl;
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(request.imsi, request.pdu_session_id);
    
    if (pImpl_->sessions.find(key) != pImpl_->sessions.end()) {
        std::cerr << "[UPF] Session already exists for " << key << std::endl;
        return false;
    }
    
    Impl::SessionInfo info;
    info.request = request;
    pImpl_->sessions[key] = info;
    
    std::cout << "[UPF] Session established: " << key << std::endl;
    std::cout << "[UPF]   N3: " << request.n3_address << ":" << request.n3_port << std::endl;
    std::cout << "[UPF]   N6: " << request.n6_address << ":" << request.n6_port << std::endl;
    
    return true;
}

bool UpfNode::modify_session(const SessionRequest& request) {
    if (!pImpl_->running) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(request.imsi, request.pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << "[UPF] Session not found: " << key << std::endl;
        return false;
    }
    
    it->second.request = request;
    std::cout << "[UPF] Session modified: " << key << std::endl;
    
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
        std::cerr << "[UPF] Session not found: " << key << std::endl;
        return false;
    }
    
    pImpl_->sessions.erase(it);
    std::cout << "[UPF] Session released: " << key << std::endl;
    
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
        std::cerr << "[UPF] Cannot process uplink: session not found for " << key << std::endl;
        return false;
    }
    
    it->second.uplink_bytes += bytes;
    it->second.packet_count++;
    
    std::cout << "[UPF] Uplink packet: " << key << " -> " << bytes << " bytes" << std::endl;
    return true;
}

bool UpfNode::process_downlink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes) {
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    std::string key = pImpl_->make_key(imsi, pdu_session_id);
    
    auto it = pImpl_->sessions.find(key);
    if (it == pImpl_->sessions.end()) {
        std::cerr << "[UPF] Cannot process downlink: session not found for " << key << std::endl;
        return false;
    }
    
    it->second.downlink_bytes += bytes;
    it->second.packet_count++;
    
    std::cout << "[UPF] Downlink packet: " << key << " -> " << bytes << " bytes" << std::endl;
    return true;
}

UpfStatusSnapshot UpfNode::status() const {
    UpfStatusSnapshot snapshot;
    snapshot.is_running = pImpl_->running;
    
    std::lock_guard<std::mutex> lock(pImpl_->sessions_mutex);
    snapshot.active_sessions = pImpl_->sessions.size();
    
    for (const auto& [key, info] : pImpl_->sessions) {
        snapshot.uplink_bytes += info.uplink_bytes;
        snapshot.downlink_bytes += info.downlink_bytes;
        snapshot.total_packets += info.packet_count;
    }
    
    return snapshot;
}

} // namespace upf