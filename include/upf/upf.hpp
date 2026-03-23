#pragma once

#include "upf/config/runtime_config.hpp"
#include <string>
#include <optional>
#include <vector>
#include <memory>

namespace upf {

// Структура для запроса сессии
struct SessionRequest {
    std::string imsi;
    uint32_t pdu_session_id = 0;
    std::string n3_address;
    uint16_t n3_port = 0;
    std::string n6_address;
    uint16_t n6_port = 0;
    uint32_t qos_flow_id = 0;
    uint64_t uplink_rate = 0;
    uint64_t downlink_rate = 0;
};

// Структура для статуса UPF
struct UpfStatusSnapshot {
    size_t active_sessions = 0;
    uint64_t uplink_bytes = 0;
    uint64_t downlink_bytes = 0;
    uint64_t total_packets = 0;
    bool is_running = false;
};

// Основной класс UPF узла
class UpfNode {
public:
    UpfNode(const std::string& n4_address, 
            const std::string& sbi_address,
            const std::vector<std::string>& peer_addresses);
    
    ~UpfNode();
    
    bool start();
    bool stop();
    bool is_running() const;
    
    // Управление сессиями
    bool establish_session(const SessionRequest& request);
    bool modify_session(const SessionRequest& request);
    bool release_session(const std::string& imsi, uint32_t pdu_session_id);
    std::optional<SessionRequest> find_session(const std::string& imsi, uint32_t pdu_session_id);
    
    // Обработка трафика
    bool process_uplink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes);
    bool process_downlink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes);
    
    // Статус и статистика
    UpfStatusSnapshot status() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace upf