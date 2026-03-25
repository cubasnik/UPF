#pragma once

#include <string>
#include <optional>
#include <filesystem>
#include <vector>
#include <memory>

#include <cstdint>
#include "upf/interfaces.hpp"

namespace upf {

// Структура для конфигурации
struct RuntimeConfig {
    bool verbose = false;
    std::string config_file;
    std::string n3_interface = "eth0";
    std::string n4_interface = "eth1";
    std::string n6_interface = "eth2";
    uint16_t n4_port = 8805;
    uint16_t sbi_port = 8080;
    size_t packet_buffer_size = 65536;
    size_t session_table_size = 1000;
    
    // Дополнительные поля для совместимости
    std::string node_id = "upf-1";
    std::string n3_bind = "0.0.0.0:2152";
    std::string n4_bind = "0.0.0.0:8805";
    std::string n6_bind = "0.0.0.0:2153";
    std::string n6_remote_host = "127.0.0.1";
    uint16_t n6_remote_port = 30001;
    std::string n6_default_protocol = "ipv4";
    uint32_t n6_downlink_wait_timeout_ms = 500;
    size_t n6_buffer_capacity = 16;
    std::string n6_buffer_overflow_policy = "drop_oldest";
    bool enable_n9 = false;
    // Для тестов и cli
    bool strict_pfcp = false;
    uint32_t heartbeat_interval_ms = 1000;
};

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


// Структура для статуса UPF теперь объявляется в interfaces.hpp

// Удаляем дублирующее определение UpfStatusSnapshot


// Функции для работы с конфигом
RuntimeConfig default_runtime_config();
RuntimeConfig load_runtime_config(const std::string& path);

} // namespace upf

// Класс для управления runtime UPF
class UpfRuntime {
public:
    explicit UpfRuntime(const upf::RuntimeConfig& config);
    ~UpfRuntime();
    
    bool initialize();
    void shutdown();
    int run_session();
    int run_session(bool no_wait);
    bool is_initialized() const { return initialized_; }
    
private:
    upf::RuntimeConfig config_;
    bool initialized_ = false;
};

// Структура контекста вызова
struct RuntimeInvocationContext {
    std::string program_name;
    std::optional<std::filesystem::path> config_path;
    bool verbose = false;
};

// Функции
std::optional<std::filesystem::path> resolve_config_path(
    const std::string& program_name,
    const std::optional<std::string>& provided_path);

int run_session_once(UpfRuntime& runtime, const RuntimeInvocationContext& ctx, bool no_wait = false);


namespace upf {


} // namespace upf