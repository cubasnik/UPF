#pragma once

#include <string>
#include <cstdint>

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
};

} // namespace upf