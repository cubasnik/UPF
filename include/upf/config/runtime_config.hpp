

#pragma once
#include <string>
#include <cstdint>

namespace upf {

struct RuntimeConfig;

// Сохраняет конфиг в JSON-файл. Если file_path пустой, сохраняет в runtime_config.json
bool save_runtime_config(const RuntimeConfig& config, const std::string& file_path, std::string* error_msg);

} // namespace upf