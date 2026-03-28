
#include <string>
#include <fstream>


#include "upf/upf.hpp"
#include "upf/config/runtime_config.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <string>

namespace upf {

// Сохраняет RuntimeConfig в JSON-файл
bool save_runtime_config(const RuntimeConfig& config, const std::string& file_path, std::string* error_msg) {
    std::string out_path = file_path.empty() ? "runtime_config.json" : file_path;
    std::ofstream out(out_path);
    if (!out.is_open()) {
        if (error_msg) *error_msg = "Cannot open file for writing: " + out_path;
        return false;
    }
    // Используем простое форматирование JSON
    out << "{\n";
    out << "  \"n3_interface\": \"" << config.n3_interface << "\",\n";
    out << "  \"n4_interface\": \"" << config.n4_interface << "\",\n";
    out << "  \"n6_interface\": \"" << config.n6_interface << "\",\n";
    out << "  \"n4_port\": " << config.n4_port << ",\n";
    out << "  \"sbi_port\": " << config.sbi_port << ",\n";
    out << "  \"verbose\": " << (config.verbose ? "true" : "false") << "\n";
    out << "}\n";
    if (!out.good()) {
        if (error_msg) *error_msg = "Write error: " + out_path;
        return false;
    }
    if (error_msg) *error_msg = "";
    return true;
}

RuntimeConfig default_runtime_config() {
    RuntimeConfig config;
    config.verbose = false;
    config.config_file = "";
    config.n3_interface = "eth0";
    config.n4_interface = "eth1";
    config.n6_interface = "eth2";
    config.n4_port = 8805;
    config.sbi_port = 8080;
    config.packet_buffer_size = 65536;
    config.session_table_size = 1000;
    return config;
}

RuntimeConfig load_runtime_config(const std::string& path) {
    RuntimeConfig config = default_runtime_config();
    config.config_file = path;
    
    std::cout << "[CONFIG] Loading config from: " << path << std::endl;
    
    // Проверяем существование файла
    if (!std::filesystem::exists(path)) {
        std::cerr << "[CONFIG] Warning: Config file does not exist: " << path << std::endl;
        std::cerr << "[CONFIG] Using default configuration" << std::endl;
        return config;
    }
    
    // Определяем тип файла по расширению
    std::string extension = std::filesystem::path(path).extension().string();
    
    try {
        if (extension == ".json") {
            // Простой парсинг JSON (для примера)
            std::ifstream file(path);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file");
            }
            
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();
            
            // Очень простой парсинг JSON (в реальном проекте используйте библиотеку типа nlohmann/json)
            auto find_value = [&content](const std::string& key) -> std::string {
                size_t pos = content.find("\"" + key + "\"");
                if (pos == std::string::npos) return "";
                pos = content.find(":", pos);
                if (pos == std::string::npos) return "";
                pos++;
                while (pos < content.length() && (content[pos] == ' ' || content[pos] == '\t')) pos++;
                if (pos >= content.length()) return "";
                
                size_t end = pos;
                if (content[pos] == '"') {
                    pos++;
                    end = content.find("\"", pos);
                    if (end == std::string::npos) return "";
                    return content.substr(pos, end - pos);
                } else {
                    while (end < content.length() && content[end] != ',' && content[end] != '}' && content[end] != '\n') end++;
                    return content.substr(pos, end - pos);
                }
            };
            
            // Загружаем значения
            std::string n3_val = find_value("n3_interface");
            if (!n3_val.empty()) config.n3_interface = n3_val;
            
            std::string n4_val = find_value("n4_interface");
            if (!n4_val.empty()) config.n4_interface = n4_val;
            
            std::string n6_val = find_value("n6_interface");
            if (!n6_val.empty()) config.n6_interface = n6_val;
            
            std::string n4_port_val = find_value("n4_port");
            if (!n4_port_val.empty()) config.n4_port = std::stoi(n4_port_val);
            
            std::string sbi_port_val = find_value("sbi_port");
            if (!sbi_port_val.empty()) config.sbi_port = std::stoi(sbi_port_val);
            
            std::string verbose_val = find_value("verbose");
            if (!verbose_val.empty()) config.verbose = (verbose_val == "true");
            
            std::cout << "[CONFIG] JSON config loaded successfully" << std::endl;
        }
        else if (extension == ".yaml" || extension == ".yml") {
            // Простой парсинг YAML (для примера)
            std::ifstream file(path);
            if (!file.is_open()) {
                throw std::runtime_error("Cannot open file");
            }
            
            std::string line;
            while (std::getline(file, line)) {
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    std::string key = line.substr(0, colon_pos);
                    std::string value = line.substr(colon_pos + 1);
                    
                    // Удаляем пробелы
                    key.erase(0, key.find_first_not_of(" \t"));
                    key.erase(key.find_last_not_of(" \t") + 1);
                    value.erase(0, value.find_first_not_of(" \t"));
                    value.erase(value.find_last_not_of(" \t\r") + 1);
                    
                    if (key == "n3_interface") config.n3_interface = value;
                    else if (key == "n4_interface") config.n4_interface = value;
                    else if (key == "n6_interface") config.n6_interface = value;
                    else if (key == "n4_port") config.n4_port = std::stoi(value);
                    else if (key == "sbi_port") config.sbi_port = std::stoi(value);
                    else if (key == "verbose") config.verbose = (value == "true");
                }
            }
            std::cout << "[CONFIG] YAML config loaded successfully" << std::endl;
        }
        else {
            std::cerr << "[CONFIG] Unknown config file format: " << extension << std::endl;
            std::cerr << "[CONFIG] Using default configuration" << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[CONFIG] Error loading config: " << e.what() << std::endl;
        std::cerr << "[CONFIG] Using default configuration" << std::endl;
    }
    
    return config;
}

} // namespace upf

// Реализация функций для main.cpp

std::optional<std::filesystem::path> resolve_config_path(
    const std::string& program_name,
    const std::optional<std::string>& provided_path) {
    
    // Если путь указан в командной строке, используем его
    if (provided_path.has_value()) {
        std::filesystem::path path(provided_path.value());
        if (std::filesystem::exists(path)) {
            return std::filesystem::absolute(path);
        }
        std::cerr << "[CONFIG] Provided config path does not exist: " << provided_path.value() << std::endl;
        return std::nullopt;
    }
    
    // Ищем в стандартных местах
    std::vector<std::filesystem::path> search_paths = {
        "runtime_config.json",
        "config/runtime_config.json",
        "../config/runtime_config.json",
        "./runtime_config.yaml",
        "./config/runtime_config.yaml",
        "../config/runtime_config.yaml",
        "upf_config.json",
        "config/upf_config.json",
        "upf_config.yaml",
        "config/upf_config.yaml"
    };
    
    // Получаем путь к исполняемому файлу
    std::filesystem::path exe_path;
    if (!program_name.empty()) {
        exe_path = std::filesystem::path(program_name).parent_path();
    }
    
    for (const auto& path : search_paths) {
        // Проверяем относительно текущей директории
        if (std::filesystem::exists(path)) {
            std::cout << "[CONFIG] Found config at: " << std::filesystem::absolute(path) << std::endl;
            return std::filesystem::absolute(path);
        }
        
        // Проверяем относительно директории исполняемого файла
        if (!exe_path.empty()) {
            std::filesystem::path full_path = exe_path / path;
            if (std::filesystem::exists(full_path)) {
                std::cout << "[CONFIG] Found config at: " << full_path << std::endl;
                return full_path;
            }
        }
    }
    
    std::cout << "[CONFIG] No config file found, using defaults" << std::endl;
    return std::nullopt;
}

// Реализация UpfRuntime


bool UpfRuntime::initialize() {
    if (initialized_) {
        return true;
    }
    
    std::cout << "[UPF] Initializing UPF runtime..." << std::endl;
    
    // Инициализация интерфейсов
    std::cout << "[UPF] N3 interface: " << config_.n3_interface << std::endl;
    std::cout << "[UPF] N4 interface: " << config_.n4_interface << std::endl;
    std::cout << "[UPF] N6 interface: " << config_.n6_interface << std::endl;
    std::cout << "[UPF] N4 port: " << config_.n4_port << std::endl;
    std::cout << "[UPF] SBI port: " << config_.sbi_port << std::endl;
    std::cout << "[UPF] Packet buffer size: " << config_.packet_buffer_size << std::endl;
    std::cout << "[UPF] Session table size: " << config_.session_table_size << std::endl;
    
    // TODO: Здесь должна быть реальная инициализация:
    // - Создание сокетов для N3, N4, N6 интерфейсов
    // - Инициализация таблицы сессий
    // - Выделение буферов для пакетов
    // - Запуск потоков обработки
    
    initialized_ = true;
    std::cout << "[UPF] UPF runtime initialized successfully" << std::endl;
    return true;
}

void UpfRuntime::shutdown() {
    if (!initialized_) {
        return;
    }
    
    std::cout << "[UPF] Shutting down UPF runtime..." << std::endl;
    
    // TODO: Очистка ресурсов:
    // - Закрытие сокетов
    // - Очистка таблицы сессий
    // - Освобождение буферов
    // - Остановка потоков
    
    initialized_ = false;
    std::cout << "[UPF] UPF runtime shutdown complete" << std::endl;
}

int UpfRuntime::run_session() {
    if (!initialize()) {
        std::cerr << "[UPF] Failed to initialize runtime" << std::endl;
        return 1;
    }
    
    std::cout << "[UPF] Running UPF session..." << std::endl;
    
    // TODO: Основная логика обработки сессий
    // Здесь должен быть основной цикл обработки:
    // - Прием PFCP сообщений на N4 интерфейсе
    // - Обработка установки/изменения/удаления сессий
    // - Пересылка пользовательского трафика между N3 и N6
    // - Сбор статистики и метрик
    
    // Для примера просто ждем Enter для завершения
    std::cout << "[UPF] UPF is running. Press Enter to stop..." << std::endl;
    std::cin.get();
    
    return 0;
}

// Реализация run_session_once

int run_session_once(UpfRuntime& runtime, const RuntimeInvocationContext& ctx, bool no_wait) {
    if (ctx.verbose) {
        std::cout << "[MAIN] Running session with context:" << std::endl;
        std::cout << "[MAIN]   Program: " << ctx.program_name << std::endl;
        if (ctx.config_path) {
            std::cout << "[MAIN]   Config: " << ctx.config_path->string() << std::endl;
        }
        std::cout << "[MAIN]   Verbose: " << (ctx.verbose ? "enabled" : "disabled") << std::endl;
    }
    int result = runtime.run_session(no_wait);
    if (ctx.verbose) {
        std::cout << "[MAIN] Session completed with code: " << result << std::endl;
    }
    return result;
}