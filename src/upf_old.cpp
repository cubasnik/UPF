#include "upf/upf.hpp"
#include "upf/modules/observability.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <cstdlib>
#include <string>
#include <optional>
#include <filesystem>

// Вспомогательная функция для красивого времени
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

#define LOG_INFO(msg)   std::cout << "[" << get_timestamp() << "] [INFO]  " << msg << std::endl
#define LOG_DEBUG(msg)  std::cout << "[" << get_timestamp() << "] [DEBUG] " << msg << std::endl
#define LOG_ERROR(msg)  std::cerr << "[" << get_timestamp() << "] [ERROR] " << msg << std::endl

// ===== ТВОИ СТРУКТУРЫ И ФУНКЦИИ (без изменений) =====
// (вставь сюда все свои структуры, stub-функции, resolve_config_path, UpfRuntime и т.д.)

// ===== PRINT HELP =====
void print_help(const std::string& program_name) {
    std::cout << "\n=====================================\n";
    std::cout << "vUPF - Virtual User Plane Function\n";
    std::cout << "Version: 0.1 (debug build)\n";
    std::cout << "=====================================\n\n";
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --help              Show this help message\n";
    std::cout << "  --config <path>     Path to runtime config file (json/yaml)\n";
    std::cout << "  --verbose           Enable verbose output\n";
    std::cout << "\nDefault config search paths:\n";
    std::cout << "  - ./runtime_config.json\n";
    std::cout << "  - ./config/runtime_config.json\n";
    std::cout << "  - ../config/runtime_config.json\n\n";
}

// ===== MAIN =====
int main(int argc, char* argv[]) {
    std::cout << "=====================================\n";
    std::cout << "vUPF - Virtual User Plane Function\n";
    std::cout << "Version: 0.1 (debug build)\n";
    std::cout << "=====================================\n\n";

    if (argc < 1) {
        LOG_ERROR("No program name provided");
        return 1;
    }

    std::string program_name = argv[0];

    std::optional<std::string> config_path;
    bool verbose = false;
    bool show_help = false;

    // Парсинг аргументов
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            show_help = true;
        }
        else if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        }
        else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        }
        else {
            LOG_ERROR("Unknown argument: " + arg);
            show_help = true;
        }
    }

    if (show_help) {
        print_help(program_name);
        return 0;
    }

    LOG_INFO("vUPF initializing...");

    if (verbose) {
        LOG_DEBUG("Verbose mode enabled");
    }

    // Поиск и загрузка конфига
    const auto resolved = resolve_config_path(program_name, config_path);

    upf::RuntimeConfig cfg;
    if (resolved) {
        LOG_INFO("Successfully resolved config path: " + resolved->string());
        try {
            cfg = upf::load_runtime_config(resolved->string());
            LOG_INFO("Runtime config loaded successfully");
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to load config: " + std::string(e.what()));
            return 1;
        }
    } else {
        LOG_ERROR("No config file found - running with defaults");
        // Здесь можно задать дефолтный конфиг, если нужно
    }

    // Создаём runtime
    UpfRuntime runtime(cfg);

    RuntimeInvocationContext ctx{
        program_name,
        resolved
    };

    LOG_INFO("Starting session processing...");

    // Запуск основной логики
    int exit_code = run_session_once(runtime, ctx);

    LOG_INFO("vUPF session completed. Exit code: " + std::to_string(exit_code));

    return exit_code;
}