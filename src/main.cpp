#include "upf/upf.hpp"
#include "upf/modules/observability.hpp"
#include "upf/cli.hpp"
#include "upf/node.hpp"
#include <iostream>
#include <clocale>
#if defined(_WIN32)
#include <windows.h>
#endif
#include <clocale>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <cstdlib>
#include <string>
#include <optional>
#include <filesystem>


// Вспомогательная функция для временных меток
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}


constexpr const char* COLOR_INFO = "\033[34m";   // blue
constexpr const char* COLOR_DEBUG = "\033[32m";  // green
constexpr const char* COLOR_ERROR = "\033[31m";  // red
constexpr const char* COLOR_RESET = "\033[0m";

#define LOG_INFO(msg)   std::cout << COLOR_INFO << "[" << get_timestamp() << "] [INFO]  " << msg << COLOR_RESET << std::endl
#define LOG_DEBUG(msg)  std::cout << COLOR_DEBUG << "[" << get_timestamp() << "] [DEBUG] " << msg << COLOR_RESET << std::endl
#define LOG_ERROR(msg)  std::cerr << COLOR_ERROR << "[" << get_timestamp() << "] [ERROR] " << msg << COLOR_RESET << std::endl

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
    std::cout << "  - ../config/runtime_config.json\n";
    std::cout << "  - ./runtime_config.yaml\n";
    std::cout << "  - ./config/runtime_config.yaml\n";
    std::cout << "  - ../config/runtime_config.yaml\n\n";
}

// ===== MAIN =====
int main(int argc, char* argv[]) {
    // Установка локали и кодовой страницы для корректного вывода UTF-8 в консоль
    std::setlocale(LC_ALL, "");
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
#endif
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
    bool no_wait = false;
    bool cli_mode = false;

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
        else if (arg == "--no-wait") {
            no_wait = true;
        }
        else if (arg == "--cli") {
            cli_mode = true;
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
            if (verbose) {
                LOG_DEBUG("N3 interface: " + cfg.n3_interface);
                LOG_DEBUG("N4 interface: " + cfg.n4_interface);
                LOG_DEBUG("N6 interface: " + cfg.n6_interface);
                LOG_DEBUG("N4 port: " + std::to_string(cfg.n4_port));
                LOG_DEBUG("SBI port: " + std::to_string(cfg.sbi_port));
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to load config: " + std::string(e.what()));
            LOG_INFO("Using default configuration");
            cfg = upf::default_runtime_config();
        }
    } else {
        LOG_INFO("No config file found - running with defaults");
        cfg = upf::default_runtime_config();
    }
    
    if (verbose) {
        cfg.verbose = true;
    }

    if (cli_mode) {
        LOG_INFO("Starting interactive CLI mode (REPL)...");
        upf::UpfCli cli(cfg);
        std::string line;
        std::cout << "vUPF CLI (REPL) mode. Type a command or 'exit' to quit." << std::endl;
        while (true) {
            std::cout << "> ";
            if (!std::getline(std::cin, line)) break;
            if (line == "exit" || line == "quit") break;
            std::string result = cli.execute(line);
            std::cout << result << std::endl;
        }
        LOG_INFO("CLI mode finished.");
        return 0;
    } else {
        // Создаём runtime
        UpfRuntime runtime(cfg);

        RuntimeInvocationContext ctx{
            program_name,
            resolved,
            verbose
        };

        LOG_INFO("Starting session processing...");

        // Запуск основной логики
        int exit_code = run_session_once(runtime, ctx, no_wait);

        LOG_INFO("vUPF session completed. Exit code: " + std::to_string(exit_code));

        return exit_code;
    }
}