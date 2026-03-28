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
constexpr const char* COLOR_CYAN = "\033[36m";   // cyan
constexpr const char* COLOR_BOLD = "\033[1m";    // bold
constexpr const char* COLOR_YELLOW = "\033[33m"; // yellow
constexpr const char* COLOR_MAGENTA = "\033[35m"; // magenta
constexpr const char* COLOR_GREEN = "\033[92m";   // bright green
constexpr const char* COLOR_RESET = "\033[0m";

#define LOG_INFO(msg)   std::cout << COLOR_INFO << "[" << get_timestamp() << "] [INFO]  " << msg << COLOR_RESET << std::endl
#define LOG_DEBUG(msg)  std::cout << COLOR_DEBUG << "[" << get_timestamp() << "] [DEBUG] " << msg << COLOR_RESET << std::endl
#define LOG_ERROR(msg)  std::cerr << COLOR_ERROR << "[" << get_timestamp() << "] [ERROR] " << msg << COLOR_RESET << std::endl

// ===== PRINT HELP =====
void print_help(const std::string& program_name) {
    std::cout << "\n" << COLOR_CYAN << COLOR_BOLD << "=====================================\n";
    std::cout << "vUPF - Virtual User Plane Function\n";
    std::cout << "Version: 0.1 (debug build)\n";
    std::cout << "=====================================" << COLOR_RESET << "\n\n";
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
    std::cout << COLOR_CYAN << COLOR_BOLD << "=====================================\n";
    std::cout << "vUPF - Virtual User Plane Function\n";
    std::cout << "Version: 0.1 (debug build)\n";
    std::cout << "=====================================" << COLOR_RESET << "\n\n";

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
        LOG_INFO(std::string(COLOR_GREEN) + "Successfully resolved config path: " + resolved->string() + COLOR_RESET);
        try {
            cfg = upf::load_runtime_config(resolved->string());
            LOG_INFO(std::string(COLOR_GREEN) + "Runtime config loaded successfully" + COLOR_RESET);
            LOG_INFO(std::string(COLOR_GREEN) + "JSON config loaded successfully" + COLOR_RESET);
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
        LOG_INFO(std::string(COLOR_CYAN) + "Starting interactive CLI mode (REPL)..." + COLOR_RESET);
        // Construct UpfNode with config values
        std::vector<std::string> peer_addresses; // Add logic if you want to support peers from config
        std::string sbi_port_str = std::to_string(cfg.sbi_port);
        upf::UpfNode node(cfg.n4_interface, sbi_port_str, peer_addresses);
        node.start();
        // Выводим адреса N4 и SBI с выделением
        // N4 address: выделить 'lo' как magenta, иначе желтым
        if (cfg.n4_interface == std::string("lo")) {
            std::cout << "[UPF] N4 address: " << COLOR_MAGENTA << cfg.n4_interface << COLOR_RESET << std::endl;
        } else {
            std::cout << "[UPF] N4 address: " << COLOR_YELLOW << cfg.n4_interface << COLOR_RESET << std::endl;
        }
        std::cout << "[UPF] SBI address: " << COLOR_MAGENTA << sbi_port_str << COLOR_RESET << std::endl;
        upf::UpfCli cli(cfg, &node);
        std::string line;
        std::cout << "vUPF CLI (REPL) mode. Type a command or '" << COLOR_YELLOW << "exit" << COLOR_RESET << "' to quit." << std::endl;
        std::cout << "Type '" << COLOR_YELLOW << "help" << COLOR_RESET << "' to see available commands and usage examples." << std::endl;
        while (true) {
            std::cout << "> ";
            if (!std::getline(std::cin, line)) break;
            if (line == "exit" || line == "quit") break;
            std::string result = cli.execute(line);
            // Подсветка help, exit, successfully, 8080
            size_t pos = 0;
            // help
            while ((pos = result.find("help", pos)) != std::string::npos) {
                result.replace(pos, 4, std::string(COLOR_YELLOW) + "help" + COLOR_RESET);
                pos += std::string(COLOR_YELLOW).size() + 4 + std::string(COLOR_RESET).size();
            }
            pos = 0;
            // exit
            while ((pos = result.find("exit", pos)) != std::string::npos) {
                result.replace(pos, 4, std::string(COLOR_YELLOW) + "exit" + COLOR_RESET);
                pos += std::string(COLOR_YELLOW).size() + 4 + std::string(COLOR_RESET).size();
            }
            pos = 0;
            // successfully
            while ((pos = result.find("successfully", pos)) != std::string::npos) {
                result.replace(pos, 12, std::string(COLOR_GREEN) + "successfully" + COLOR_RESET);
                pos += std::string(COLOR_GREEN).size() + 12 + std::string(COLOR_RESET).size();
            }
            pos = 0;
            // 8080
            while ((pos = result.find("8080", pos)) != std::string::npos) {
                result.replace(pos, 4, std::string(COLOR_MAGENTA) + "8080" + COLOR_RESET);
                pos += std::string(COLOR_MAGENTA).size() + 4 + std::string(COLOR_RESET).size();
            }
            std::cout << result << std::endl;
        }
        node.stop();
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