// Корректное начало файла
#include "upf/upf.hpp"
#include <iostream>
#include <filesystem>

// Реализация UpfRuntime
UpfRuntime::UpfRuntime(const upf::RuntimeConfig& config)
    : config_(config), initialized_(false) {}

UpfRuntime::~UpfRuntime() {
    if (initialized_) {
        shutdown();
    }
}

int UpfRuntime::run_session(bool no_wait) {
    if (!initialize()) {
        std::cerr << "[UPF] Failed to initialize runtime" << std::endl;
        return 1;
    }
    std::cout << "[UPF] Running UPF session..." << std::endl;
    if (no_wait) {
        std::cout << "[UPF] [TEST MODE] Auto-exit enabled (no wait for Enter)" << std::endl;
        return 0;
    }
    std::cout << "[UPF] UPF is running. Press Enter to stop..." << std::endl;
    std::cin.get();
    return 0;
}