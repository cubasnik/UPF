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