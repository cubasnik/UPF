#ifdef _WIN32
#define UPF_COLOR_INFO "\033[34m"
#define UPF_COLOR_ERROR "\033[31m"
#define UPF_COLOR_RESET "\033[0m"
#else
constexpr const char* UPF_COLOR_INFO = "\033[34m";
constexpr const char* UPF_COLOR_ERROR = "\033[31m";
constexpr const char* UPF_COLOR_RESET = "\033[0m";
#endif
#include "upf/config/runtime_config.hpp"
#include <string>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <cstring>
#include <optional>
#include "upf/upf.hpp"

// Implementation is now in config/runtime_config.cpp