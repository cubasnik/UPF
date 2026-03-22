#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstdlib>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <vector>

#include "upf/adapters/console_adapters.hpp"
#include "upf/adapters/network_adapters.hpp"
#include "upf/cli.hpp"
#include "upf/config/runtime_config.hpp"
#include "upf/modules/observability.hpp"
#include "upf/upf.hpp"

namespace {

constexpr const char* kDefaultDemoImsi = "250200123456789";
constexpr const char* kDefaultDemoPduSessionId = "10";

struct DemoSessionTarget {
    std::string imsi {kDefaultDemoImsi};
    std::string pdu_session_id {kDefaultDemoPduSessionId};
    std::string dnn {"internet"};
    std::string profile;
};

struct DemoBytesTarget {
    std::size_t bytes {0};
    DemoSessionTarget target {};
};

struct DemoToolCommandPreview {
    std::filesystem::path tool_path {};
    std::optional<std::filesystem::path> config_path {};
    std::string command;
};

struct DemoMatrixQuery {
    DemoBytesTarget target {};
    std::optional<std::string> preset_filter {};
    std::vector<std::string> compare_presets {};
};

struct DemoCompareQuery {
    DemoBytesTarget target {};
    std::vector<std::string> compare_presets {};
};

struct DemoOptionFlags {
    bool seen_dnn {false};
    bool seen_preset {false};
    bool seen_profile {false};
};

std::string trim(std::string value);
std::string to_lower(std::string value);
const std::vector<std::pair<std::string, std::string>>& demo_preset_mappings();
std::optional<std::pair<std::string, std::string>> parse_demo_preset(const std::string& value);
std::optional<DemoBytesTarget> parse_demo_bytes_target(const std::vector<std::string>& args,
                                                       std::size_t default_bytes,
                                                       bool prefer_bytes_suffix,
                                                       std::string* error);

std::optional<std::vector<std::string>> parse_demo_preset_compare(const std::string& value) {
    const std::size_t separator = value.find(',');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= value.size()) {
        return std::nullopt;
    }

    const std::string first = to_lower(trim(value.substr(0, separator)));
    const std::string second = to_lower(trim(value.substr(separator + 1)));
    if (first.empty() || second.empty() || first == second) {
        return std::nullopt;
    }
    if (!parse_demo_preset(first).has_value() || !parse_demo_preset(second).has_value()) {
        return std::nullopt;
    }
    return std::vector<std::string> {first, second};
}

std::vector<std::string> selected_demo_matrix_presets(const DemoMatrixQuery& query) {
    if (!query.compare_presets.empty()) {
        return query.compare_presets;
    }
    if (query.preset_filter.has_value()) {
        return std::vector<std::string> {*query.preset_filter};
    }

    std::vector<std::string> presets;
    for (const auto& preset : demo_preset_mappings()) {
        presets.push_back(preset.first);
    }
    return presets;
}

std::optional<DemoCompareQuery> parse_demo_compare_query(const std::vector<std::string>& args,
                                                        bool prefer_bytes_suffix,
                                                        std::string* error) {
    std::vector<std::string> filtered_args;
    DemoCompareQuery query {};
    query.target.bytes = 1200;
    bool seen_compare = false;

    for (const auto& arg : args) {
        const std::size_t separator = arg.find('=');
        if (separator == std::string::npos) {
            filtered_args.push_back(arg);
            continue;
        }

        const std::string key = to_lower(arg.substr(0, separator));
        const std::string value = arg.substr(separator + 1);
        if (key == "compare" && !value.empty()) {
            if (seen_compare) {
                if (error != nullptr) {
                    *error = "ERR: duplicate compare option";
                }
                return std::nullopt;
            }
            const auto compare = parse_demo_preset_compare(value);
            if (!compare.has_value()) {
                if (error != nullptr) {
                    *error = "ERR: compare must be preset1,preset2";
                }
                return std::nullopt;
            }
            seen_compare = true;
            query.compare_presets = *compare;
            continue;
        }

        if (error != nullptr) {
            *error = "ERR: compare cannot be combined with preset, dnn, or profile";
        }
        return std::nullopt;
    }

    if (query.compare_presets.empty()) {
        if (error != nullptr) {
            *error = "ERR: compare must be preset1,preset2";
        }
        return std::nullopt;
    }

    const auto target = parse_demo_bytes_target(filtered_args, 1200, prefer_bytes_suffix, error);
    if (!target.has_value()) {
        return std::nullopt;
    }
    query.target = *target;
    return query;
}

struct RuntimeInvocationContext;

upf::PfcpSessionRequest build_demo_request(const upf::RuntimeConfig& cfg,
                                           const std::string& imsi,
                                           const std::string& pdu_session_id,
                                           const std::string& dnn,
                                           const std::string& profile);

std::string resolve_demo_profile(const upf::PfcpSessionRequest& request, const upf::RuntimeConfig& cfg);

std::string format_demo_target_validation(const upf::PfcpSessionRequest& request,
                                          const upf::RuntimeConfig& cfg,
                                          std::size_t bytes);

std::string format_demo_tool_command_validation(const upf::PfcpSessionRequest& request,
                                                const upf::RuntimeConfig& cfg,
                                                std::size_t bytes,
                                                const DemoToolCommandPreview& preview);

std::string format_demo_tool_command_validation_json(const upf::PfcpSessionRequest& request,
                                                     const upf::RuntimeConfig& cfg,
                                                     std::size_t bytes,
                                                     const DemoToolCommandPreview& preview);

std::optional<std::size_t> parse_size_token(const std::string& value);

std::optional<DemoToolCommandPreview> build_demo_tool_command_preview(const RuntimeInvocationContext& invocation,
                                                                      std::size_t bytes,
                                                                      const DemoSessionTarget& target,
                                                                      std::string* error);

std::string trim(std::string value) {
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool is_unsigned_number(const std::string& value) {
    if (value.empty()) {
        return false;
    }
    for (const char ch : value) {
        if (ch < '0' || ch > '9') {
            return false;
        }
    }
    return true;
}

std::string to_lower(std::string value) {
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return value;
}

bool is_supported_profile_name(const std::string& profile) {
    return profile == "ipv4" || profile == "ipv6" || profile == "ethernet";
}

const std::vector<std::pair<std::string, std::string>>& demo_preset_mappings() {
    static const std::vector<std::pair<std::string, std::string>> presets {
        {"internet-ipv4", "internet ipv4"},
        {"internet-ipv6", "internet ipv6"},
        {"ims-ipv4", "ims ipv4"},
        {"ims-ipv6", "ims ipv6"},
        {"enterprise-ipv4", "enterprise ipv4"},
        {"enterprise-ipv6", "enterprise ipv6"},
        {"enterprise-ethernet", "enterprise ethernet"},
    };
    return presets;
}

std::string format_demo_presets() {
    std::ostringstream output;
    output << "demo-presets\n";
    for (const auto& preset : demo_preset_mappings()) {
        const std::size_t separator = preset.second.find(' ');
        output << "  " << preset.first;
        if (separator != std::string::npos) {
            output << " -> dnn=" << preset.second.substr(0, separator)
                   << " profile=" << preset.second.substr(separator + 1);
        }
        output << "\n";
    }
    return output.str();
}

std::string format_demo_presets_json() {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoPresetsSchema) << ','
           << "\"presets\":[";

    bool first = true;
    for (const auto& preset : demo_preset_mappings()) {
        const std::size_t separator = preset.second.find(' ');
        if (separator == std::string::npos) {
            continue;
        }
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{'
               << "\"name\":\"" << upf::json_escape(preset.first) << "\"," 
               << "\"dnn\":\"" << upf::json_escape(preset.second.substr(0, separator)) << "\"," 
               << "\"profile\":\"" << upf::json_escape(preset.second.substr(separator + 1)) << "\""
               << '}';
    }

    output << "]}";
    return output.str();
}

std::optional<DemoMatrixQuery> parse_demo_matrix_query(const std::vector<std::string>& args,
                                                       std::string* error) {
    std::vector<std::string> positional;
    DemoMatrixQuery query {};
    query.target.bytes = 1200;
    bool seen_preset = false;
    bool seen_compare = false;

    for (const auto& arg : args) {
        const std::size_t separator = arg.find('=');
        if (separator == std::string::npos) {
            positional.push_back(arg);
            continue;
        }

        const std::string key = to_lower(arg.substr(0, separator));
        const std::string value = arg.substr(separator + 1);
        if ((key == "preset" || key == "only") && !value.empty()) {
            if (seen_preset) {
                if (error != nullptr) {
                    *error = "ERR: duplicate preset option";
                }
                return std::nullopt;
            }
            if (!query.compare_presets.empty()) {
                if (error != nullptr) {
                    *error = "ERR: preset and compare cannot be combined";
                }
                return std::nullopt;
            }
            if (!parse_demo_preset(value).has_value()) {
                if (error != nullptr) {
                    *error = "ERR: unknown preset";
                }
                return std::nullopt;
            }
            seen_preset = true;
            query.preset_filter = to_lower(value);
            continue;
        }
        if (key == "compare" && !value.empty()) {
            if (seen_compare) {
                if (error != nullptr) {
                    *error = "ERR: duplicate compare option";
                }
                return std::nullopt;
            }
            if (query.preset_filter.has_value()) {
                if (error != nullptr) {
                    *error = "ERR: preset and compare cannot be combined";
                }
                return std::nullopt;
            }
            const auto compare = parse_demo_preset_compare(value);
            if (!compare.has_value()) {
                if (error != nullptr) {
                    *error = "ERR: compare must be preset1,preset2";
                }
                return std::nullopt;
            }
            seen_compare = true;
            query.compare_presets = *compare;
            continue;
        }

        if (error != nullptr) {
            *error = "ERR: unknown demo-matrix option";
        }
        return std::nullopt;
    }

    if (positional.empty()) {
        return query;
    }

    const auto target = parse_demo_bytes_target(positional, 1200, true, error);
    if (!target.has_value()) {
        return std::nullopt;
    }

    query.target = *target;
    return query;
}

std::string format_demo_matrix(const upf::RuntimeConfig& cfg, const DemoMatrixQuery& matrix_query) {
    std::ostringstream output;
    output << "demo-matrix imsi=" << matrix_query.target.target.imsi
           << " pdu=" << matrix_query.target.target.pdu_session_id
           << " bytes=" << matrix_query.target.bytes;
    if (matrix_query.preset_filter.has_value()) {
        output << " preset=" << *matrix_query.preset_filter;
    } else if (!matrix_query.compare_presets.empty()) {
        output << " compare=" << matrix_query.compare_presets[0] << ',' << matrix_query.compare_presets[1];
    }
    output << "\n";
    for (const auto& preset_name : selected_demo_matrix_presets(matrix_query)) {
        const auto resolved = parse_demo_preset(preset_name);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = matrix_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        output << "  preset=" << preset_name << ' '
               << format_demo_target_validation(request, cfg, matrix_query.target.bytes) << "\n";
    }
    return output.str();
}

std::string format_demo_matrix(const upf::RuntimeConfig& cfg) {
    DemoMatrixQuery query {};
    query.target.bytes = 1200;
    return format_demo_matrix(cfg, query);
}

std::string format_demo_matrix_json(const upf::RuntimeConfig& cfg, const DemoMatrixQuery& matrix_query) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoMatrixSchema) << ','
           << "\"imsi\":\"" << upf::json_escape(matrix_query.target.target.imsi) << "\","
           << "\"pdu\":\"" << upf::json_escape(matrix_query.target.target.pdu_session_id) << "\","
           << "\"bytes\":" << matrix_query.target.bytes << ',';
    if (matrix_query.preset_filter.has_value()) {
        output << "\"preset\":\"" << upf::json_escape(*matrix_query.preset_filter) << "\",";
    } else if (!matrix_query.compare_presets.empty()) {
        output << "\"compare\":[\"" << upf::json_escape(matrix_query.compare_presets[0])
               << "\",\"" << upf::json_escape(matrix_query.compare_presets[1]) << "\"],";
    }
    output
           << "\"entries\":[";

    bool first = true;
    for (const auto& preset : selected_demo_matrix_presets(matrix_query)) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = matrix_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{'
             << "\"preset\":\"" << upf::json_escape(preset) << "\","
               << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\","
               << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\","
               << "\"teid\":\"" << upf::json_escape(request.teid) << "\","
               << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
               << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
               << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
               << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\""
               << '}';
    }

    output << "]}";
    return output.str();
}

std::string format_demo_matrix_json(const upf::RuntimeConfig& cfg) {
    DemoMatrixQuery query {};
    query.target.bytes = 1200;
    return format_demo_matrix_json(cfg, query);
}

std::optional<std::string> format_demo_matrix_tool_command(const upf::RuntimeConfig& cfg,
                                                           const RuntimeInvocationContext& invocation,
                                                           const DemoMatrixQuery& matrix_query,
                                                           std::string* error) {
    std::ostringstream output;
    output << "demo-matrix imsi=" << matrix_query.target.target.imsi
           << " pdu=" << matrix_query.target.target.pdu_session_id
           << " bytes=" << matrix_query.target.bytes;
    if (matrix_query.preset_filter.has_value()) {
        output << " preset=" << *matrix_query.preset_filter;
    } else if (!matrix_query.compare_presets.empty()) {
        output << " compare=" << matrix_query.compare_presets[0] << ',' << matrix_query.compare_presets[1];
    }
    output << " tool-cmd\n";
    for (const auto& preset : selected_demo_matrix_presets(matrix_query)) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = matrix_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto preview = build_demo_tool_command_preview(invocation, matrix_query.target.bytes, target, error);
        if (!preview.has_value()) {
            return std::nullopt;
        }
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        output << "  preset=" << preset << ' '
               << format_demo_tool_command_validation(request, cfg, matrix_query.target.bytes, *preview) << "\n";
    }
    return output.str();
}

std::optional<std::string> format_demo_matrix_tool_command_json(const upf::RuntimeConfig& cfg,
                                                                const RuntimeInvocationContext& invocation,
                                                                const DemoMatrixQuery& matrix_query,
                                                                std::string* error) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoMatrixToolCommandSchema) << ','
           << "\"imsi\":\"" << upf::json_escape(matrix_query.target.target.imsi) << "\","
           << "\"pdu\":\"" << upf::json_escape(matrix_query.target.target.pdu_session_id) << "\","
           << "\"bytes\":" << matrix_query.target.bytes << ',';
    if (matrix_query.preset_filter.has_value()) {
        output << "\"preset\":\"" << upf::json_escape(*matrix_query.preset_filter) << "\",";
    } else if (!matrix_query.compare_presets.empty()) {
        output << "\"compare\":[\"" << upf::json_escape(matrix_query.compare_presets[0])
               << "\",\"" << upf::json_escape(matrix_query.compare_presets[1]) << "\"],";
    }
    output
           << "\"entries\":[";

    bool first = true;
    for (const auto& preset : selected_demo_matrix_presets(matrix_query)) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = matrix_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto preview = build_demo_tool_command_preview(invocation, matrix_query.target.bytes, target, error);
        if (!preview.has_value()) {
            return std::nullopt;
        }
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{'
             << "\"preset\":\"" << upf::json_escape(preset) << "\","
               << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\","
               << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\","
               << "\"teid\":\"" << upf::json_escape(request.teid) << "\","
               << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
               << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
               << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
               << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\","
               << "\"tool_path\":\"" << upf::json_escape(preview->tool_path.string()) << "\","
               << "\"config_path\":" << (preview->config_path.has_value() ? '"' + upf::json_escape(preview->config_path->string()) + '"' : std::string("null")) << ','
               << "\"command\":\"" << upf::json_escape(preview->command) << "\""
               << '}';
    }

    output << "]}";
    return output.str();
}

std::string format_demo_compare(const upf::RuntimeConfig& cfg, const DemoCompareQuery& compare_query) {
    std::ostringstream output;
    output << "demo-compare imsi=" << compare_query.target.target.imsi
           << " pdu=" << compare_query.target.target.pdu_session_id
           << " bytes=" << compare_query.target.bytes
           << " compare=" << compare_query.compare_presets[0] << ',' << compare_query.compare_presets[1] << "\n";
    for (const auto& preset : compare_query.compare_presets) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = compare_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        output << "  preset=" << preset << ' '
               << format_demo_target_validation(request, cfg, compare_query.target.bytes) << "\n";
    }
    return output.str();
}

std::string format_demo_compare_json(const upf::RuntimeConfig& cfg, const DemoCompareQuery& compare_query) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoCompareSchema) << ','
           << "\"imsi\":\"" << upf::json_escape(compare_query.target.target.imsi) << "\","
           << "\"pdu\":\"" << upf::json_escape(compare_query.target.target.pdu_session_id) << "\","
           << "\"bytes\":" << compare_query.target.bytes << ','
           << "\"compare\":[\"" << upf::json_escape(compare_query.compare_presets[0])
           << "\",\"" << upf::json_escape(compare_query.compare_presets[1]) << "\"],"
           << "\"entries\":[";

    bool first = true;
    for (const auto& preset : compare_query.compare_presets) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = compare_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{'
               << "\"preset\":\"" << upf::json_escape(preset) << "\","
               << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\","
               << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\","
               << "\"teid\":\"" << upf::json_escape(request.teid) << "\","
               << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
               << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
               << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
               << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\""
               << '}';
    }

    output << "]}";
    return output.str();
}

std::optional<std::string> format_demo_compare_tool_command(const upf::RuntimeConfig& cfg,
                                                            const RuntimeInvocationContext& invocation,
                                                            const DemoCompareQuery& compare_query,
                                                            std::string* error) {
    std::ostringstream output;
    output << "demo-compare imsi=" << compare_query.target.target.imsi
           << " pdu=" << compare_query.target.target.pdu_session_id
           << " bytes=" << compare_query.target.bytes
           << " compare=" << compare_query.compare_presets[0] << ',' << compare_query.compare_presets[1]
           << " tool-cmd\n";
    for (const auto& preset : compare_query.compare_presets) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = compare_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto preview = build_demo_tool_command_preview(invocation, compare_query.target.bytes, target, error);
        if (!preview.has_value()) {
            return std::nullopt;
        }
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        output << "  preset=" << preset << ' '
               << format_demo_tool_command_validation(request, cfg, compare_query.target.bytes, *preview) << "\n";
    }
    return output.str();
}

std::optional<std::string> format_demo_compare_tool_command_json(const upf::RuntimeConfig& cfg,
                                                                 const RuntimeInvocationContext& invocation,
                                                                 const DemoCompareQuery& compare_query,
                                                                 std::string* error) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoCompareToolCommandSchema) << ','
           << "\"imsi\":\"" << upf::json_escape(compare_query.target.target.imsi) << "\","
           << "\"pdu\":\"" << upf::json_escape(compare_query.target.target.pdu_session_id) << "\","
           << "\"bytes\":" << compare_query.target.bytes << ','
           << "\"compare\":[\"" << upf::json_escape(compare_query.compare_presets[0])
           << "\",\"" << upf::json_escape(compare_query.compare_presets[1]) << "\"],"
           << "\"entries\":[";

    bool first = true;
    for (const auto& preset : compare_query.compare_presets) {
        const auto resolved = parse_demo_preset(preset);
        if (!resolved.has_value()) {
            continue;
        }
        DemoSessionTarget target = compare_query.target.target;
        target.dnn = resolved->first;
        target.profile = resolved->second;
        const auto preview = build_demo_tool_command_preview(invocation, compare_query.target.bytes, target, error);
        if (!preview.has_value()) {
            return std::nullopt;
        }
        const auto request = build_demo_request(cfg, target.imsi, target.pdu_session_id, target.dnn, target.profile);
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{'
               << "\"preset\":\"" << upf::json_escape(preset) << "\","
               << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\","
               << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\","
               << "\"teid\":\"" << upf::json_escape(request.teid) << "\","
               << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
               << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
               << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
               << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\","
               << "\"tool_path\":\"" << upf::json_escape(preview->tool_path.string()) << "\","
               << "\"config_path\":" << (preview->config_path.has_value() ? '"' + upf::json_escape(preview->config_path->string()) + '"' : std::string("null")) << ','
               << "\"command\":\"" << upf::json_escape(preview->command) << "\""
               << '}';
    }

    output << "]}";
    return output.str();
}

std::string resolve_demo_profile(const upf::PfcpSessionRequest& request, const upf::RuntimeConfig& cfg) {
    if (request.prefer_n6_ethernet) {
        return "ethernet";
    }
    if (request.prefer_n6_ipv6) {
        return "ipv6";
    }
    return to_lower(cfg.n6_default_protocol);
}

std::string format_demo_target_validation(const upf::PfcpSessionRequest& request,
                        const upf::RuntimeConfig& cfg,
                        std::size_t bytes) {
    std::ostringstream output;
    output << "bytes=" << bytes
        << " imsi=" << request.imsi
           << " pdu=" << request.pdu_session_id
           << " dnn=" << request.dnn
           << " profile=" << resolve_demo_profile(request, cfg)
           << " teid=" << request.teid
           << " ue_ipv4=" << (request.ue_ipv4.empty() ? std::string("-") : request.ue_ipv4)
           << " ue_ipv6=" << (request.ue_ipv6.empty() ? std::string("-") : request.ue_ipv6)
           << " ue_mac=" << (request.ue_mac.empty() ? std::string("-") : request.ue_mac)
           << " request_id=" << request.procedure.request_id;
    return output.str();
}

std::string format_demo_target_validation_json(const upf::PfcpSessionRequest& request,
                                               const upf::RuntimeConfig& cfg,
                                               std::size_t bytes) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoTargetSchema) << ','
           << "\"bytes\":" << bytes << ','
           << "\"imsi\":\"" << upf::json_escape(request.imsi) << "\"," 
           << "\"pdu\":\"" << upf::json_escape(request.pdu_session_id) << "\"," 
           << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\"," 
           << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\"," 
           << "\"teid\":\"" << upf::json_escape(request.teid) << "\"," 
           << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
           << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
           << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
           << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\""
           << '}';
    return output.str();
}

std::string format_demo_tool_command_validation(const upf::PfcpSessionRequest& request,
                                                const upf::RuntimeConfig& cfg,
                                                std::size_t bytes,
                                                const DemoToolCommandPreview& preview) {
    std::ostringstream output;
    output << format_demo_target_validation(request, cfg, bytes)
           << " tool_path=" << preview.tool_path.string()
           << " config_path=" << (preview.config_path.has_value() ? preview.config_path->string() : std::string("-"))
           << " command=" << preview.command;
    return output.str();
}

std::string format_demo_tool_command_validation_json(const upf::PfcpSessionRequest& request,
                                                     const upf::RuntimeConfig& cfg,
                                                     std::size_t bytes,
                                                     const DemoToolCommandPreview& preview) {
    std::ostringstream output;
    output << '{'
           << upf::format_schema_json(upf::kDemoToolCommandSchema) << ','
           << "\"bytes\":" << bytes << ','
           << "\"imsi\":\"" << upf::json_escape(request.imsi) << "\","
           << "\"pdu\":\"" << upf::json_escape(request.pdu_session_id) << "\","
           << "\"dnn\":\"" << upf::json_escape(request.dnn) << "\","
           << "\"profile\":\"" << upf::json_escape(resolve_demo_profile(request, cfg)) << "\","
           << "\"teid\":\"" << upf::json_escape(request.teid) << "\","
           << "\"ue_ipv4\":" << (request.ue_ipv4.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv4) + '"') << ','
           << "\"ue_ipv6\":" << (request.ue_ipv6.empty() ? "null" : '"' + upf::json_escape(request.ue_ipv6) + '"') << ','
           << "\"ue_mac\":" << (request.ue_mac.empty() ? "null" : '"' + upf::json_escape(request.ue_mac) + '"') << ','
           << "\"request_id\":\"" << upf::json_escape(request.procedure.request_id) << "\","
           << "\"tool_path\":\"" << upf::json_escape(preview.tool_path.string()) << "\","
           << "\"config_path\":" << (preview.config_path.has_value() ? '"' + upf::json_escape(preview.config_path->string()) + '"' : std::string("null")) << ','
           << "\"command\":\"" << upf::json_escape(preview.command) << "\""
           << '}';
    return output.str();
}

std::optional<std::pair<std::string, std::string>> parse_demo_preset(const std::string& value) {
    const std::string normalized = to_lower(value);
    for (const auto& preset : demo_preset_mappings()) {
        if (normalized != preset.first) {
            continue;
        }
        const std::size_t separator = preset.second.find(' ');
        if (separator == std::string::npos) {
            break;
        }
        return std::pair<std::string, std::string> {
            preset.second.substr(0, separator),
            preset.second.substr(separator + 1)
        };
    }
    return std::nullopt;
}

std::optional<std::pair<std::string, std::string>> parse_profile_alias(const std::string& value) {
    const std::string normalized = to_lower(value);
    if (is_supported_profile_name(normalized)) {
        return std::pair<std::string, std::string> {std::string(), normalized};
    }

    const std::size_t separator = normalized.rfind('-');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= normalized.size()) {
        return std::nullopt;
    }

    const std::string alias_dnn = normalized.substr(0, separator);
    const std::string alias_profile = normalized.substr(separator + 1);
    if (!is_supported_profile_name(alias_profile)) {
        return std::nullopt;
    }

    return std::pair<std::string, std::string> {alias_dnn, alias_profile};
}

std::string format_demo_mac(std::uint32_t seed) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0')
           << "02:10:"
           << std::setw(2) << ((seed >> 16) & 0xFFU) << ':'
           << std::setw(2) << ((seed >> 8) & 0xFFU) << ':'
           << std::setw(2) << (seed & 0xFFU) << ':'
           << std::setw(2) << ((seed >> 24) & 0xFFU);
    return stream.str();
}

std::uint32_t demo_seed(const std::string& imsi, const std::string& pdu_session_id) {
    return static_cast<std::uint32_t>(std::hash<std::string> {}(imsi + '|' + pdu_session_id));
}

std::optional<std::size_t> parse_size_token(const std::string& value) {
    if (!is_unsigned_number(value)) {
        return std::nullopt;
    }

    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || errno == ERANGE || parsed > std::numeric_limits<std::size_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(parsed);
}

std::optional<std::uint32_t> parse_pdu_session_id_token(const std::string& value) {
    if (!is_unsigned_number(value)) {
        return std::nullopt;
    }

    errno = 0;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0' || errno == ERANGE || parsed == 0 || parsed > 255UL) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(parsed);
}

std::optional<DemoSessionTarget> parse_demo_target(const std::vector<std::string>& args,
                                                   std::size_t start_index,
                                                   std::string* error) {
    if (args.size() == start_index) {
        return DemoSessionTarget {};
    }
    if (args.size() != start_index + 2) {
        if (error != nullptr) {
            *error = "ERR: expected [imsi pdu]";
        }
        return std::nullopt;
    }

    if (args[start_index].empty() || args[start_index + 1].empty()) {
        if (error != nullptr) {
            *error = "ERR: imsi and pdu must be non-empty";
        }
        return std::nullopt;
    }

    if (!is_unsigned_number(args[start_index])) {
        if (error != nullptr) {
            *error = "ERR: imsi must contain only digits";
        }
        return std::nullopt;
    }
    if (!parse_pdu_session_id_token(args[start_index + 1]).has_value()) {
        if (error != nullptr) {
            *error = "ERR: pdu must be an unsigned integer in range 1..255";
        }
        return std::nullopt;
    }

    DemoSessionTarget target {};
    target.imsi = args[start_index];
    target.pdu_session_id = args[start_index + 1];
    return target;
}

bool apply_demo_option(DemoSessionTarget* target, DemoOptionFlags* flags, const std::string& token, std::string* error) {
    if (target == nullptr) {
        return false;
    }

    const std::size_t separator = token.find('=');
    if (separator == std::string::npos || separator == 0 || separator + 1 >= token.size()) {
        if (error != nullptr) {
            *error = "ERR: expected option key=value";
        }
        return false;
    }

    const std::string key = to_lower(token.substr(0, separator));
    const std::string value = token.substr(separator + 1);
    if (key == "dnn") {
        if (flags != nullptr && flags->seen_dnn) {
            if (error != nullptr) {
                *error = "ERR: duplicate demo option: dnn";
            }
            return false;
        }
        if (flags != nullptr) {
            flags->seen_dnn = true;
        }
        target->dnn = value;
        return true;
    }
    if (key == "preset") {
        if (flags != nullptr && flags->seen_preset) {
            if (error != nullptr) {
                *error = "ERR: duplicate demo option: preset";
            }
            return false;
        }
        const auto preset = parse_demo_preset(value);
        if (!preset.has_value()) {
            if (error != nullptr) {
                *error = "ERR: unknown preset";
            }
            return false;
        }
        if (flags != nullptr) {
            flags->seen_preset = true;
        }
        target->dnn = preset->first;
        target->profile = preset->second;
        return true;
    }
    if (key == "profile") {
        if (flags != nullptr && flags->seen_profile) {
            if (error != nullptr) {
                *error = "ERR: duplicate demo option: profile";
            }
            return false;
        }
        const auto alias = parse_profile_alias(value);
        if (!alias.has_value()) {
            if (error != nullptr) {
                *error = "ERR: profile must be ipv4, ipv6, ethernet, or legacy <dnn>-<profile>";
            }
            return false;
        }
        if (flags != nullptr) {
            flags->seen_profile = true;
        }
        if (!alias->first.empty()) {
            target->dnn = alias->first;
        }
        target->profile = alias->second;
        return true;
    }

    if (error != nullptr) {
        *error = "ERR: unknown demo option";
    }
    return false;
}

std::optional<DemoSessionTarget> parse_demo_command_target(const std::vector<std::string>& args,
                                                           std::string* error) {
    std::vector<std::string> positional;
    DemoSessionTarget target {};
    DemoOptionFlags flags {};

    for (const auto& arg : args) {
        if (arg.find('=') != std::string::npos) {
            if (!apply_demo_option(&target, &flags, arg, error)) {
                return std::nullopt;
            }
            continue;
        }
        positional.push_back(arg);
    }

    const auto parsed_target = parse_demo_target(positional, 0, error);
    if (!parsed_target.has_value()) {
        return std::nullopt;
    }

    target.imsi = parsed_target->imsi;
    target.pdu_session_id = parsed_target->pdu_session_id;
    return target;
}

std::optional<DemoBytesTarget> parse_demo_bytes_target(const std::vector<std::string>& args,
                                                       std::size_t default_bytes,
                                                       bool prefer_bytes_suffix,
                                                       std::string* error) {
    std::vector<std::string> positional;
    DemoSessionTarget target {};
    DemoOptionFlags flags {};

    for (const auto& arg : args) {
        if (arg.find('=') != std::string::npos) {
            if (!apply_demo_option(&target, &flags, arg, error)) {
                return std::nullopt;
            }
            continue;
        }
        positional.push_back(arg);
    }

    if (positional.empty()) {
        return DemoBytesTarget {default_bytes, target};
    }
    if (positional.size() == 2) {
        const auto parsed_target = parse_demo_target(positional, 0, error);
        if (!parsed_target.has_value()) {
            return std::nullopt;
        }
        target.imsi = parsed_target->imsi;
        target.pdu_session_id = parsed_target->pdu_session_id;
        return DemoBytesTarget {default_bytes, target};
    }
    if (positional.size() == 1) {
        const auto bytes = parse_size_token(positional.front());
        if (!bytes.has_value()) {
            if (error != nullptr) {
                *error = "ERR: bytes must be an unsigned integer";
            }
            return std::nullopt;
        }

        DemoBytesTarget parsed_view {default_bytes, target};
        parsed_view.bytes = *bytes;
        return parsed_view;
    }
    if (positional.size() == 3) {
        DemoBytesTarget parsed_view {default_bytes, target};
        if (prefer_bytes_suffix) {
            const auto bytes = parse_size_token(positional[2]);
            if (!bytes.has_value()) {
                if (error != nullptr) {
                    *error = "ERR: bytes must be an unsigned integer";
                }
                return std::nullopt;
            }

            const std::vector<std::string> target_tokens {positional[0], positional[1]};
            const auto parsed_target = parse_demo_target(target_tokens, 0, error);
            if (!parsed_target.has_value()) {
                return std::nullopt;
            }

            parsed_view.bytes = *bytes;
            parsed_view.target.imsi = parsed_target->imsi;
            parsed_view.target.pdu_session_id = parsed_target->pdu_session_id;
            return parsed_view;
        }

        const auto bytes = parse_size_token(positional.front());
        if (!bytes.has_value()) {
            if (error != nullptr) {
                *error = "ERR: bytes must be an unsigned integer";
            }
            return std::nullopt;
        }

        const auto parsed_target = parse_demo_target(positional, 1, error);
        if (!parsed_target.has_value()) {
            return std::nullopt;
        }

        parsed_view.bytes = *bytes;
        parsed_view.target.imsi = parsed_target->imsi;
        parsed_view.target.pdu_session_id = parsed_target->pdu_session_id;
        return parsed_view;
    }

    if (error != nullptr) {
        *error = "ERR: expected [bytes] [imsi pdu]";
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> resolve_config_path(const std::string& argv0, const std::optional<std::string>& explicit_path) {
    if (explicit_path.has_value()) {
        const std::filesystem::path configured(*explicit_path);
        if (std::filesystem::exists(configured)) {
            return configured;
        }
    }

    std::vector<std::filesystem::path> candidates;
    const auto cwd = std::filesystem::current_path();
    candidates.push_back(cwd / "config" / "upf-config.yaml");
    candidates.push_back(cwd.parent_path() / "config" / "upf-config.yaml");

    if (!argv0.empty()) {
        const auto exe_dir = std::filesystem::absolute(std::filesystem::path(argv0)).parent_path();
        candidates.push_back(exe_dir / "config" / "upf-config.yaml");
        candidates.push_back(exe_dir.parent_path() / "config" / "upf-config.yaml");
    }

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::optional<std::filesystem::path> resolve_binary_path(const std::string& argv0, const std::string& stem) {
    std::vector<std::filesystem::path> candidates;
    const auto cwd = std::filesystem::current_path();

#if defined(_WIN32)
    const std::string file_name = stem + ".exe";
#else
    const std::string file_name = stem;
#endif

    candidates.push_back(cwd / file_name);
    candidates.push_back(cwd / "build" / file_name);

    if (!argv0.empty()) {
        const auto exe_dir = std::filesystem::absolute(std::filesystem::path(argv0)).parent_path();
        candidates.push_back(exe_dir / file_name);
        candidates.push_back(exe_dir.parent_path() / "build" / file_name);
    }

    for (const auto& candidate : candidates) {
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}

std::string quote_shell_argument(const std::string& value) {
    return '"' + value + '"';
}

std::string build_n6_tool_command(const std::filesystem::path& tool_path,
                                  const std::optional<std::filesystem::path>& config_path,
                                  std::size_t bytes,
                                  const DemoSessionTarget& target) {
    std::ostringstream command;
    const std::string tool_args = [&]() {
        std::ostringstream args;
        args << quote_shell_argument(tool_path.string());
        if (config_path.has_value()) {
            args << " --config " << quote_shell_argument(config_path->string());
        }
        args << " --imsi " << quote_shell_argument(target.imsi);
        args << " --pdu " << quote_shell_argument(target.pdu_session_id);
        args << " --dnn " << quote_shell_argument(target.dnn);
        if (!target.profile.empty()) {
            args << " --protocol " << quote_shell_argument(target.profile);
        }
        args << " --delay-ms 200 --bytes " << bytes << " --count 5 --interval-ms 120";
        return args.str();
    }();

#if defined(_WIN32)
    command << "cmd /c \"" << tool_args << "\"";
#else
    command << tool_args;
#endif
    return command.str();
}

struct RuntimeInvocationContext {
    std::string argv0;
    std::optional<std::filesystem::path> resolved_config;
};

std::optional<DemoToolCommandPreview> build_demo_tool_command_preview(const RuntimeInvocationContext& invocation,
                                                                      std::size_t bytes,
                                                                      const DemoSessionTarget& target,
                                                                      std::string* error) {
    const auto tool_path = resolve_binary_path(invocation.argv0, "n6_traffic_tool");
    if (!tool_path.has_value()) {
        if (error != nullptr) {
            *error = "ERR: n6_traffic_tool not found";
        }
        return std::nullopt;
    }

    DemoToolCommandPreview preview {};
    preview.tool_path = *tool_path;
    preview.config_path = invocation.resolved_config;
    preview.command = build_n6_tool_command(*tool_path, invocation.resolved_config, bytes, target);
    return preview;
}

upf::PfcpSessionRequest build_demo_request(const upf::RuntimeConfig& cfg,
                                           const std::string& imsi,
                                           const std::string& pdu_session_id,
                                           const std::string& dnn,
                                           const std::string& profile);

upf::PfcpSessionRequest build_demo_request(const upf::RuntimeConfig& cfg) {
    return build_demo_request(cfg, kDefaultDemoImsi, kDefaultDemoPduSessionId, "internet", "");
}

upf::PfcpSessionRequest build_demo_request(const upf::RuntimeConfig& cfg,
                                           const std::string& imsi,
                                           const std::string& pdu_session_id,
                                           const std::string& dnn,
                                           const std::string& profile) {
    const std::uint32_t seed = demo_seed(imsi, pdu_session_id);
    const std::uint32_t teid = 0x1000U + (seed & 0x0FFFU);
    const std::uint32_t ipv4_subnet = ((seed >> 8) % 250U) + 1U;
    const std::uint32_t ipv4_host = (seed % 253U) + 2U;
    const std::uint32_t ipv6_suffix = (seed % 0xFFFDU) + 2U;

    upf::PfcpSessionRequest request {};
    request.imsi = imsi;
    request.pdu_session_id = pdu_session_id;
    {
        std::ostringstream teid_text;
        teid_text << "0x" << std::hex << teid;
        request.teid = teid_text.str();
    }
    request.ue_ipv4 = "10.10." + std::to_string(ipv4_subnet) + '.' + std::to_string(ipv4_host);
    request.dnn = dnn.empty() ? "internet" : dnn;
    request.s_nssai = "1-010203";
    request.qos_profile = "default";
    request.procedure.request_id = "demo-" + request.imsi + '-' + request.pdu_session_id;

    const std::string resolved_profile = profile.empty() ? to_lower(cfg.n6_default_protocol) : to_lower(profile);
    if (resolved_profile == "ipv6") {
        std::ostringstream ipv6;
        ipv6 << "2001:db8:10::" << std::hex << ipv6_suffix;
        request.ue_ipv6 = ipv6.str();
        request.prefer_n6_ipv6 = true;
    } else if (resolved_profile == "ethernet") {
        request.ue_mac = format_demo_mac(seed);
        request.prefer_n6_ethernet = true;
    }

    return request;
}

class UpfRuntime final {
public:
    explicit UpfRuntime(upf::RuntimeConfig cfg) {
        restart(cfg);
    }

    ~UpfRuntime() {
        if (node_ != nullptr) {
            node_->stop();
        }
    }

    void restart(const upf::RuntimeConfig& cfg) {
        if (node_ != nullptr) {
            node_->stop();
        }

        cfg_ = cfg;
        n4_ = std::make_unique<upf::NetworkN4Adapter>(cfg_.n4_remote_host, cfg_.n4_remote_port, cfg_.n4_timeout_ms, cfg_.node_id);
        n6_ = std::make_unique<upf::NetworkN6Adapter>(cfg_.n6_remote_host,
                                                      cfg_.n6_remote_port,
                                                      cfg_.n6_bind,
                                                      cfg_.n6_downlink_wait_timeout_ms,
                                                      cfg_.n6_buffer_capacity,
                                                      cfg_.n6_buffer_overflow_policy);
        n9_ = std::make_unique<upf::ConsoleN9Adapter>(cfg_.enable_n9);

        upf::UpfPeerInterfaces peers {};
        peers.n3 = &n3_;
        peers.n6 = n6_.get();
        peers.n9 = n9_.get();

        node_ = std::make_unique<upf::UpfNode>(*n4_, sbi_, peers);
        node_->start();
        cli_ = std::make_unique<upf::UpfCli>(cfg_, node_.get());
    }

    upf::UpfCli& cli() {
        return *cli_;
    }

    upf::UpfNode& node() {
        return *node_;
    }

    const upf::RuntimeConfig& running_config() const {
        return cli_->running();
    }

    upf::PfcpSessionRequest demo_request(const DemoSessionTarget& target = DemoSessionTarget {}) const {
        return build_demo_request(cfg_, target.imsi, target.pdu_session_id, target.dnn, target.profile);
    }

private:
    upf::RuntimeConfig cfg_ {};
    upf::ConsoleN3Adapter n3_;
    upf::ConsoleSbiAdapter sbi_;
    std::unique_ptr<upf::NetworkN4Adapter> n4_;
    std::unique_ptr<upf::NetworkN6Adapter> n6_;
    std::unique_ptr<upf::ConsoleN9Adapter> n9_;
    std::unique_ptr<upf::UpfNode> node_;
    std::unique_ptr<upf::UpfCli> cli_;
};

void print_help() {
    std::cout
        << "Commands:\n"
        << "  help\n"
        << "  exit | quit\n"
        << "  tick\n"
        << "  clear-stats\n"
        << "  demo validate [tool-cmd] [bytes] [imsi pdu] [preset=<name>|compare=<a,b>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>] [json]\n"
        << "  demo compare [tool-cmd] [bytes] [imsi pdu] compare=<a,b> [json]\n"
        << "  demo full [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo establish [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo full-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo modify [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo release [imsi pdu]\n"
        << "  demo uplink [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo downlink [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo downlink-tool [bytes] [imsi pdu] [preset=<name>] [dnn=<name>] [profile=<ipv4|ipv6|ethernet>]\n"
        << "  demo notify <message>\n"
        << "  set <key> <value>\n"
        << "  commit\n"
        << "  discard\n"
        << "  show running [json]\n"
        << "  show candidate [json]\n"
        << "  show status [json]\n"
        << "  show n6-buffer [json]\n"
        << "  show n6-buffer session <imsi> <pdu> [json]\n"
        << "  show demo-presets [json]\n"
        << "  show demo-matrix [imsi pdu [bytes]] [tool-cmd] [json]\n"
        << "  show demo-compare [imsi pdu [bytes]] compare=<a,b> [tool-cmd] [json]\n"
        << "\n"
        << "Compare Examples:\n"
        << "  demo compare 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6\n"
        << "  show demo-compare 250200123450002 22 1440 compare=ims-ipv4,ims-ipv6\n"
        << "  demo compare tool-cmd 1440 250200123450002 22 compare=ims-ipv4,ims-ipv6 json\n";
}

bool run_demo_downlink_with_tool(UpfRuntime& runtime,
                                 const RuntimeInvocationContext& invocation,
                                 std::size_t bytes,
                                 const DemoSessionTarget& target,
                                 std::string* output) {
    const auto request = runtime.demo_request(target);
    if (!runtime.node().find_session(request.imsi, request.pdu_session_id).has_value()) {
        *output = "ERR: establish required";
        return false;
    }

    const auto tool_path = resolve_binary_path(invocation.argv0, "n6_traffic_tool");
    if (!tool_path.has_value()) {
        *output = "ERR: n6_traffic_tool not found";
        return false;
    }

    const std::string tool_command = build_n6_tool_command(*tool_path, invocation.resolved_config, bytes, target);
    if (std::system(tool_command.c_str()) != 0) {
        *output = "ERR: n6_traffic_tool failed";
        return false;
    }

    *output = runtime.node().process_downlink(request.imsi, request.pdu_session_id, bytes) ? "OK" : "ERR: downlink failed";
    return *output == "OK";
}

bool run_demo_command(UpfRuntime& runtime,
                      const RuntimeInvocationContext& invocation,
                      const std::string& command_line,
                      std::string* output) {
    std::istringstream stream(command_line);
    std::string demo;
    std::string action;
    std::vector<std::string> args;
    stream >> demo >> action;
    for (std::string token; stream >> token;) {
        args.push_back(token);
    }
    if (demo != "demo") {
        return false;
    }

    if (action == "validate" || action == "compare") {
        bool json_output = false;
        bool tool_cmd_output = false;
        std::vector<std::string> filtered_args;
        filtered_args.reserve(args.size());
        for (const auto& arg : args) {
            const std::string normalized = to_lower(arg);
            if (normalized == "json") {
                json_output = true;
                continue;
            }
            if (normalized == "tool-cmd") {
                tool_cmd_output = true;
                continue;
            }
            filtered_args.push_back(arg);
        }
        bool compare_output = action == "compare";
        if (!compare_output) {
            for (const auto& arg : filtered_args) {
                if (to_lower(arg).rfind("compare=", 0) == 0) {
                    compare_output = true;
                    break;
                }
            }
        }
        if (compare_output) {
            const auto compare_query = parse_demo_compare_query(filtered_args, false, output);
            if (!compare_query.has_value()) {
                return true;
            }
            if (tool_cmd_output) {
                const auto formatted = json_output
                    ? format_demo_compare_tool_command_json(runtime.running_config(), invocation, *compare_query, output)
                    : format_demo_compare_tool_command(runtime.running_config(), invocation, *compare_query, output);
                if (!formatted.has_value()) {
                    return true;
                }
                *output = *formatted;
            } else {
                *output = json_output
                    ? format_demo_compare_json(runtime.running_config(), *compare_query)
                    : format_demo_compare(runtime.running_config(), *compare_query);
            }
            return true;
        }
        const auto args_view = parse_demo_bytes_target(filtered_args, 1200, false, output);
        if (!args_view.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(args_view->target);
        if (tool_cmd_output) {
            const auto preview = build_demo_tool_command_preview(invocation, args_view->bytes, args_view->target, output);
            if (!preview.has_value()) {
                return true;
            }
            *output = json_output
                ? format_demo_tool_command_validation_json(request, runtime.running_config(), args_view->bytes, *preview)
                : format_demo_tool_command_validation(request, runtime.running_config(), args_view->bytes, *preview);
            return true;
        }
        *output = json_output
            ? format_demo_target_validation_json(request, runtime.running_config(), args_view->bytes)
            : format_demo_target_validation(request, runtime.running_config(), args_view->bytes);
        return true;
    }
    if (action == "full") {
        const auto target = parse_demo_command_target(args, output);
        if (!target.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(*target);
        if (!runtime.node().establish_session(request)) {
            *output = "ERR: establish failed";
            return true;
        }
        if (!runtime.node().process_uplink(request.imsi, request.pdu_session_id, 1500)) {
            *output = "ERR: uplink failed";
            return true;
        }
        if (!runtime.node().process_downlink(request.imsi, request.pdu_session_id, 1200)) {
            *output = "ERR: downlink failed";
            return true;
        }
        if (!runtime.node().notify_sbi("nupf-event-exposure", "session-up")) {
            *output = "ERR: notify failed";
            return true;
        }
        *output = runtime.node().release_session(request.imsi, request.pdu_session_id) ? "OK" : "ERR: release failed";
        return true;
    }
    if (action == "full-tool") {
        const auto args_view = parse_demo_bytes_target(args, 1200, false, output);
        if (!args_view.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(args_view->target);
        if (!runtime.node().establish_session(request)) {
            *output = "ERR: establish failed";
            return true;
        }
        if (!runtime.node().process_uplink(request.imsi, request.pdu_session_id, 1500)) {
            *output = "ERR: uplink failed";
            return true;
        }
        if (!run_demo_downlink_with_tool(runtime, invocation, args_view->bytes, args_view->target, output)) {
            return true;
        }
        if (!runtime.node().notify_sbi("nupf-event-exposure", "session-up")) {
            *output = "ERR: notify failed";
            return true;
        }
        *output = runtime.node().release_session(request.imsi, request.pdu_session_id) ? "OK" : "ERR: release failed";
        return true;
    }
    if (action == "establish") {
        const auto target = parse_demo_command_target(args, output);
        if (!target.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(*target);
        *output = runtime.node().establish_session(request) ? "OK" : "ERR: establish failed";
        return true;
    }
    if (action == "modify") {
        const auto target = parse_demo_command_target(args, output);
        if (!target.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(*target);
        *output = runtime.node().modify_session(request) ? "OK" : "ERR: modify failed";
        return true;
    }
    if (action == "release") {
        const auto target = parse_demo_command_target(args, output);
        if (!target.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(*target);
        *output = runtime.node().release_session(request.imsi, request.pdu_session_id) ? "OK" : "ERR: release failed";
        return true;
    }
    if (action == "uplink") {
        const auto args_view = parse_demo_bytes_target(args, 1500, false, output);
        if (!args_view.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(args_view->target);
        *output = runtime.node().process_uplink(request.imsi, request.pdu_session_id, args_view->bytes) ? "OK" : "ERR: uplink failed";
        return true;
    }
    if (action == "downlink") {
        const auto args_view = parse_demo_bytes_target(args, 1200, false, output);
        if (!args_view.has_value()) {
            return true;
        }
        const auto request = runtime.demo_request(args_view->target);
        *output = runtime.node().process_downlink(request.imsi, request.pdu_session_id, args_view->bytes) ? "OK" : "ERR: downlink failed";
        return true;
    }
    if (action == "downlink-tool") {
        const auto args_view = parse_demo_bytes_target(args, 1200, false, output);
        if (!args_view.has_value()) {
            return true;
        }
        run_demo_downlink_with_tool(runtime, invocation, args_view->bytes, args_view->target, output);
        return true;
    }
    if (action == "notify") {
        std::string message;
        for (std::size_t index = 0; index < args.size(); ++index) {
            if (index != 0) {
                message += ' ';
            }
            message += args[index];
        }
        message = trim(message);
        if (message.empty()) {
            message = "session-up";
        }
        *output = runtime.node().notify_sbi("nupf-event-exposure", message) ? "OK" : "ERR: notify failed";
        return true;
    }

    *output = "ERR: unknown demo command";
    return true;
}

int run_demo_once(UpfRuntime& runtime) {
    const auto request = runtime.demo_request();
    const bool session_established = runtime.node().establish_session(request);
    bool downlink_delivered = false;
    if (session_established) {
        runtime.node().process_uplink(request.imsi, request.pdu_session_id, 1500);
        downlink_delivered = runtime.node().process_downlink(request.imsi, request.pdu_session_id, 1200);
        runtime.node().notify_sbi("nupf-event-exposure", "session-up");
    } else {
        std::cout << "N4 session establishment failed for "
                  << runtime.running_config().n4_remote_host << ':' << runtime.running_config().n4_remote_port
                  << "\n";
    }

    runtime.node().tick();
    const auto status = runtime.node().status();
    std::cout << "UPF state=" << upf::to_string(status.state)
              << " active_sessions=" << status.active_sessions
              << " n4_messages=" << status.stats.n4_messages
              << "\n";
    std::cout << "N6 bind=" << runtime.running_config().n6_bind
              << " remote=" << runtime.running_config().n6_remote_host << ':' << runtime.running_config().n6_remote_port
              << "\n";
    std::cout << "N6 downlink=" << (downlink_delivered ? "delivered" : "timeout") << "\n";
    std::cout << runtime.cli().execute("show running") << "\n";
    std::cout << runtime.cli().execute("show status") << "\n";
    std::cout << runtime.cli().execute("show n6-buffer") << "\n";
    std::cout << runtime.cli().execute("show n6-buffer session " + request.imsi + ' ' + request.pdu_session_id) << "\n";
    if (session_established) {
        runtime.node().release_session(request.imsi, request.pdu_session_id);
    }
    return 0;
}

int run_repl(UpfRuntime& runtime, const RuntimeInvocationContext& invocation) {
    std::cout << "UPF interactive CLI. Type 'help' for commands.\n";
    std::cout << "N4 peer: " << runtime.running_config().n4_remote_host << ':' << runtime.running_config().n4_remote_port << "\n";

    std::string line;
    while (true) {
        std::cout << "upf> ";
        if (!std::getline(std::cin, line)) {
            std::cout << "\n";
            break;
        }

        line = trim(line);
        if (line.empty()) {
            continue;
        }
        if (line == "exit" || line == "quit") {
            break;
        }
        if (line == "help") {
            print_help();
            continue;
        }
        if (line == "tick") {
            runtime.node().tick();
            std::cout << "OK\n";
            continue;
        }
        if (line == "clear-stats") {
            runtime.node().clear_stats();
            std::cout << "OK\n";
            continue;
        }
        if (line == "show demo-presets") {
            std::cout << format_demo_presets();
            continue;
        }
        if (line == "show demo-presets json") {
            std::cout << format_demo_presets_json() << "\n";
            continue;
        }
        if (line.rfind("show demo-matrix", 0) == 0) {
            std::istringstream matrix_stream(line);
            std::string show;
            std::string matrix;
            std::vector<std::string> args;
            matrix_stream >> show >> matrix;
            for (std::string token; matrix_stream >> token;) {
                args.push_back(token);
            }

            bool json_output = false;
            if (!args.empty() && to_lower(args.back()) == "json") {
                json_output = true;
                args.pop_back();
            }

            bool tool_cmd_output = false;
            std::vector<std::string> filtered_args;
            for (const auto& arg : args) {
                if (to_lower(arg) == "tool-cmd") {
                    tool_cmd_output = true;
                    continue;
                }
                filtered_args.push_back(arg);
            }

            std::string matrix_error;
            const auto matrix_query = parse_demo_matrix_query(filtered_args, &matrix_error);
            if (!matrix_query.has_value()) {
                std::cout << matrix_error << "\n";
                continue;
            }

            if (tool_cmd_output) {
                const auto formatted = json_output
                    ? format_demo_matrix_tool_command_json(runtime.running_config(), invocation, *matrix_query, &matrix_error)
                    : format_demo_matrix_tool_command(runtime.running_config(), invocation, *matrix_query, &matrix_error);
                if (!formatted.has_value()) {
                    std::cout << matrix_error << "\n";
                    continue;
                }
                if (json_output) {
                    std::cout << *formatted << "\n";
                } else {
                    std::cout << *formatted;
                }
            } else if (json_output) {
                std::cout << format_demo_matrix_json(runtime.running_config(), *matrix_query) << "\n";
            } else {
                std::cout << format_demo_matrix(runtime.running_config(), *matrix_query);
            }
            continue;
        }
        if (line.rfind("show demo-compare", 0) == 0) {
            std::istringstream compare_stream(line);
            std::string show;
            std::string compare;
            std::vector<std::string> args;
            compare_stream >> show >> compare;
            for (std::string token; compare_stream >> token;) {
                args.push_back(token);
            }

            bool json_output = false;
            if (!args.empty() && to_lower(args.back()) == "json") {
                json_output = true;
                args.pop_back();
            }

            bool tool_cmd_output = false;
            std::vector<std::string> filtered_args;
            for (const auto& arg : args) {
                if (to_lower(arg) == "tool-cmd") {
                    tool_cmd_output = true;
                    continue;
                }
                filtered_args.push_back(arg);
            }

            std::string compare_error;
            const auto compare_query = parse_demo_compare_query(filtered_args, true, &compare_error);
            if (!compare_query.has_value()) {
                std::cout << compare_error << "\n";
                continue;
            }

            if (tool_cmd_output) {
                const auto formatted = json_output
                    ? format_demo_compare_tool_command_json(runtime.running_config(), invocation, *compare_query, &compare_error)
                    : format_demo_compare_tool_command(runtime.running_config(), invocation, *compare_query, &compare_error);
                if (!formatted.has_value()) {
                    std::cout << compare_error << "\n";
                    continue;
                }
                if (json_output) {
                    std::cout << *formatted << "\n";
                } else {
                    std::cout << *formatted;
                }
            } else if (json_output) {
                std::cout << format_demo_compare_json(runtime.running_config(), *compare_query) << "\n";
            } else {
                std::cout << format_demo_compare(runtime.running_config(), *compare_query);
            }
            continue;
        }

        std::string output;
        if (run_demo_command(runtime, invocation, line, &output)) {
            std::cout << output << "\n";
            continue;
        }

        if (line == "commit") {
            output = runtime.cli().execute(line);
            if (output == "OK") {
                runtime.restart(runtime.running_config());
            }
            std::cout << output << "\n";
            continue;
        }

        output = runtime.cli().execute(line);
        std::cout << output << "\n";
    }

    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::optional<std::string> config_path;
    bool demo_mode = false;
    bool interactive_mode = false;

    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: upf.exe [--demo] [--interactive] [--config <path>]\n";
            return 0;
        }
        if (arg == "--demo") {
            demo_mode = true;
            continue;
        }
        if (arg == "--interactive") {
            interactive_mode = true;
            continue;
        }
        if (arg == "--config" && index + 1 < argc) {
            config_path = argv[++index];
            continue;
        }
    }

    const auto resolved_config = resolve_config_path(argc > 0 ? argv[0] : std::string(), config_path);
    const upf::RuntimeConfig cfg = upf::load_runtime_config(resolved_config.has_value() ? resolved_config->string() : std::string());
    if (resolved_config.has_value()) {
        std::cout << "Using config: " << resolved_config->string() << "\n";
    } else {
        std::cout << "Using built-in defaults (config file not found)\n";
    }

    UpfRuntime runtime(cfg);
    const RuntimeInvocationContext invocation {argc > 0 ? argv[0] : std::string(), resolved_config};
    if (interactive_mode && !demo_mode) {
        return run_repl(runtime, invocation);
    }
    return run_demo_once(runtime);
}
