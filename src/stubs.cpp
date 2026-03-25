
#include <string>
#include <cstdint>
#include <vector>
#include "upf/upf.hpp"
#include "upf/cli.hpp"

namespace upf {

struct UpfCli::Impl {};
UpfCli::~UpfCli() {}

std::string format_schema_json(const char*) { return "{}"; }
std::string format_sbi_event_request_body(const std::string&, const std::string&) { return "{}"; }
std::string format_http_post_request(const std::string&, const std::string&, const std::string&) { return "{}"; }
const char* to_string(UpfState) { return "RUNNING"; }
const char* to_string(N6BufferOverflowPolicy) { return "drop_oldest"; }

} // namespace upf
