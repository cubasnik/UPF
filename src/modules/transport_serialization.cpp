#include "upf/modules/transport_serialization.hpp"
#include <cstring>
#include <sstream>

namespace upf {
namespace modules {

std::vector<uint8_t> TransportSerialization::serialize(const std::string& data) {
    std::vector<uint8_t> result(data.begin(), data.end());
    return result;
}

std::string TransportSerialization::deserialize(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

// Реализация format_pfcp_default_response_detail
} // namespace modules

std::string format_pfcp_default_response_detail(upf::PfcpCause cause) {
    switch (cause) {
        case upf::PfcpCause::RequestAccepted:
            return "Request accepted";
        case upf::PfcpCause::MandatoryIeMissing:
            return "Mandatory IE missing";
        case upf::PfcpCause::SessionContextNotFound:
            return "Session context not found";
        case upf::PfcpCause::RuleCreationModificationFailure:
            return "Rule creation/modification failure";
        case upf::PfcpCause::SemanticErrorInTheTft:
            return "Semantic error in the TFT";
        case upf::PfcpCause::InvalidQfi:
            return "Invalid QFI";
        case upf::PfcpCause::InvalidGateStatus:
            return "Invalid gate status";
        default:
            return "Unknown PFCP cause";
    }
}

} // namespace upf