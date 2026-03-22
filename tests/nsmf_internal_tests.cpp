#include <algorithm>
#include <cstdlib>

#include "upf/adapters/network_adapters.hpp"

int main() {
    upf::NetworkNsmfAdapter nsmf;

    if (!nsmf.register_internal_component("CU-UP")) {
        return EXIT_FAILURE;
    }
    if (!nsmf.register_internal_component("DU-UP")) {
        return EXIT_FAILURE;
    }
    if (nsmf.register_internal_component("CU-UP")) {
        return EXIT_FAILURE;
    }

    const auto components = nsmf.get_registered_components();
    if (components.size() != 2 ||
        std::find(components.begin(), components.end(), "CU-UP") == components.end() ||
        std::find(components.begin(), components.end(), "DU-UP") == components.end()) {
        return EXIT_FAILURE;
    }

    upf::InternalComponentMessage message {};
    message.source_component = "CU-UP";
    message.target_component = "DU-UP";
    message.message_type = "SESSION_SYNC";
    message.payload = "session=42";
    message.timestamp_ms = 123456;

    if (!nsmf.send_internal_message(message)) {
        return EXIT_FAILURE;
    }

    const auto received = nsmf.receive_internal_message(10);
    if (!received.has_value()) {
        return EXIT_FAILURE;
    }
    if (received->source_component != "CU-UP" ||
        received->target_component != "DU-UP" ||
        received->message_type != "SESSION_SYNC" ||
        received->payload != "session=42" ||
        received->timestamp_ms != 123456) {
        return EXIT_FAILURE;
    }

    if (nsmf.receive_internal_message(2).has_value()) {
        return EXIT_FAILURE;
    }

    upf::InternalComponentMessage bad_message {};
    bad_message.source_component = "CU-UP";
    bad_message.target_component = "UNKNOWN";
    bad_message.message_type = "FAIL";
    if (nsmf.send_internal_message(bad_message)) {
        return EXIT_FAILURE;
    }

    if (!nsmf.unregister_internal_component("DU-UP")) {
        return EXIT_FAILURE;
    }
    if (nsmf.unregister_internal_component("DU-UP")) {
        return EXIT_FAILURE;
    }
    if (!nsmf.unregister_internal_component("CU-UP")) {
        return EXIT_FAILURE;
    }
    if (!nsmf.get_registered_components().empty()) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}