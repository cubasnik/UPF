cmake_minimum_required(VERSION 3.16)

project(upf_node LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(UPF_BUILD_TESTS "Build UPF unit tests" ON)
set(BUILD_TESTING ${UPF_BUILD_TESTS} CACHE BOOL "Enable testing via CTest" FORCE)
include(CTest)

add_library(upf_core
    src/upf.cpp
    src/cli.cpp
    src/adapters/console_adapters.cpp
    src/adapters/network_adapters.cpp
    src/protocol/pfcp_wire.cpp
    src/config/runtime_config.cpp
    src/modules/observability.cpp
    src/modules/transport_serialization.cpp
    src/modules/n6_packet_buffer.cpp
    src/modules/session_table.cpp
)

target_include_directories(upf_core PUBLIC include)

if(WIN32)
    target_link_libraries(upf_core PUBLIC ws2_32)
endif()

add_executable(upf
    src/main.cpp
)

target_link_libraries(upf PRIVATE upf_core)

add_executable(n4_mock_peer
    src/n4_mock_peer.cpp
)

target_link_libraries(n4_mock_peer PRIVATE upf_core)

add_executable(n6_traffic_tool
    src/n6_traffic_tool.cpp
)

target_link_libraries(n6_traffic_tool PRIVATE upf_core)

if(UPF_BUILD_TESTS)
    add_executable(upf_tests
        tests/upf_tests.cpp
    )
    target_link_libraries(upf_tests PRIVATE upf_core)
    add_test(NAME upf_tests COMMAND upf_tests)

    add_executable(upf_cli_tests
        tests/cli_tests.cpp
    )
    target_link_libraries(upf_cli_tests PRIVATE upf_core)
    add_test(NAME upf_cli_tests COMMAND upf_cli_tests)

    add_executable(upf_config_tests
        tests/config_tests.cpp
    )
    target_link_libraries(upf_config_tests PRIVATE upf_core)
    add_test(NAME upf_config_tests COMMAND upf_config_tests)

    add_executable(n4_pfcp_tests
        tests/n4_pfcp_tests.cpp
    )
    target_link_libraries(n4_pfcp_tests PRIVATE upf_core)
    add_test(NAME n4_pfcp_tests COMMAND n4_pfcp_tests)

    add_executable(n3_n6_forwarding_tests
        tests/n3_n6_forwarding_tests.cpp
    )
    target_link_libraries(n3_n6_forwarding_tests PRIVATE upf_core)
    add_test(NAME n3_n6_forwarding_tests COMMAND n3_n6_forwarding_tests)

    add_executable(n4_network_transport_tests
        tests/n4_network_transport_tests.cpp
    )
    target_link_libraries(n4_network_transport_tests PRIVATE upf_core)
    add_test(NAME n4_network_transport_tests COMMAND n4_network_transport_tests)

    add_executable(n4_network_transport_lifecycle_tests
        tests/n4_network_transport_lifecycle_tests.cpp
    )
    target_link_libraries(n4_network_transport_lifecycle_tests PRIVATE upf_core)
    add_test(NAME n4_network_transport_lifecycle_tests COMMAND n4_network_transport_lifecycle_tests)

    add_executable(n4_network_transport_negative_tests
        tests/n4_network_transport_negative_tests.cpp
    )
    target_link_libraries(n4_network_transport_negative_tests PRIVATE upf_core)
    add_test(NAME n4_network_transport_negative_tests COMMAND n4_network_transport_negative_tests)

    add_executable(n6_network_transport_tests
        tests/n6_network_transport_tests.cpp
    )
    target_link_libraries(n6_network_transport_tests PRIVATE upf_core)
    add_test(NAME n6_network_transport_tests COMMAND n6_network_transport_tests)

    add_executable(n6_packet_buffer_tests
        tests/n6_packet_buffer_tests.cpp
    )
    target_link_libraries(n6_packet_buffer_tests PRIVATE upf_core)
    add_test(NAME n6_packet_buffer_tests COMMAND n6_packet_buffer_tests)

    add_executable(n6_runtime_integration_tests
        tests/n6_runtime_integration_tests.cpp
    )
    target_link_libraries(n6_runtime_integration_tests PRIVATE upf_core)
    add_test(NAME n6_runtime_integration_tests COMMAND n6_runtime_integration_tests)

    add_executable(n6_runtime_interactive_tests
        tests/n6_runtime_interactive_tests.cpp
    )
    target_link_libraries(n6_runtime_interactive_tests PRIVATE upf_core)
    add_test(NAME n6_runtime_interactive_tests COMMAND n6_runtime_interactive_tests)

    add_executable(n3_network_transport_tests
        tests/n3_network_transport_tests.cpp
    )
    target_link_libraries(n3_network_transport_tests PRIVATE upf_core)
    add_test(NAME n3_network_transport_tests COMMAND n3_network_transport_tests)

    add_executable(sbi_network_transport_tests
        tests/sbi_network_transport_tests.cpp
    )
    target_link_libraries(sbi_network_transport_tests PRIVATE upf_core)
    add_test(NAME sbi_network_transport_tests COMMAND sbi_network_transport_tests)

    add_executable(n19_nx_network_transport_tests
        tests/n19_nx_network_transport_tests.cpp
    )
    target_link_libraries(n19_nx_network_transport_tests PRIVATE upf_core)
    add_test(NAME n19_nx_network_transport_tests COMMAND n19_nx_network_transport_tests)

    add_executable(nsmf_internal_tests
        tests/nsmf_internal_tests.cpp
    )
    target_link_libraries(nsmf_internal_tests PRIVATE upf_core)
    add_test(NAME nsmf_internal_tests COMMAND nsmf_internal_tests)

    add_executable(upf_extended_interfaces_tests
        tests/upf_extended_interfaces_tests.cpp
    )
    target_link_libraries(upf_extended_interfaces_tests PRIVATE upf_core)
    add_test(NAME upf_extended_interfaces_tests COMMAND upf_extended_interfaces_tests)
endif()