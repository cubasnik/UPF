cmake_minimum_required(VERSION 3.16)

project(upf_node LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(UPF_BUILD_TESTS "Build UPF unit tests" ON)

add_library(upf_core
    src/upf.cpp
    src/cli.cpp
    src/adapters/console_adapters.cpp
    src/adapters/network_adapters.cpp
    src/config/runtime_config.cpp
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

if(UPF_BUILD_TESTS)
    enable_testing()

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

    add_executable(sbi_network_transport_tests
        tests/sbi_network_transport_tests.cpp
    )
    target_link_libraries(sbi_network_transport_tests PRIVATE upf_core)
    add_test(NAME sbi_network_transport_tests COMMAND sbi_network_transport_tests)
endif()
