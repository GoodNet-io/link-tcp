cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_tcp
        VERSION   0.1.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
    goodnet_standalone_plugin_includes()
    include(CTest)
    if(BUILD_TESTING)
        find_package(GTest      REQUIRED)
        find_package(rapidcheck QUIET)
        goodnet_patch_rapidcheck_targets()
        set(GOODNET_BUILD_TESTS ON)
    endif()
endif()

# TCP transport plugin — MIT (common transports per LICENSE convention).
# Two artefacts share the source: an OBJECT library so unit tests link
# the C++ class directly, and a SHARED plugin via add_plugin() that the
# kernel's PluginManager loads through dlopen.

add_library(goodnet_tcp_objects OBJECT
    tcp.cpp
)
target_link_libraries(goodnet_tcp_objects PUBLIC GoodNet::sdk asio::asio Threads::Threads)
target_compile_features(goodnet_tcp_objects PUBLIC cxx_std_23)
target_compile_options(goodnet_tcp_objects PRIVATE
    -Wall -Wextra -Wpedantic -Wno-unused-parameter)
target_include_directories(goodnet_tcp_objects PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(goodnet_tcp_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

add_plugin(goodnet_link_tcp
    plugin_entry.cpp
)
target_link_libraries(goodnet_link_tcp
    PRIVATE goodnet_tcp_objects asio::asio Threads::Threads)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
