cmake_minimum_required(VERSION 3.22)

if(NOT TARGET GoodNet::sdk)
    project(goodnet_link_tcp
        VERSION   1.0.0
        LANGUAGES CXX)
    find_package(GoodNet REQUIRED)
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
    tcp_composer_session.cpp
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

# Static archive for consumers (examples/bench, integration fixtures)
# that link TcpLink directly instead of dlopen-ing the plugin.
# Exported as GoodNet::link_tcp_static so install-tree consumers
# spell the dependency identically to the in-tree alias.
add_library(goodnet_link_tcp_static STATIC
    $<TARGET_OBJECTS:goodnet_tcp_objects>
)
add_library(GoodNet::link_tcp_static ALIAS goodnet_link_tcp_static)
set_target_properties(goodnet_link_tcp_static PROPERTIES
    EXPORT_NAME           link_tcp_static
    POSITION_INDEPENDENT_CODE ON
)
target_link_libraries(goodnet_link_tcp_static
    PUBLIC GoodNet::sdk asio::asio Threads::Threads
)
target_include_directories(goodnet_link_tcp_static PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:include/goodnet/plugins/links/tcp>"
)
target_compile_features(goodnet_link_tcp_static PUBLIC cxx_std_23)

install(TARGETS goodnet_link_tcp_static
    EXPORT   GoodNetLinkTcpTargets
    ARCHIVE  DESTINATION lib
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/tcp.hpp"
    DESTINATION "include/goodnet/plugins/links/tcp"
)
install(EXPORT GoodNetLinkTcpTargets
    NAMESPACE   GoodNet::
    DESTINATION lib/cmake/GoodNetLinkTcp
)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/GoodNetLinkTcpConfig.cmake"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/GoodNetLinkTcpTargets.cmake\")\n"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/GoodNetLinkTcpConfig.cmake"
    DESTINATION lib/cmake/GoodNetLinkTcp
)

if(GOODNET_BUILD_TESTS)
    add_subdirectory(tests)
endif()
