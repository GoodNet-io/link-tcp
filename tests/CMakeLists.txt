# TCP link plugin unit tests — MIT.
include(GoogleTest)

add_executable(test_tcp test_tcp.cpp)
target_link_libraries(test_tcp PRIVATE
    GoodNet::sdk
    goodnet_tcp_objects
    asio::asio
    Threads::Threads
    GTest::gtest
    GTest::gtest_main)
target_compile_features(test_tcp PRIVATE cxx_std_23)
if(COMMAND goodnet_apply_pch)
    goodnet_apply_pch(test_tcp)
endif()
gtest_discover_tests(test_tcp
    DISCOVERY_TIMEOUT 30
    PROPERTIES TIMEOUT 60)
