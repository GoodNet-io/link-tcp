// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tests/test_tcp_conformance.cpp
/// @brief  Instantiates the SDK link teardown conformance suite
///         against `gn::link::tcp::TcpLink` so a `link.md` §9
///         shutdown regression in this plugin fails this plugin's
///         own `nix run .#test` instead of a kernel-side runner.

#include <sdk/test/conformance/link_teardown.hpp>
#include <tcp.hpp>

#include <memory>
#include <string>

namespace gn::test::link::conformance {

template <>
struct LinkTraits<gn::link::tcp::TcpLink> {
    static constexpr const char* scheme = "tcp";
    static std::shared_ptr<gn::link::tcp::TcpLink> make() {
        return std::make_shared<gn::link::tcp::TcpLink>();
    }
    static std::string listen_uri() { return "tcp://127.0.0.1:0"; }
    static std::string connect_uri(std::uint16_t port) {
        return "tcp://127.0.0.1:" + std::to_string(port);
    }
    static bool wire_credentials(gn::link::tcp::TcpLink&,
                                  gn::link::tcp::TcpLink&) {
        return true;
    }
};

INSTANTIATE_TYPED_TEST_SUITE_P(
    TcpLink,
    LinkTeardownConformance,
    ::testing::Types<gn::link::tcp::TcpLink>);

}  // namespace gn::test::link::conformance
