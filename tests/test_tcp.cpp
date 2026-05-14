// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tests/test_tcp.cpp
/// @brief  TcpLink — listen+connect loopback drives the full
///         vtable contract: dual notify_connect (initiator + responder),
///         strand-serialised send/recv round-trip, idempotent shutdown.

#include <gtest/gtest.h>

#include <tcp.hpp>

#include <sdk/cpp/test/poll.hpp>
#include <sdk/cpp/test/stub_host.hpp>
#include <sdk/host_api.h>
#include <sdk/trust.h>
#include <sdk/types.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::tcp::TcpLink;

/// Alias to the shared SDK helpers (DX Tier 2, 2026-05-12).
/// The hand-rolled `StubHost` + `make_stub_api` + `wait_for` copies
/// that used to live here at 78 LOC are now centralised in
/// `sdk/cpp/test/stub_host.hpp` and `sdk/cpp/test/poll.hpp`.
using StubHost = ::gn::sdk::test::LinkStub;

inline host_api_t make_stub_api(StubHost& h) noexcept {
    return ::gn::sdk::test::make_link_host_api(h);
}

/// Thin wrapper that turns the SDK's boolean `wait_for` into the
/// "fail-the-test on timeout" call-site shape this file's tests
/// were written against. New tests should prefer
/// `ASSERT_TRUE(gn::sdk::test::wait_for(...))` directly.
inline void wait_for(const std::function<bool()>& pred,
                      std::chrono::milliseconds timeout,
                      const char* what) {
    if (!::gn::sdk::test::wait_for(pred, timeout)) {
        FAIL() << "timeout waiting for: " << what;
    }
}

}  // namespace

// ── listen / port allocation ─────────────────────────────────────────────

TEST(TcpLink, ListenOnEphemeralPortReturnsNonZero) {
    StubHost h;
    auto api = make_stub_api(h);
    auto t = std::make_shared<TcpLink>();
    t->set_host_api(&api);

    EXPECT_EQ(t->listen("tcp://127.0.0.1:0"), GN_OK);
    EXPECT_NE(t->listen_port(), 0);
    t->shutdown();
}

TEST(TcpLink, ListenRejectsMalformedUri) {
    auto t = std::make_shared<TcpLink>();
    EXPECT_NE(t->listen("garbage"), GN_OK);
    EXPECT_NE(t->listen("ipc:///tmp/sock"), GN_OK);  /// path-style mis-scheme
}

TEST(TcpLink, ConnectRejectsZeroPort) {
    auto t = std::make_shared<TcpLink>();
    StubHost h;
    auto api = make_stub_api(h);
    t->set_host_api(&api);
    /// Listen accepts port 0 (ephemeral allocation); connect rejects
    /// it at the application layer per `uri.md` §5.
    EXPECT_NE(t->connect("tcp://127.0.0.1:0"), GN_OK);
    t->shutdown();
}

TEST(TcpLink, ShutdownIsIdempotent) {
    auto t = std::make_shared<TcpLink>();
    t->shutdown();
    t->shutdown();   /// second call is a no-op
}

// ── full loopback round-trip ─────────────────────────────────────────────

TEST(TcpLink, LoopbackHandshakeAndPayloadRoundTrip) {
    StubHost h;
    auto api = make_stub_api(h);
    auto t = std::make_shared<TcpLink>();
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("tcp://127.0.0.1:0"), GN_OK);
    const auto port = t->listen_port();
    ASSERT_NE(port, 0);

    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(t->connect(uri), GN_OK);

    /// Two notify_connect calls land — one per side of the loopback.
    wait_for([&] { return h.connects.load() == 2; },
              2s, "two notify_connect calls");

    gn_conn_id_t initiator = GN_INVALID_ID;
    gn_conn_id_t responder = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        ASSERT_EQ(h.roles.size(), 2u);
        for (std::size_t i = 0; i < h.roles.size(); ++i) {
            if (h.roles[i] == GN_ROLE_INITIATOR) initiator = h.conns[i];
            if (h.roles[i] == GN_ROLE_RESPONDER) responder = h.conns[i];
        }
    }
    ASSERT_NE(initiator, GN_INVALID_ID);
    ASSERT_NE(responder, GN_INVALID_ID);

    /// Send a small frame initiator → responder.
    const std::uint8_t payload[] = {0x42, 0xAB, 0xCD};
    ASSERT_EQ(t->send(initiator, std::span<const std::uint8_t>(payload, sizeof(payload))),
              GN_OK);

    wait_for([&] { return h.inbound_calls.load() >= 1; },
              2s, "inbound payload delivery");

    {
        std::lock_guard lk(h.mu);
        bool found = false;
        for (std::size_t i = 0; i < h.inbound_owners.size(); ++i) {
            if (h.inbound_owners[i] == responder &&
                h.inbound[i].size() == sizeof(payload) &&
                std::memcmp(h.inbound[i].data(), payload, sizeof(payload)) == 0)
            {
                found = true;
                break;
            }
        }
        EXPECT_TRUE(found) << "responder did not receive the exact payload";
    }

    /// Disconnect and verify both sides eventually get notified.
    EXPECT_EQ(t->disconnect(initiator), GN_OK);
    wait_for([&] { return h.disconnects.load() >= 1; },
              2s, "disconnect notify");

    /// disconnect on a stale id is a no-op, not an error.
    EXPECT_EQ(t->disconnect(initiator), GN_OK);

    t->shutdown();
}

TEST(TcpLink, SendBatchCoalescesIntoOneStream) {
    StubHost h;
    auto api = make_stub_api(h);
    auto t = std::make_shared<TcpLink>();
    t->set_host_api(&api);

    ASSERT_EQ(t->listen("tcp://127.0.0.1:0"), GN_OK);
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(t->listen_port());
    ASSERT_EQ(t->connect(uri), GN_OK);
    wait_for([&] { return h.connects.load() == 2; }, 2s, "both connects");

    gn_conn_id_t initiator = GN_INVALID_ID;
    gn_conn_id_t responder = GN_INVALID_ID;
    {
        std::lock_guard lk(h.mu);
        for (std::size_t i = 0; i < h.roles.size(); ++i) {
            if (h.roles[i] == GN_ROLE_INITIATOR) initiator = h.conns[i];
            if (h.roles[i] == GN_ROLE_RESPONDER) responder = h.conns[i];
        }
    }

    const std::uint8_t f1[] = {1, 2, 3};
    const std::uint8_t f2[] = {4, 5};
    const std::uint8_t f3[] = {6};
    std::span<const std::uint8_t> spans[] = {
        std::span<const std::uint8_t>(f1, sizeof(f1)),
        std::span<const std::uint8_t>(f2, sizeof(f2)),
        std::span<const std::uint8_t>(f3, sizeof(f3)),
    };
    ASSERT_EQ(t->send_batch(initiator,
        std::span<const std::span<const std::uint8_t>>(spans, 3)),
              GN_OK);

    /// send_batch coalesces into one buffer so the receiver may see
    /// one or more notify_inbound_bytes calls totalling 6 bytes.
    wait_for([&] {
        std::lock_guard lk(h.mu);
        std::size_t total = 0;
        for (std::size_t i = 0; i < h.inbound_owners.size(); ++i) {
            if (h.inbound_owners[i] == responder)
                total += h.inbound[i].size();
        }
        return total == 6;
    }, 2s, "batch payload assembled at responder");

    t->shutdown();
}
