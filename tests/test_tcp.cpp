// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tests/test_tcp.cpp
/// @brief  TcpLink — listen+connect loopback drives the full
///         vtable contract: dual notify_connect (initiator + responder),
///         strand-serialised send/recv round-trip, idempotent shutdown.

#include <gtest/gtest.h>

#include <plugins/links/tcp/tcp.hpp>

#include <sdk/host_api.h>
#include <sdk/types.h>
#include <sdk/trust.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::tcp::TcpLink;

/// Stub host_api: the test owns its callbacks; no real kernel.
struct StubHost {
    std::atomic<int>                         connects{0};
    std::atomic<int>                         disconnects{0};
    std::atomic<int>                         inbound_calls{0};
    std::mutex                               mu;
    std::vector<gn_conn_id_t>                conns;
    std::vector<gn_handshake_role_t>         roles;
    std::vector<std::vector<std::uint8_t>>   inbound;        // by conn_id index
    std::vector<gn_conn_id_t>                inbound_owners;

    /// Each notify_connect allocates a fresh id; tests drive the
    /// transport on whichever id matches the role they care about.
    std::atomic<gn_conn_id_t>                next_id{1};

    static gn_result_t on_connect(void* host_ctx,
                                   const std::uint8_t /*remote_pk*/[GN_PUBLIC_KEY_BYTES],
                                   const char* /*uri*/,
                                   gn_trust_class_t /*trust*/,
                                   gn_handshake_role_t role,
                                   gn_conn_id_t* out_conn) {
        auto* h = static_cast<StubHost*>(host_ctx);
        const auto id = h->next_id.fetch_add(1);
        {
            std::lock_guard lk(h->mu);
            h->conns.push_back(id);
            h->roles.push_back(role);
        }
        *out_conn = id;
        h->connects.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_inbound(void* host_ctx, gn_conn_id_t conn,
                                   const std::uint8_t* bytes, std::size_t size) {
        auto* h = static_cast<StubHost*>(host_ctx);
        std::lock_guard lk(h->mu);
        h->inbound.emplace_back(bytes, bytes + size);
        h->inbound_owners.push_back(conn);
        h->inbound_calls.fetch_add(1);
        return GN_OK;
    }

    static gn_result_t on_disconnect(void* host_ctx, gn_conn_id_t /*conn*/,
                                      gn_result_t /*reason*/) {
        auto* h = static_cast<StubHost*>(host_ctx);
        h->disconnects.fetch_add(1);
        return GN_OK;
    }
};

host_api_t make_stub_api(StubHost& h) {
    host_api_t api{};
    api.api_size              = sizeof(host_api_t);
    api.host_ctx              = &h;
    api.notify_connect        = &StubHost::on_connect;
    api.notify_inbound_bytes  = &StubHost::on_inbound;
    api.notify_disconnect     = &StubHost::on_disconnect;
    return api;
}

/// Spin-poll a predicate up to `timeout` milliseconds; fail the
/// enclosing test on timeout. Async transport completions land on
/// the worker thread; the poller serialises observation via the
/// supplied `StubHost`'s atomics.
void wait_for(const std::function<bool()>& pred,
              std::chrono::milliseconds timeout,
              const char* what) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return;
        std::this_thread::sleep_for(5ms);
    }
    FAIL() << "timeout waiting for: " << what;
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
