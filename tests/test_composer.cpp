// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tests/test_composer.cpp
/// @brief  TcpLink composer L2 surface — listen+connect+accept-bus+data
///         roundtrip without engaging kernel notify_connect; verifies
///         the contract in `link.en.md` §8.

#include <gtest/gtest.h>

#include <tcp.hpp>

#include <sdk/extensions/link.h>
#include <sdk/types.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace std::chrono_literals;
using gn::link::tcp::TcpLink;

// Spin-wait helper — composer paths are async; tests poll on
// atomics until the worker thread has driven the callback.
template <class Pred>
bool wait_until(Pred p, std::chrono::milliseconds timeout = 2s) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (p()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return p();
}

struct AcceptRecorder {
    std::atomic<int>           hits{0};
    std::atomic<gn_conn_id_t>  last_conn{GN_INVALID_ID};
    std::mutex                 uri_mu;
    std::string                last_uri;

    static void thunk(void* ud, gn_conn_id_t conn, const char* uri) {
        auto* r = static_cast<AcceptRecorder*>(ud);
        r->last_conn.store(conn);
        {
            std::lock_guard lk(r->uri_mu);
            r->last_uri = uri ? uri : "";
        }
        r->hits.fetch_add(1);
    }
};

struct DataRecorder {
    std::atomic<std::size_t>  bytes{0};
    std::atomic<int>          calls{0};
    std::mutex                buf_mu;
    std::vector<std::uint8_t> buf;
    gn_conn_id_t              expected_conn = GN_INVALID_ID;

    static void thunk(void* ud, gn_conn_id_t conn,
                      const std::uint8_t* bytes, std::size_t size) {
        auto* r = static_cast<DataRecorder*>(ud);
        if (r->expected_conn != GN_INVALID_ID) {
            ASSERT_EQ(conn, r->expected_conn);
        }
        {
            std::lock_guard lk(r->buf_mu);
            r->buf.insert(r->buf.end(), bytes, bytes + size);
        }
        r->bytes.fetch_add(size);
        r->calls.fetch_add(1);
    }
};

}  // namespace

// ─── Composer listen + accept-bus ────────────────────────────────

TEST(TcpComposer, ListenAndConnectFiresAcceptCb) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder rec;
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &rec, &token), GN_OK);
    EXPECT_NE(token, GN_INVALID_SUBSCRIPTION_ID);

    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();
    ASSERT_NE(port, 0u);

    gn_conn_id_t client_conn = GN_INVALID_ID;
    const std::string uri = "tcp://127.0.0.1:" + std::to_string(port);
    ASSERT_EQ(client->composer_connect(uri, &client_conn), GN_OK);
    EXPECT_NE(client_conn, GN_INVALID_ID);
    EXPECT_TRUE(client_conn & TcpLink::kComposerIdBit);

    ASSERT_TRUE(wait_until([&]() { return rec.hits.load() == 1; }));
    EXPECT_TRUE(rec.last_conn.load() & TcpLink::kComposerIdBit);

    server->shutdown();
    client->shutdown();
}

TEST(TcpComposer, ListenPortReflectsComposerAcceptor) {
    auto server = std::make_shared<TcpLink>();
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    // `listen_port_` is shared between the kernel and composer
    // listen paths — whichever acceptor opened publishes its
    // OS-assigned port.
    EXPECT_NE(server->listen_port(), 0u);
    server->shutdown();
}

// ─── Data roundtrip ──────────────────────────────────────────────

TEST(TcpComposer, DataRoundtripClientToServer) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder accept_rec;
    gn_subscription_id_t accept_token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &accept_rec, &accept_token),
              GN_OK);

    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();
    ASSERT_NE(port, 0u);

    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &client_conn), GN_OK);

    ASSERT_TRUE(wait_until([&]() { return accept_rec.hits.load() == 1; }));
    const gn_conn_id_t server_conn = accept_rec.last_conn.load();

    DataRecorder server_rec;
    server_rec.expected_conn = server_conn;
    ASSERT_EQ(server->composer_subscribe_data(
                  server_conn, &DataRecorder::thunk, &server_rec), GN_OK);

    const std::vector<std::uint8_t> payload = {'h','e','l','l','o',0x00,0xFF,0x42};
    ASSERT_EQ(client->send(client_conn, std::span<const std::uint8_t>(payload)),
              GN_OK);

    ASSERT_TRUE(wait_until([&]() {
        return server_rec.bytes.load() == payload.size();
    }));
    {
        std::lock_guard lk(server_rec.buf_mu);
        EXPECT_EQ(server_rec.buf, payload);
    }

    server->shutdown();
    client->shutdown();
}

TEST(TcpComposer, DataRoundtripBidirectional) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder accept_rec;
    gn_subscription_id_t accept_token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &accept_rec, &accept_token), GN_OK);
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();

    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &client_conn), GN_OK);
    ASSERT_TRUE(wait_until([&]() { return accept_rec.hits.load() == 1; }));
    const gn_conn_id_t server_conn = accept_rec.last_conn.load();

    DataRecorder server_rec, client_rec;
    server_rec.expected_conn = server_conn;
    client_rec.expected_conn = client_conn;
    ASSERT_EQ(server->composer_subscribe_data(
                  server_conn, &DataRecorder::thunk, &server_rec), GN_OK);
    ASSERT_EQ(client->composer_subscribe_data(
                  client_conn, &DataRecorder::thunk, &client_rec), GN_OK);

    const std::vector<std::uint8_t> c2s = {1,2,3,4,5};
    const std::vector<std::uint8_t> s2c = {9,8,7};
    ASSERT_EQ(client->send(client_conn, std::span<const std::uint8_t>(c2s)),
              GN_OK);
    ASSERT_EQ(server->send(server_conn, std::span<const std::uint8_t>(s2c)),
              GN_OK);

    ASSERT_TRUE(wait_until([&]() {
        return server_rec.bytes.load() == c2s.size() &&
               client_rec.bytes.load() == s2c.size();
    }));

    server->shutdown();
    client->shutdown();
}

// ─── Disconnect & id-range dispatch ──────────────────────────────

TEST(TcpComposer, DisconnectComposerConnIsIdempotent) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder accept_rec;
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &accept_rec, &token), GN_OK);
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();

    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &client_conn), GN_OK);
    ASSERT_TRUE(wait_until([&]() { return accept_rec.hits.load() == 1; }));

    EXPECT_EQ(client->disconnect(client_conn), GN_OK);
    EXPECT_EQ(client->disconnect(client_conn), GN_OK);  // idempotent

    server->shutdown();
    client->shutdown();
}

TEST(TcpComposer, ShutdownDrainsComposerSessionsCleanly) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder accept_rec;
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &accept_rec, &token), GN_OK);
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);

    const std::uint16_t port = server->listen_port();
    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &client_conn), GN_OK);
    ASSERT_TRUE(wait_until([&]() { return accept_rec.hits.load() == 1; }));

    // No exceptions / leaks expected — sanitizer builds catch lifecycle bugs
    server->shutdown();
    client->shutdown();
}

// ─── Unsubscribe semantics ───────────────────────────────────────

TEST(TcpComposer, UnsubscribeAcceptStopsCallbacks) {
    auto server = std::make_shared<TcpLink>();
    auto client1 = std::make_shared<TcpLink>();
    auto client2 = std::make_shared<TcpLink>();

    AcceptRecorder rec;
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &rec, &token), GN_OK);
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();

    gn_conn_id_t c1 = GN_INVALID_ID;
    ASSERT_EQ(client1->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &c1), GN_OK);
    ASSERT_TRUE(wait_until([&]() { return rec.hits.load() == 1; }));

    EXPECT_EQ(server->composer_unsubscribe_accept(token), GN_OK);

    gn_conn_id_t c2 = GN_INVALID_ID;
    ASSERT_EQ(client2->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &c2), GN_OK);
    std::this_thread::sleep_for(50ms);  // give the accept time to fire
    EXPECT_EQ(rec.hits.load(), 1);  // unchanged after unsubscribe

    server->shutdown();
    client1->shutdown();
    client2->shutdown();
}

TEST(TcpComposer, UnsubscribeDataStopsCallbacks) {
    auto server = std::make_shared<TcpLink>();
    auto client = std::make_shared<TcpLink>();

    AcceptRecorder accept_rec;
    gn_subscription_id_t token = GN_INVALID_SUBSCRIPTION_ID;
    ASSERT_EQ(server->composer_subscribe_accept(
                  &AcceptRecorder::thunk, &accept_rec, &token), GN_OK);
    ASSERT_EQ(server->composer_listen("tcp://127.0.0.1:0"), GN_OK);
    const std::uint16_t port = server->listen_port();

    gn_conn_id_t client_conn = GN_INVALID_ID;
    ASSERT_EQ(client->composer_connect(
        "tcp://127.0.0.1:" + std::to_string(port), &client_conn), GN_OK);
    ASSERT_TRUE(wait_until([&]() { return accept_rec.hits.load() == 1; }));
    const gn_conn_id_t server_conn = accept_rec.last_conn.load();

    DataRecorder rec;
    rec.expected_conn = server_conn;
    ASSERT_EQ(server->composer_subscribe_data(
                  server_conn, &DataRecorder::thunk, &rec), GN_OK);
    EXPECT_EQ(server->composer_unsubscribe_data(server_conn), GN_OK);

    const std::vector<std::uint8_t> payload = {1,2,3};
    ASSERT_EQ(client->send(client_conn,
                           std::span<const std::uint8_t>(payload)), GN_OK);
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(rec.bytes.load(), 0u);

    server->shutdown();
    client->shutdown();
}
