// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp.hpp
/// @brief  Asio TCP transport plugin per `docs/contracts/link.md`.
///
/// One io_context per plugin runs on a single worker thread; sessions
/// are owned via `shared_ptr` and refer back to the transport with
/// `weak_ptr` so async completions that fire after `shutdown()` are
/// no-ops instead of UAF (per audit TR-C1 lesson). Per-session strand
/// keeps the single-writer invariant from `link.md` §4: every
/// `async_write` runs on the strand, every close dispatches through
/// it (closes the socket while the read tail is in-flight is the
/// classic epoll_reactor race — TR-S2/TR-S3 in the audit). The
/// `shutdown()` guard uses `exchange(true)` for idempotency
/// (TR-S5). IPv6 wildcard listens disable `IPV6_V6ONLY` so a single
/// listener accepts dual-stack traffic on Linux (TR-S4).

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

#include <sdk/extensions/link.h>
#include <sdk/host_api.h>
#include <sdk/types.h>
#include <sdk/trust.h>

namespace gn::link::tcp {

/// Public interface a plugin entry or in-tree test instantiates.
/// Lives behind a `shared_ptr` because async sessions take a
/// `weak_ptr<TcpLink>` to make late callbacks safe.
class TcpLink : public std::enable_shared_from_this<TcpLink> {
public:
    /// Build a transport that drives its own `io_context` on one
    /// worker thread. The thread starts on construction and stops
    /// on `shutdown()` / destruction.
    TcpLink();
    ~TcpLink();

    TcpLink(const TcpLink&)            = delete;
    TcpLink& operator=(const TcpLink&) = delete;

    /// Bind the URI and start accepting. URI form per
    /// `docs/contracts/uri.md` — `tcp://host:port` or
    /// `tcp://[::1]:port`. Port 0 lets the OS pick; the actual
    /// bound port is available through `listen_port()`.
    [[nodiscard]] gn_result_t listen(std::string_view uri);

    /// Initiate an outbound connection. Returns `GN_OK` immediately
    /// once the async connect is posted; the kernel learns of the
    /// completed handshake through `notify_connect` once it actually
    /// connects (or through `notify_disconnect` on failure).
    [[nodiscard]] gn_result_t connect(std::string_view uri);

    /// Send a frame to an existing connection. Strand-serialised per
    /// session to honor the single-writer invariant.
    [[nodiscard]] gn_result_t send(gn_conn_id_t conn,
                                    std::span<const std::uint8_t> bytes);

    /// Send a scatter-gather batch as a single coalesced write.
    [[nodiscard]] gn_result_t send_batch(gn_conn_id_t conn,
                                          std::span<const std::span<const std::uint8_t>> frames);

    /// Idempotent close. A second call returns GN_OK no-op.
    [[nodiscard]] gn_result_t disconnect(gn_conn_id_t conn);

    /// Bind the kernel-provided host_api; subsequent
    /// `notify_*` calls flow through it. Pass `nullptr` to detach
    /// before destruction.
    void set_host_api(const host_api_t* api) noexcept;

    /// Tear down. Idempotent; closes the acceptor, all sessions, and
    /// stops the io_context worker. Called once from the plugin
    /// entry's `gn_plugin_unregister` and again by the destructor.
    void shutdown();

    /// Actual bound port after `listen()`. Returns 0 if not yet
    /// bound.
    [[nodiscard]] std::uint16_t listen_port() const noexcept;

    /// Number of live sessions; useful for tests.
    [[nodiscard]] std::size_t session_count() const noexcept;

    /// Aggregate counters surfaced through the
    /// `gn.link.tcp` extension. All values are monotonic over
    /// the transport's lifetime; consumers handle wrap themselves.
    struct Stats {
        std::uint64_t bytes_in            = 0;
        std::uint64_t bytes_out           = 0;
        std::uint64_t frames_in           = 0;
        std::uint64_t frames_out          = 0;
        std::uint64_t active_connections  = 0;
    };
    [[nodiscard]] Stats stats() const noexcept;

    [[nodiscard]] static gn_link_caps_t capabilities() noexcept;

private:
    class Session;

    /// Compute trust class from a remote endpoint per
    /// `link.md` §3: loopback addresses → `Loopback`, public →
    /// `Untrusted`. Trust upgrades to `Peer` happen later in the
    /// kernel after Noise completes.
    [[nodiscard]] gn_trust_class_t resolve_trust(
        const asio::ip::tcp::endpoint& peer) const noexcept;

    /// Re-arm the acceptor for the next inbound connection. No-op
    /// when shutdown has been signalled.
    void start_accept();

    /// Called from the acceptor's completion. Promotes the half-open
    /// session into the registered set after `notify_connect` returns
    /// a fresh conn id, then chains the next accept.
    void on_accept(std::shared_ptr<Session> session,
                    const std::error_code& ec);

    void register_session(gn_conn_id_t id, std::shared_ptr<Session> s);
    void erase_session(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    /// Build a uri-string for the conn record from a peer endpoint.
    [[nodiscard]] static std::string endpoint_to_uri(
        const asio::ip::tcp::endpoint& ep);

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    std::thread                                                      worker_;

    std::optional<asio::ip::tcp::acceptor> acceptor_;
    std::atomic<std::uint16_t>                    listen_port_{0};
    std::atomic<bool>                             shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    /// Per-transport counters. Updated from the worker thread on each
    /// completed read / write, snapshotted lock-free through `stats()`.
    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.md`
    /// §1. Read from `api_->limits()` once `set_host_api` binds.
    /// Hard cap 0 disables hard reject; high cap 0 disables soft
    /// watermark publishing (the trio is independent at the slot
    /// level even though `Config::validate` keeps them ordered).
    std::uint64_t pending_queue_bytes_low_  = 0;
    std::uint64_t pending_queue_bytes_high_ = 0;
    std::uint64_t pending_queue_bytes_hard_ = 0;

    const host_api_t* api_ = nullptr;
};

} // namespace gn::link::tcp
