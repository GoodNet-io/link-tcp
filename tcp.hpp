// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp.hpp
/// @brief  Asio TCP transport plugin per `docs/contracts/link.en.md`.
///
/// One io_context per plugin runs on a single worker thread; sessions
/// are owned via `shared_ptr` and refer back to the transport with
/// `weak_ptr` so async completions that fire after `shutdown()` are
/// no-ops instead of a use-after-free. Per-session strand keeps the
/// single-writer invariant from `link.en.md` §4: every
/// `async_write` runs on the strand, every close dispatches through
/// it (closing the socket while the read tail is in-flight is the
/// classic epoll_reactor race). The `shutdown()` guard uses
/// `exchange(true)` for idempotency. IPv6 wildcard listens disable
/// `IPV6_V6ONLY` so a single listener accepts dual-stack traffic
/// on Linux.

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
    /// `docs/contracts/uri.en.md` — `tcp://host:port` or
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

    /// L2-composition surface per `link.en.md` §8. Composer (WSS,
    /// TLS, ICE — built on this L1) drives connection lifecycle
    /// independently of the kernel `notify_connect` flow.
    ///
    /// `composer_listen(uri)` binds an L1 listener; accepted
    /// connections are kept in the composer-owned session set and
    /// **not** announced to the kernel. The composer attaches
    /// per-conn data callbacks through `composer_subscribe_data`.
    ///
    /// `composer_connect(uri, &out)` initiates an outbound L1 conn
    /// the composer owns. The L2 plugin then runs its handshake,
    /// finally calls `host_api->notify_connect` for the L2 conn it
    /// publishes upward.
    ///
    /// Composer-owned conn ids are issued from a private range
    /// (high bit set) so they cannot collide with kernel-managed
    /// ids. `send` / `disconnect` route to the composer session set
    /// when the id is in that range.
    ///
    /// Composer L2 surface. Used by upper-layer plugins (WSS, TLS,
    /// ICE) that want to own L1 conn lifecycle without engaging the
    /// kernel's `notify_connect` flow. Composer conn ids carry
    /// `kComposerIdBit` so `send` / `disconnect` route by range
    /// without scanning two maps.
    [[nodiscard]] gn_result_t composer_listen(std::string_view uri);
    [[nodiscard]] gn_result_t composer_connect(std::string_view uri,
                                                gn_conn_id_t* out_conn);
    [[nodiscard]] gn_result_t composer_subscribe_data(
        gn_conn_id_t conn,
        ::gn_link_data_cb_t cb,
        void* user_data);
    [[nodiscard]] gn_result_t composer_unsubscribe_data(gn_conn_id_t conn);
    [[nodiscard]] gn_result_t composer_subscribe_accept(
        ::gn_link_accept_cb_t cb,
        void* user_data,
        gn_subscription_id_t* out_token);
    [[nodiscard]] gn_result_t composer_unsubscribe_accept(
        gn_subscription_id_t token);

    /// Bound port of the composer acceptor (port 0 listen). Returns
    /// @ref GN_ERR_INVALID_STATE when no composer-listen is active.
    [[nodiscard]] gn_result_t composer_listen_port(
        std::uint16_t* out_port) const noexcept;

    /// High-bit flag distinguishing composer-owned conn ids from
    /// kernel-managed ones. Composer ids never collide because the
    /// composer allocator counts up from 1 inside its own range.
    static constexpr gn_conn_id_t kComposerIdBit =
        gn_conn_id_t{1} << 63;

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
    class ComposerSession;

    struct ComposerDataSub {
        ::gn_link_data_cb_t cb        = nullptr;
        void*               user_data = nullptr;
    };
    struct ComposerAcceptSub {
        gn_subscription_id_t  token     = GN_INVALID_SUBSCRIPTION_ID;
        ::gn_link_accept_cb_t cb        = nullptr;
        void*                 user_data = nullptr;
    };

    /// Compute trust class from a remote endpoint per
    /// `link.en.md` §3: loopback addresses → `Loopback`, public →
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
    /// Atomically claim disconnect emission for @p id: under
    /// `sessions_mu_`, fail-fast if `shutdown_` is set (the shutdown
    /// path will emit on the caller thread instead) and otherwise
    /// erase the session record. Returns true when the caller owns
    /// the `notify_disconnect` emission for this id; false when
    /// shutdown owns it or the id was already gone.
    [[nodiscard]] bool claim_disconnect(gn_conn_id_t id);
    [[nodiscard]] std::shared_ptr<Session> find_session(gn_conn_id_t id) const;

    /// Build a uri-string for the conn record from a peer endpoint.
    [[nodiscard]] static std::string endpoint_to_uri(
        const asio::ip::tcp::endpoint& ep);

    asio::io_context                                          ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
    /// Multiple workers run the same `io_context` so concurrent
    /// connections progress in parallel; per-Session strands keep
    /// each connection's I/O serialised, so the only thing the
    /// extra threads buy us is parallelism *across* connections.
    /// `hardware_concurrency()/2` matches the legacy default —
    /// half the cores leaves headroom for kernel-side
    /// frame/encrypt work that runs on caller threads.
    std::vector<std::thread>                                  workers_;

    std::optional<asio::ip::tcp::acceptor> acceptor_;
    std::atomic<std::uint16_t>                    listen_port_{0};
    std::atomic<bool>                             shutdown_{false};

    mutable std::mutex                                                  sessions_mu_;
    std::unordered_map<gn_conn_id_t, std::shared_ptr<Session>>          sessions_;

    /// Append-only record of every conn id ever registered via
    /// register_session. shutdown() drains this through
    /// notify_disconnect on the caller thread so each notify_connect
    /// maps to one caller-thread notify_disconnect even when a worker
    /// callback already emitted runtime disconnect on its own thread.
    std::vector<gn_conn_id_t>                                           published_ids_;

    /// Per-transport counters. Updated from the worker thread on each
    /// completed read / write, snapshotted lock-free through `stats()`.
    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint64_t> frames_in_{0};
    std::atomic<std::uint64_t> frames_out_{0};

    /// Per-connection write-queue thresholds per `backpressure.en.md`
    /// §1. Read from `api_->limits()` once `set_host_api` binds.
    /// Hard cap 0 disables hard reject; high cap 0 disables soft
    /// watermark publishing (the trio is independent at the slot
    /// level even though `Config::validate` keeps them ordered).
    std::uint64_t pending_queue_bytes_low_  = 0;
    std::uint64_t pending_queue_bytes_high_ = 0;
    std::uint64_t pending_queue_bytes_hard_ = 0;

    const host_api_t* api_ = nullptr;

    /// Composer-mode state — disjoint from the kernel-managed
    /// session set above. Composer conn ids carry `kComposerIdBit`;
    /// `send` / `disconnect` dispatch by range so the two worlds
    /// never share a map.
    std::optional<asio::ip::tcp::acceptor> composer_acceptor_;
    mutable std::mutex                                                composer_mu_;
    std::unordered_map<gn_conn_id_t,
                       std::shared_ptr<ComposerSession>>              composer_sessions_;
    std::unordered_map<gn_conn_id_t, ComposerDataSub>                 composer_data_subs_;
    std::vector<ComposerAcceptSub>                                    composer_accept_subs_;
    std::atomic<std::uint64_t>                                        next_composer_id_{1};
    std::atomic<std::uint64_t>                                        next_accept_token_{1};

    void composer_start_accept();
    void composer_on_accept(std::shared_ptr<ComposerSession> s,
                             std::error_code ec);
    void composer_dispatch_data(gn_conn_id_t conn,
                                 const std::uint8_t* bytes,
                                 std::size_t size);
    void composer_drop_session(gn_conn_id_t conn);
};

} // namespace gn::link::tcp
