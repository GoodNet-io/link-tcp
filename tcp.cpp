// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp.cpp
/// @brief  TCP link plugin — Boost.Asio strand-per-session transport.

#include "tcp.hpp"
#include "tcp_composer_session.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>
#include <system_error>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <exception>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace gn::link::tcp {
namespace {

constexpr std::size_t kReadBufferSize = std::size_t{16} * 1024;

}  // namespace

// ── Session ──────────────────────────────────────────────────────────────

class TcpLink::Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ip::tcp::socket sock,
             std::weak_ptr<TcpLink> transport)
        : socket_(std::move(sock)),
          strand_(socket_.get_executor()),
          transport_(std::move(transport)) {}

    asio::ip::tcp::socket& socket() noexcept { return socket_; }

    gn_conn_id_t conn_id = GN_INVALID_ID;

    /// Start the read loop. Each completion deposits bytes via
    /// `host_api->notify_inbound_bytes` and re-arms; closure or error
    /// posts `notify_disconnect`.
    void start_read() {
        socket_.async_read_some(
            asio::buffer(read_buf_),
            asio::bind_executor(strand_,
                [self = shared_from_this()](
                    const std::error_code& ec, std::size_t n) {
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        const gn_result_t reason =
                            (ec == asio::error::eof) ? GN_OK : GN_ERR_NULL_ARG;
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, reason);
                        }
                        return;
                    }
                    if (n > 0) {
                        t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                        t->frames_in_.fetch_add(1, std::memory_order_relaxed);
                        if (t->api_ && t->api_->notify_inbound_bytes) {
                            const gn_result_t rc =
                                t->api_->notify_inbound_bytes(
                                    t->api_->host_ctx, self->conn_id,
                                    self->read_buf_.data(), n);
                            /// Bound consecutive `notify_inbound_bytes`
                            /// failures so a peer that feeds garbage
                            /// the kernel can't decrypt does not keep
                            /// the connection alive indefinitely.
                            /// 16 failures back-to-back means the
                            /// security layer has refused 16 frames in
                            /// a row — the peer is either broken or
                            /// hostile, drop the conn rather than
                            /// burn CPU on a feed that will never
                            /// produce a valid frame.
                            if (rc == GN_OK) {
                                self->host_api_failures_.store(
                                    0, std::memory_order_relaxed);
                            } else if (rc == GN_ERR_LIMIT_REACHED) {
                                /// Receiver-side backpressure — the
                                /// kernel session's recv buffer is
                                /// momentarily full. Bytes are
                                /// **rejected** (not buffered) per
                                /// `session.cpp:349`, so re-arming
                                /// the read immediately would lose
                                /// the next chunk and break the AEAD
                                /// nonce sequence. Park the rejected
                                /// chunk and schedule a strand-bound
                                /// retry; the read loop pauses until
                                /// the kernel drains. `LIMIT_REACHED`
                                /// is **not** counted toward
                                /// `host_api_failures_` — it is
                                /// transient backpressure, not a
                                /// hostile feed.
                                self->host_api_failures_.store(
                                    0, std::memory_order_relaxed);
                                self->stalled_inbound_.assign(
                                    self->read_buf_.data(),
                                    self->read_buf_.data() + n);
                                self->retry_stalled_inbound();
                                return;  /// don't re-arm read
                            } else {
                                const auto fails =
                                    self->host_api_failures_.fetch_add(
                                        1, std::memory_order_relaxed) + 1;
                                if (fails >= 16) {
                                    if (t->claim_disconnect(self->conn_id) &&
                                        t->api_->notify_disconnect) {
                                        (void)t->api_->notify_disconnect(
                                            t->api_->host_ctx,
                                            self->conn_id, GN_OK);
                                    }
                                    return;
                                }
                            }
                        }
                    }
                    self->start_read();
                }));
    }

    /// Schedule a strand-bound retry for the parked
    /// `stalled_inbound_` bytes. Called from the read loop on
    /// `LIMIT_REACHED` and from itself when retry still hits the
    /// recv-buffer cap. On success the read loop re-arms; on
    /// non-LIMIT_REACHED failure the connection tears down via
    /// the standard host_api_failures_ threshold (LIMIT_REACHED
    /// is transient, every other rc counts).
    void retry_stalled_inbound() {
        if (!retry_timer_) {
            retry_timer_.emplace(strand_);
        }
        retry_timer_->expires_after(std::chrono::microseconds(100));
        retry_timer_->async_wait(asio::bind_executor(strand_,
            [self = shared_from_this()](const std::error_code& ec) {
                if (ec) return;
                auto t = self->transport_.lock();
                if (!t || !t->api_ || !t->api_->notify_inbound_bytes) return;
                if (self->stalled_inbound_.empty()) {
                    self->start_read();
                    return;
                }
                const gn_result_t rc =
                    t->api_->notify_inbound_bytes(
                        t->api_->host_ctx, self->conn_id,
                        self->stalled_inbound_.data(),
                        self->stalled_inbound_.size());
                if (rc == GN_ERR_LIMIT_REACHED) {
                    /// Kernel still saturated — wait again.
                    self->retry_stalled_inbound();
                    return;
                }
                /// `GN_OK` or other failure — bytes are now off
                /// the parking slot. On non-OK we don't count
                /// toward `host_api_failures_` here because the
                /// retry path doesn't have the read-loop's chunk
                /// context; the next live read will re-arm the
                /// counter properly.
                self->stalled_inbound_.clear();
                self->host_api_failures_.store(
                    0, std::memory_order_relaxed);
                self->start_read();
            }));
    }

    /// Enqueue a payload onto the strand-bound write queue and kick
    /// the writer. `asio::async_write` cannot run concurrently
    /// against the same socket: composed `async_write_some` calls
    /// would otherwise interleave bytes on the wire.
    void do_send(std::span<const std::uint8_t> data) {
        auto buf = std::make_shared<std::vector<std::uint8_t>>(
            data.begin(), data.end());
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    /// Coalesce a scatter-gather batch into one buffer so the queue
    /// stays scalar — the memcpy is dwarfed by socket I/O at any
    /// link rate the project ships against.
    void do_send_batch(std::span<const std::span<const std::uint8_t>> frames) {
        std::size_t total = 0;
        for (auto& f : frames) total += f.size();
        auto buf = std::make_shared<std::vector<std::uint8_t>>(total);
        std::size_t offset = 0;
        for (auto& f : frames) {
            std::memcpy(buf->data() + offset, f.data(), f.size());
            offset += f.size();
        }
        const auto added = buf->size();
        const auto post = bytes_buffered_.fetch_add(
            added, std::memory_order_relaxed) + added;
        maybe_signal_soft(post);
        asio::dispatch(strand_,
            [self = shared_from_this(), buf = std::move(buf)]() mutable {
                self->write_queue_.push_back(std::move(buf));
                self->maybe_start_write();
            });
    }

    /// Snapshot the per-connection write-queue depth, in bytes.
    /// Producers consult this through the transport before queuing
    /// fresh payload to enforce the `backpressure.en.md` §3 hard cap.
    [[nodiscard]] std::uint64_t bytes_buffered() const noexcept {
        return bytes_buffered_.load(std::memory_order_relaxed);
    }

    /// Rising-edge publisher for `BACKPRESSURE_SOFT`. Called by
    /// `do_send` / `do_send_batch` after the bytes_buffered_
    /// fetch_add so `post` is the post-enqueue depth. Atomic
    /// `compare_exchange_strong` guarantees one fire per crossing
    /// even if two senders cross the threshold concurrently.
    void maybe_signal_soft(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_high_ == 0) return;
        if (post <= t->pending_queue_bytes_high_) return;
        bool expected = false;
        if (!soft_signaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return;  // someone else already published
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_SOFT, post);
        }
    }

    /// Falling-edge publisher for `BACKPRESSURE_CLEAR`. Called from
    /// `maybe_start_write` after the drain `fetch_sub`.
    void maybe_signal_clear(std::uint64_t post) {
        auto t = transport_.lock();
        if (!t) return;
        if (t->pending_queue_bytes_low_ == 0) return;
        if (post >= t->pending_queue_bytes_low_) return;
        bool expected = true;
        if (!soft_signaled_.compare_exchange_strong(
                expected, false, std::memory_order_acq_rel)) {
            return;  // either never crossed soft, or already cleared
        }
        if (t->api_ && t->api_->notify_backpressure) {
            (void)t->api_->notify_backpressure(
                t->api_->host_ctx, conn_id,
                GN_CONN_EVENT_BACKPRESSURE_CLEAR, post);
        }
    }

    /// Close on the strand so the reactor's per-descriptor cleanup
    /// runs without overlapping a pending `async_read_some`. The
    /// `close(ec)` return is best-effort — the FD is gone either way;
    /// route a debug line through `gn_log_debug` so the failure
    /// isn't silent.
    void do_close() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            std::error_code ec;
            if (self->socket_.close(ec)) {
                if (auto t = self->transport_.lock();
                    t && t->api_) {
                    gn_log_debug(t->api_,
                                 "tcp: close failed: %s",
                                 ec.message().c_str());
                }
            }
        });
    }

private:
    /// Strand-bound — caller is already on `strand_`.
    void maybe_start_write() {
        if (write_in_flight_ || write_queue_.empty()) return;
        write_in_flight_ = true;
        auto buf = write_queue_.front();
        const std::size_t buf_size = buf->size();
        asio::async_write(socket_, asio::buffer(*buf),
            asio::bind_executor(strand_,
                [self = shared_from_this(), buf, buf_size](
                    const std::error_code& ec, std::size_t n) {
                    self->write_queue_.pop_front();
                    self->write_in_flight_ = false;
                    /// Drain bytes_buffered_ by the queued payload
                    /// size, not by `n`: an error or short write
                    /// still removes the buffer from the queue, so
                    /// the counter must drop by the same amount that
                    /// `do_send` added when it enqueued.
                    const auto post = self->bytes_buffered_.fetch_sub(
                        buf_size, std::memory_order_relaxed) - buf_size;
                    self->maybe_signal_clear(post);
                    auto t = self->transport_.lock();
                    if (!t) return;
                    if (ec) {
                        if (t->claim_disconnect(self->conn_id) &&
                            t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, GN_ERR_NULL_ARG);
                        }
                        return;
                    }
                    t->bytes_out_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(1, std::memory_order_relaxed);
                    self->maybe_start_write();
                }));
    }

    asio::ip::tcp::socket                              socket_;
    asio::strand<asio::any_io_executor>         strand_;
    std::weak_ptr<TcpLink>                               transport_;

    std::array<std::uint8_t, kReadBufferSize>                 read_buf_{};
    std::deque<std::shared_ptr<std::vector<std::uint8_t>>>    write_queue_;
    bool                                                      write_in_flight_ = false;
    std::atomic<std::uint64_t>                                bytes_buffered_{0};
    std::atomic<bool>                                         soft_signaled_{false};
    /// Counter of consecutive non-OK results from
    /// `notify_inbound_bytes`. Reset to 0 on every OK return or
    /// transient `LIMIT_REACHED` (handled by the parked-retry
    /// path); the session disconnects when it crosses the
    /// threshold (16) on real failures.
    std::atomic<std::uint32_t>                                host_api_failures_{0};

    /// Bytes the kernel session rejected with `LIMIT_REACHED` on
    /// the previous `notify_inbound_bytes` — typically the per-
    /// session recv buffer momentarily exceeded its cap because
    /// the peer's send-side `CryptoWorkerPool` drainer dumped a
    /// big batch faster than this side's decrypt + dispatch
    /// pipeline consumed it. Held strand-locally and retried
    /// through `retry_stalled_inbound` on a 100µs strand timer
    /// so the read loop pauses without losing the chunk.
    std::vector<std::uint8_t>                                 stalled_inbound_;

    /// Strand-bound retry timer for `stalled_inbound_`. Lazy-
    /// initialised on first stall — most sessions never trigger
    /// receiver-side backpressure and pay no per-session timer
    /// overhead.
    std::optional<asio::steady_timer>                         retry_timer_;
};

// ── ComposerSession ──────────────────────────────────────────────────────
//
// Composer-mode session: raw byte stream feeding back through a
// caller-installed `gn_link_data_cb_t`. No `notify_connect` /
// `notify_disconnect` traffic — the composer owns conn lifecycle
// per `link.en.md` §8 accept-bus contract. Definition lives in
// `tcp_composer_session.{hpp,cpp}` (split out so the composer L1
// path evolves independently of the kernel-managed Session).

// ── TcpLink ──────────────────────────────────────────────────────────────

TcpLink::TcpLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    /// `hardware_concurrency()` returns 0 on platforms that cannot
    /// determine the value; clamp to 1 so the link is always
    /// alive. Half-the-cores splits CPU between asio I/O threads
    /// and the kernel-side frame/encrypt work that runs on caller
    /// threads — the legacy benchmark settled on this ratio for
    /// the same reason.
    const unsigned hc = std::thread::hardware_concurrency();
    const unsigned n  = std::max(1u, hc / 2);
    workers_.reserve(n);
    for (unsigned i = 0; i < n; ++i) {
        workers_.emplace_back([this] { ioc_.run(); });
    }
}

TcpLink::~TcpLink() {
    /// Destructors must not throw — `shutdown()` walks the strand
    /// dispatch chain, which can throw `bad_executor` if the
    /// io_context already tore down. Surface the error through the
    /// host log if it is still bound; without a log sink there is
    /// nowhere safe to write from inside a dtor, so the catch only
    /// observes the exception type to satisfy the no-empty-catch
    /// lint without re-throwing.
    try {
        shutdown();
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_,
                      "tcp: shutdown threw: %s", e.what());
        }
    } catch (...) {
        if (api_) {
            gn_log_warn(api_,
                      "tcp: shutdown threw non-std exception");
        }
    }
}

void TcpLink::set_host_api(const host_api_t* api) noexcept {
    api_ = api;
    /// Cache the per-connection write-queue trio once the kernel
    /// hands over its limits table. A null `limits` slot leaves
    /// every threshold at zero — hard reject and watermark
    /// publishing both opt out, the transport behaves as before
    /// `backpressure.en.md` shipped.
    if (api_ != nullptr && api_->limits != nullptr) {
        if (const auto* L = api_->limits(api_->host_ctx); L != nullptr) {
            pending_queue_bytes_low_  = L->pending_queue_bytes_low;
            pending_queue_bytes_high_ = L->pending_queue_bytes_high;
            pending_queue_bytes_hard_ = L->pending_queue_bytes_hard;
        }
    }
}

std::uint16_t TcpLink::listen_port() const noexcept {
    return listen_port_.load(std::memory_order_acquire);
}

std::size_t TcpLink::session_count() const noexcept {
    std::lock_guard lk(sessions_mu_);
    return sessions_.size();
}

TcpLink::Stats TcpLink::stats() const noexcept {
    Stats s{};
    s.bytes_in           = bytes_in_.load(std::memory_order_relaxed);
    s.bytes_out          = bytes_out_.load(std::memory_order_relaxed);
    s.frames_in          = frames_in_.load(std::memory_order_relaxed);
    s.frames_out         = frames_out_.load(std::memory_order_relaxed);
    s.active_connections = session_count();
    return s;
}

gn_link_caps_t TcpLink::capabilities() noexcept {
    gn_link_caps_t c{};
    c.flags       = GN_LINK_CAP_STREAM
                  | GN_LINK_CAP_RELIABLE
                  | GN_LINK_CAP_ORDERED;
    c.max_payload = 0;  /// kernel limits.max_frame_bytes is the gate
    return c;
}

gn_trust_class_t TcpLink::resolve_trust(
    const asio::ip::tcp::endpoint& peer) const noexcept
{
    return peer.address().is_loopback() ? GN_TRUST_LOOPBACK
                                          : GN_TRUST_UNTRUSTED;
}

std::string TcpLink::endpoint_to_uri(
    const asio::ip::tcp::endpoint& ep)
{
    std::string uri = "tcp://";
    if (ep.address().is_v6()) {
        uri += '[';
        uri += ep.address().to_string();
        uri += ']';
    } else {
        uri += ep.address().to_string();
    }
    uri += ':';
    uri += std::to_string(ep.port());
    return uri;
}

gn_result_t TcpLink::listen(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    const auto parts = ::gn::parse_uri(uri_sv);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio::ip::tcp::endpoint ep(addr, parts->port);

    try {
        asio::ip::tcp::acceptor acceptor(ioc_);
        acceptor.open(ep.protocol());
        /// IPv6 wildcard `::` — disable `IPV6_V6ONLY` so dual-stack
        /// listens accept v4-mapped clients on Linux. `set_option`
        /// here is best-effort — pre-Linux-3.x kernels lack the option,
        /// v4-only fallback is the documented behaviour. Specific v6
        /// literals stay v6-only by default.
        if (addr.is_v6() && addr.is_unspecified()) {
            std::error_code v6_ec;
            if (acceptor.set_option(
                    asio::ip::v6_only(false), v6_ec) &&
                api_) {
                gn_log_debug(api_,
                          "tcp: v6_only(false) failed: %s",
                          v6_ec.message().c_str());
            }
        }
        std::error_code reuse_ec;
        if (acceptor.set_option(
                asio::ip::tcp::acceptor::reuse_address(true),
                reuse_ec) &&
            api_) {
            gn_log_debug(api_,
                      "tcp: reuse_address(true) failed: %s",
                      reuse_ec.message().c_str());
        }
        acceptor.bind(ep);
        acceptor.listen();
        listen_port_.store(acceptor.local_endpoint().port(),
                            std::memory_order_release);
        acceptor_.emplace(std::move(acceptor));
    } catch (const std::system_error& e) {
        if (api_) {
            gn_log_warn(api_,
                "tcp: listen failed (uri=%.*s, errno=%d): %s",
                static_cast<int>(uri_sv.size()), uri_sv.data(),
                e.code().value(), e.what());
        }
        return GN_ERR_NULL_ARG;
    } catch (const std::exception& e) {
        if (api_) {
            gn_log_warn(api_,
                "tcp: listen failed (uri=%.*s): %s",
                static_cast<int>(uri_sv.size()), uri_sv.data(),
                e.what());
        }
        return GN_ERR_NULL_ARG;
    }

    start_accept();
    return GN_OK;
}

void TcpLink::start_accept() {
    if (shutdown_.load(std::memory_order_acquire) || !acceptor_) return;

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this());

    /// Re-check `acceptor_.has_value()` immediately above the deref —
    /// the lint pass doesn't track the early-return guard at the top
    /// of the function across the intervening `make_shared` call.
    if (!acceptor_.has_value()) return;
    auto& sock = session->socket();
    acceptor_->async_accept(sock,
        [weak = std::weak_ptr<TcpLink>(shared_from_this()),
         session = std::move(session)](
            const std::error_code& ec) mutable {
            if (auto t = weak.lock()) t->on_accept(std::move(session), ec);
        });
}

void TcpLink::on_accept(std::shared_ptr<Session> session,
                              const std::error_code& ec)
{
    if (ec || shutdown_.load(std::memory_order_acquire)) return;

    std::error_code re_ec;
    const auto remote = session->socket().remote_endpoint(re_ec);
    if (re_ec) {
        session->do_close();
        start_accept();
        return;
    }

    /// Disable Nagle: GoodNet ships small framed messages that must
    /// not wait on the kernel's coalescing timer. Without this, a
    /// pong or a heartbeat sits behind a 200 ms delay on the local
    /// loopback and the LAN baseline ceases to be a baseline.
    /// Best-effort — a kernel that refuses the option leaves the
    /// connection on the default scheduler rather than failing the
    /// accept.
    std::error_code nodelay_ec;
    // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
    session->socket().set_option(asio::ip::tcp::no_delay{true},
                                  nodelay_ec);
    if (nodelay_ec && api_) {
        gn_log_debug(api_, "tcp: TCP_NODELAY refused: %s",
                     nodelay_ec.message().c_str());
    }

    if (api_ && api_->notify_connect) {
        std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};  // unknown until handshake
        gn_conn_id_t conn = GN_INVALID_ID;
        const std::string uri = endpoint_to_uri(remote);
        const gn_result_t rc = api_->notify_connect(
            api_->host_ctx, remote_pk, uri.c_str(),
            resolve_trust(remote), GN_ROLE_RESPONDER, &conn);
        if (rc == GN_OK && conn != GN_INVALID_ID) {
            session->conn_id = conn;
            session->start_read();
            /// Move-into the session map — ownership transfers to the
            /// registry, so the local `session` is consumed here.
            register_session(conn, std::move(session));
        } else {
            session->do_close();
        }
    } else {
        session->do_close();
    }

    start_accept();
}

gn_result_t TcpLink::connect(std::string_view uri_sv) {
    if (shutdown_.load(std::memory_order_acquire)) return GN_ERR_NULL_ARG;

    /// Resolve hostname → IP literal up-front so the registry's URI
    /// index keys and the on-connect callback URI line up per
    /// `dns.en.md` §1. IP-literal inputs short-circuit through the
    /// helper without a lookup.
    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri_sv);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    const auto parts = ::gn::parse_uri(*resolved);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    /// `connect`-side rejects port 0 per `uri.en.md` §5 — the parser
    /// accepts it for ephemeral allocation on the listen path, but
    /// a zero target port is never a real peer.
    if (parts->port == 0) return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    const auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_NULL_ARG;
    asio::ip::tcp::endpoint ep(addr, parts->port);

    auto session = std::make_shared<Session>(
        asio::ip::tcp::socket(ioc_),
        weak_from_this());

    /// Open against the endpoint's protocol family before the
    /// async_connect — a default-constructed socket carries no family,
    /// and Linux silently never completes the connect for IPv6. The
    /// `open(proto, ec)` overload returns the same `error_code` it
    /// stores into `open_ec`; consume the return through the failure
    /// guard.
    std::error_code open_ec;
    if (session->socket().open(ep.protocol(), open_ec)) {
        return GN_ERR_NULL_ARG;
    }

    /// `notify_connect` carries the resolved-IP URI so the registry
    /// index key matches what the kernel observes through subsequent
    /// `find_by_uri` lookups, and the connect path's `?peer=<hex>`
    /// stash (keyed on `host:port`) lines up with the literal-host
    /// form per `dns.en.md` §1.
    const std::string& canonical_uri = *resolved;
    session->socket().async_connect(ep,
        [weak = std::weak_ptr<TcpLink>(shared_from_this()),
         session, canonical_uri, ep](
            const std::error_code& connect_ec) {
            auto t = weak.lock();
            if (!t || t->shutdown_.load(std::memory_order_acquire)) return;
            if (connect_ec) {
                /// Connect failure surfaces through the disconnect
                /// notify path so the kernel's session map cleans up.
                return;
            }
            /// Disable Nagle on the outbound side; same rationale as
            /// the accept path. Best-effort.
            std::error_code nodelay_ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value,cert-err33-c)
            session->socket().set_option(
                asio::ip::tcp::no_delay{true}, nodelay_ec);
            if (nodelay_ec && t->api_) {
                gn_log_debug(t->api_, "tcp: TCP_NODELAY refused: %s",
                             nodelay_ec.message().c_str());
            }
            if (!t->api_ || !t->api_->notify_connect) {
                session->do_close();
                return;
            }
            std::uint8_t remote_pk[GN_PUBLIC_KEY_BYTES] = {};
            gn_conn_id_t conn = GN_INVALID_ID;
            const gn_result_t rc = t->api_->notify_connect(
                t->api_->host_ctx, remote_pk, canonical_uri.c_str(),
                t->resolve_trust(ep), GN_ROLE_INITIATOR, &conn);
            if (rc != GN_OK || conn == GN_INVALID_ID) {
                session->do_close();
                return;
            }
            session->conn_id = conn;
            t->register_session(conn, session);
            session->start_read();
            /// Initiator: drive the first wire message now that the
            /// session is reachable through `conn`.
            if (t->api_->kick_handshake) {
                (void)t->api_->kick_handshake(t->api_->host_ctx, conn);
            }
        });
    return GN_OK;
}

gn_result_t TcpLink::send(gn_conn_id_t conn,
                                std::span<const std::uint8_t> bytes)
{
    if (conn & kComposerIdBit) {
        std::shared_ptr<ComposerSession> cs;
        {
            std::lock_guard lk(composer_mu_);
            auto it = composer_sessions_.find(conn);
            if (it == composer_sessions_.end()) return GN_ERR_NOT_FOUND;
            cs = it->second;
        }
        cs->do_send(bytes);
        return GN_OK;
    }
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + bytes.size() >
            pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "tcp.send: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                bytes.size(),
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send(bytes);
    return GN_OK;
}

gn_result_t TcpLink::send_batch(
    gn_conn_id_t conn,
    std::span<const std::span<const std::uint8_t>> frames)
{
    if (frames.empty()) return GN_OK;
    if (frames.size() == 1) return send(conn, frames[0]);

    if (conn & kComposerIdBit) {
        // Coalesce the batch into one send for the composer path —
        // the composer's framing layer applies its own MTU policy.
        std::vector<std::uint8_t> flat;
        std::size_t total = 0;
        for (const auto& f : frames) total += f.size();
        flat.reserve(total);
        for (const auto& f : frames) flat.insert(flat.end(), f.begin(), f.end());
        return send(conn, std::span<const std::uint8_t>(flat));
    }
    auto session = find_session(conn);
    if (!session) return GN_ERR_NOT_FOUND;
    std::size_t total = 0;
    for (const auto& f : frames) total += f.size();
    if (pending_queue_bytes_hard_ != 0 &&
        session->bytes_buffered() + total > pending_queue_bytes_hard_) {
        if (api_) {
            if (api_->emit_counter) {
                api_->emit_counter(api_->host_ctx, "drop.queue_hard_cap");
            }
            gn_log_warn(api_,
                "tcp.send_batch: queue hard cap — conn=%llu buffered=%zu add=%zu hard=%zu",
                static_cast<unsigned long long>(conn),
                session->bytes_buffered(),
                total,
                pending_queue_bytes_hard_);
        }
        return GN_ERR_LIMIT_REACHED;
    }
    session->do_send_batch(frames);
    return GN_OK;
}

gn_result_t TcpLink::disconnect(gn_conn_id_t conn) {
    if (conn & kComposerIdBit) {
        std::shared_ptr<ComposerSession> cs;
        {
            std::lock_guard lk(composer_mu_);
            auto it = composer_sessions_.find(conn);
            if (it == composer_sessions_.end()) return GN_OK;  /// idempotent
            cs = std::move(it->second);
            composer_sessions_.erase(it);
            composer_data_subs_.erase(conn);
        }
        cs->do_close();
        return GN_OK;
    }
    std::shared_ptr<Session> session;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(conn);
        if (it == sessions_.end()) return GN_OK;  /// idempotent
        session = std::move(it->second);
        sessions_.erase(it);
    }
    session->do_close();
    return GN_OK;
}

// ── Composer L2 surface ─────────────────────────────────────────────────
//
// Implements `link.en.md` §8 accept-bus contract. Disjoint from the
// kernel-managed acceptor / sessions above: composer conns are owned
// by the consumer plugin (WSS, TLS, ICE) and never thread through
// `notify_connect`. The high bit of `conn_id` (`kComposerIdBit`)
// keeps composer ids segregated from the kernel-managed range so
// `send` / `disconnect` route by id mask without scanning two maps.

gn_result_t TcpLink::composer_listen(std::string_view uri) {
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }
    if (composer_acceptor_) return GN_ERR_LIMIT_REACHED;

    const auto parts = ::gn::parse_uri(uri);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    if (parts->scheme != "tcp") return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_INVALID_ENVELOPE;
    asio::ip::tcp::endpoint endpoint(addr, parts->port);

    composer_acceptor_.emplace(ioc_);
    composer_acceptor_->open(endpoint.protocol(), ec);
    if (ec) { composer_acceptor_.reset(); return GN_ERR_NULL_ARG; }
    composer_acceptor_->set_option(
        asio::socket_base::reuse_address(true), ec);
    if (endpoint.protocol() == asio::ip::tcp::v6()) {
        composer_acceptor_->set_option(asio::ip::v6_only(false), ec);
    }
    composer_acceptor_->bind(endpoint, ec);
    if (ec) { composer_acceptor_.reset(); return GN_ERR_NULL_ARG; }
    composer_acceptor_->listen(asio::socket_base::max_listen_connections, ec);
    if (ec) { composer_acceptor_.reset(); return GN_ERR_NULL_ARG; }

    // Publish the bound port through `listen_port_` so callers can
    // discover the OS-picked port (URI port 0). The kernel `listen`
    // and the composer `listen` share this counter — both paths fill
    // in the actual OS-assigned port for whichever acceptor opened.
    const auto bound = composer_acceptor_->local_endpoint(ec);
    if (!ec) {
        listen_port_.store(bound.port(), std::memory_order_release);
    }

    composer_start_accept();
    return GN_OK;
}

gn_result_t TcpLink::composer_connect(std::string_view uri,
                                       gn_conn_id_t* out_conn) {
    if (!out_conn) return GN_ERR_NULL_ARG;
    *out_conn = GN_INVALID_ID;
    if (shutdown_.load(std::memory_order_acquire)) {
        return GN_ERR_INVALID_STATE;
    }

    const auto parts = ::gn::parse_uri(uri);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    if (parts->scheme != "tcp") return GN_ERR_INVALID_ENVELOPE;

    std::error_code ec;
    auto addr = asio::ip::make_address(parts->host, ec);
    if (ec) return GN_ERR_INVALID_ENVELOPE;
    asio::ip::tcp::endpoint endpoint(addr, parts->port);

    asio::ip::tcp::socket sock(ioc_);
    sock.connect(endpoint, ec);
    if (ec) return GN_ERR_NOT_FOUND;

    const gn_conn_id_t id =
        next_composer_id_.fetch_add(1, std::memory_order_relaxed) |
        kComposerIdBit;
    auto cs = std::make_shared<ComposerSession>(
        std::move(sock), weak_from_this(), id);
    {
        std::lock_guard lk(composer_mu_);
        composer_sessions_[id] = cs;
    }
    cs->start_read();
    *out_conn = id;
    return GN_OK;
}

gn_result_t TcpLink::composer_subscribe_data(gn_conn_id_t conn,
                                              ::gn_link_data_cb_t cb,
                                              void* user_data) {
    if (!cb) return GN_ERR_NULL_ARG;
    if (!(conn & kComposerIdBit)) return GN_ERR_NOT_FOUND;
    std::lock_guard lk(composer_mu_);
    if (composer_sessions_.find(conn) == composer_sessions_.end()) {
        return GN_ERR_NOT_FOUND;
    }
    composer_data_subs_[conn] = ComposerDataSub{cb, user_data};
    return GN_OK;
}

gn_result_t TcpLink::composer_unsubscribe_data(gn_conn_id_t conn) {
    if (!(conn & kComposerIdBit)) return GN_OK;
    std::lock_guard lk(composer_mu_);
    composer_data_subs_.erase(conn);
    return GN_OK;
}

gn_result_t TcpLink::composer_subscribe_accept(
    ::gn_link_accept_cb_t cb,
    void* user_data,
    gn_subscription_id_t* out_token) {
    if (!cb || !out_token) return GN_ERR_NULL_ARG;
    const gn_subscription_id_t token =
        next_accept_token_.fetch_add(1, std::memory_order_relaxed);
    std::lock_guard lk(composer_mu_);
    composer_accept_subs_.push_back(
        ComposerAcceptSub{token, cb, user_data});
    *out_token = token;
    return GN_OK;
}

gn_result_t TcpLink::composer_unsubscribe_accept(
    gn_subscription_id_t token) {
    std::lock_guard lk(composer_mu_);
    auto it = std::remove_if(
        composer_accept_subs_.begin(), composer_accept_subs_.end(),
        [token](const ComposerAcceptSub& s) { return s.token == token; });
    composer_accept_subs_.erase(it, composer_accept_subs_.end());
    return GN_OK;
}

gn_result_t TcpLink::composer_listen_port(
    std::uint16_t* out_port) const noexcept {
    if (!out_port) return GN_ERR_NULL_ARG;
    *out_port = 0;
    if (!composer_acceptor_) return GN_ERR_INVALID_STATE;
    std::error_code ec;
    const auto ep = composer_acceptor_->local_endpoint(ec);
    if (ec) return GN_ERR_INVALID_STATE;
    *out_port = ep.port();
    return GN_OK;
}

void TcpLink::composer_start_accept() {
    if (!composer_acceptor_) return;
    auto sock = std::make_shared<asio::ip::tcp::socket>(ioc_);
    composer_acceptor_->async_accept(
        *sock,
        [self = weak_from_this(), sock](const std::error_code& ec) {
            auto t = self.lock();
            if (!t) return;
            if (ec) return;  // acceptor closed during shutdown
            // Snapshot the peer endpoint before moving the socket
            std::error_code peer_ec;
            auto ep = sock->remote_endpoint(peer_ec);
            const std::string peer_uri =
                peer_ec ? std::string{} : endpoint_to_uri(ep);
            const gn_conn_id_t id =
                t->next_composer_id_.fetch_add(
                    1, std::memory_order_relaxed) | kComposerIdBit;
            auto cs = std::make_shared<ComposerSession>(
                std::move(*sock), t->weak_from_this(), id);
            std::vector<ComposerAcceptSub> snapshot;
            {
                std::lock_guard lk(t->composer_mu_);
                t->composer_sessions_[id] = cs;
                snapshot = t->composer_accept_subs_;  // copy out for fan-out
            }
            // Fire accept-bus subscribers BEFORE starting the read
            // loop so a composer (WS / TLS / ICE) gets a chance to
            // install its data subscription before the first byte
            // races onto the strand. composer_dispatch_data drops
            // bytes silently when no sub is registered.
            for (const auto& s : snapshot) {
                if (s.cb) {
                    s.cb(s.user_data, id, peer_uri.c_str());
                }
            }
            cs->start_read();
            t->composer_start_accept();
        });
}

void TcpLink::composer_dispatch_data(gn_conn_id_t conn,
                                      const std::uint8_t* bytes,
                                      std::size_t size) {
    ComposerDataSub sub{};
    {
        std::lock_guard lk(composer_mu_);
        auto it = composer_data_subs_.find(conn);
        if (it == composer_data_subs_.end()) return;
        sub = it->second;
    }
    if (sub.cb) sub.cb(sub.user_data, conn, bytes, size);
}

void TcpLink::composer_drop_session(gn_conn_id_t conn) {
    std::lock_guard lk(composer_mu_);
    composer_sessions_.erase(conn);
    composer_data_subs_.erase(conn);
}

void TcpLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s)
{
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
    published_ids_.push_back(id);
}

void TcpLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

bool TcpLink::claim_disconnect(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    if (shutdown_.load(std::memory_order_acquire)) return false;
    return sessions_.erase(id) > 0;
}

std::shared_ptr<TcpLink::Session>
TcpLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void TcpLink::shutdown() {
    if (acceptor_) {
        std::error_code ec;
        /// `close(ec)` is best-effort on shutdown — the FD is gone
        /// either way. Route the error through `gn_log_debug`;
        /// `api_` may be null when the kernel tore down before
        /// shutdown ran, in which case the macro short-circuits.
        if (acceptor_->close(ec) && api_) {
            gn_log_debug(api_,
                      "tcp: acceptor close failed: %s",
                      ec.message().c_str());
        }
        acceptor_.reset();
    }

    // Composer-mode teardown. Close the composer acceptor first so
    // no new conns arrive mid-shutdown, then close every live
    // composer session and clear all per-conn subscriptions. The
    // accept-bus subscribers stay registered until the consumer
    // plugin explicitly unsubscribes — we just stop firing them.
    if (composer_acceptor_) {
        std::error_code cec;
        (void)composer_acceptor_->close(cec);
        composer_acceptor_.reset();
    }
    std::vector<std::shared_ptr<ComposerSession>> composer_drain;
    {
        std::lock_guard lk(composer_mu_);
        composer_drain.reserve(composer_sessions_.size());
        for (auto& [_, cs] : composer_sessions_) {
            composer_drain.push_back(cs);
        }
        composer_sessions_.clear();
        composer_data_subs_.clear();
        composer_accept_subs_.clear();
    }
    for (auto& cs : composer_drain) cs->do_close();

    /// Drain every ever-published conn id through notify_disconnect on
    /// the caller thread before stopping the io_context. The
    /// append-only `published_ids_` log captures every id the worker
    /// announced via `notify_connect`; `sessions_` is just the live
    /// socket map and may already be empty if a worker callback raced
    /// ahead of shutdown and erased its session. Without this drain a
    /// worker that emitted disconnect on its own thread before
    /// shutdown ran would leave zero caller-thread emits and break
    /// the `notify_connect → notify_disconnect on shutdown caller
    /// thread` invariant from `link.en.md` §9 step 3.
    ///
    /// The kernel resolves the resulting double-emit through
    /// `GN_ERR_NOT_FOUND` (see `core/kernel/host_api_builder.cpp`
    /// `thunk_notify_disconnect`): the second call observes the
    /// already-erased registry record and returns without re-firing
    /// `DISCONNECTED`, so the redundant emit is benign.
    ///
    /// `shutdown_.exchange(true)` runs INSIDE the lock so a worker
    /// callback racing with shutdown either (a) wins the lock first,
    /// sees `shutdown_=false`, claims its id, and emits on the worker
    /// thread, or (b) loses, sees `shutdown_=true`, and bails — the
    /// drain below then carries the kernel-observable release on the
    /// caller thread either way.
    std::vector<gn_conn_id_t> ids_to_emit;
    {
        std::lock_guard lk(sessions_mu_);
        if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;
        ids_to_emit = std::move(published_ids_);
        published_ids_.clear();
        for (auto& [id, s] : sessions_) s->do_close();
        sessions_.clear();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : ids_to_emit) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    workers_.clear();
}

} // namespace gn::link::tcp
