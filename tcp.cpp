// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp.cpp
/// @brief  TCP link plugin — Boost.Asio strand-per-session transport.

#include "tcp.hpp"

#include <sdk/convenience.h>
#include <sdk/cpp/dns.hpp>
#include <sdk/cpp/uri.hpp>

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/dispatch.hpp>
#include <asio/ip/v6_only.hpp>
#include <asio/post.hpp>
#include <asio/read.hpp>
#include <asio/write.hpp>
#include <system_error>

#include <array>
#include <cstring>
#include <deque>
#include <exception>
#include <utility>

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
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id,
                                ec == asio::error::eof
                                    ? GN_OK
                                    : GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
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
                            } else {
                                const auto fails =
                                    self->host_api_failures_.fetch_add(
                                        1, std::memory_order_relaxed) + 1;
                                if (fails >= 16) {
                                    if (t->api_->notify_disconnect) {
                                        (void)t->api_->notify_disconnect(
                                            t->api_->host_ctx,
                                            self->conn_id, GN_OK);
                                    }
                                    t->erase_session(self->conn_id);
                                    return;
                                }
                            }
                        }
                    }
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
    /// fresh payload to enforce the `backpressure.md` §3 hard cap.
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
                        if (t->api_ && t->api_->notify_disconnect) {
                            t->api_->notify_disconnect(
                                t->api_->host_ctx, self->conn_id, GN_ERR_NULL_ARG);
                        }
                        t->erase_session(self->conn_id);
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
    /// `notify_inbound_bytes`. Reset to 0 on every OK return; the
    /// session disconnects when it crosses the threshold (16).
    std::atomic<std::uint32_t>                                host_api_failures_{0};
};

// ── TcpLink ──────────────────────────────────────────────────────────────

TcpLink::TcpLink()
    : ioc_(),
      work_(asio::make_work_guard(ioc_)) {
    worker_ = std::thread([this] { ioc_.run(); });
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
    /// `backpressure.md` shipped.
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
    /// `dns.md` §1. IP-literal inputs short-circuit through the
    /// helper without a lookup.
    auto resolved = ::gn::sdk::resolve_uri_host(ioc_, uri_sv);
    if (!resolved) return GN_ERR_INVALID_ENVELOPE;

    const auto parts = ::gn::parse_uri(*resolved);
    if (!parts || parts->is_path_style()) return GN_ERR_INVALID_ENVELOPE;
    /// `connect`-side rejects port 0 per `uri.md` §5 — the parser
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
    /// form per `dns.md` §1.
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

void TcpLink::register_session(gn_conn_id_t id,
                                     std::shared_ptr<Session> s)
{
    std::lock_guard lk(sessions_mu_);
    sessions_[id] = std::move(s);
}

void TcpLink::erase_session(gn_conn_id_t id) {
    std::lock_guard lk(sessions_mu_);
    sessions_.erase(id);
}

std::shared_ptr<TcpLink::Session>
TcpLink::find_session(gn_conn_id_t id) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(id);
    return (it == sessions_.end()) ? nullptr : it->second;
}

void TcpLink::shutdown() {
    if (shutdown_.exchange(true, std::memory_order_acq_rel)) return;

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

    /// Snapshot conn ids under the lock, close sockets, then notify
    /// the kernel side SYNCHRONOUSLY for each session before stopping
    /// the io_context. `ioc_.stop()` would otherwise drop pending
    /// strand-bound continuations — including the read-completion
    /// path that normally fires `notify_disconnect`. Without sync
    /// notification, kernel-side `SessionRegistry` keeps live
    /// `SecuritySession` records past tcp shutdown, which in turn
    /// keeps the security plugin's lifetime anchor alive past the
    /// PluginManager drain budget. Per `link.md` §7 the shutdown
    /// must release every kernel-observable session before the
    /// io_context tear-down.
    std::vector<gn_conn_id_t> live_ids;
    {
        std::lock_guard lk(sessions_mu_);
        live_ids.reserve(sessions_.size());
        for (auto& [id, s] : sessions_) {
            live_ids.push_back(id);
            s->do_close();
        }
        sessions_.clear();
    }

    if (api_ && api_->notify_disconnect) {
        for (const auto id : live_ids) {
            (void)api_->notify_disconnect(api_->host_ctx, id, GN_OK);
        }
    }

    work_.reset();
    ioc_.stop();
    if (worker_.joinable()) worker_.join();
}

} // namespace gn::link::tcp
