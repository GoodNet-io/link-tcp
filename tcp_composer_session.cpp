// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp_composer_session.cpp
/// @brief  Implementation of TcpLink::ComposerSession. The session
///         is split out of tcp.cpp so the composer L1-bytes loop and
///         the kernel-managed Session (Noise pipeline, retries) can
///         evolve in separate translation units — same shape as the
///         TLS plugin's composer-session split.

#include "tcp_composer_session.hpp"

#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/post.hpp>
#include <asio/write.hpp>

#include <system_error>
#include <utility>

namespace gn::link::tcp {

TcpLink::ComposerSession::ComposerSession(
    asio::ip::tcp::socket sock,
    std::weak_ptr<TcpLink> transport,
    gn_conn_id_t id)
    : socket_(std::move(sock)),
      strand_(socket_.get_executor()),
      transport_(std::move(transport)),
      conn_id_(id) {}

void TcpLink::ComposerSession::start_read() {
    socket_.async_read_some(
        asio::buffer(read_buf_),
        asio::bind_executor(strand_,
            [self = shared_from_this()](
                const std::error_code& ec, std::size_t n) {
                auto t = self->transport_.lock();
                if (!t) return;
                if (ec) {
                    // Composer owns lifecycle; let the data_sub
                    // discover the close by socket EOF on the
                    // next write attempt, and drop the session
                    // record. The composer plugin will detect
                    // teardown through its own framing layer.
                    t->composer_drop_session(self->conn_id_);
                    return;
                }
                if (n > 0) {
                    t->bytes_in_.fetch_add(n, std::memory_order_relaxed);
                    t->frames_in_.fetch_add(1, std::memory_order_relaxed);
                    t->composer_dispatch_data(
                        self->conn_id_, self->read_buf_.data(), n);
                }
                self->start_read();
            }));
}

void TcpLink::ComposerSession::do_send(std::span<const std::uint8_t> bytes) {
    // Single-writer invariant per link.md §4: every async_write
    // runs on the strand; queue any concurrent send so the prior
    // write completes first.
    std::vector<std::uint8_t> payload(bytes.begin(), bytes.end());
    asio::post(strand_,
        [self = shared_from_this(),
         payload = std::move(payload)]() mutable {
            self->write_queue_.push_back(std::move(payload));
            if (self->write_queue_.size() == 1) {
                self->kick_write();
            }
        });
}

void TcpLink::ComposerSession::do_close() {
    asio::post(strand_,
        [self = shared_from_this()]() {
            std::error_code ec;
            (void)self->socket_.shutdown(
                asio::ip::tcp::socket::shutdown_both, ec);
            (void)self->socket_.close(ec);
        });
}

void TcpLink::ComposerSession::kick_write() {
    if (write_queue_.empty()) return;
    auto& front = write_queue_.front();
    asio::async_write(
        socket_,
        asio::buffer(front),
        asio::bind_executor(strand_,
            [self = shared_from_this()](
                const std::error_code& ec, std::size_t n) {
                auto t = self->transport_.lock();
                if (t && !ec) {
                    t->bytes_out_.fetch_add(
                        n, std::memory_order_relaxed);
                    t->frames_out_.fetch_add(
                        1, std::memory_order_relaxed);
                }
                if (!self->write_queue_.empty()) {
                    self->write_queue_.pop_front();
                }
                if (ec) {
                    if (t) t->composer_drop_session(self->conn_id_);
                    return;
                }
                if (!self->write_queue_.empty()) {
                    self->kick_write();
                }
            }));
}

}  // namespace gn::link::tcp
