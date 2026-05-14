// SPDX-License-Identifier: MIT
/// @file   plugins/links/tcp/tcp_composer_session.hpp
/// @brief  TcpLink::ComposerSession — lean L1-bytes session for the
///         composer accept-bus path. Split out of tcp.cpp so the
///         kernel-managed Session (Noise pipeline, host_api_failures
///         retry, stalled-recv parking) and the composer-side L1
///         bytes (raw read loop, no protocol awareness) can evolve
///         independently — same split pattern as the TLS plugin.
///
/// The class is nested inside `TcpLink` so it can reach the parent's
/// `composer_*` helpers + atomic byte counters via `transport_.lock()`
/// without a friend declaration. Splitting the definition out is
/// purely source-organisation — visibility is unchanged.

#pragma once

#include "tcp.hpp"

#include <asio/ip/tcp.hpp>
#include <asio/strand.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <vector>

namespace gn::link::tcp {

class TcpLink::ComposerSession
    : public std::enable_shared_from_this<TcpLink::ComposerSession> {
public:
    ComposerSession(asio::ip::tcp::socket sock,
                    std::weak_ptr<TcpLink> transport,
                    gn_conn_id_t id);

    ComposerSession(const ComposerSession&)            = delete;
    ComposerSession& operator=(const ComposerSession&) = delete;

    [[nodiscard]] gn_conn_id_t conn_id() const noexcept { return conn_id_; }
    asio::ip::tcp::socket&     socket() noexcept        { return socket_; }

    /// Spin up the indefinite read loop; each completion dispatches
    /// raw bytes to the composer's subscribed callback and re-arms.
    void start_read();

    /// Queue an application send; serialised on the strand so the
    /// single-writer invariant per `link.md` §4 holds for the L1
    /// socket without contending with the read loop.
    void do_send(std::span<const std::uint8_t> bytes);

    /// Half-close the socket; the read loop sees ECONNRESET on the
    /// next completion and calls back into `composer_drop_session`.
    void do_close();

private:
    void kick_write();

    asio::ip::tcp::socket                                       socket_;
    asio::strand<asio::ip::tcp::socket::executor_type>          strand_;
    std::weak_ptr<TcpLink>                                      transport_;
    gn_conn_id_t                                                conn_id_;
    std::array<std::uint8_t, 64 * 1024>                         read_buf_{};
    std::deque<std::vector<std::uint8_t>>                       write_queue_;
};

}  // namespace gn::link::tcp
