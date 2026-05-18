# Changelog — goodnet-link-tcp

All notable changes to this plugin are listed here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions track the kernel ABI through `gn_link_vtable_t` /
`gn.link.tcp` extension.

## [Unreleased]

### ComposerSession translation unit split

The composer L2 surface moves out of the main session source
into its own translation unit. Build-time isolation lets the
composer slot evolve without churning the base session header,
and reduces the rebuild blast radius when the composer surface
changes.

## [1.0.0-rc1] — 2026-05-12

Initial release. Brings the legacy in-tree `links/tcp` link
forward as a v1 GoodNet link plugin, with the composer surface
that lets TLS / QUIC sit on top of it.

### Added

- TCP transport with `tcp://host:port` URI scheme. Inbound
  bytes surface through `host_api->notify_inbound_bytes`;
  per-connection counters are published through the
  `gn.link.tcp` extension.
- SDK link teardown conformance — disconnect emit serialized
  with the shutdown flag, every published conn tracked so
  caller-thread `shutdown()` emits the matching `DISCONNECTED`
  notification for every active session.
- Multi-threaded `io_context` worker pool sized to half
  `hardware_concurrency()`. Throughput scales with concurrent
  connection count rather than blocking on the single
  asio strand.
- Recv-side backpressure: when the kernel-side recv buffer
  reaches `LIMIT_REACHED`, the session pauses read and retries
  on a strand timer instead of dropping the connection or
  spinning.
- Real composer L2 surface implementation — the
  `LinkCarrier(tcp)` slot exposes the post-handshake byte
  stream to upper composers (`link-tls`, `link-quic` via QUIC
  over TCP fallback paths in `link-ice` TURN/TCP, etc).
- Trust-class plumbing per
  `docs/contracts/security-trust.en.md` — TCP defaults to
  `WAN`, with operator override available at manifest level.
