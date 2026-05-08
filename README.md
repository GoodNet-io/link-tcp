# goodnet-link-tcp

TCP transport for GoodNet. Listens on an `tcp://host:port` URI,
dials remote URIs, hands inbound bytes up to the kernel router via
`host_api->notify_inbound_bytes`, and surfaces per-connection
counters through the `gn.link.tcp` extension.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

This plugin lives in its own git with a flake that pulls the
kernel SDK as a Nix input. From this checkout:

```sh
nix run .#build         # release build of libgoodnet_link_tcp.so
nix run .#test          # vanilla ctest (link teardown conformance, etc.)
nix run .#test-asan     # AddressSanitizer + UBSan
nix run .#test-tsan     # ThreadSanitizer
```

The kernel monorepo also builds this plugin in-tree through its
own `nix run .#build -- release` — operator install consumes
every bundled `.so` from there.

## Load

The kernel's `PluginManager` opens the `.so` from a manifest entry
that pins its SHA-256 digest; the plugin registers the `tcp` scheme
through `gn_plugin_init`. See `docs/install.en.md` and
`docs/contracts/plugin-manifest.en.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.en.md`
- Trust-class policy: `docs/contracts/security-trust.en.md`
