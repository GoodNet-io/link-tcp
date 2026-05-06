# goodnet-link-tcp

TCP transport for GoodNet. Listens on an `tcp://host:port` URI,
dials remote URIs, hands inbound bytes up to the kernel router via
`host_api->notify_inbound_bytes`, and surfaces per-connection
counters through the `gn.link.tcp` extension.

**Kind**: link · **Artefact**: dynamic plugin (`.so` via dlopen)
· **License**: GPL-2.0 with Linking Exception (see `LICENSE`)

## Build

In-tree, alongside the kernel:

```sh
nix build .#goodnet-link-tcp
# result/lib/goodnet/plugins/libgoodnet_link_tcp.so
```

Standalone, against an installed kernel SDK:

```sh
cd plugins/links/tcp
cmake -B build -DCMAKE_PREFIX_PATH=/usr/local -DBUILD_TESTING=OFF
cmake --build build
```

## Load

The kernel's `PluginManager` opens the `.so` from a manifest entry
that pins its SHA-256 digest; the plugin registers the `tcp` scheme
through `gn_plugin_init`. See `docs/install.md` and
`docs/contracts/plugin-manifest.md` in the kernel tree.

## Contract

- Kernel-side link contract: `docs/contracts/link.md`
- Trust-class policy: `docs/contracts/security-trust.md`
