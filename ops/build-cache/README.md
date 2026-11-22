# Build-cache utilities

SentinelO2 owns only the remaining small service integration utilities.
Machine-wide Cargo/sccache wrappers and the release updater are owned by
[sccache-deduplicated](https://github.com/codeandsolder/sccache-deduplicated/tree/main/contrib/codeandsolder).
Cargo's ephemeral intermediates and shared offline resolution are implemented
by [cargo-ephemeral](https://github.com/codeandsolder/cargo-ephemeral).
Native dependencies, including BoringSSL, build normally through Cargo and their
upstream build scripts. The managed C/C++ compiler cache handles reuse across
workspaces. Do not introduce a separate native-package cache or override native
dependency build paths for caching.

The remaining service/timer files are provisioning templates, not an
alternative implementation of the updater. Install the updater from its
authoritative repository.

Run the preflight integration test and shell syntax validation:

    cargo test --locked -p sentinel0-build-cache-tests
    bash ops/build-cache/check-shell-contracts

The test uses isolated temporary directories and exercises the actual
disposable distributed-client cache subtree.
