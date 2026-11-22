# Build-cache utilities

SentinelO2 owns the native package helper and the remaining small service
integration utilities. Machine-wide Cargo/sccache wrappers and the release
updater are owned by
[sccache-deduplicated](https://github.com/codeandsolder/sccache-deduplicated/tree/main/contrib/codeandsolder).
Cargo's ephemeral intermediates and shared offline resolution are implemented
by [cargo-ephemeral](https://github.com/codeandsolder/cargo-ephemeral).
Do not reinstall the obsolete SentinelO2 Cargo scratch wrapper or updater.

The remaining service/timer files are provisioning templates, not an
alternative implementation of the updater. Install the updater from its
authoritative repository.

Run the remaining native-package and preflight integration tests:

    cargo test --locked -p sentinel0-build-cache-tests
    bash ops/build-cache/check-shell-contracts

The tests use isolated temporary directories. The preflight exercises the
actual disposable distributed-client cache subtree; the native-package tests
check integrity and canonical-view confinement. See
[BoringSSL native package reuse](BORINGSSL_PREBUILT.md) for the real link test.
