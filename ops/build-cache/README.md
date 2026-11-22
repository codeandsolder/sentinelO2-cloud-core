# Build-cache regression tests

Run the independent integration tests from the workspace root:

```sh
cargo test --locked -p sentinel0-build-cache-tests
bash ops/build-cache/check-shell-contracts
```

The Rust tests exercise the actual maintenance scripts against isolated temporary directories and deterministic subprocess fixtures. They cover pruning and lifetime locks, offline resolution readiness, Cargo wrapper lifecycle and artifact reclamation, and native package integrity and identity. Environment passed to child processes is the scripts' deployment interface, not the test configuration interface.

The shell contract checker covers script syntax and existing source-level updater/routing invariants. It does not replace end-to-end privileged service tests. See [native package integration](BORINGSSL_PREBUILT.md) for the real cross-workspace native link test.
