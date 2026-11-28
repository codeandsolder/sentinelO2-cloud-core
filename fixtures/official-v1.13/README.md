# Independent official protocol 1.13.5 reference fixtures

The 13 JSON files in this directory are frozen semantic outputs of the
official SentinelX Python protocol, not outputs of our Rust implementation.
They were generated using upstream
[pensados/sentinelx-cloud-protocol at 0894b18e](https://github.com/pensados/sentinelx-cloud-protocol/tree/0894b18e7793d8289b9f36421b2766664edcefde).
The exact original generator, project manifest and lock are preserved in
[the pre-migration source tree](https://github.com/codeandsolder/sentinelO2-cloud-core/tree/1dcc8be8d3de903735757f0d19568aa6645c8e5f/.github/scripts).
No interpreter is needed for normal Rust testing.

The corpus covers protocol constants, full/minimal hello, welcome, every
operation name, success and error responses, ping/pong, events, fatal errors,
binary-frame bytes, and six response-bounding cases. All input/output pairs
are retained unchanged. Do not regenerate expected results with the Rust
implementation being tested. When updating the independent reference to a new
upstream version, capture new outputs from that pinned official release
in a scratch checkout and review the semantic differences explicitly.
