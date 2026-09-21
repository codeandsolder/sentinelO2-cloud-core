# SentinelX Rust RIR

A compatibility-first Rust reimplementation of the official SentinelX agent.

**Current scope is deliberately boring:** match SentinelX 1:1 closely enough
that the Python and Rust agents can be swapped without changing workflows,
while fixing bugs that are not part of the hosted wire contract.

This is not the Sentinel0² redesign. P2P transport, session containers,
reviewer policy, MQTT/QUIC and other 2.0 ideas stay out of this implementation
until the drop-in replacement is complete and reliable.

See [COMPATIBILITY.md](COMPATIBILITY.md) for the executable compatibility
surface and the remaining work.

The test suite uses real local WebSocket peers for connection-lifecycle
behavior and checked-in fixtures generated from the official Python protocol
for wire conformance.
