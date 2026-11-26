# EVM RPC Security Guardrail

High-performance JSON-RPC 2.0 security proxy for EVM and zkEVM environments. Inspects incoming transaction payloads, enforces pre-flight security policies (such as unbounded ERC-20 approvals and calldata anomalies), and verifies cloud IAM context before transactions hit node RPC endpoints.

## Features

- **JSON-RPC Pre-Flight Inspection**: Intercepts `eth_sendRawTransaction` and `eth_sendTransaction` before mempool propagation.
- **Unbounded Approval Detection**: Catches unlimited (`uint256.max`) token allowance approvals that put user funds at risk.
- **Cloud IAM Signature Verification**: Enforces AWS IAM / HMAC signature validation on transaction relay endpoints to prevent unauthorized signing requests.
- **Low Latency**: Pure Go implementation with zero external runtime dependencies.

## Quick Start

```bash
# Run unit tests with race detection
go test -v -race ./...
```
