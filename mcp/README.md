# `@n170/verify-mcp`

Zero-dependency outbound Model Context Protocol (MCP) JSON-RPC 2.0 server for cryptographically verifying **N170 Verify v3** selective-disclosure proof bundles (`Apache-2.0`).

## Highlights

- **Zero External npm Dependencies**: Built exclusively on Node.js `>= 20` standard library modules (`node:crypto` WebCrypto Ed25519, `node:readline`, `node:test`, `node:assert`). Runs offline without `node_modules`.
- **Byte-for-Byte Python Parity**: Matches `n170_verify.contracts.verify_proof_bundle` across RFC 8785 JCS canonicalization, domain-separated Ed25519 signatures, 256-bit salted 7-leaf Merkle audit paths (`0x00` leaf / `0x01` internal node), C2SP `tlog-checkpoint` registry trust, dynamic $k \ge 2$ org- and ASN-disjoint TLSNotary witness quorums, and all five prospective chain continuity invariants.
- **Zero-Credential & Zero-Path Surface**: Enforces `additionalProperties: false` on every tool schema and rejects broker API keys, tokens, cookies, filesystem paths, and arbitrary URLs.
- **LLM Transcript Privacy Notice**: Explicitly reminds callers and host models that MCP tool inputs and outputs enter the LLM conversation transcript, so only selectively redacted public `VerifyProofBundle` objects or public `proof_id` identifiers should ever be submitted.

## Exposed Read-Only Tools

1. `n170_verify_capabilities` — Lists supported cryptographic primitives, canonical leaf names, hard-disabled mutating/credential actions, and the transcript-privacy notice.
2. `n170_verify_check_bundle` — Verifies a `VerifyProofBundle` end-to-end offline and derives the six-axis `AssuranceProfile`.
3. `n170_verify_inspect_public_proof` — Verifies and extracts selected disclosed leaves (`core_metrics`, `indexed_curve`, `reconciliation`, `coaching_and_context`, `capital_bracket`, `benchmark_alpha`, `delayed_closed_trades`) from a public proof bundle.

## Running Tests

```bash
node --test mcp/server.test.js
```
