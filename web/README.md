# N170 Verify Wave-4 - Web Studio & In-Browser WebCrypto Verifier (`@n170/verify-web`)

Open-source (`Apache-2.0`) Next.js 15 App Router + Tailwind CSS frontend for **N170 Verify**: cryptographic brokerage performance verification, salted 7-leaf RFC 8785 JCS Merkle selective disclosure, calibrated accounting/market reconciliation, and zero-paywall trader coaching.

## Routes & Product Modules

| Route | Module | Purpose |
| --- | --- | --- |
| `/` | `src/app/page.tsx` | Landing page with live 3-mode cryptographic preview switcher: **(a)** Continuous Track Record (`k >= 2` Disjoint Notaries), **(b)** Unreconciled Statement Discrepancy X-Ray, and **(c)** Personal Trader Coaching Studio |
| `/connect` | `src/app/connect/page.tsx` | Transparent 3-step Connect Wizard: IBKR Dual-Track UX (Official OAuth + Local CLI/MCP + 6h IP-restricted Flex Wave-4 Token Wizard + Offline XML), Alpaca/Tradier/Schwab/Trading 212/Crypto CEX read-only scope introspection, `RLIMIT_CORE=0` ephemeral vs `AES-256-GCM` sync lifecycle, and salted Merkle selective disclosure |
| `/p/[proofId]` | `src/app/p/[proofId]/page.tsx` | Public Tear Sheet + 3-Tab Trader Coaching Studio (`Performance & GLM/PSR`, `Reconciliation & Diagnostics`, `Improve Your Trading & Catalysts`) |
| `/p/[proofId]/opengraph-image` | `src/app/p/[proofId]/opengraph-image.tsx` | Dynamic `1200x630` OpenGraph card rendering the 4-chip orthogonal assurance profile and Indexed-100 TWR with zero dollar NAV disclosure |
| `/verify` | `src/app/verify/page.tsx` | Offline drag-and-drop `.verify.json` bundle verifier, adversarial tamper testbench, and client-side selective leaf redaction tool |
| `/leaderboard` | `src/app/leaderboard/page.tsx` | Multi-filter track-record directory dynamically verified in-browser by origin floor, subaccount completeness, prospective chain continuity, and reconciliation status |
| `/.well-known/n170-verify-keys.json` | `src/app/.well-known/n170-verify-keys.json/route.ts` | Canonical publisher Ed25519 key registry, registered MPC-TLS notary ASNs/orgs, witness-cosigned C2SP `tlog-checkpoint`, and Base L2 (`chain_id=8453`) batch anchor |

## Zero-Dependency Browser & Node WebCrypto Verifier (`src/lib/browserVerify.ts`)

`src/lib/contracts.ts` and `src/lib/browserVerify.ts` use standard Web APIs (`crypto.subtle`, `TextEncoder`, `atob`/`btoa`) with **zero external runtime dependencies**, mirroring Wave-1 Python (`n170_verify.contracts` & `n170_verify.crypto`) byte-for-byte:

- **RFC 8785 JCS Canonicalization**: UTF-16 code-unit key sorting (`compareUtf16CodeUnits`) and ECMA-262 IEEE-754 shortest float serialization.
- **Salted 7-Leaf Merkle Selective Disclosure**: `n170.verify.leaf.Wave-4\x00` (`0x00`) leaf commitments with 256-bit salts and `n170.verify.node.Wave-4\x01` (`0x01`) internal nodes across `core_metrics`, `indexed_curve`, `reconciliation`, `coaching_and_context`, `capital_bracket`, `benchmark_alpha`, and `delayed_closed_trades`.
- **Domain-Separated Ed25519**: `crypto.subtle.verify("Ed25519", ...)` across `n170.verify.bundle.Wave-4`, `n170.verify.checkpoint.Wave-4`, `n170.verify.witness.Wave-4`, and `n170.verify.broker.Wave-4`.
- **Dynamic Origin Assurance**: Never trusts `claimed_origin_assurance`; solves for the maximum mutually org- and ASN-disjoint production TLSNotary (`tlsn-v0.1.0-alpha.15`) quorum within the skew window and enforces transcript secret/account-ID redaction safety.
- **5 Prospective Chain Invariants**: Verifies the 24-hour genesis enrollment window, monotonic `prev_proof_hash` linkage, immutable cadence policy, `blinded_account_tag` pinning, contiguous flow-adjusted index intervals, and C2SP transparency-log tail freshness.

## Verification & Development

Run the native Node.js WebCrypto + Python cross-language verification test suite (no `npm install` required on Node `>= 23.6` / `v25`):

```bash
node --test web/tests/browserVerify.test.ts
```

For local Next.js development in an online environment:

```bash
cd web
npm install
npm run dev
```

## License

Apache-2.0
