# applesauce v7.1.0 — security review of the new surfaces

**Commit:** `a294534c` (v7.1.0 release) · **Date:** 2026-11-09
**Scope:** Kehto napplet host (`packages/extra/src/kehto`, ~5k lines plus the pinned `@kehto/*` runtime deps), the messaging stack (`GiftWrapReceiver`, `WrappedMessagesClient`, `LegacyMessagesClient`, `NdrMessagesClient`, about 9k lines), and encrypted file attachments (`encrypted-file.ts`, `attachments.ts`).
**Method:** code review plus proof-of-concept tests run against the release code. Each finding below says how it was verified.

## Verdict

**The messaging stack is solid. The napplet host is not ready for untrusted napplets with its defaults.**

- Messaging: no critical or high findings. NIP-59 unwrap order, sender binding, error isolation, recipient-scoped encryption and timestamp randomization were all confirmed with PoC tests.
- Encrypted attachments: the cryptography is sound. Two handling gaps in `loadAttachment`.
- Kehto host: consent and DM decryption are **on by default**, so a third-party napplet can sign and read as the user unless the app opts in to prompts. Separately, the browser host's startup handshake does not complete with the shipped dependency versions.

## Findings

| ID | Sev | Area | Finding | Verified |
|---|---|---|---|---|
| K1 | **High** | Kehto | Signing is fail-open: `approve` is optional and "signing is allowed when omitted" (`types.ts:42`, `foundation/signer.ts:31`). The same pattern runs through outbox, lists, DM, actions and upload services. The ACL default is `permissive`. A napplet can sign deletions, follow-list changes, DMs and posts with no prompt | PoC 8/8, re-run by me |
| K2 | **High** | Kehto | DMs are decrypted for napplets by default: `decrypt` is only off when set to `false` (`foundation/encryption.ts:44`). A napplet with default `relay:read` can query kind 4 and receive plaintext. The DM service exposes full history under the permissive `dm:read` grant | PoC for the decrypt step; delivery path code-read |
| K3 | **High** (functional) | Kehto | The browser host never becomes ready. `host/index.ts:55` waits for a window-level `shell.ready`, but `@kehto/shell@0.32.0` delivers it over the MessagePort. Every napplet is destroyed after `readyTimeout` | **Reproduced**: 5/12 of the repo's own `host.browser.test.ts` fail with "Napplet initialization timed out"; browser tests are excluded from CI |
| K4 | Medium | Kehto | Napplets choose relays: `m.relay` and `options.relays` are passed straight to the host pool, so a napplet can make the host connect and publish to attacker relays. This leaks identity if the app auto-answers NIP-42 | PoC; the auth escalation depends on app config, unverified |
| K5 | Medium (conditional) | Kehto | Resource service fetches any `https:` URL for a napplet. The only guard is a regex on the literal hostname, so DNS-to-private and redirects are not re-checked. Blossom `xs` hints accept `http://` | Code-read |
| K6 | Low | Kehto | No per-window subscription cap; the sustained rate limit only flags (60 REQ/min indefinitely) | Code-read |
| K7 | Low | Kehto | `intent.deliver` posts with targetOrigin `"*"` (unavoidable for opaque frames); small race during navigation | Code-read |
| M1 | Medium | Messaging | One invalid row in `processingStore` makes `restore()` throw. Five entry points await it, so receiving, unlocking and reading all stop until the app clears the store. Triggers include a truncated write after a crash or a future `version: 2` | Code verified by me |
| M2 | Low | Messaging | Processing checkpoints are trusted as ground truth: a forged `failed` record silently skips a message; a forged `completed` record re-attributes an envelope. Requires write access to the app store | PoC |
| M3 | Low | Messaging | Legacy NIP-04 decryption cache is keyed by event id only, with no ciphertext binding, so a forged cache entry can impersonate a correspondent. Gift-wrap restores are safe because they are re-verified | Code-read |
| M4 | Low | Messaging | Unbounded failure state per hostile envelope (memory and durable rows) | Code-read |
| M5 | Low | Messaging | NDR `removeMember` rotates the sender key via `manager?.rotateSenderKey(...)`. If the group manager isn't ready, rotation is silently skipped and the removed member keeps reading | Code verified by me; reachability unverified |
| A1 | Medium | Attachments | `loadAttachment` downloads with no size cap and ignores the declared size. Any NIP-17 correspondent can make a client fetch gigabytes; the examples load attachments automatically on render | PoC (32 MiB served for a declared 10 bytes) |
| A2 | Low | Attachments | The returned Blob carries the sender-declared MIME type (`text/html` with the script intact). The examples are safe (inline only for image/video/audio, else a download link); apps that open the blob are not | PoC |
| I1 | Info | Messaging | Plaintext at rest: drafts, decryption caches and NDR history/ratchet state go into app storage unencrypted. The library documents this but doesn't enforce encryption. Single-writer is enforced only via Web Locks in browsers | Code-read |
| I2 | Info | Messaging | NDR `approveLink` registers the inviter from an unauthenticated link URL; approval is the trust decision, so the UI must show the device identity | Code-read |

## Checked and safe

- **NIP-59 unwrap**: the seal signature is verified before it is used as a lookup key; the rumor id is recomputed before any cache use; author binding `rumor.pubkey === seal.pubkey`; kind checks; hostile envelopes return `undefined` instead of throwing. PoC-confirmed: spoofed author, tampered id, forged seal and id-collision reuse are all rejected.
- **Error isolation**: a garbage-seal wrap between two good wraps leaves both good ones stored and the stream alive (PoC).
- **Sending**: one wrap per participant plus a self-copy, each decryptable only by its recipient; NIP-59 timestamp randomization on seal and wrap; no NIP-17 to NIP-04 downgrade path (PoC).
- **Relay auth (messaging)**: challenges are answered on the same connection and are user-gated; `autoAuth` defaults to false.
- **NDR device authorization**: sessions install only for devices in the owner-signed roster; nothing self-registers.
- **Kehto isolation**: `sandbox="allow-scripts"` only (opaque origin), `srcdoc` loading, strict CSP (`default-src 'none'`, `connect-src 'none'`), manifest signature plus artifact sha256 verified, and the verified bytes are exactly what runs (no re-fetch). postMessage is bound by `event.source` with per-instance MessagePorts, so cross-napplet forgery isn't possible. The CVM service signs with an ephemeral key, never the account.
- **Encrypted files**: AES-256-GCM with a fresh random key and 96-bit nonce per file (so no nonce reuse), ciphertext hash checked before decryption and plaintext hash after, GCM authentication on top.

## Tests

- `common` 904/904, `extra` 742/743 (1 skipped), `signers` 93/93 on the node suite.
- `host.browser.test.ts` (chromium, not run in CI): **7/12 pass, 5 fail** (K3).
- PoC files (untracked, branch `review/v7.1` in `applesauce-audit/`):
  - `packages/extra/src/kehto/foundation/__tests__/consent-defaults.audit-poc.test.ts` (8/8)
  - `packages/extra/src/kehto/host/__tests__/iframe-isolation.audit-poc.test.ts` (4/4, chromium; config `vitest.audit-poc.config.mts`)
  - `packages/extra/src/gift-wrap/__tests__/security.audit-poc.test.ts` (9/9)
  - `packages/extra/src/messages/common/attachments.audit-poc.test.ts` (3/3)

## Not covered

- `nostr-double-ratchet` internals (external, ~15k lines): only the trust boundaries the wrapper relies on were checked.
- End-to-end napplet-to-plaintext-DM delivery through a live port (each stage was verified separately).
- Whether typical apps auto-answer NIP-42 on their pool, which would escalate K4.

## Proposed upstream work — status (updated 2026-11-12)

| Proposal | Type | Status |
|---|---|---|
| Fix the Kehto ready handshake (K3) + browser suite in CI | — | **Fixed upstream** in 3a976991 (verified: browser suite 23/23 on master) |
| `loadAttachment` size cap + active-MIME guard (A1, A2) | PR | **#111 MERGED**, released in 7.2.0 |
| `GiftWrapReceiver.restore` quarantine (M1) | PR | **#109 MERGED**, released in 7.2.0 |
| NDR `removeMember` waits for group manager (M5) | PR | **#110 OPEN** — maintainer traced the flow and disputes reachability; reworded to immediacy-only, awaiting decision |
| Kehto fail-closed defaults (K1, K2, K4) | Issue + PR | Signing fail-closed **fixed upstream** (e466d74f, refs [#112](https://github.com/hzrd149/applesauce/issues/112)); decryption opt-in + relay-hint gate in **#119 MERGED** (120788b); the `m.relay` runtime path is tracked in kehto/web[#435](https://github.com/kehto/web/issues/435) |
| M2/M3 checkpoint + cache binding | Issue | Design posted on [#114](https://github.com/hzrd149/applesauce/issues/114): device-local HMAC key, tagged checkpoint rows, ciphertext-hash-bound cache entries; awaiting go-ahead |
| Resource service hardening (K5) | — | **Fixed upstream** in e40eadc4 (HTTPS-required fetchServer, expanded host regex incl. CGNAT/`.localhost`, `redirect: "error"`, `allowHost` hook) |

## Upstream status (2026-11-09)

- **K3 fixed upstream** in 3a976991 (MessagePort readiness): Kehto browser suite 23/23 on master. No PR needed.
- **K7 fixed upstream** in the same commit: `intent.deliver` now goes through `postToNapplet` with an `instanceDestroyed` check instead of `postMessage(..., "*")`.
- **New finding while verifying K5:** `fetchBlossom` never checks `xs` hint servers against `PRIVATE_HOST` and accepts `http://` hints, so a napplet can make the host send blind GETs to loopback/LAN addresses (bodies are hash-verified, so no content injection). Included in #113.
- **PRs:** #109 (M1, checkpoint restore), #110 (M5, NDR rotation, red→green), #111 (A1+A2, attachment limits and type downgrade, two commits).
- **Issues:** #112 (K1, K2, K4 defaults), #113 (K5 + Blossom hints), #114 (M2, M3, M4).
