# Security & Privacy Audit — applesauce

**Target:** `mptfire/applesauce` (fork of `hzrd149/applesauce`), branch `fix/nip46-pairing-secret` @ `ab42e42` (includes upstream master @ `c2cee99`)
**Date:** 2026-10-14
**Scope:** All 14 published packages (~61k LOC TS), apps (docs, examples, llms), scripts, dependencies. Static review + local test execution. No dynamic testing against live relays.
**Method:** Manual review of crypto/signer/gift-wrap paths; two exhaustive sweeps (network egress, storage/persistence); dependency audit; independent reproduction of PR #97's test claims (all 53 signer tests pass on the branch; exactly the 2 regression tests fail on unpatched master — verified locally in both directions).

---

## Executive summary

The cryptographic primitives are sound (delegated to `nostr-tools`/`@noble`), there is **no telemetry or analytics anywhere**, and the code under review is generally careful — several files carry unusually rigorous inline security reasoning. The two systemic problems are:

1. **A pattern of plaintext secrets at rest**, taught by the docs and implemented in the defaults (identity private keys, bunker pairing secrets, Cashu bearer tokens, NIP-47 wallet secrets, Concord channel keys).
2. **Verification escape hatches and integrity gaps** in the event-authentication layer: a global, publicly-swappable verifier hook (`setVerifyWrappedEventMethod` + exported `fakeVerifyEvent`), a weak `isEvent` type guard, and rumor IDs that are never checked against their contents.

Seven previously-reported upstream security issues (#58–#63, #96) were re-verified against this branch — **all are still present**. The NIP-46 pairing bypass fixed by PR #97 is real, correctly fixed, and independently regression-proven.

Overall risk: **Medium-High** for downstream client apps that follow the documented patterns; the library itself does not phone home and its E2E crypto is solid.

---

## Findings

### HIGH

**H1 — NIP-46 pairing bypass (FIXED by PR #97)**
`packages/signers/src/signers/nostr-connect-signer.ts:226`
On master, an unpaired client accepted `result: "ack"` (or any result when a secret was configured) from *any* signed kind-24133 event, pinning the sender as its remote bunker. An attacker knowing only the client's public key (public on relays) could hijack the signing channel: receive all subsequent `sign_event` / decrypt requests, and MITM or starve the real session.
*Fix verified:* requires exact `connectSecret` match with no `error`, and preserves `ack` for an already-pinned bunker (bunker-initiated flow unaffected — `remote` is pre-pinned there, and `wallet-connect`'s analogous path was checked and is safe: responses are pinned to the service pubkey at `packages/wallet-connect/src/wallet-connect.ts:214-228`).
*Tests independently reproduced:* 2/6 pairing tests fail on master; 53/53 signer tests pass on the branch.
*Compat note:* non-compliant bunkers replying bare `"ack"` to client-initiated connect will no longer pair. Per NIP-46 §direct-connection-initiated-by-the-client, echoing the secret is the specified behavior.

**H2 — Plaintext long-lived secrets at rest, by documented default** (systemic)
- `PrivateKeyAccount.toJSON()` emits the **raw identity private key hex** (`packages/accounts/src/accounts/private-key-account.ts:19-23`); docs instruct saving `manager.toJSON()` to localStorage with **no security warning** (`apps/docs/apps/accounts/manager.md:80-98`), and the examples app does exactly that (`apps/examples/src/components/login-view.tsx:46-87`, key `accounts`).
- **`nbunksec` is unencrypted** despite the name: plain bech32 TLV containing the **client private key + bunker pairing secret** (`packages/signers/src/helpers/nbunksec.ts:25-99`). Any reader of the string fully controls the NIP-46 session channel. Documented as "treat it like a secret" (`apps/docs/creating/signers/nostr-connect.md:176`) — but no encrypted variant exists.
- **Cashu bearer tokens in plaintext**: localStorage key `applesauce:couch:tokens` (`packages/wallet/src/helpers/local-storage-couch.ts:33-46`) and IndexedDB `applesauce-wallet-couch/tokens` (`packages/wallet/src/helpers/indexed-db-couch.ts:71-97`). Whoever reads the storage steals the money.
- **Decrypted NIP-60 wallet content cache** default pattern writes raw Cashu proofs to plaintext storage (`packages/wallet/src/wallet/nut-wallet.ts:497-519`; docs admit it: `apps/docs/money/wallet/nut-wallet.md:117`).
- **NIP-47 spending secret** serialized plaintext: `WalletConnect.toJSON()` (`packages/wallet-connect/src/wallet-connect.ts:588-597`); example persists to `localStorage["wallet-connect"]`.
- **Concord channel keys**: `saveMirror` writes community `JoinMaterial` (owner_salt, community_root, hex channel decryption keys) to **plaintext** localStorage keyed by user pubkey (`packages/concord/src/client/client.ts:1029-1042`), via `defaultStorage()` raw localStorage passthrough (`client/storage.ts:55-64`). The relay-side copy is NIP-44-encrypted; the local mirror is not.
- Only `PasswordAccount` (NIP-49 `ncryptsec`) encrypts at rest. No encrypted-storage helper is exported from any package (a weak AES-CBC example with a hardcoded salt exists only in the examples app, `apps/examples/src/extra/encrypted-storage.tsx:7-9`).

### MEDIUM

**M1 — Global verifier swap + exported `fakeVerifyEvent`** (upstream #62)
`packages/core/src/helpers/event.ts:165-181`. `setVerifyWrappedEventMethod()` replaces the function used for **all** seal/gift-wrap/zap verification repo-wide; `fakeVerifyEvent()` marks any event verified without checks. Both are public API with no guardrails. No in-repo caller swaps it (verified), but one dependency or app call silently disables signature verification everywhere. Recommend removing `fakeVerifyEvent` from the public export or gating the hook.

**M2 — `isEvent()` accepts malformed events** (upstream #60)
`packages/core/src/helpers/event.ts:99-112`. Shape-only check: `id`/`pubkey` need only be 64 chars (any bytes, not hex), hash and signature never checked. Used as gate in `notifyEventUpdate` and elsewhere.

**M3 — Rumor ID never verified against contents** (upstream #96)
`packages/common/src/helpers/gift-wrap.ts:182-226` and `packages/concord/src/helpers/gift-wrap.ts:70-82`. After decrypting a seal, the code checks the seal's signature and the rumor↔seal author binding, but never recomputes the rumor hash (`verifyRumor` exists at `core/helpers/event.ts:70` and is unused here). The attacker-controlled `rumor.id` is additionally used as a **store lookup key** (`internalGiftWrapEvents.getEvent(rumor.id)` — `common/gift-wrap.ts:200-202`), so a crafted wrap can collide with an existing rumor's identity, corrupting dedupe/reply/deletion logic that trusts IDs. Fix is two lines per path.

**M4 — Unbounded regex from muted words** (upstream #63)
`packages/common/src/helpers/mute.ts:112-118, 142-144`. Words *are* escaped (no ReDoS injection), but the regex is rebuilt from the full mute list for **every event tested** with no count/length cap; large mute lists make timeline rendering O(events × words). Cache the compiled regex and cap input.

**M5 — Hardcoded third-party destinations as library defaults**
- `packages/concord/src/helpers/invite-bundle.ts:40-46`: `STOCK_RELAYS` (jskitty.com, vectorapp.io, relay.ditto.pub, relay.dreamith.to) become the default relays for `ConcordClient`/community engines when `relays` is omitted (`client.ts:348`, `community.ts:363`) — all community traffic, including NIP-42 auth events with the user pubkey, flows to four third parties by default.
- `packages/extra/src/vertex.ts:7,34-47`: default `wss://relay.vertexlab.io`, **auto-authenticates as the user** on challenge; `userSearch()` publishes the user's query + pubkey as a public signed event.
- `packages/extra/src/primal.ts:6,248-259`: default `wss://cache2.primal.net/v1`; sends pubkeys, search queries, media URLs, and full events to Primal.
- `packages/extra/src/open-ranking.ts:8,92-188`: default provider `https://staging.brainstorm.world`; with a signer attached, every search carries a signed Nostr Web Token cryptographically binding query → identity.
These are opt-out-able but default-on. Privacy-sensitive defaults should be explicit.

**M6 — NIP-05 identity loader fetches event-chosen domains**
`packages/loaders/src/loaders/dns-identity-loader.ts:34`. Domain comes from markers inside any processed event content; rendering user content can trigger identity-probing fetches to arbitrary servers (viewer IP + interest leak). Standard NIP-05 behavior, but loaders make it automatic; apps should be able to allowlist.

### LOW

- **L1 — Negentropy varint overflow** (upstream #59): `packages/relay/src/lib/negentropy.ts:66-94` uses 32-bit `<<`/`>>>`; long varints from a malicious relay wrap silently. Bounded loop, no memory growth — correctness issue, limited DoS.
- **L2 — Secrets in debug logs**: `nostr-connect-signer.ts:283` logs full request params (includes the **bunker pairing secret** in `connect`; plaintext in `nip44_encrypt`); `:239,253` log decrypted responses (DM plaintext). `debug` is off by default, but `localStorage.debug=applesauce*` turns it on. Redact sensitive params.
- **L3 — Request map leak / no timeouts**: `nostr-connect-signer.ts:285-286` defers are never deleted from `this.requests` and have no timeout; long sessions leak and stale requests hang forever.
- **L4 — `switch_relays` redirect**: remote signer can move the client to arbitrary relays with only `typeof === "string"` validation (`nostr-connect-signer.ts:438-462`).
- **L5 — NIP-04 fallback** still accepted on the NIP-46 channel (`:218-219`); legacy crypto with known weaknesses.
- **L6 — Amber clipboard signer** routes DM plaintext and drafts through the system clipboard/Android intents (`packages/signers/src/signers/amber-clipboard-signer.ts:124-173`). Inherent to Amber's API; document it.
- **L7 — `close()` does not reset `this.remote`** (`:186-203`): a reused signer instance stays pinned to its old bunker.
- **L8 — Example-app patterns worth not cargo-culting**: default Blossom upload to `blossom.primal.net` (`apps/examples/src/examples/notes/composing.tsx:45`), zap request in URL query string (`zap-modal.tsx:260-264`, lands in server logs), plaintext `nwc-service:<pubkey>` localStorage (`admin.tsx:101-115`).
- **L9 — Repo hygiene**: no `SECURITY.md`, no root `LICENSE` file (MIT declared only in package.json — GitHub shows "no license").
- **L10 — Weak reference encryption example**: hardcoded shared salt, AES-CBC, no MAC (`apps/examples/src/extra/encrypted-storage.tsx`).

---

## Verified status of upstream security issues

| Issue | Claim | Verified on this branch | Location |
|---|---|---|---|
| #58 | Seal signature verification bypass via verifier hook | Present (mechanism) | `core/helpers/event.ts:165-181` + all `verifyWrappedEvent` sites |
| #59 | Negentropy varint 32-bit overflow | Present | `relay/src/lib/negentropy.ts:66-94` |
| #60 | `isEvent` weak validation | Present | `core/helpers/event.ts:99-112` |
| #61 | Missing timeouts/size limits on fetches | Present (no fetch wrapper; NIP-05/LNURL/NIP-11 unbounded) | e.g. `loaders/src/loaders/dns-identity-loader.ts:34` |
| #62 | `fakeVerifyEvent` public API enables bypass | Present | `core/helpers/event.ts:178-181` |
| #63 | Unbounded muted-words regex | Present | `common/src/helpers/mute.ts:112-118` |
| #96 | Rumor id never checked against contents | Present (both paths, incl. id-as-lookup-key) | `common/gift-wrap.ts:200-202`, `concord/gift-wrap.ts:70-82` |

---

## Privacy review

**Telemetry: none.** Exhaustive sweep found no analytics, error-reporting, version-ping, or `sendBeacon` in any package or app. The docs site (VitePress) is clean (local search, no CDN/analytics); fonts self-hosted. Only doc-site egress: the "copy page" button can fetch from `raw.githubusercontent.com` on click.

**What does leave the device (by protocol design):**
- Relay connections expose IP + subscription filters (reading patterns) and publishes; relay selection is app-controlled (no default relay list in `applesauce-relay` itself — see M5 for packages that do have defaults).
- **NIP-46 metadata is public**: kind-24133 events are published unwrapped (sender `p`-tagged, both pubkeys visible to relays). NIP-46 recommends gift-wrapping; this implementation doesn't. Wire content is NIP-44 E2E.
- NIP-05 resolution (`name@domain` → arbitrary domain fetch), NIP-42 (opt-in relay auth), NIP-98 (opt-in management/ranking tokens — identity-bound).
- Event-content-driven destinations: relay hints (kind 10002), Cashu mint URLs (NIP-60 wallet event), Blossom server hints (kind 10063 / `blossom:` URIs) — a malicious event can direct the client to contact attacker servers (expected per the NIPs, but unvalidated beyond URL shape).
- Secrets never travel in URLs on the NIP-46 path (URIs containing secrets are shared out-of-band by design); LNURL zap callbacks carry the sender pubkey in the query string (protocol standard).

**Data at rest:** see H2. Nothing user-owned is persisted by library code unless the app supplies a store; where the library supplies defaults (concord mirror, wallet couch), they are plaintext.

---

## Dependencies

`pnpm audit`: **47 advisories (25 high, 20 moderate, 2 low, 0 critical)**.
- Published packages have lean runtime deps (`nostr-tools`, `@noble/*`, `@scure/base`, `rxjs`, `nanoid`, `debug`, `hash-sum`, `light-bolt11-decoder`, remark/unified, `@cashu/cashu-ts`). Only runtime-relevant advisory: `nanoid` (custom-generator infinite loop; not reachable via normal `nanoid()` usage). **No known-vulnerable runtime crypto deps.**
- All high-severity hits are dev/app tooling: `vite` (fs.deny bypass), `react-router` (RSC CSRF — also upstream PR #92), `prosemirror-view`/`@tiptap` (XSS/ReDoS, examples), `brace-expansion`/`braces`/`fast-uri`/`js-yaml`/`source-map-js` (build chain).
- Recommended: lockfile bump for the build chain; add Renovate/dependabot group updates.

---

## PR #97 assessment

**Approve.** Minimal, correct, and independently verified:
- Requires exact `connectSecret` match + no error before pinning a remote; preserves `ack` for pinned bunkers (bunker-initiated flow unaffected).
- New suite uses real signatures + NIP-44; **locally reproduced both claims**: all 53 signer tests pass on the branch; on unpatched master exactly the 2 regression tests fail.
- Proper patch changeset (`applesauce-signers`).
- Only caveat: the compat tradeoff noted in H1 (non-compliant "ack" bunkers), which matches the NIP.

## Recommendations (priority order)

1. Land PR #97 upstream (awaiting maintainer CI approval — one click on their side).
2. Fix M3 (rumor-id verification — 2 lines per path), M1 (retire/guard `fakeVerifyEvent`), M2 (harden `isEvent`), M4 (cache + cap mute regex), L1 (varint bound) — all small, all already tracked upstream.
3. Elevate the at-rest story: export an encrypted-storage helper from a package, encrypt `nbunksec` (NIP-49-style) or rename it to stop implying "sec", add security warnings to the accounts-serialization docs, and redact secrets from debug logs (L2).
4. Make M5 defaults opt-in (concord `STOCK_RELAYS`, Vertex auto-auth, Primal/OpenRanking defaults) or emit a console warning when used unset.
5. Repo hygiene: add `SECURITY.md` and a root `LICENSE`.
