// AUDIT PoC (v7.1.0 security review) — run against the vulnerable tree (a294534c).
// These demonstrate the fail-open defaults behind PR #119. On the fixed tree they FAIL,
// which is the desired outcome.
import { EventStore } from "applesauce-core";
import { finalizeEvent, kinds, unixNow } from "applesauce-core/helpers";
import { getPublicKey, generateSecretKey } from "applesauce-core/helpers/keys";
import type { RelayPool } from "applesauce-relay";
import { PrivateKeySigner } from "applesauce-signers";
import { firstValueFrom, Subject } from "rxjs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { KehtoContext } from "../../types.js";
import { createKehtoSigner } from "../../foundation/signer.js";
import { decryptForNapplet } from "../../foundation/encryption.js";

const alice = new PrivateKeySigner(new Uint8Array(32).fill(1));
const bob = new PrivateKeySigner(new Uint8Array(32).fill(2));
const pk = (s: PrivateKeySigner) => getPublicKey(s.key);

/** A fake pool whose req() messages are pushed by the test */
function fakePool() {
  const req$ = new Subject<any>();
  return {
    req$,
    req: vi.fn(() => req$),
    request: vi.fn(),
    publish: vi.fn(async (relays: string[]) => relays.map((from) => ({ from, ok: true }))),
    count: vi.fn(),
  };
}

let store: EventStore;
let pool: ReturnType<typeof fakePool>;
const create = (ctx: Partial<KehtoContext> = {}): KehtoContext => ({
  pool: pool as unknown as RelayPool,
  eventStore: store,
  ...ctx,
});

beforeEach(() => {
  store = new EventStore({ verifyEvent: () => true });
  pool = fakePool();
});

describe("consent defaults (v7.1.0 audit)", () => {
  // A napplet can sign a deletion (or anything else) with no approval callback configured
  it("signs arbitrary events without prompting when approve is omitted", async () => {
    const state = create({ signer: alice });
    const signer = createKehtoSigner(alice, state);

    const signed = await signer.signEvent!({
      kind: 5,
      tags: [["e", "e".repeat(64)]],
      content: "",
      created_at: unixNow(),
    });
    expect(signed.kind).toBe(5);
  });

  it("honors a host deny callback, but only when the host supplies one (the option is opt-in)", async () => {
    // The consent mechanism exists but is fail-open: omitting `approve` allows every signature,
    // which is the default state any minimal integration ships with.
    const state = create({ signer: alice, approve: () => false });
    const signer = createKehtoSigner(alice, state);
    await expect(
      signer.signEvent!({ kind: 1, tags: [], content: "x", created_at: unixNow() }),
    ).rejects.toThrow("User denied");
  });

  it("decrypts a NIP-04 DM for napplets without any opt-in", async () => {
    const plaintext = "plaintext dm body";
    const ciphertext = await alice.nip04.encrypt(pk(bob), plaintext);
    const event = finalizeEvent(
      { kind: kinds.EncryptedDirectMessage, content: ciphertext, tags: [["p", pk(bob)]], created_at: unixNow() },
      alice.key,
    );

    // No decrypt: false — the v7.1.0 default decrypts for the napplet
    const state = create({ signer: bob });
    const result = await decryptForNapplet(state, event);
    expect(result.content).toBe(plaintext);
  });
});
