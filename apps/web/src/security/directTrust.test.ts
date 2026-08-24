import { describe, expect, it } from "vitest";
import { DirectTrustStore, type DirectTrustContext } from "./directTrust";

function context(generation = 7): DirectTrustContext {
  return {
    chatId: "dm_peer",
    peerUsername: "Peer",
    safetyNumber: "1234 5678 9012",
    verificationToken: "abyssal:verify:v1:test-token",
    sessionGeneration: 3,
    connectionGeneration: generation,
    localIdentity: Uint8Array.from({ length: 608 }, (_, index) => index < 64 ? 1 : 2),
    peerIdentity: Uint8Array.from({ length: 608 }, (_, index) => index < 64 ? 4 : 5),
  };
}

describe("DirectTrustStore", () => {
  it("requires exact confirmation and binds verification to complete identities and generation", () => {
    const store = new DirectTrustStore();
    const trusted = context();
    expect(store.markVerified(trusted, "abyssal:verify:v1:wrong-token")).toBe(false);
    expect(store.isVerified(trusted)).toBe(false);
    expect(store.markVerified(trusted, trusted.verificationToken)).toBe(true);
    expect(store.isVerified(trusted)).toBe(true);

    expect(store.isVerified({ ...context(8) })).toBe(false);
    expect(store.isVerified({ ...context(), sessionGeneration: 4 })).toBe(false);
    expect(store.isVerified({ ...context(), chatId: "dm_other" })).toBe(false);
    expect(store.isVerified({ ...context(), peerUsername: "Other" })).toBe(false);
    expect(store.isVerified({
      ...context(),
      localIdentity: Uint8Array.from({ length: 608 }, (_, index) => index < 64 ? 1 : 9),
    })).toBe(true);
    expect(store.isVerified({
      ...context(),
      peerIdentity: Uint8Array.from({ length: 608 }, (_, index) => index < 64 ? 4 : 9),
    })).toBe(true);
    expect(store.isVerified({
      ...context(),
      localIdentity: Uint8Array.from({ length: 608 }, (_, index) => index === 0 ? 9 : index < 64 ? 1 : 2),
    })).toBe(false);
    expect(store.isVerified({
      ...context(),
      peerIdentity: Uint8Array.from({ length: 608 }, (_, index) => index === 63 ? 9 : index < 64 ? 4 : 5),
    })).toBe(false);
  });

  it("preserves trust across prekey-only changes and clears all identity material", () => {
    const store = new DirectTrustStore();
    const trusted = context();
    expect(store.markVerified(trusted, trusted.verificationToken)).toBe(true);
    // Prekey rotation is intentionally absent from the trust context.
    expect(store.isVerified({ ...trusted })).toBe(true);
    store.clear();
    expect(store.isVerified(trusted)).toBe(false);
  });

  it("retains a bounded verification record for each direct peer", () => {
    const store = new DirectTrustStore();
    const first = context();
    expect(store.markVerified(first, first.verificationToken)).toBe(true);
    for (let index = 0; index < DirectTrustStore.MAX_PEERS; index += 1) {
      const peer = {
        ...first,
        chatId: `dm_peer_${index}`,
        peerUsername: `Peer${index}`,
      };
      expect(store.markVerified(peer, peer.verificationToken)).toBe(true);
    }
    expect(store.isVerified(first)).toBe(false);
    const newest = {
      ...first,
      chatId: `dm_peer_${DirectTrustStore.MAX_PEERS - 1}`,
      peerUsername: `Peer${DirectTrustStore.MAX_PEERS - 1}`,
    };
    expect(store.isVerified(newest)).toBe(true);
  });
});
