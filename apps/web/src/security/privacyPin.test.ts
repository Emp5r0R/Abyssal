import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  createPinVerifier,
  PrivacyPinGate,
  verifyPin,
  wipePinVerifier,
} from "./privacyPin";

const TEST_ITERATIONS = 1_000;

describe("privacy PIN verification", () => {
  it("requires at least six digits and distinct duress credentials", async () => {
    await expect(PrivacyPinGate.create("1234", "", { iterations: TEST_ITERATIONS }))
      .rejects.toThrow("Invalid PIN");
    await expect(PrivacyPinGate.create("123456", "123456", { iterations: TEST_ITERATIONS }))
      .rejects.toThrow("Invalid PIN");
  });

  it("verifies cover and duress PINs without retaining plaintext PIN state", async () => {
    const gate = await PrivacyPinGate.create("123456", "654321", {
      iterations: TEST_ITERATIONS,
      backoffMs: 1,
    });
    await expect(gate.verify("123456")).resolves.toBe("unlock");
    await expect(gate.verify("654321")).resolves.toBe("duress");
    gate.destroy();
    await expect(gate.verify("123456")).resolves.toBe("invalid");
  });

  it("serializes attempts and applies exponential backoff per gate", async () => {
    let now = 1_000;
    const gate = await PrivacyPinGate.create("123456", "", {
      iterations: TEST_ITERATIONS,
      backoffMs: 100,
      maxBackoffMs: 800,
      now: () => now,
    });
    const first = gate.verify("111111");
    const queued = gate.verify("123456");
    await expect(first).resolves.toBe("invalid");
    await expect(queued).resolves.toBe("blocked");
    now += 100;
    await expect(gate.verify("123456")).resolves.toBe("unlock");
    gate.destroy();
  });

  it("wipes mutable verifier arrays and compares every byte", async () => {
    const verifier = await createPinVerifier("123456", TEST_ITERATIONS);
    expect(await verifyPin(verifier, "123456")).toBe(true);
    expect(await verifyPin(verifier, "123457")).toBe(false);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1]))).toBe(false);
    wipePinVerifier(verifier);
    expect([...verifier.salt, ...verifier.digest, verifier.iterations].every((value) => value === 0)).toBe(true);
  });
});
