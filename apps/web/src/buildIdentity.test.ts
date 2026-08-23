import { describe, expect, it } from "vitest";
import { currentBuildAttestation, RELEASE_BUILD_IDENTITY } from "./buildIdentity";

describe("release build identity", () => {
  it("uses a fail-closed unconfigured identity outside release packaging", () => {
    expect(RELEASE_BUILD_IDENTITY).toEqual({
      buildId: "web@0.0.0",
      buildSignatureB64: "",
      sourceCommit: "0000000000000000000000000000000000000000",
      configured: false,
    });
    expect(Object.isFrozen(RELEASE_BUILD_IDENTITY)).toBe(true);
    expect(currentBuildAttestation()).toEqual({
      platform: "web",
      version: "0.0.0",
      build_signature_b64: "",
    });
  });
});
