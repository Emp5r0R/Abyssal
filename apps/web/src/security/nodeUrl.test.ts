import { describe, expect, it } from "vitest";
import { normalizeNodeUrl } from "./nodeUrl";

describe("normalizeNodeUrl", () => {
  it("defaults to HTTPS and derives WSS", () => {
    expect(normalizeNodeUrl("abyssal.example.com", "https:")).toEqual({
      apiBaseUrl: "https://abyssal.example.com",
      wsBaseUrl: "wss://abyssal.example.com",
      displayHost: "abyssal.example.com",
    });
  });

  it("keeps a safe path and strips trailing slashes", () => {
    const result = normalizeNodeUrl("wss://NODE.example.com/relay///", "https:");
    expect(result.apiBaseUrl).toBe("https://node.example.com/relay");
    expect(result.wsBaseUrl).toBe("wss://node.example.com/relay");
  });

  it("rejects credentials, query values, and insecure remote nodes", () => {
    expect(() => normalizeNodeUrl("https://user:pass@example.com", "https:")).toThrow();
    expect(() => normalizeNodeUrl("https://example.com?token=value", "https:")).toThrow();
    expect(() => normalizeNodeUrl("http://192.0.2.10:4020", "https:")).toThrow();
  });

  it("allows loopback HTTP for local development", () => {
    expect(normalizeNodeUrl("http://127.0.0.1:4020", "https:").wsBaseUrl).toBe("ws://127.0.0.1:4020");
  });
});

