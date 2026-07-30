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

  it("accepts one trailing root slash", () => {
    const result = normalizeNodeUrl("wss://NODE.example.com/", "https:");
    expect(result.apiBaseUrl).toBe("https://node.example.com");
    expect(result.wsBaseUrl).toBe("wss://node.example.com");
  });

  it("rejects credentials, query values, and insecure remote nodes", () => {
    expect(() => normalizeNodeUrl("https://user:pass@example.com", "https:")).toThrow();
    expect(() => normalizeNodeUrl("https://example.com?token=value", "https:")).toThrow();
    expect(() => normalizeNodeUrl("http://192.0.2.10:4020", "https:")).toThrow();
  });

  it("allows loopback HTTP for local development", () => {
    expect(normalizeNodeUrl("http://127.0.0.1:4020", "https:").wsBaseUrl).toBe("ws://127.0.0.1:4020");
  });

  it("throws on empty input", () => {
    expect(() => normalizeNodeUrl("", "https:")).toThrow("Node URL required");
    expect(() => normalizeNodeUrl("   ", "https:")).toThrow("Node URL required");
  });

  it("allows IPv6 loopback", () => {
    const result = normalizeNodeUrl("http://[::1]:4020", "https:");
    expect(result.apiBaseUrl).toBe("http://[::1]:4020");
    expect(result.wsBaseUrl).toBe("ws://[::1]:4020");
  });

  it("preserves non-default ports", () => {
    const result = normalizeNodeUrl("example.com:8443", "https:");
    expect(result.apiBaseUrl).toBe("https://example.com:8443");
    expect(result.wsBaseUrl).toBe("wss://example.com:8443");
  });

  it("rejects hash fragments", () => {
    expect(() => normalizeNodeUrl("https://example.com#fragment", "https:")).toThrow();
  });

  it("rejects unsupported schemes", () => {
    expect(() => normalizeNodeUrl("ftp://example.com", "https:")).toThrow();
    expect(() => normalizeNodeUrl("file:///etc/passwd", "https:")).toThrow();
  });

  it("allows secure websocket schemes and rejects remote plaintext websocket", () => {
    expect(() => normalizeNodeUrl("ws://example.com:4020", "http:")).toThrow("Remote nodes require HTTPS");
    const wss = normalizeNodeUrl("wss://example.com:4443", "https:");
    expect(wss.apiBaseUrl).toBe("https://example.com:4443");
    expect(wss.wsBaseUrl).toBe("wss://example.com:4443");
  });

  it("rejects path-based route overrides", () => {
    expect(() => normalizeNodeUrl("example.com/a/b/c", "https:")).toThrow("Node URL must not include a path");
  });

  it("allows loopback from http page", () => {
    const result = normalizeNodeUrl("http://127.0.0.1:4020", "http:");
    expect(result.apiBaseUrl).toBe("http://127.0.0.1:4020");
  });

  it("rejects non-loopback HTTP even from an HTTP page", () => {
    expect(() => normalizeNodeUrl("http://example.com:4020", "http:")).toThrow("Remote nodes require HTTPS");
  });

  it("rejects non-loopback HTTP from https page", () => {
    expect(() => normalizeNodeUrl("http://10.0.0.1:4020", "https:")).toThrow();
  });

  it("lowercases host", () => {
    const result = normalizeNodeUrl("EXAMPLE.COM", "https:");
    expect(result.apiBaseUrl).toBe("https://example.com");
  });
});
