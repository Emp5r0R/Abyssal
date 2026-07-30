import type { NodeEndpoint } from "../domain/types";

const SUPPORTED = new Set(["http:", "https:", "ws:", "wss:"]);

export function normalizeNodeUrl(input: string, pageProtocol = window.location.protocol): NodeEndpoint {
  void pageProtocol;
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Node URL required");

  const withScheme = trimmed.includes("://") ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  if (!SUPPORTED.has(url.protocol)) throw new Error("Unsupported node scheme");
  if (url.username || url.password || url.search || url.hash) throw new Error("Unsafe node URL");

  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  const apiProtocol = url.protocol === "ws:" ? "http:" : url.protocol === "wss:" ? "https:" : url.protocol;
  if (apiProtocol !== "https:" && !loopback) {
    throw new Error("Remote nodes require HTTPS");
  }
  if (url.pathname !== "/" && url.pathname !== "") throw new Error("Node URL must not include a path");

  const wsProtocol = apiProtocol === "https:" ? "wss:" : "ws:";
  const authority = url.host.toLowerCase();
  return {
    apiBaseUrl: `${apiProtocol}//${authority}`,
    wsBaseUrl: `${wsProtocol}//${authority}`,
    displayHost: authority,
  };
}
