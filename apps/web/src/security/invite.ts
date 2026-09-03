import {
  parseInviteCapsule as rustParseInviteCapsule,
  verifyInviteNodeDescriptor as rustVerifyInviteNodeDescriptor,
} from "../generated/abyssal_core/abyssal_core";
import type { NodeEndpoint } from "../domain/types";
import { normalizeNodeUrl } from "./nodeUrl";
import { initializeSecurityRuntime } from "./runtime";

const MAX_NODE_DESCRIPTOR_BYTES = 1024;
const BYTE_VALUES = 256;

interface RustParsedInvite {
  node_id: unknown;
  node_public_key: unknown;
  node_url: unknown;
  capability: unknown;
  account_context: unknown;
  expires_at: unknown;
}

export interface ParsedInvite {
  nodeId: string;
  nodePublicKey: Uint8Array;
  endpoint: NodeEndpoint;
  capability: Uint8Array;
  accountContext: Uint8Array;
  expiresAt?: number;
}

export async function parseInvite(input: string, now = Date.now()): Promise<ParsedInvite> {
  await initializeSecurityRuntime();
  const allowDevelopment = isExplicitDevelopmentOrigin(window.location);
  const raw = rustParseInviteCapsule(
    input,
    BigInt(Math.floor(now / 1000)),
    allowDevelopment,
  ) as RustParsedInvite;
  const nodeId = strictString(raw.node_id, 128);
  const nodeUrl = strictString(raw.node_url, 512);
  const nodePublicKey = strictBytes(raw.node_public_key, 32);
  const capability = strictBytes(raw.capability, 32);
  const accountContext = strictBytes(raw.account_context, 32);
  const expiresAt = raw.expires_at === null
    ? undefined
    : strictSafeInteger(raw.expires_at);
  try {
    return {
      nodeId,
      nodePublicKey,
      endpoint: normalizeNodeUrl(nodeUrl),
      capability,
      accountContext,
      expiresAt,
    };
  } catch (error) {
    nodePublicKey.fill(0);
    capability.fill(0);
    accountContext.fill(0);
    throw error;
  }
}

export async function verifyConnectedInviteNode(
  invite: ParsedInvite,
  signal: AbortSignal,
  runtimeLocation: Pick<Location, "hostname" | "origin" | "protocol"> = window.location,
): Promise<void> {
  enforceBrowserLocatorPolicy(invite.endpoint, runtimeLocation);
  let response: Response;
  try {
    response = await fetch(`${invite.endpoint.apiBaseUrl}/v1/node`, {
      method: "GET",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Accept: "application/cbor" },
      signal,
    });
  } catch (error) {
    if (signal.aborted) throw error;
    throw new Error("Unable to reach node", { cause: error });
  }
  if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0] !== "application/cbor") {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("Unable to verify node");
  }
  const descriptor = await readBoundedBytes(response, MAX_NODE_DESCRIPTOR_BYTES, signal);
  try {
    rustVerifyInviteNodeDescriptor(
      descriptor,
      invite.nodePublicKey,
      invite.endpoint.apiBaseUrl,
    );
  } finally {
    descriptor.fill(0);
  }
}

export function wipeParsedInvite(invite: ParsedInvite | null | undefined): void {
  invite?.capability.fill(0);
  invite?.accountContext.fill(0);
  invite?.nodePublicKey.fill(0);
}

function isExplicitDevelopmentOrigin(location: Pick<Location, "hostname" | "protocol">): boolean {
  return location.protocol === "http:" &&
    ["localhost", "127.0.0.1", "::1", "[::1]"].includes(location.hostname);
}

function enforceBrowserLocatorPolicy(
  endpoint: NodeEndpoint,
  location: Pick<Location, "hostname" | "origin" | "protocol">,
): void {
  if (location.protocol === "https:") {
    const expected = normalizeNodeUrl(location.origin).apiBaseUrl;
    if (endpoint.apiBaseUrl !== expected) throw new Error("Node identity mismatch");
    return;
  }
  if (!isExplicitDevelopmentOrigin(location)) {
    throw new Error("Unsupported transport");
  }
  const host = new URL(endpoint.apiBaseUrl).hostname;
  if (!["localhost", "127.0.0.1", "[::1]", "10.0.2.2"].includes(host)) {
    throw new Error("Unsupported transport");
  }
}

async function readBoundedBytes(
  response: Response,
  maximum: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("Node descriptor rejected");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Node descriptor rejected");
  const output = new Uint8Array(maximum);
  let offset = 0;
  try {
    while (true) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const { done, value } = await reader.read();
      if (done) break;
      if (offset + value.byteLength > maximum) throw new Error("Node descriptor rejected");
      output.set(value, offset);
      offset += value.byteLength;
    }
    if (offset === 0) throw new Error("Node descriptor rejected");
    return output.slice(0, offset);
  } finally {
    output.fill(0);
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

function strictBytes(value: unknown, expectedLength: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== expectedLength ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte >= BYTE_VALUES)) {
    throw new Error("Invalid invite");
  }
  return value;
}

function strictString(value: unknown, maximum: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new Error("Invalid invite");
  }
  return value;
}

function strictSafeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error("Invalid invite");
  }
  return value;
}
