export interface SenderProfile { version: 1; display_name: string }

const PREFIXES = ["Silent", "Silver", "Lunar", "Solar", "Quiet", "Hidden", "Distant", "Bright", "Amber", "Crimson", "Arctic", "Astral", "Velvet", "Crystal", "Cobalt", "Emerald"];
const SUFFIXES = ["Orbit", "Signal", "Comet", "Prism", "Echo", "Nova", "Pulse", "Aurora", "Horizon", "Vertex", "Beacon", "Quasar", "Cipher", "Zenith", "Vector", "Drift"];

export function newPrivateDisplayName(): string {
  const entropy = crypto.getRandomValues(new Uint8Array(8));
  try { return displayNameFromEntropy(entropy); } finally { entropy.fill(0); }
}

export function displayNameFromEntropy(entropy: Uint8Array): string {
  if (entropy.length !== 8) throw new Error("Profile unavailable");
  const suffix = [...entropy.subarray(2)].map((value) => value.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${PREFIXES[entropy[0] & 15]}${SUFFIXES[entropy[1] & 15]}${suffix}`;
}

export function senderProfile(displayName: string): SenderProfile {
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,35}$/u.test(displayName)) throw new Error("Profile unavailable");
  return { version: 1, display_name: displayName };
}

export function readSenderProfile(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== 2) throw new Error("Profile unavailable");
  const profile = value as Record<string, unknown>;
  if (profile.version !== 1 || typeof profile.display_name !== "string") throw new Error("Profile unavailable");
  return senderProfile(profile.display_name).display_name;
}
