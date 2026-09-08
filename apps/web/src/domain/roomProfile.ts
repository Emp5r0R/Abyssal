export interface RoomProfile { version: 1; name: string }

export function roomProfile(name: string): RoomProfile {
  if (!name || name.length > 36 || name !== name.trim() || /[\p{Cc}\uD800-\uDFFF]/u.test(name)) {
    throw new Error("Room unavailable");
  }
  return { version: 1, name };
}

export function readRoomProfile(value: unknown): RoomProfile {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== 2) throw new Error("Room unavailable");
  const profile = value as Record<string, unknown>;
  if (profile.version !== 1 || typeof profile.name !== "string") throw new Error("Room unavailable");
  return roomProfile(profile.name);
}
