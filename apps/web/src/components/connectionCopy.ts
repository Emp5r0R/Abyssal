import type { ConnectionState } from "../domain/types";

/** User-facing relay status copy shared by the sidebar, home, and chat surfaces. */
export function connectionLabel(state: ConnectionState): string {
  switch (state) {
    case "connected": return "Connected";
    case "connecting": return "Connecting";
    default: return "Offline";
  }
}

/** Explains a non-live relay; null while connected. */
export function connectionNotice(state: ConnectionState): string | null {
  switch (state) {
    case "connected": return null;
    case "connecting": return "Connecting to the relay. Rooms and messages appear once the connection is ready.";
    default: return "The relay is unreachable. Abyssal keeps retrying; rooms and messages return when it reconnects.";
  }
}
