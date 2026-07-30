export type ConnectionState = "connecting" | "connected" | "disconnected";
export type MediaType = "IMAGE" | "VIDEO" | "FILE";

export interface NodeEndpoint {
  apiBaseUrl: string;
  wsBaseUrl: string;
  displayHost: string;
}

export interface AccountSession {
  token: string;
  nodeId: string;
  username: string;
  maxRoomsPerUser: number;
  sessionInactivitySec: number;
  endpoint: NodeEndpoint;
  created: boolean;
}

export interface AccountResponse {
  accepted: boolean;
  created: boolean;
  token?: string | null;
  node_id: string;
  username?: string | null;
  max_rooms_per_user: number;
  session_inactivity_sec: number;
  error?: string | null;
}

export interface PresenceUser {
  username: string;
  connected: boolean;
}

export interface RoomRecord {
  id: string;
  name: string;
  owner_username?: string;
  self_destruct_timer_sec: number;
  overall_expiry_sec: number;
  allow_images: boolean;
  allow_videos: boolean;
  allow_files: boolean;
  enforce_text_absolute_expiry: boolean;
  image_read_timer_sec: number;
  image_overall_expiry_sec: number;
  enforce_image_absolute_expiry: boolean;
  video_read_timer_sec: number;
  video_overall_expiry_sec: number;
  enforce_video_absolute_expiry: boolean;
  file_read_timer_sec: number;
  file_overall_expiry_sec: number;
  enforce_file_absolute_expiry: boolean;
  conversation_type?: "room" | "direct";
  peer_username?: string;
}

export interface DirectRecord {
  id: string;
  peer_username: string;
}

export interface ChatMessage {
  id: string;
  chatId: string;
  sender: string;
  content: string;
  kind: "text" | "attachment";
  createdAtMs: number;
  receivedAtMs: number;
  readAtMs?: number;
  selfDestructSec: number;
  absoluteExpirySec: number;
  replyToId?: string;
  mine: boolean;
  mentionsCurrentUser?: boolean;
  repliesToCurrentUser?: boolean;
  attachment?: {
    id: string;
    name: string;
    mediaType: MediaType;
    mimeType: string;
    sizeBytes: number;
    oneTime: boolean;
    deleteAfterDownload: boolean;
    reactionShortcode?: string;
  };
}

export interface DecryptedMedia {
  messageId: string;
  name: string;
  mediaType: MediaType;
  mimeType: string;
  objectUrl: string;
  oneTime: boolean;
}

export type IncomingFrame =
  | { type: "message"; chat_id: string; payload_b64: string; sender_username?: string }
  | { type: "read_receipt"; chat_id: string; message_id?: string | null }
  | { type: "presence"; users: PresenceUser[] }
  | { type: "GLOBAL_WIPE" | "global_wipe" }
  | { type: "rooms"; rooms: RoomRecord[] }
  | { type: "room_created"; room: RoomRecord }
  | { type: "room_deleted"; chat_id: string }
  | { type: "directs"; directs: DirectRecord[] }
  | { type: "direct_opened"; direct: DirectRecord };

export interface AttachmentOptions {
  oneTime: boolean;
  deleteAfterDownload: boolean;
  ttlSec: number;
}

export interface UploadProgress {
  loaded: number;
  total: number;
}
