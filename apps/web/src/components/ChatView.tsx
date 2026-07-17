import {
  ArrowDownToLine,
  ArrowLeft,
  Clock3,
  FileArchive,
  Image,
  LockKeyhole,
  MessageSquareReply,
  Paperclip,
  Play,
  Send,
  ShieldCheck,
  SmilePlus,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { remainingSeconds } from "../domain/messagePolicy";
import { formatBytes } from "../domain/format";
import type { ChatMessage, RoomRecord, UploadProgress } from "../domain/types";
import { GifPicker } from "./GifPicker";
import { IconButton } from "./Ui";

interface ChatViewProps {
  room: RoomRecord;
  username: string;
  connected: boolean;
  messages: ChatMessage[];
  upload: UploadProgress & { active: boolean; name: string };
  onBack: () => void;
  onSend: (content: string, replyToId?: string) => Promise<boolean>;
  onReply: (message: ChatMessage | null) => void;
  replyTarget: ChatMessage | null;
  onOpenAttachment: () => void;
  onViewAttachment: (message: ChatMessage) => void;
  onExportAttachment: (message: ChatMessage) => void;
  onSendGif: (path: string, replyToId?: string) => Promise<void>;
}

export function ChatView({
  room,
  username,
  connected,
  messages,
  upload,
  onBack,
  onSend,
  onReply,
  replyTarget,
  onOpenAttachment,
  onViewAttachment,
  onExportAttachment,
  onSendGif,
}: ChatViewProps) {
  const [draft, setDraft] = useState("");
  const [showGifs, setShowGifs] = useState(false);
  const [now, setNow] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const wasNearBottom = useRef(true);

  useEffect(() => {
    const initial = window.setTimeout(() => setNow(Date.now()), 0);
    const timer = window.setInterval(() => setNow(Date.now()), 500);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const element = scrollRef.current;
    if (element && wasNearBottom.current) element.scrollTop = element.scrollHeight;
  }, [messages.length]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.trim()) return;
    if (await onSend(draft, replyTarget?.id)) {
      setDraft("");
      onReply(null);
    }
  };

  const byId = useMemo(() => new Map(messages.map((message) => [message.id, message])), [messages]);
  const sendGif = async (path: string) => {
    setShowGifs(false);
    await onSendGif(path, replyTarget?.id);
    onReply(null);
  };

  return (
    <section className="chat-view">
      <header className="chat-header">
        <IconButton className="mobile-only" label="Back to rooms" onClick={onBack}><ArrowLeft size={20} /></IconButton>
        <div className="room-avatar">#</div>
        <div className="chat-title">
          <h1>{room.name}</h1>
          <span><ShieldCheck size={13} /> {room.self_destruct_timer_sec}s after read</span>
        </div>
        <div className={`connection-pill state-${connected ? "connected" : "disconnected"}`}>
          <span />{connected ? "LIVE" : "OFFLINE"}
        </div>
      </header>

      <div
        className="message-stream"
        ref={scrollRef}
        onScroll={(event) => {
          const element = event.currentTarget;
          wasNearBottom.current = element.scrollHeight - element.scrollTop - element.clientHeight < 100;
        }}
      >
        {messages.length === 0 ? (
          <div className="empty-chat">
            <LockKeyhole size={28} />
            <strong>ROOM EMPTY</strong>
            <span>Waiting for encrypted traffic</span>
          </div>
        ) : messages.map((message) => {
          const original = message.replyToId ? byId.get(message.replyToId) : undefined;
          return (
            <article className={`message-row ${message.mine ? "is-mine" : ""}`} key={message.id} id={`message-${message.id}`}>
              <div className="message-meta">
                <span>{message.mine ? username : message.sender}</span>
                <time>{formatTime(message.createdAtMs)}</time>
              </div>
              <div className="message-line">
                <div className="message-bubble">
                  {message.replyToId ? (
                    <button
                      className="reply-preview"
                      type="button"
                      onClick={() => document.getElementById(`message-${message.replyToId}`)?.scrollIntoView({ behavior: "smooth", block: "center" })}
                    >
                      <MessageSquareReply size={14} />
                      <span>{original ? `${original.sender}: ${original.content}` : "Original message unavailable"}</span>
                    </button>
                  ) : null}
                  {message.kind === "text" ? (
                    <p>{message.content}</p>
                  ) : (
                    <AttachmentMessage
                      message={message}
                      onView={() => onViewAttachment(message)}
                      onExport={() => onExportAttachment(message)}
                    />
                  )}
                  <div className="message-expiry">
                    <Clock3 size={12} />
                    <span>{expiryLabel(message, now)}</span>
                  </div>
                </div>
                <IconButton className="reply-action" label="Reply" onClick={() => onReply(message)}><MessageSquareReply size={16} /></IconButton>
              </div>
            </article>
          );
        })}
      </div>

      <footer className="composer-wrap">
        {upload.active ? (
          <div className="upload-progress">
            <span>{upload.name}</span>
            <progress max={upload.total || 1} value={upload.loaded} aria-label="Attachment upload progress" />
            <strong>{upload.total ? Math.round(upload.loaded / upload.total * 100) : 0}%</strong>
          </div>
        ) : null}
        {replyTarget ? (
          <div className="composer-reply">
            <MessageSquareReply size={16} />
            <span><strong>{replyTarget.sender}</strong>{replyTarget.content}</span>
            <IconButton label="Cancel reply" onClick={() => onReply(null)}><X size={17} /></IconButton>
          </div>
        ) : null}
        {showGifs ? <GifPicker onClose={() => setShowGifs(false)} onSelect={(path) => void sendGif(path)} /> : null}
        <form className="composer" onSubmit={submit}>
          <IconButton label="Attach file" disabled={!connected} onClick={onOpenAttachment}><Paperclip size={20} /></IconButton>
          <IconButton label="Send GIF" disabled={!connected || !room.allow_images} onClick={() => setShowGifs((value) => !value)}><SmilePlus size={20} /></IconButton>
          <textarea
            aria-label="Message"
            placeholder={connected ? "Message" : "Reconnecting"}
            rows={1}
            maxLength={8000}
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
          />
          <IconButton className="send-button" label="Send message" disabled={!connected || !draft.trim()} type="submit"><Send size={19} /></IconButton>
        </form>
      </footer>
    </section>
  );
}

function AttachmentMessage({ message, onView, onExport }: { message: ChatMessage; onView: () => void; onExport: () => void }) {
  const attachment = message.attachment;
  if (!attachment) return null;
  const Icon = attachment.mediaType === "IMAGE" ? Image : attachment.mediaType === "VIDEO" ? Play : FileArchive;
  return (
    <div className="attachment-message">
      <div className={`attachment-icon type-${attachment.mediaType.toLowerCase()}`}><Icon size={22} /></div>
      <div className="attachment-info">
        <strong>{attachment.name}</strong>
        <span>{attachment.mediaType} · {formatBytes(attachment.sizeBytes)}{attachment.oneTime ? " · ONE-TIME" : ""}</span>
      </div>
      <IconButton label="View attachment" onClick={onView}><Play size={17} /></IconButton>
      {!attachment.oneTime ? <IconButton label="Save encrypted attachment" onClick={onExport}><ArrowDownToLine size={17} /></IconButton> : null}
    </div>
  );
}

function formatTime(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(timestamp);
}

function expiryLabel(message: ChatMessage, now: number): string {
  if (now === 0) return `${message.selfDestructSec}s on read`;
  const remaining = remainingSeconds(message, now);
  if (remaining === null) return `${message.selfDestructSec}s on read`;
  return `${remaining}s`;
}
