import {
  AtSign,
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
import { splitMentionText } from "../domain/messageAttention";
import { exactReactionShortcut, reactionByShortcode, searchReactions, type ReactionAsset } from "../domain/reactions";
import type { ChatMessage, PresenceUser, RoomRecord, UploadProgress } from "../domain/types";
import { GifPicker } from "./GifPicker";
import { Dialog, IconButton } from "./Ui";

interface ChatViewProps {
  room: RoomRecord;
  username: string;
  connected: boolean;
  safetyNumber: string | null;
  directTrust?: { verified: boolean };
  messages: ChatMessage[];
  users: PresenceUser[];
  upload: UploadProgress & { active: boolean; name: string };
  onBack: () => void;
  onSend: (content: string, replyToId?: string, retentionSec?: number) => Promise<boolean>;
  onReply: (message: ChatMessage | null) => void;
  replyTarget: ChatMessage | null;
  onOpenAttachment: (retentionSec: number) => void;
  onViewAttachment: (message: ChatMessage) => void;
  onExportAttachment: (message: ChatMessage) => void;
  onSendGif: (reaction: ReactionAsset, replyToId?: string, retentionSec?: number) => Promise<boolean>;
  onVerifySafetyNumber?: (safetyNumber: string) => boolean;
}

export function ChatView({
  room,
  username,
  connected,
  safetyNumber,
  directTrust = { verified: false },
  messages,
  users,
  upload,
  onBack,
  onSend,
  onReply,
  replyTarget,
  onOpenAttachment,
  onViewAttachment,
  onExportAttachment,
  onSendGif,
  onVerifySafetyNumber,
}: ChatViewProps) {
  const isDirect = room.conversation_type === "direct";
  const [draft, setDraft] = useState("");
  const [showGifs, setShowGifs] = useState(false);
  const [directRetentionSec, setDirectRetentionSec] = useState(5);
  const [submitting, setSubmitting] = useState(false);
  const [now, setNow] = useState(0);
  const [flashTargetId, setFlashTargetId] = useState<string | null>(null);
  const [showTrustDialog, setShowTrustDialog] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
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
    if (!draft.trim() || submitting || upload.active) return;
    setSubmitting(true);
    const reaction = exactReactionShortcut(draft);
    try {
      if (reaction) {
        if (await onSendGif(reaction, replyTarget?.id, effectiveRetentionSec)) {
          setDraft("");
          onReply(null);
        }
        return;
      }
      if (await onSend(draft, replyTarget?.id, effectiveRetentionSec)) {
        setDraft("");
        onReply(null);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const byId = useMemo(() => new Map(messages.map((message) => [message.id, message])), [messages]);
  const mentionQuery = trailingComposerQuery(draft, "@");
  const reactionQuery = trailingComposerQuery(draft, ":");
  const mentionSuggestions = useMemo(() => {
    if (mentionQuery === null) return [];
    const unique = new Map<string, PresenceUser>();
    users.forEach((user) => {
      if (user.username !== username) unique.set(user.username.toLowerCase(), user);
    });
    return [...unique.values()]
      .filter((user) => user.username.toLowerCase().includes(mentionQuery.toLowerCase()))
      .sort((left, right) => Number(right.connected) - Number(left.connected) || left.username.localeCompare(right.username))
      .slice(0, 7);
  }, [mentionQuery, username, users]);
  const reactionSuggestions = useMemo(
    () => reactionQuery === null ? [] : searchReactions(reactionQuery, 7),
    [reactionQuery],
  );

  const focusComposer = () => window.requestAnimationFrame(() => textareaRef.current?.focus());
  const insertComposerToken = (token: string) => {
    setDraft((current) => replaceTrailingComposerToken(current, token));
    focusComposer();
  };
  const sendGif = async (reaction: ReactionAsset) => {
    if (submitting || upload.active) return;
    setSubmitting(true);
    try {
      if (!await onSendGif(reaction, replyTarget?.id, effectiveRetentionSec)) return;
      setShowGifs(false);
      onReply(null);
    } finally {
      setSubmitting(false);
    }
  };
  const focusMessage = (messageId: string) => {
    document.getElementById(`message-${messageId}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    setFlashTargetId(messageId);
    window.setTimeout(() => setFlashTargetId((current) => current === messageId ? null : current), 1_300);
  };
  const effectiveRetentionSec = isDirect ? directRetentionSec : room.self_destruct_timer_sec;

  return (
    <section className="chat-view">
      <header className="chat-header">
        <IconButton className="mobile-only" label="Back to conversations" onClick={onBack}><ArrowLeft size={20} /></IconButton>
        <div className={`room-avatar ${isDirect ? "is-direct" : ""}`}>{isDirect ? "@" : "#"}</div>
        <div className="chat-title">
          <h1>{room.name}</h1>
          {isDirect ? (
            <button
              type="button"
              className={`trust-status ${directTrust.verified ? "is-verified" : "is-unverified"}`}
              onClick={() => setShowTrustDialog(true)}
              disabled={!safetyNumber || !onVerifySafetyNumber}
              aria-label={directTrust.verified
                ? "Direct chat safety number comparison confirmed"
                : "Confirm direct chat safety number comparison"}
            >
              <ShieldCheck size={13} />
              {directTrust.verified ? "COMPARISON CONFIRMED" : "NOT COMPARED"}
              {safetyNumber ? ` · Safety ${safetyNumber}` : " · Safety unavailable"}
            </button>
          ) : (
            <span>
              <ShieldCheck size={13} /> {retentionLabel(room.self_destruct_timer_sec)}
            </span>
          )}
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
            <strong>{isDirect ? "DIRECT EMPTY" : "ROOM EMPTY"}</strong>
            <span>{isDirect ? "Send the first private message" : "Waiting for encrypted traffic"}</span>
          </div>
        ) : messages.map((message) => {
          const original = message.replyToId ? byId.get(message.replyToId) : undefined;
          const attention = !message.mine && (message.mentionsCurrentUser || message.repliesToCurrentUser);
          const attentionLabel = message.mentionsCurrentUser && message.repliesToCurrentUser
            ? "MENTIONED + REPLIED"
            : message.repliesToCurrentUser ? "REPLIED TO YOU" : "MENTIONED YOU";
          return (
            <article
              className={`message-row ${message.mine ? "is-mine" : ""} ${attention ? "is-attention" : ""} ${flashTargetId === message.id ? "is-targeted" : ""}`}
              key={message.id}
              id={`message-${message.id}`}
            >
              <div className="message-meta">
                {message.mine ? <span>{username}</span> : (
                  <button type="button" className="message-author" onClick={() => insertComposerToken(`@${message.sender}`)}>
                    {message.sender}
                  </button>
                )}
                <time>{formatTime(message.createdAtMs)}</time>
                {attention ? (
                  <span className="attention-badge">
                    {message.mentionsCurrentUser ? <AtSign size={11} /> : <MessageSquareReply size={11} />}
                    {attentionLabel}
                  </span>
                ) : null}
              </div>
              <div className="message-line">
                <div className="message-bubble">
                  {message.replyToId ? (
                    <button
                      className="reply-preview"
                      type="button"
                      onClick={() => message.replyToId && focusMessage(message.replyToId)}
                    >
                      <MessageSquareReply size={14} />
                      <span>{original ? `${original.sender}: ${original.content}` : "Original message unavailable"}</span>
                    </button>
                  ) : null}
                  {message.kind === "text" ? (
                    <MessageText content={message.content} currentUsername={username} />
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
        <div className="composer-retention" aria-label="Message retention">
          <span><Clock3 size={13} />{isDirect ? "MESSAGE RETENTION" : "ROOM RETENTION"}</span>
          <div role="group" aria-label="Disappearing message timer">
            {(isDirect ? [0, 5, 10, 30, 60] : [room.self_destruct_timer_sec]).map((seconds) => (
              <button
                type="button"
                key={seconds}
                className={effectiveRetentionSec === seconds ? "is-active" : ""}
                disabled={!isDirect}
                onClick={() => setDirectRetentionSec(seconds)}
              >
                {seconds === 0 ? "NEVER" : seconds === 60 ? "1M" : `${seconds}S`}
              </button>
            ))}
          </div>
        </div>
        {replyTarget ? (
          <div className="composer-reply">
            <MessageSquareReply size={16} />
            <span><strong>{replyTarget.sender}</strong>{replyTarget.content}</span>
            <IconButton label="Cancel reply" onClick={() => onReply(null)}><X size={17} /></IconButton>
          </div>
        ) : null}
        {showGifs ? <GifPicker onClose={() => setShowGifs(false)} onSelect={(reaction) => void sendGif(reaction)} /> : null}
        {mentionSuggestions.length > 0 ? (
          <div className="composer-suggestions" role="listbox" aria-label="Mention users">
            {mentionSuggestions.map((user) => (
              <button key={user.username} type="button" role="option" onClick={() => insertComposerToken(`@${user.username}`)}>
                <AtSign size={14} />
                <strong>{user.username}</strong>
                <span className={user.connected ? "is-online" : ""}>{user.connected ? "ONLINE" : "OFFLINE"}</span>
              </button>
            ))}
          </div>
        ) : reactionSuggestions.length > 0 ? (
          <div className="composer-suggestions reaction-suggestions" role="listbox" aria-label="Reaction shortcuts">
            {reactionSuggestions.map((reaction) => (
              <button key={reaction.shortcode} type="button" role="option" onClick={() => insertComposerToken(reaction.shortcode)}>
                <img src={reaction.path} alt="" />
                <code>{reaction.shortcode}</code>
              </button>
            ))}
          </div>
        ) : null}
        <form className="composer" onSubmit={submit}>
          <IconButton label="Attach file" disabled={!connected || submitting || upload.active} onClick={() => onOpenAttachment(effectiveRetentionSec)}><Paperclip size={20} /></IconButton>
          <IconButton label="Send GIF" disabled={!connected || !room.allow_images || submitting || upload.active} onClick={() => setShowGifs((value) => !value)}><SmilePlus size={20} /></IconButton>
          <textarea
            ref={textareaRef}
            aria-label="Message"
            placeholder={connected ? "Message" : "Reconnecting"}
            rows={1}
            maxLength={8000}
            value={draft}
            onChange={(event) => {
              setDraft(event.target.value);
              setShowGifs(false);
            }}
            onKeyDown={(event) => {
              if (event.key === "Tab" && mentionSuggestions[0]) {
                event.preventDefault();
                insertComposerToken(`@${mentionSuggestions[0].username}`);
                return;
              }
              if (event.key === "Tab" && reactionSuggestions[0]) {
                event.preventDefault();
                insertComposerToken(reactionSuggestions[0].shortcode);
                return;
              }
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                event.currentTarget.form?.requestSubmit();
              }
            }}
          />
          <IconButton className="send-button" label="Send message" disabled={!connected || !draft.trim() || submitting || upload.active} type="submit"><Send size={19} /></IconButton>
        </form>
      </footer>
      {showTrustDialog && isDirect && safetyNumber && onVerifySafetyNumber ? (
        <Dialog
          title="Verify direct chat"
          description="Compare this safety number with your peer through a separate trusted channel."
          actions={
            <>
              <button className="secondary-button" type="button" onClick={() => setShowTrustDialog(false)}>CANCEL</button>
              <button
                className="primary-button"
                type="button"
                onClick={() => {
                  if (onVerifySafetyNumber(safetyNumber)) setShowTrustDialog(false);
                }}
              >
                I COMPARED — CONFIRM
              </button>
            </>
          }
        >
          <p className="safety-number-value" aria-label={`Safety number ${safetyNumber}`}>{safetyNumber}</p>
          <p>Only confirm when every digit matches. Verification is held in this session and clears after reconnect, identity change, logout, wipe, or expiry.</p>
        </Dialog>
      ) : null}
    </section>
  );
}

function AttachmentMessage({ message, onView, onExport }: { message: ChatMessage; onView: () => void; onExport: () => void }) {
  const attachment = message.attachment;
  if (!attachment) return null;
  const reaction = reactionByShortcode(attachment.reactionShortcode);
  if (reaction && !attachment.oneTime) {
    return (
      <div className="inline-reaction">
        <button type="button" className="inline-reaction-preview" onClick={onView} aria-label={`Open ${reaction.shortcode}`}>
          <img src={reaction.path} alt={reaction.label} />
        </button>
        <div className="inline-reaction-footer">
          <code>{reaction.shortcode}</code>
          <IconButton label="Save reaction" onClick={onExport}><ArrowDownToLine size={16} /></IconButton>
        </div>
      </div>
    );
  }
  const Icon = attachment.mediaType === "IMAGE" ? Image : attachment.mediaType === "VIDEO" ? Play : FileArchive;
  return (
    <div className="attachment-message">
      <div className={`attachment-icon type-${attachment.mediaType.toLowerCase()}`}><Icon size={22} /></div>
      <div className="attachment-info">
        <strong>{attachment.name}</strong>
        <span>{attachment.mediaType} · {formatBytes(attachment.sizeBytes)}{attachment.oneTime ? " · ONE-TIME" : ""}</span>
      </div>
      <IconButton label="View attachment" onClick={onView}><Play size={17} /></IconButton>
      {!attachment.oneTime ? <IconButton label="Save attachment" onClick={onExport}><ArrowDownToLine size={17} /></IconButton> : null}
    </div>
  );
}

function MessageText({ content, currentUsername }: { content: string; currentUsername: string }) {
  return (
    <p>
      {splitMentionText(content).map((part, index) => part.username ? (
        <span
          className={`mention-token ${part.username.toLowerCase() === currentUsername.toLowerCase() ? "is-self" : ""}`}
          key={`${part.text}-${index}`}
        >
          {part.text}
        </span>
      ) : part.text)}
    </p>
  );
}

function trailingComposerQuery(value: string, marker: "@" | ":"): string | null {
  const pattern = marker === "@" ? /(?:^|\s)@([A-Za-z0-9_]*)$/ : /(?:^|\s):([A-Za-z0-9_]*)$/;
  return value.match(pattern)?.[1] ?? null;
}

function replaceTrailingComposerToken(value: string, token: string): string {
  const match = value.match(/(^|\s)[@:][A-Za-z0-9_]*$/);
  if (match?.index !== undefined) {
    return `${value.slice(0, match.index)}${match[1]}${token} `;
  }
  return `${value}${value && !/\s$/.test(value) ? " " : ""}${token} `;
}

function formatTime(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(timestamp);
}

function expiryLabel(message: ChatMessage, now: number): string {
  if (message.selfDestructSec === 0 && message.absoluteExpirySec === 0) return "kept in session";
  if (now === 0) return message.selfDestructSec === 0 ? "absolute timer" : `${message.selfDestructSec}s on read`;
  const remaining = remainingSeconds(message, now);
  if (remaining === null) return message.selfDestructSec === 0 ? "kept in session" : `${message.selfDestructSec}s on read`;
  return `${remaining}s`;
}

function retentionLabel(seconds: number): string {
  return seconds === 0 ? "No read expiry" : `${seconds}s after read`;
}
