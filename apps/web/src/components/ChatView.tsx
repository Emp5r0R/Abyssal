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
  ShieldAlert,
  Smartphone,
  SmilePlus,
  TriangleAlert,
  WifiOff,
  X,
} from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { remainingSeconds } from "../domain/messagePolicy";
import { formatBytes } from "../domain/format";
import { splitMentionText } from "../domain/messageAttention";
import { isWebSender, senderOriginNotice } from "../domain/senderClient";
import { exactReactionShortcut, reactionByShortcode, searchReactions, type ReactionAsset } from "../domain/reactions";
import type { ChatMessage, PresenceUser, RoomRecord, UploadProgress } from "../domain/types";
import { accountInitials, displayNamesBySender, roomLabel, shortAccountId } from "../domain/displayLabels";
import { PrivacyBlur } from "./PrivacyBlur";
import { privacyBlurProps, usePrivacyBlur } from "./privacyBlurContext";
import { DirectVerificationQr } from "./DirectVerificationQr";
import { GifPicker } from "./GifPicker";
import { ReactionImage } from "./ReactionImage";
import { Dialog, Field, IconButton } from "./Ui";

interface ChatViewProps {
  room: RoomRecord;
  username: string;
  connected: boolean;
  safetyNumber: string | null;
  directTrust?: { verified: boolean; verificationToken?: string | null };
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
  onVerifyToken?: (presentedToken: string) => boolean;
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
  onVerifyToken,
}: ChatViewProps) {
  const isDirect = room.conversation_type === "direct";
  const blur = usePrivacyBlur();
  const retentionLabelId = useId();
  const [draft, setDraft] = useState("");
  const [showGifs, setShowGifs] = useState(false);
  const [directRetentionSec, setDirectRetentionSec] = useState(5);
  const [submitting, setSubmitting] = useState(false);
  const [now, setNow] = useState(0);
  const [flashTargetId, setFlashTargetId] = useState<string | null>(null);
  const [showTrustDialog, setShowTrustDialog] = useState(false);
  const [presentedVerificationToken, setPresentedVerificationToken] = useState("");
  const [verificationRejected, setVerificationRejected] = useState(false);
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
  const closeTrustDialog = () => {
    setPresentedVerificationToken("");
    setVerificationRejected(false);
    setShowTrustDialog(false);
  };
  const effectiveRetentionSec = isDirect ? directRetentionSec : room.self_destruct_timer_sec;
  const senderNames = displayNamesBySender({ [room.id]: messages });
  const peer = isDirect ? room.peer_username ?? room.name : null;
  const title = peer ? senderNames.get(peer.toLowerCase()) ?? shortAccountId(peer) : roomLabel(room);
  const peerOnline = peer ? users.find((user) => user.username === peer)?.connected === true : false;
  const canVerify = !!safetyNumber && !!directTrust.verificationToken && !!onVerifyToken;

  return (
    <section className="chat-view">
      <header className="chat-header">
        <IconButton className="mobile-only" label="Back to conversations" onClick={onBack}><ArrowLeft size={20} /></IconButton>
        <span className={`avatar ${isDirect ? "" : "is-room"}`} aria-hidden="true">{isDirect ? accountInitials(title) : "#"}</span>
        <div className="chat-title">
          <h1 title={peer ?? room.id}><PrivacyBlur>{title}</PrivacyBlur></h1>
          {isDirect ? (
            <div className="chat-subtitle">
              <span className={`presence-dot ${peerOnline ? "is-online" : ""}`} aria-hidden="true" />
              <span>{peerOnline ? "Online" : "Offline"}</span>
              <span aria-hidden="true">·</span>
              <button
                type="button"
                className={`trust-status ${directTrust.verified ? "is-verified" : "is-unverified"}`}
                onClick={() => setShowTrustDialog(true)}
                disabled={!canVerify}
                aria-label={directTrust.verified ? "Peer identity verified" : "Verify peer identity (recommended)"}
                title={safetyNumber ? `Safety number ${safetyNumber}` : "Safety number unavailable"}
              >
                {directTrust.verified ? <ShieldCheck size={14} aria-hidden="true" /> : <ShieldAlert size={14} aria-hidden="true" />}
                {directTrust.verified ? "Verified" : "Not verified"}
              </button>
            </div>
          ) : (
            <div className="chat-subtitle">
              <span>{room.visibility === "public" ? "Public room" : "Private room"}</span>
              <span aria-hidden="true">·</span>
              <span>{retentionLabel(room.self_destruct_timer_sec)}</span>
            </div>
          )}
        </div>
        {connected ? null : <span className="offline-badge"><WifiOff size={14} aria-hidden="true" />Offline</span>}
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
            <LockKeyhole size={26} aria-hidden="true" />
            <strong>No messages yet</strong>
            <span>{isDirect ? "Messages are end-to-end encrypted. Say hello." : "Messages in this room are end-to-end encrypted."}</span>
          </div>
        ) : messages.map((message) => {
          const original = message.replyToId ? byId.get(message.replyToId) : undefined;
          const attention = !message.mine && (message.mentionsCurrentUser || message.repliesToCurrentUser);
          const attentionLabel = message.mentionsCurrentUser && message.repliesToCurrentUser
            ? "Mentioned and replied"
            : message.repliesToCurrentUser ? "Replied to you" : "Mentioned you";
          return (
            <article
              className={`message-row ${message.mine ? "is-mine" : ""} ${attention ? "is-attention" : ""} ${flashTargetId === message.id ? "is-targeted" : ""}`}
              key={message.id}
              id={`message-${message.id}`}
            >
              <div className="message-meta">
                {message.mine ? <PrivacyBlur className="message-self">You</PrivacyBlur> : (
                  <button
                    type="button"
                    {...privacyBlurProps(blur, "message-author")}
                    aria-label={message.senderDisplayName ? `${message.senderDisplayName} (${message.sender})` : message.sender}
                    title={`Mention ${message.sender}`}
                    onClick={() => insertComposerToken(`@${message.sender}`)}
                  >
                    {message.senderDisplayName ?? shortAccountId(message.sender)}
                    {message.senderDisplayName ? <small className="message-account-id">{shortAccountId(message.sender)}</small> : null}
                  </button>
                )}
                <time>{formatTime(message.createdAtMs)}</time>
                {!message.mine && message.senderClient ? (
                  <span
                    className={`origin-badge ${isWebSender(message.senderClient) ? "is-web" : "is-android"}`}
                    title={senderOriginNotice(message.senderClient)}
                    aria-label={senderOriginNotice(message.senderClient)}
                    role="img"
                  >
                    {isWebSender(message.senderClient) ? <TriangleAlert size={11} /> : <Smartphone size={11} />}
                  </span>
                ) : null}
                {attention ? (
                  <span className="attention-badge">
                    {message.mentionsCurrentUser ? <AtSign size={11} /> : <MessageSquareReply size={11} />}
                    {attentionLabel}
                  </span>
                ) : null}
              </div>
              <div className="message-line">
                <div {...privacyBlurProps(blur, "message-bubble")}>
                  {message.replyToId ? (
                    <button
                      className="reply-preview"
                      type="button"
                      onClick={() => message.replyToId && focusMessage(message.replyToId)}
                    >
                      <MessageSquareReply size={14} />
                      <span>{original ? `${original.mine ? "You" : original.senderDisplayName ?? shortAccountId(original.sender)}: ${original.content}` : "Original message unavailable"}</span>
                    </button>
                  ) : null}
                  {message.kind === "text" ? (
                    <MessageText content={message.content} currentUsername={username} />
                  ) : (
                    <AttachmentMessage
                      message={message}
                      disabled={!connected}
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
        {isDirect ? (
          <div className="composer-retention">
            <span id={retentionLabelId}><Clock3 size={13} aria-hidden="true" />Disappear after reading</span>
            <div className="segmented" role="group" aria-labelledby={retentionLabelId}>
              {DIRECT_RETENTION_OPTIONS.map((seconds) => (
                <button
                  type="button"
                  key={seconds}
                  className={effectiveRetentionSec === seconds ? "is-active" : ""}
                  aria-pressed={effectiveRetentionSec === seconds}
                  aria-label={seconds === 0 ? "Never" : `${retentionChip(seconds)} after reading`}
                  onClick={() => setDirectRetentionSec(seconds)}
                >
                  {retentionChip(seconds)}
                </button>
              ))}
            </div>
          </div>
        ) : null}
        {replyTarget ? (
          <div className="composer-reply">
            <MessageSquareReply size={16} />
            <span className="composer-reply-text">
              <span className="composer-reply-label">Replying to {replyTarget.mine ? "yourself" : replyTarget.senderDisplayName ?? shortAccountId(replyTarget.sender)}</span>
              <PrivacyBlur>{replyTarget.content}</PrivacyBlur>
            </span>
            <IconButton label="Cancel reply" onClick={() => onReply(null)}><X size={17} /></IconButton>
          </div>
        ) : null}
        {showGifs ? <GifPicker onClose={() => setShowGifs(false)} onSelect={(reaction) => void sendGif(reaction)} /> : null}
        {mentionSuggestions.length > 0 ? (
          <div className="composer-suggestions" role="listbox" aria-label="Mention users">
            {mentionSuggestions.map((user) => (
              <button key={user.username} type="button" role="option" onClick={() => insertComposerToken(`@${user.username}`)}>
                <AtSign size={14} />
                <PrivacyBlur><strong>{user.username}</strong></PrivacyBlur>
                <span className={user.connected ? "is-online" : ""}>{user.connected ? "Online" : "Offline"}</span>
              </button>
            ))}
          </div>
        ) : reactionSuggestions.length > 0 ? (
          <div className="composer-suggestions reaction-suggestions" role="listbox" aria-label="Reaction shortcuts">
            {reactionSuggestions.map((reaction) => (
              <button key={reaction.shortcode} type="button" role="option" onClick={() => insertComposerToken(reaction.shortcode)}>
                <ReactionImage reaction={reaction} alt="" />
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
            data-composer="true"
            aria-label="Message"
            placeholder={connected ? (isDirect ? "Write a message" : "Message the room") : "Offline — waiting for the relay"}
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
      {showTrustDialog && isDirect && safetyNumber && directTrust.verificationToken && onVerifyToken ? (
        <Dialog
          className="verify-dialog"
          title="Verify peer identity"
          description="Compare the safety number or verification code with your peer through a trusted channel, such as in person. Verification is recommended but optional."
          onClose={closeTrustDialog}
          actions={
            <>
              <button className="secondary-button" type="button" onClick={closeTrustDialog}>Cancel</button>
              <button
                className="primary-button"
                type="button"
                disabled={!presentedVerificationToken.trim()}
                onClick={() => {
                  const accepted = onVerifyToken(presentedVerificationToken);
                  setVerificationRejected(!accepted);
                  if (accepted) {
                    setPresentedVerificationToken("");
                    setShowTrustDialog(false);
                  }
                }}
              >
                Verify code
              </button>
            </>
          }
        >
          <DirectVerificationQr
            token={directTrust.verificationToken}
            onScanned={(token) => {
              setPresentedVerificationToken(token);
              setVerificationRejected(false);
            }}
          />
          <div className="safety-number">
            <span className="copyable-label">Safety number</span>
            <p className="safety-number-value" aria-label={`Safety number ${safetyNumber}`}>{safetyNumber}</p>
          </div>
          <Field
            label="Peer verification code"
            placeholder="abyssal:verify:v1:…"
            value={presentedVerificationToken}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => {
              setPresentedVerificationToken(event.target.value);
              setVerificationRejected(false);
            }}
          />
          {verificationRejected ? <p className="field-error" role="alert">That code does not match. Make sure you are comparing with the right person.</p> : null}
          <p className="dialog-note">The QR code and safety number are computed on this device. Verification is kept in memory and clears after a reconnect, identity change, sign-out, wipe, or expiry.</p>
        </Dialog>
      ) : null}
    </section>
  );
}

function AttachmentMessage({
  message,
  disabled,
  onView,
  onExport,
}: {
  message: ChatMessage;
  disabled: boolean;
  onView: () => void;
  onExport: () => void;
}) {
  const attachment = message.attachment;
  if (!attachment) return null;
  const reaction = reactionByShortcode(attachment.reactionShortcode);
  if (reaction && !attachment.oneTime) {
    return (
      <div className="inline-reaction">
        <button
          type="button"
          className="inline-reaction-preview"
          onClick={onView}
          disabled={disabled}
          aria-label={disabled ? `Open ${reaction.shortcode} (offline)` : `Open ${reaction.shortcode}`}
        >
          <ReactionImage reaction={reaction} alt={reaction.label} />
        </button>
        <div className="inline-reaction-footer">
          <code>{reaction.shortcode}</code>
          <IconButton label={disabled ? "Save reaction (offline)" : "Save reaction"} disabled={disabled} onClick={onExport}><ArrowDownToLine size={16} /></IconButton>
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
        <span>{MEDIA_LABEL[attachment.mediaType]} · {formatBytes(attachment.sizeBytes)}{attachment.oneTime ? " · View once" : ""}</span>
      </div>
      <IconButton label={disabled ? "View attachment (offline)" : "View attachment"} disabled={disabled} onClick={onView}><Play size={17} /></IconButton>
      {!attachment.oneTime ? <IconButton label={disabled ? "Save attachment (offline)" : "Save attachment"} disabled={disabled} onClick={onExport}><ArrowDownToLine size={17} /></IconButton> : null}
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
          title={part.text}
        >
          @{part.username.toLowerCase() === currentUsername.toLowerCase() ? "you" : shortAccountId(part.username)}
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

const DIRECT_RETENTION_OPTIONS = [0, 5, 10, 30, 60];
const MEDIA_LABEL = { IMAGE: "Image", VIDEO: "Video", FILE: "File" } as const;

function retentionChip(seconds: number): string {
  if (seconds === 0) return "Off";
  return seconds % 60 === 0 ? `${seconds / 60}m` : `${seconds}s`;
}

function retentionLabel(seconds: number): string {
  if (seconds === 0) return "Messages stay for the session";
  if (seconds < 60) return `Messages vanish ${seconds}s after reading`;
  if (seconds < 3600) return `Messages vanish ${Math.round(seconds / 60)} min after reading`;
  if (seconds < 86_400) return `Messages vanish ${Math.round(seconds / 3600)} h after reading`;
  return `Messages vanish ${Math.round(seconds / 86_400)} d after reading`;
}
