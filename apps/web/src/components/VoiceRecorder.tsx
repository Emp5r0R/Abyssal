import { Mic, Send, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { MAX_VOICE_DURATION_MS, VOICE_MIME_CANDIDATES, formatVoiceDuration, voiceFileName } from "../domain/voiceNotes";
import { IconButton } from "./Ui";

type RecorderState =
  | { kind: "idle" }
  | { kind: "recording"; startedAt: number }
  | { kind: "error"; message: string };

/**
 * Records a voice message in memory with the browser's MediaRecorder. The
 * microphone is released as soon as recording stops; nothing touches disk.
 */
export function VoiceRecorder({
  disabled,
  onSend,
  onRecordingChange,
}: {
  disabled: boolean;
  onSend: (file: File, durationMs: number) => Promise<boolean>;
  onRecordingChange?: (recording: boolean) => void;
}) {
  const [state, setState] = useState<RecorderState>({ kind: "idle" });
  const [now, setNow] = useState(0);
  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<Blob[]>([]);
  const sendOnStopRef = useRef(false);
  const startedAtRef = useRef(0);

  const release = () => {
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    recorderRef.current = null;
  };

  useEffect(() => () => {
    sendOnStopRef.current = false;
    chunksRef.current = [];
    if (recorderRef.current?.state === "recording") recorderRef.current.stop();
    release();
  }, []);

  useEffect(() => {
    if (state.kind !== "recording") return;
    const timer = window.setInterval(() => {
      const current = Date.now();
      setNow(current);
      // At the length limit the recording stops and is sent.
      if (current - state.startedAt >= MAX_VOICE_DURATION_MS && recorderRef.current?.state === "recording") {
        sendOnStopRef.current = true;
        recorderRef.current.stop();
      }
    }, 250);
    return () => window.clearInterval(timer);
  }, [state]);

  const start = async () => {
    if (disabled || state.kind === "recording") return;
    if (typeof MediaRecorder === "undefined" || !navigator.mediaDevices?.getUserMedia) {
      setState({ kind: "error", message: "This browser cannot record audio." });
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = VOICE_MIME_CANDIDATES.find((candidate) => MediaRecorder.isTypeSupported(candidate));
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      streamRef.current = stream;
      recorderRef.current = recorder;
      chunksRef.current = [];
      sendOnStopRef.current = false;
      recorder.ondataavailable = (event) => {
        if (event.data.size > 0) chunksRef.current.push(event.data);
      };
      recorder.onstop = () => {
        const durationMs = Math.min(MAX_VOICE_DURATION_MS, Date.now() - startedAtRef.current);
        const type = recorder.mimeType || mimeType || "audio/webm";
        const blob = new Blob(chunksRef.current, { type });
        chunksRef.current = [];
        release();
        setState({ kind: "idle" });
        onRecordingChange?.(false);
        if (sendOnStopRef.current && blob.size > 0 && durationMs >= 500) {
          void onSend(new File([blob], voiceFileName(type), { type: type.split(";")[0] }), durationMs);
        }
      };
      startedAtRef.current = Date.now();
      recorder.start(1000);
      setNow(startedAtRef.current);
      setState({ kind: "recording", startedAt: startedAtRef.current });
      onRecordingChange?.(true);
    } catch {
      release();
      setState({ kind: "error", message: "Microphone unavailable. Allow access in the browser to record." });
    }
  };

  const stop = (send: boolean) => {
    sendOnStopRef.current = send;
    if (recorderRef.current?.state === "recording") recorderRef.current.stop();
  };

  if (state.kind === "recording") {
    return (
      <div className="voice-recorder" role="group" aria-label="Recording voice message">
        <span className="recording-dot" aria-hidden="true" />
        <span role="timer">{formatVoiceDuration(now - state.startedAt)}</span>
        <span className="voice-limit">/ {formatVoiceDuration(MAX_VOICE_DURATION_MS)}</span>
        <IconButton label="Discard recording" onClick={() => stop(false)}><Trash2 size={18} /></IconButton>
        <IconButton className="send-button" label="Send voice message" onClick={() => stop(true)}><Send size={19} /></IconButton>
      </div>
    );
  }

  return (
    <>
      <IconButton
        label="Record voice message"
        disabled={disabled}
        onClick={() => void start()}
        title={state.kind === "error" ? state.message : undefined}
      >
        <Mic size={20} />
      </IconButton>
      {state.kind === "error" ? <span className="sr-only" role="alert">{state.message}</span> : null}
    </>
  );
}
