import { decodeQrFrame, MAX_QR_SIDE, MAX_QR_TEXT } from "./qrDecoder";

export type CameraScanState = "starting" | "scanning" | "invalid" | "unavailable" | "stopped";
export interface QrCameraOptions {
  video: HTMLVideoElement;
  onValue: (value: string, signal: AbortSignal) => Promise<boolean>;
  onState: (state: CameraScanState) => void;
  requestStream?: () => Promise<MediaStream>;
  readFrame?: () => string | null;
}

const SCAN_TIMEOUT_MS = 60_000;
const SCAN_INTERVAL_MS = 250;

/** One bounded camera lifetime, including pending permission and late callbacks. */
export function startQrCamera(options: QrCameraOptions): () => void {
  const { video, onState, onValue } = options;
  const canvas = document.createElement("canvas");
  const lifetime = new AbortController();
  let active = true;
  let stream: MediaStream | undefined;
  let frameTimer: ReturnType<typeof setTimeout> | undefined;
  const deadline = setTimeout(() => stop("stopped"), SCAN_TIMEOUT_MS);

  function stop(state?: CameraScanState) {
    if (!active) return;
    active = false;
    lifetime.abort();
    clearTimeout(deadline);
    clearTimeout(frameTimer);
    document.removeEventListener("visibilitychange", visibilityChanged);
    window.removeEventListener("pagehide", pageHidden);
    stream?.getTracks().forEach((track) => {
      track.removeEventListener("ended", trackEnded);
      track.stop();
    });
    stream = undefined;
    video.pause();
    video.srcObject = null;
    canvas.width = 0;
    canvas.height = 0;
    if (state) onState(state);
  }
  function visibilityChanged() { if (document.hidden) stop("stopped"); }
  function pageHidden() { stop("stopped"); }
  function trackEnded() { stop("unavailable"); }

  function readFrame(): string | null {
    if (video.readyState < 2 || !video.videoWidth || !video.videoHeight) return null;
    const scale = Math.min(1, MAX_QR_SIDE / Math.max(video.videoWidth, video.videoHeight));
    canvas.width = Math.max(1, Math.floor(video.videoWidth * scale));
    canvas.height = Math.max(1, Math.floor(video.videoHeight * scale));
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("Camera unavailable");
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    const frame = context.getImageData(0, 0, canvas.width, canvas.height);
    try { return decodeQrFrame(frame.data, frame.width, frame.height); }
    finally {
      frame.data.fill(0);
      context.clearRect(0, 0, canvas.width, canvas.height);
    }
  }

  async function scan() {
    if (!active) return;
    try {
      const value = (options.readFrame ?? readFrame)();
      if (value && value.length <= MAX_QR_TEXT) {
        const accepted = await onValue(value, lifetime.signal);
        if (!active) return;
        if (accepted) { stop("stopped"); return; }
        onState("invalid");
      }
    } catch {
      stop("unavailable");
      return;
    }
    if (active) frameTimer = setTimeout(() => void scan(), SCAN_INTERVAL_MS);
  }

  document.addEventListener("visibilitychange", visibilityChanged);
  window.addEventListener("pagehide", pageHidden);
  onState("starting");
  if (document.hidden) { stop("stopped"); return () => stop(); }
  void (async () => {
    try {
      const pending = await (options.requestStream ?? (() => navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: "environment" }, width: { ideal: 960 }, height: { ideal: 720 } },
      })))();
      if (!active) { pending.getTracks().forEach((track) => track.stop()); return; }
      stream = pending;
      stream.getTracks().forEach((track) => track.addEventListener("ended", trackEnded));
      video.srcObject = stream;
      await video.play();
      if (!active) return;
      onState("scanning");
      frameTimer = setTimeout(() => void scan(), SCAN_INTERVAL_MS);
    } catch { stop("unavailable"); }
  })();
  return () => stop();
}
