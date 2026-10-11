import { CameraOff } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { startQrCamera, type CameraScanState } from "../security/qrCamera";
import { AbyssalMarkLoader } from "./Ui";

export function QrScanner({ onScanned, onClose }: {
  onScanned: (value: string, signal: AbortSignal) => Promise<boolean>;
  onClose: () => void;
}) {
  const video = useRef<HTMLVideoElement>(null);
  const [state, setState] = useState<CameraScanState>("starting");
  useEffect(() => {
    if (!video.current) return;
    let mounted = true;
    const dispose = startQrCamera({
      video: video.current,
      onState: (next) => { if (mounted) setState(next); },
      onValue: async (value, signal) => mounted ? onScanned(value, signal) : false,
    });
    return () => { mounted = false; dispose(); };
  }, [onScanned]);
  const message: Record<CameraScanState, string> = {
    starting: "Waiting for camera permission…",
    scanning: "Point the camera at the QR code.",
    invalid: "That QR code was not accepted. Try again.",
    unavailable: "Camera unavailable. Paste the code or open a QR image instead.",
    stopped: "Camera stopped.",
  };
  return (
    <section className="invite-scanner" aria-label="QR scanner">
      <video ref={video} autoPlay muted playsInline aria-label="QR scanner preview" />
      <p role="status" aria-live="polite">{state === "starting" ? <AbyssalMarkLoader size="compact" /> : null}{message[state]}</p>
      <button type="button" className="secondary-button" onClick={onClose}>
        <CameraOff size={16} aria-hidden="true" />Close camera
      </button>
    </section>
  );
}
