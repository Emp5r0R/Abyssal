import { ImageUp } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { pastedQrImage } from "../security/qrClipboard";
import { readQrImage } from "../security/qrImage";
import { AbyssalMarkLoader } from "./Ui";

/**
 * Reads a QR code from an image the user opens, pastes (Ctrl+V / Cmd+V anywhere on
 * the page while this is shown) or drops onto it. Images stay local Blobs.
 */
export function QrImageInput({ disabled, onScanned, onBusyChange, resetKey = "", compact = false }: {
  disabled?: boolean;
  compact?: boolean;
  onScanned: (value: string, signal: AbortSignal) => Promise<boolean>;
  onBusyChange?: (busy: boolean) => void;
  resetKey?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const operation = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [failed, setFailed] = useState<{ key: string; message: string } | null>(null);

  const scan = useCallback((file: File) => {
    if (disabled || operation.current) return;
    const controller = new AbortController();
    operation.current = controller;
    setBusy(true);
    onBusyChange?.(true);
    setFailed(null);
    void (async () => {
      try {
        const value = await readQrImage(file, controller.signal);
        if (controller.signal.aborted) return;
        if (!(await onScanned(value, controller.signal))) throw new Error("QR image rejected");
      } catch {
        if (mounted.current && !controller.signal.aborted) setFailed({ key: resetKey, message: "No valid QR code found in that image." });
      } finally {
        operation.current = null;
        if (mounted.current) {
          setBusy(false);
          onBusyChange?.(false);
        }
      }
    })();
  }, [disabled, onBusyChange, onScanned, resetKey]);

  useEffect(() => {
    mounted.current = true;
    const cancel = () => operation.current?.abort();
    const onHidden = () => { if (document.hidden) cancel(); };
    document.addEventListener("visibilitychange", onHidden);
    window.addEventListener("pagehide", cancel);
    return () => {
      mounted.current = false;
      cancel();
      document.removeEventListener("visibilitychange", onHidden);
      window.removeEventListener("pagehide", cancel);
    };
  }, []);
  useEffect(() => { if (disabled) operation.current?.abort(); }, [disabled]);

  useEffect(() => {
    if (disabled) return;
    const onPaste = (event: ClipboardEvent) => {
      const pasted = pastedQrImage(event);
      if (pasted.kind === "none") return;
      event.preventDefault();
      if (pasted.kind === "unsupported") {
        setFailed({ key: resetKey, message: "Paste a PNG or JPEG image of the QR code." });
        return;
      }
      scan(pasted.file);
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [disabled, resetKey, scan]);

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) scan(file);
  };

  return (
    <div
      className={`qr-image-input${dragging ? " is-dragging" : ""}`}
      onDragOver={(event) => {
        if (disabled || !event.dataTransfer.types.includes("Files")) return;
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
    >
      <input ref={input} type="file" accept="image/png,image/jpeg" hidden aria-label="QR image" onChange={(event) => {
        const file = event.currentTarget.files?.[0];
        event.currentTarget.value = "";
        if (file) scan(file);
      }} />
      <button
        type="button"
        className={`secondary-button ${compact ? "is-compact" : ""}`}
        disabled={disabled || busy}
        onClick={() => input.current?.click()}
        title="Open, paste (Ctrl+V) or drop a QR image"
      >
        {busy ? <AbyssalMarkLoader size="compact" /> : <ImageUp size={15} aria-hidden="true" />}{busy ? "Reading image…" : "Open QR image"}
      </button>
      {failed?.key === resetKey ? <p className="field-error" role="status">{failed.message}</p> : null}
    </div>
  );
}
