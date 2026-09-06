import { ImageUp } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { readQrImage } from "../security/qrImage";
import { AbyssalMarkLoader } from "./Ui";

export function QrImageInput({ disabled, onScanned, onBusyChange, resetKey = "" }: {
  disabled?: boolean;
  onScanned: (value: string, signal: AbortSignal) => Promise<boolean>;
  onBusyChange?: (busy: boolean) => void;
  resetKey?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  const operation = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState<{ key: string } | null>(null);
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
  return (
    <div className="qr-image-input">
      <input ref={input} type="file" accept="image/png,image/jpeg" hidden aria-label="QR image" onChange={(event) => {
        const file = event.currentTarget.files?.[0];
        event.currentTarget.value = "";
        if (!file || disabled || operation.current) return;
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
            if (mounted.current && !controller.signal.aborted) setFailed({ key: resetKey });
          } finally {
            operation.current = null;
            if (mounted.current) {
              setBusy(false);
              onBusyChange?.(false);
            }
          }
        })();
      }} />
      <button type="button" className="secondary-button" disabled={disabled || busy} onClick={() => input.current?.click()}>
        {busy ? <AbyssalMarkLoader size="compact" /> : <ImageUp size={16} />} {busy ? "READING IMAGE" : "OPEN QR IMAGE"}
      </button>
      {failed?.key === resetKey ? <p className="field-error" role="status">QR image not accepted.</p> : null}
    </div>
  );
}
