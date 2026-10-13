import { Check, Copy } from "lucide-react";
import { useEffect, useId, useState } from "react";
import { IconButton } from "./Ui";

const COPIED_FEEDBACK_MS = 1_600;

/** Copy state that falls back to "idle" shortly after a copy attempt. */
function useCopyStatus(value: string) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (status === "idle") return undefined;
    const timer = window.setTimeout(() => setStatus("idle"), COPIED_FEEDBACK_MS);
    return () => window.clearTimeout(timer);
  }, [status]);
  const copy = () => {
    void navigator.clipboard.writeText(value).then(() => setStatus("copied"), () => setStatus("failed"));
  };
  return { status, copy };
}

/** An icon-only copy button, e.g. for a room ID in a list row or header. */
export function CopyIconButton({ label, value, size = 17 }: { label: string; value: string; size?: number }) {
  const { status, copy } = useCopyStatus(value);
  return (
    <IconButton
      label={status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : label}
      title={status === "failed" ? "Copy failed. Open the room and copy the ID from the address shown." : label}
      onClick={copy}
    >
      {status === "copied" ? <Check size={size} aria-hidden="true" /> : <Copy size={size} aria-hidden="true" />}
    </IconButton>
  );
}

/** A labelled, selectable value with a copy-to-clipboard button. */
export function CopyableValue({ label, value, title, hint }: { label: string; value: string; title?: string; hint?: string }) {
  const id = useId();
  const { status, copy } = useCopyStatus(value);
  return (
    <div className="copyable">
      <span className="copyable-label" id={`${id}-label`}>{label}</span>
      <div className="copyable-body">
        <code className="copyable-value" aria-labelledby={`${id}-label`} title={title}>{value}</code>
        <button className="secondary-button is-compact" type="button" onClick={copy} aria-label={`Copy ${label.toLowerCase()}`}>
          {status === "copied" ? <Check size={15} aria-hidden="true" /> : <Copy size={15} aria-hidden="true" />}
          {status === "copied" ? "Copied" : "Copy"}
        </button>
      </div>
      {status === "failed" ? <span className="field-error" role="status">Copy failed. Select the text and copy it manually.</span> : null}
      {hint ? <span className="field-hint">{hint}</span> : null}
    </div>
  );
}
