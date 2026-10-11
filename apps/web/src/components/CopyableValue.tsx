import { Check, Copy } from "lucide-react";
import { useEffect, useId, useState } from "react";

const COPIED_FEEDBACK_MS = 1_600;

/** A labelled, selectable value with a copy-to-clipboard button. */
export function CopyableValue({ label, value, title, hint }: { label: string; value: string; title?: string; hint?: string }) {
  const id = useId();
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (status === "idle") return undefined;
    const timer = window.setTimeout(() => setStatus("idle"), COPIED_FEEDBACK_MS);
    return () => window.clearTimeout(timer);
  }, [status]);
  const copy = () => {
    void navigator.clipboard.writeText(value).then(() => setStatus("copied"), () => setStatus("failed"));
  };
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
