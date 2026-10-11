import { forwardRef, useId, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { useDialogA11y } from "./useDialogA11y";

export const IconButton = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & { label: string; children: ReactNode }>(function IconButton({
  label,
  children,
  className = "",
  ...props
}, ref) {
  return (
    <button ref={ref} className={`icon-button ${className}`} aria-label={label} title={label} type="button" {...props}>
      {children}
    </button>
  );
});

export function Field({
  label,
  hint,
  "aria-describedby": describedBy,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  const hintId = `${useId()}-hint`;
  const description = [hint ? hintId : undefined, describedBy].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field">
      <label className="field-control">
        <span className="field-label">{label}</span>
        <input aria-describedby={description} {...props} />
      </label>
      {hint ? <span id={hintId} className="field-hint">{hint}</span> : null}
    </div>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled = false,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  description?: string;
  disabled?: boolean;
}) {
  const descriptionId = `${useId()}-description`;
  return (
    <label className={`toggle-row ${disabled ? "is-disabled" : ""}`}>
      <span className="toggle-text">
        <span className="toggle-label">{label}</span>
        {description ? <span id={descriptionId} className="toggle-description">{description}</span> : null}
      </span>
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        aria-describedby={description ? descriptionId : undefined}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="toggle-track" aria-hidden="true"><span /></span>
    </label>
  );
}

export function AbyssalMarkLoader({
  animated = true,
  className = "",
  size = "medium",
}: {
  animated?: boolean;
  className?: string;
  size?: "compact" | "medium" | "large";
}) {
  return (
    <span
      className={`abyssal-mark-loader abyssal-mark-loader-${size} ${animated ? "" : "is-static"} ${className}`.trim()}
      aria-hidden="true"
    >
      <span />
      <span />
      <span />
      <span />
    </span>
  );
}

export function Dialog({
  title,
  description,
  children,
  actions,
  className = "",
  onClose,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
  onClose?: () => void;
}) {
  const titleId = `${useId()}-title`;
  const descriptionId = `${titleId}-description`;
  const dialogRef = useDialogA11y({ onClose });

  return (
    <div className="dialog-backdrop" role="presentation">
      <section
        ref={dialogRef}
        className={`dialog ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
      >
        <header className="dialog-header">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description ? <p id={descriptionId}>{description}</p> : null}
          </div>
        </header>
        <div className="dialog-body">{children}</div>
        {actions ? <footer className="dialog-actions">{actions}</footer> : null}
      </section>
    </div>
  );
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? "brand-compact" : ""}`}>
      <img src="/abyssal-mark.svg" alt="" width={compact ? 26 : 40} height={compact ? 26 : 40} />
      <div>
        <strong>Abyssal</strong>
        {!compact ? <span>Ephemeral encrypted chat</span> : null}
      </div>
    </div>
  );
}
