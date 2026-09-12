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
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return (
    <label className="field">
      <span className="field-label">{label}</span>
      <input {...props} />
      {hint ? <span className="field-hint">{hint}</span> : null}
    </label>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className={`toggle-row ${disabled ? "is-disabled" : ""}`}>
      <span>{label}</span>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
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
      <img src="/abyssal-mark.svg" alt="" width={compact ? 34 : 48} height={compact ? 34 : 48} />
      <div>
        <strong>ABYSSAL</strong>
        {!compact ? <span>EPHEMERAL RELAY</span> : null}
      </div>
    </div>
  );
}
