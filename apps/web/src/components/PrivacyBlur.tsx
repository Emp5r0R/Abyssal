import type { ReactNode } from "react";

export const PRIVACY_BLUR_CLASS = "privacy-blur";

export function PrivacyBlur({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={`${PRIVACY_BLUR_CLASS} ${className}`.trim()}
      data-privacy-blur="true"
      tabIndex={0}
    >
      {children}
    </span>
  );
}
