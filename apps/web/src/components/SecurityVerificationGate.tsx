import { AbyssalMarkLoader } from "./Ui";
import type { OriginAttestationStatus } from "../security/originAttestation";

const COPY: Record<Exclude<OriginAttestationStatus, "OK">, { title: string; detail: string }> = {
  CHECKING: {
    title: "Verifying release",
    detail: "Checking this build before account access.",
  },
  MISMATCH: {
    title: "Release not verified",
    detail: "A trusted Abyssal release could not be verified. Do not enter account details.",
  },
  STALE: {
    title: "Release approval expired",
    detail: "This build is outside the current signed release window.",
  },
  UNAVAILABLE: {
    title: "Verification unavailable",
    detail: "Required signed release data could not be retrieved. Account access remains blocked.",
  },
  ATTESTATION_REJECTED: {
    title: "Build rejected by node",
    detail: "This node does not accept the current signed build.",
  },
};

export function SecurityVerificationGate({
  status,
  onRetry,
  onEndSession,
}: {
  status: Exclude<OriginAttestationStatus, "OK">;
  onRetry: () => void;
  onEndSession?: () => void;
}) {
  const copy = COPY[status];
  return (
    <main
      className={`verification-root security-verification-page security-verification-${status.toLowerCase()}`}
      aria-labelledby="security-verification-title"
      aria-describedby="security-verification-detail"
      aria-busy={status === "CHECKING"}
    >
      <section className="security-verification-content">
        <AbyssalMarkLoader
          className="security-verification-mark"
          animated={status === "CHECKING"}
          size="medium"
        />
        <div className="security-verification-copy">
          <p className="eyebrow">SECURITY ADMISSION</p>
          <h1 id="security-verification-title">{copy.title}</h1>
          <p
            id="security-verification-detail"
            className="security-verification-status"
            role="status"
            aria-live="polite"
          >
            {copy.detail}
          </p>
        </div>
        {status === "CHECKING" ? null : (
          <div className="security-verification-actions">
            {onEndSession ? (
              <button className="secondary-button" type="button" onClick={onEndSession}>END SESSION</button>
            ) : null}
            <button className="primary-button" type="button" onClick={onRetry}>RETRY</button>
          </div>
        )}
      </section>
    </main>
  );
}
