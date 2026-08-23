import { Dialog } from "./Ui";
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
    detail: "The signed release record could not be reached. Account access remains blocked.",
  },
  ATTESTATION_REJECTED: {
    title: "Build rejected by node",
    detail: "This node does not accept the current signed build.",
  },
};

export function SecurityVerificationDialog({
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
    <Dialog
      title={copy.title}
      description={copy.detail}
      className="security-verification-dialog"
      actions={status === "CHECKING" ? undefined : (
        <>
          {onEndSession ? <button className="secondary-button" type="button" onClick={onEndSession}>END SESSION</button> : null}
          <button className="primary-button" type="button" onClick={onRetry}>RETRY</button>
        </>
      )}
    >
      <div className="security-verification-mark" aria-hidden="true" />
    </Dialog>
  );
}
