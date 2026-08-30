import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OriginAttestationStatus } from "../security/originAttestation";
import { SecurityVerificationGate } from "./SecurityVerificationGate";

afterEach(cleanup);

describe("security verification admission", () => {
  it("keeps account access absent while checking and exposes a live status", () => {
    render(<SecurityVerificationGate status="CHECKING" onRetry={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "Verifying release" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Checking this build before account access.");
    expect(screen.getByRole("main")).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("main")).not.toHaveAttribute("aria-modal");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "RETRY" })).not.toBeInTheDocument();
    const loader = document.querySelector(".abyssal-mark-loader");
    expect(loader).not.toHaveClass("is-static");
    expect(loader?.querySelectorAll(":scope > span")).toHaveLength(4);
  });

  it.each(["MISMATCH", "STALE", "UNAVAILABLE"] as const)(
    "fails closed inline for %s and offers retry",
    (status: Exclude<OriginAttestationStatus, "OK" | "CHECKING" | "ATTESTATION_REJECTED">) => {
      const onRetry = vi.fn();
      render(<SecurityVerificationGate status={status} onRetry={onRetry} />);

      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(screen.getByRole("status")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "RETRY" })).toBeInTheDocument();
      expect(document.querySelector(".abyssal-mark-loader")).toHaveClass("is-static");
      fireEvent.click(screen.getByRole("button", { name: "RETRY" }));
      expect(onRetry).toHaveBeenCalledOnce();
    },
  );

  it("keeps the authenticated workspace out of the rejection surface", () => {
    const onRetry = vi.fn();
    const onEndSession = vi.fn();
    render(
      <SecurityVerificationGate
        status="ATTESTATION_REJECTED"
        onRetry={onRetry}
        onEndSession={onEndSession}
      />,
    );

    expect(screen.getByRole("heading", { name: "Build rejected by node" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "END SESSION" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "END SESSION" }));
    expect(onEndSession).toHaveBeenCalledOnce();
  });
});
