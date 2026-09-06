import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DirectVerificationQr } from "./DirectVerificationQr";

const token = `abyssal:verify:v1:${"A".repeat(43)}`;
vi.mock("./QrScanner", () => ({
  QrScanner: ({ onScanned, onClose }: { onScanned: (value: string, signal: AbortSignal) => Promise<boolean>; onClose: () => void }) => (
    <div>
      <button onClick={() => void onScanned(`abyssal:verify:v1:${"A".repeat(43)}`, new AbortController().signal)}>valid</button>
      <button onClick={() => void onScanned("https://evil.example", new AbortController().signal)}>invalid</button>
      <button onClick={onClose}>close</button>
    </div>
  ),
}));
vi.mock("./QrImageInput", () => ({ QrImageInput: () => null }));
afterEach(cleanup);
describe("DirectVerificationQr", () => {
  it("renders locally and passes only a bounded verification token", async () => {
    const scanned = vi.fn();
    render(<DirectVerificationQr token={token} onScanned={scanned} />);
    expect(screen.getByRole("img", { name: "Direct chat verification QR code" })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "SCAN PEER QR" }));
    fireEvent.click(screen.getByText("invalid"));
    expect(scanned).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("valid"));
    await waitFor(() => expect(scanned).toHaveBeenCalledWith(token));
    expect(screen.getByRole("button", { name: "SCAN PEER QR" })).toBeVisible();
  });
  it("cancels camera UI without a verification callback", () => {
    const scanned = vi.fn();
    render(<DirectVerificationQr token={token} onScanned={scanned} />);
    fireEvent.click(screen.getByRole("button", { name: "SCAN PEER QR" }));
    fireEvent.click(screen.getByText("close"));
    expect(scanned).not.toHaveBeenCalled();
  });
});
