import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DirectVerificationQr } from "./DirectVerificationQr";

const mocks = vi.hoisted(() => ({
  detect: vi.fn<() => Promise<Array<{ rawValue: string }>>>(),
  stop: vi.fn(),
}));

describe("DirectVerificationQr", () => {
  beforeEach(() => {
    mocks.detect.mockReset();
    mocks.stop.mockReset();
    mocks.detect.mockResolvedValue([{ rawValue: "abyssal:verify:v1:peer-token" }]);
    Object.defineProperty(globalThis, "BarcodeDetector", {
      configurable: true,
      value: class {
        static async getSupportedFormats() { return ["qr_code"]; }
        detect() { return mocks.detect(); }
      },
    });
    Object.defineProperty(navigator, "mediaDevices", {
      configurable: true,
      value: {
        getUserMedia: vi.fn(async () => ({
          getTracks: () => [{ stop: mocks.stop }],
        })),
      },
    });
    vi.spyOn(HTMLMediaElement.prototype, "play").mockResolvedValue();
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    Reflect.deleteProperty(globalThis, "BarcodeDetector");
  });

  it("renders locally and stops every camera track after an exact scan", async () => {
    const scanned = vi.fn();
    render(<DirectVerificationQr token="abyssal:verify:v1:local-token" onScanned={scanned} />);
    expect(screen.getByRole("img", { name: "Direct chat verification QR code" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "SCAN PEER QR" }));
    await waitFor(() => expect(scanned).toHaveBeenCalledWith("abyssal:verify:v1:peer-token"));
    expect(mocks.stop).toHaveBeenCalledOnce();
  });

  it("stops active camera tracks when the dialog unmounts", async () => {
    mocks.detect.mockResolvedValue([]);
    const view = render(<DirectVerificationQr token="abyssal:verify:v1:local-token" onScanned={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "SCAN PEER QR" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "STOP CAMERA" })).toBeInTheDocument());
    view.unmount();
    expect(mocks.stop).toHaveBeenCalledOnce();
  });
});
