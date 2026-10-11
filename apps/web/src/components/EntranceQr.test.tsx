import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Entrance } from "./Entrance";
import { QR_TEST_INVITE } from "../test/qrFixture";

const camera = vi.hoisted(() => ({ accept: undefined as undefined | ((value: string, signal: AbortSignal) => Promise<boolean>) }));
const image = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("../security/runtime", () => ({ initializeSecurityRuntime: vi.fn(async () => undefined) }));
vi.mock("../security/qrImage", () => ({ readQrImage: image.read }));
vi.mock("./QrScanner", () => ({ QrScanner: ({ onScanned, onClose }: {
  onScanned: typeof camera.accept; onClose: () => void;
}) => { camera.accept = onScanned; return <button onClick={onClose}>Close camera</button>; } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); camera.accept = undefined; });

describe("invite QR entry", () => {
  it("requires a valid signature and explicit submit; scanning cannot authenticate", async () => {
    const onLogin = vi.fn(async () => ({}) as never);
    const onPreflight = vi.fn(async () => true);
    render(<Entrance onLogin={onLogin} onPreflight={onPreflight} />);
    fireEvent.click(screen.getByRole("button", { name: "Scan invite" }));
    await act(async () => {
      for (const value of ["file:///etc/passwd", "https://evil.example", QR_TEST_INVITE.slice(0, -1) + "A"]) {
        expect(await camera.accept!(value, new AbortController().signal)).toBe(false);
      }
    });
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue("");
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password123" } });
    fireEvent.submit(document.querySelector("form")!);
    expect(onPreflight).not.toHaveBeenCalled();
    await act(async () => { expect(await camera.accept!(QR_TEST_INVITE, new AbortController().signal)).toBe(true); });
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue(QR_TEST_INVITE);
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(document.body.textContent).not.toContain(QR_TEST_INVITE);
    expect(onLogin).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(onLogin).toHaveBeenCalledOnce());
    expect(onLogin).toHaveBeenCalledWith(expect.objectContaining({ invite: QR_TEST_INVITE }));
  });

  it("rejects late verification after closing the camera", async () => {
    render(<Entrance onLogin={vi.fn()} onPreflight={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Scan invite" }));
    let result: Promise<boolean>;
    await act(async () => {
      result = camera.accept!(QR_TEST_INVITE, new AbortController().signal);
      fireEvent.click(screen.getByRole("button", { name: "Close camera" }));
      expect(await result).toBe(false);
    });
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue("");
  });

  it("blocks submit during image reads and cancels late image results on pagehide", async () => {
    let finish!: (value: string) => void;
    image.read.mockImplementation(() => new Promise<string>((resolve) => { finish = resolve; }));
    const login = vi.fn();
    const preflight = vi.fn();
    render(<Entrance onLogin={login} onPreflight={preflight} />);
    fireEvent.change(screen.getByLabelText("Abyssal invite"), { target: { value: QR_TEST_INVITE } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password123" } });
    fireEvent.change(screen.getByLabelText("QR image"), { target: { files: [new File(["bytes"], "../qr.png", { type: "image/png" })] } });
    expect(screen.getByRole("button", { name: "Reading image…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reading image…" }).querySelector(".abyssal-mark-loader")).not.toBeNull();
    fireEvent.submit(document.querySelector("form")!);
    expect(preflight).not.toHaveBeenCalled();
    fireEvent(window, new Event("pagehide"));
    expect(image.read.mock.calls[0][1].aborted).toBe(true);
    await act(async () => { finish("replacement"); });
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue(QR_TEST_INVITE);
    expect(login).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Open QR image" })).toBeEnabled();
  });

  it("reports invalid image data without changing invite or navigating", async () => {
    image.read.mockResolvedValue("intent://arbitrary");
    const view = render(<Entrance onLogin={vi.fn()} onPreflight={vi.fn()} />);
    fireEvent.change(screen.getByLabelText("QR image"), { target: { files: [new File(["data"], "qr.png")] } });
    await waitFor(() => expect(screen.getByText("No valid QR code found in that image.")).toBeVisible());
    expect(screen.getByLabelText("Abyssal invite")).toHaveValue("");
    expect(document.body.textContent).not.toContain("intent://arbitrary");
    view.unmount();
    expect(image.read.mock.calls[0][1].aborted).toBe(false);
  });

  it("scans a pasted screenshot but leaves text pasted into a field alone", async () => {
    image.read.mockResolvedValue(QR_TEST_INVITE);
    render(<Entrance onLogin={vi.fn()} onPreflight={vi.fn()} />);
    const screenshot = new File(["png"], "image.png", { type: "image/png" });

    fireEvent.paste(screen.getByLabelText("Password"), { clipboardData: { files: [screenshot], getData: () => "hunter2" } });
    expect(image.read).not.toHaveBeenCalled();

    fireEvent.paste(document.body, { clipboardData: { files: [new File(["gif"], "a.gif", { type: "image/gif" })], getData: () => "" } });
    expect(await screen.findByText("Paste a PNG or JPEG image of the QR code.")).toBeVisible();
    expect(image.read).not.toHaveBeenCalled();

    fireEvent.paste(document.body, { clipboardData: { files: [screenshot], getData: () => "" } });
    await waitFor(() => expect(screen.getByLabelText("Abyssal invite")).toHaveValue(QR_TEST_INVITE));
    expect(image.read).toHaveBeenCalledWith(screenshot, expect.any(AbortSignal));
  });

  it("scans an image dropped onto the QR image control", async () => {
    image.read.mockResolvedValue(QR_TEST_INVITE);
    render(<Entrance onLogin={vi.fn()} onPreflight={vi.fn()} />);
    const dropped = new File(["jpg"], "photo.jpg", { type: "image/jpeg" });
    fireEvent.drop(document.querySelector(".qr-image-input")!, { dataTransfer: { files: [dropped], types: ["Files"] } });
    await waitFor(() => expect(screen.getByLabelText("Abyssal invite")).toHaveValue(QR_TEST_INVITE));
  });

  it("keeps a successful image invite masked, including after a login error", async () => {
    image.read.mockResolvedValue(QR_TEST_INVITE);
    const onLogin = vi.fn(async () => { throw new Error(QR_TEST_INVITE); });
    render(<Entrance onLogin={onLogin} onPreflight={vi.fn(async () => true)} />);
    fireEvent.change(screen.getByLabelText("QR image"), { target: { files: [new File(["data"], "qr.png")] } });
    await waitFor(() => expect(screen.getByLabelText("Abyssal invite")).toHaveValue(QR_TEST_INVITE));
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(onLogin).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password123" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(screen.getByText("Sign-in failed. Check the invite and password.")).toBeVisible());
    expect(screen.getByLabelText("Abyssal invite")).toHaveAttribute("type", "password");
    expect(document.body.textContent).not.toContain(QR_TEST_INVITE);
  });
});
