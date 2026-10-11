import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import type { AccountSession } from "./domain/types";

const mocks = vi.hoisted(() => {
  class FakePinGate {
    static readonly create = vi.fn(async () => {
      const gate = new FakePinGate();
      mocks.gates.push(gate);
      return gate;
    });

    destroyed = false;

    destroy(): void {
      this.destroyed = true;
    }
  }

  const session: AccountSession = {
    token: "123e4567-e89b-42d3-a456-426614174000",
    nodeId: "node-one",
    username: "Alice",
    maxRoomsPerUser: 2,
    sessionInactivitySec: 900,
    endpoint: {
      apiBaseUrl: "https://node.example.test",
      wsBaseUrl: "wss://node.example.test",
      displayHost: "node.example.test",
    },
    created: false,
    identityPublicKey: new Uint8Array(608),
    identityPrekeyId: "prekey-one",
  };

  const controller = {
    session: session as AccountSession | null,
    securityWarning: null as "ATTESTATION_REJECTED" | null,
    connection: "connected" as const,
    rooms: [],
    directs: [],
    presence: [],
    messages: {},
    activeRoom: null,
    activeRoomId: null,
    safetyNumber: null,
    remainingSessionSec: 900,
    upload: { active: false, name: "", loaded: 0, total: 0 },
    media: null,
    notice: null as string | null,
    login: vi.fn(),
    logout: vi.fn(async () => undefined),
    clearMemory: vi.fn(),
    clearPrivateView: vi.fn(),
    touchActivity: vi.fn(),
    openRoom: vi.fn(),
    openDirect: vi.fn(),
    markRoomRead: vi.fn(),
    sendText: vi.fn(),
    sendAttachment: vi.fn(),
    viewAttachment: vi.fn(),
    exportAttachment: vi.fn(),
    clearMedia: vi.fn(),
    createRoom: vi.fn(),
    deleteRoom: vi.fn(),
    wipeRelay: vi.fn(),
    clearNotice: vi.fn(),
  };
  const preflight = vi.fn(async (): Promise<{ status: "OK" | "MISMATCH" }> => ({ status: "OK" }));

  return {
    FakePinGate,
    controller,
    preflight,
    gates: [] as FakePinGate[],
    reset: () => {
      controller.session = session;
      controller.securityWarning = null;
      controller.notice = null;
      mocks.gates.length = 0;
      preflight.mockResolvedValue({ status: "OK" });
    },
  };
});

vi.mock("./hooks/useAbyssalSession", () => ({
  useAbyssalSession: () => mocks.controller,
}));

vi.mock("./security/privacyPin", () => ({
  PrivacyPinGate: mocks.FakePinGate,
}));

vi.mock("./security/originAttestation", () => ({
  verifyOriginAttestation: vi.fn().mockResolvedValue({ status: "OK" }),
  verifyOriginPreflight: mocks.preflight,
}));

vi.mock("./components/Entrance", () => ({
  Entrance: ({ onLogin, onPreflight }: {
    onLogin: (...args: unknown[]) => unknown;
    onPreflight: () => Promise<boolean | void>;
  }) => (
    <div data-testid="entrance">
      <button type="button" onClick={async () => {
        if ((await onPreflight()) === false) return;
        await onLogin();
      }}>Enter</button>
    </div>
  ),
}));

vi.mock("./components/AppShell", () => ({
  AppShell: ({ children, canLock, onLock, onOpenSettings }: {
    children?: ReactNode;
    canLock: boolean;
    onLock: () => void;
    onOpenSettings: () => void;
  }) => (
    <div data-testid="workspace">
      <button type="button" onClick={onOpenSettings}>Open settings</button>
      {canLock ? <button type="button" onClick={onLock}>Lock workspace</button> : null}
      {children}
    </div>
  ),
}));

vi.mock("./components/ChatView", () => ({
  ChatView: () => <div data-testid="chat-view" />,
}));

vi.mock("./components/AttachmentDialog", () => ({
  AttachmentDialog: () => <div data-testid="attachment-dialog" />,
}));

vi.mock("./components/CreateRoomDialog", () => ({
  CreateRoomDialog: () => <div data-testid="create-room-dialog" />,
}));

vi.mock("./components/MediaViewer", () => ({
  MediaViewer: () => <div data-testid="media-viewer" />,
}));

vi.mock("./components/Privacy", () => ({
  PinSetup: ({ onComplete, onSkip }: { onComplete: (pin: string, duress: string) => Promise<void>; onSkip?: () => void }) => (
    <div>
      <button type="button" onClick={() => void onComplete("123456", "")}>Configure cover</button>
      <button type="button" onClick={onSkip}>Skip cover</button>
    </div>
  ),
  CalculatorCover: ({ onUnlock, onDuress }: { onUnlock: () => void; onDuress: () => void }) => (
    <div data-testid="calculator-cover">
      <button type="button" onClick={onUnlock}>Unlock</button>
      <button type="button" onClick={onDuress}>Duress</button>
    </div>
  ),
}));

import App from "./App";

function setVisibility(value: "visible" | "hidden"): void {
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value,
  });
}

async function configureCover(): Promise<void> {
  fireEvent.click(await screen.findByRole("button", { name: "Configure cover" }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Configure cover" })).not.toBeInTheDocument());
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.reset();
  setVisibility("visible");
});

afterEach(() => {
  cleanup();
  setVisibility("visible");
});

describe("App privacy lifecycle policy", () => {
  it("locks behind the configured cover while retaining the intentional RAM session", async () => {
    render(<App />);
    await configureCover();

    setVisibility("hidden");
    act(() => document.dispatchEvent(new Event("visibilitychange")));

    expect(screen.getByTestId("calculator-cover")).toBeInTheDocument();
    expect(mocks.controller.clearPrivateView).toHaveBeenCalledOnce();
    expect(mocks.controller.logout).not.toHaveBeenCalled();
  });

  it("signs out when hidden after the cover is skipped", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Skip cover" }));
    expect(screen.queryByRole("button", { name: "Configure cover" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock workspace" })).not.toBeInTheDocument();

    setVisibility("hidden");
    act(() => document.dispatchEvent(new Event("visibilitychange")));

    expect(mocks.controller.logout).toHaveBeenCalledOnce();
    expect(screen.queryByTestId("calculator-cover")).not.toBeInTheDocument();
  });

  it("keeps the session open when the hidden-tab setting is stay signed in", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: "Skip cover" }));
    fireEvent.click(screen.getByRole("button", { name: "Open settings" }));
    expect(screen.getByRole("radio", { name: /Lock behind the calculator/u })).toBeDisabled();
    fireEvent.click(screen.getByRole("radio", { name: /Stay signed in/u }));
    fireEvent.click(screen.getByRole("button", { name: "Done" }));

    setVisibility("hidden");
    act(() => document.dispatchEvent(new Event("visibilitychange")));

    expect(mocks.controller.logout).not.toHaveBeenCalled();
    expect(screen.queryByTestId("calculator-cover")).not.toBeInTheDocument();
  });

  it("destroys the PIN verifier when the cover is turned off and asks for a new PIN when it returns", async () => {
    render(<App />);
    await configureCover();
    const gate = mocks.gates[0];
    fireEvent.click(screen.getByRole("button", { name: "Open settings" }));
    const coverSwitch = screen.getByRole("switch", { name: /Calculator privacy cover/u });
    expect(coverSwitch).toBeChecked();

    fireEvent.click(coverSwitch);
    expect(gate.destroyed).toBe(true);
    expect(screen.queryByRole("button", { name: "Lock workspace" })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("switch", { name: /Calculator privacy cover/u }));
    expect(await screen.findByRole("button", { name: "Configure cover" })).toBeInTheDocument();
  });

  it("locks on demand from the workspace once a PIN exists", async () => {
    render(<App />);
    await configureCover();
    fireEvent.click(screen.getByRole("button", { name: "Lock workspace" }));
    expect(screen.getByTestId("calculator-cover")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    expect(screen.getByTestId("workspace")).toBeInTheDocument();
  });

  it("wipes the relay from settings only after explicit confirmation", async () => {
    render(<App />);
    await configureCover();
    fireEvent.click(screen.getByRole("button", { name: "Open settings" }));
    fireEvent.click(screen.getByRole("button", { name: "Wipe relay…" }));
    expect(mocks.controller.wipeRelay).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Wipe now" }));
    expect(mocks.controller.wipeRelay).toHaveBeenCalledOnce();
    await waitFor(() => expect(mocks.controller.logout).toHaveBeenCalledOnce());
  });

  it("destroys the in-memory verifier and transient view on pagehide", async () => {
    render(<App />);
    await configureCover();
    const gate = mocks.gates[0];
    expect(gate).toBeDefined();

    act(() => window.dispatchEvent(new Event("pagehide")));

    expect(gate.destroyed).toBe(true);
    expect(mocks.controller.clearPrivateView).toHaveBeenCalledOnce();
  });

  it("blocks account entry when the fresh preflight rejects", async () => {
    mocks.controller.session = null;
    mocks.preflight.mockResolvedValue({ status: "MISMATCH" });
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Enter" }));
    await waitFor(() => expect(mocks.preflight).toHaveBeenCalledOnce());
    expect(mocks.controller.login).not.toHaveBeenCalled();
  });

  it("passes account entry to login only after a fresh preflight succeeds", async () => {
    mocks.controller.session = null;
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: "Enter" }));
    await waitFor(() => expect(mocks.controller.login).toHaveBeenCalledOnce());
    expect(mocks.preflight).toHaveBeenCalledOnce();
  });

  it("does not expose the workspace after an authenticated node rejects the build", async () => {
    mocks.controller.securityWarning = "ATTESTATION_REJECTED";
    render(<App />);

    expect(await screen.findByRole("heading", { name: "Build rejected by node" })).toBeInTheDocument();
    expect(screen.queryByTestId("workspace")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("announces notices and exposes a separate dismiss action", async () => {
    mocks.controller.notice = "Action unavailable.";
    render(<App />);
    await configureCover();

    expect(screen.getByRole("status")).toHaveTextContent("Action unavailable.");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss notice" }));
    expect(mocks.controller.clearNotice).toHaveBeenCalledOnce();
  });
});
