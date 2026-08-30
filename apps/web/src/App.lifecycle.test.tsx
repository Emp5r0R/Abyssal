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
    notice: null,
    retainWhenHiddenRef: { current: true },
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
      controller.retainWhenHiddenRef.current = true;
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
  AppShell: ({ children }: { children?: ReactNode }) => <div data-testid="workspace">{children}</div>,
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
  PinSetup: ({ onComplete }: { onComplete: (pin: string, duress: string) => Promise<void> }) => (
    <button type="button" onClick={() => void onComplete("123456", "")}>Configure cover</button>
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

  it("logs out when hidden-session retention is disabled", async () => {
    mocks.controller.retainWhenHiddenRef.current = false;
    render(<App />);
    await configureCover();

    setVisibility("hidden");
    act(() => document.dispatchEvent(new Event("visibilitychange")));

    expect(mocks.controller.logout).toHaveBeenCalledOnce();
    expect(mocks.controller.clearPrivateView).not.toHaveBeenCalled();
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
    expect(screen.getByRole("button", { name: "END SESSION" })).toBeInTheDocument();
  });
});
