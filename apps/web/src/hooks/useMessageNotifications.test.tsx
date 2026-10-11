import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { NotificationLevel } from "../domain/notificationPolicy";
import type { ChatMessage } from "../domain/types";
import { createBrowserNotifier, type Notifier } from "../platform/notifier";
import { useMessageNotifications } from "./useMessageNotifications";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const message = (id: string, overrides: Partial<ChatMessage> = {}): ChatMessage => ({
  id, chatId: "dm_1", sender: "acct_peer", content: `text ${id}`, kind: "text",
  createdAtMs: 1, receivedAtMs: 1, selfDestructSec: 0, absoluteExpirySec: 0, mine: false, ...overrides,
});

function fakeNotifier() {
  return {
    permission: () => "granted" as const,
    requestPermission: async () => true,
    show: vi.fn<Notifier["show"]>(),
    closeAll: vi.fn<Notifier["closeAll"]>(),
  } satisfies Notifier;
}

function Harness(props: {
  notifier: Notifier;
  messages: Record<string, ChatMessage[]>;
  level?: NotificationLevel;
  enabled?: boolean;
  locked?: boolean;
  onOpen?: (chatId: string) => void;
}) {
  useMessageNotifications({
    notifier: props.notifier,
    enabled: props.enabled ?? true,
    level: props.level ?? "preview",
    locked: props.locked ?? false,
    activeChatId: null,
    messages: props.messages,
    labelsFor: () => ({ sender: "Peer", conversation: null }),
    onOpen: props.onOpen ?? (() => undefined),
  });
  return null;
}

describe("useMessageNotifications", () => {
  it("notifies only about messages that arrive after it starts", () => {
    const notifier = fakeNotifier();
    const onOpen = vi.fn();
    const view = render(<Harness notifier={notifier} messages={{ dm_1: [message("old")] }} onOpen={onOpen} />);
    expect(notifier.show).not.toHaveBeenCalled();

    view.rerender(<Harness notifier={notifier} messages={{ dm_1: [message("old"), message("new"), message("mine", { mine: true })] }} onOpen={onOpen} />);
    expect(notifier.show).toHaveBeenCalledOnce();
    expect(notifier.show.mock.calls[0][0]).toEqual({ title: "Peer", body: "text new", tag: "abyssal-dm_1" });
    notifier.show.mock.calls[0][1]();
    expect(onOpen).toHaveBeenCalledWith("dm_1");
  });

  it("keeps tracking while off, so turning it on never replays a backlog", () => {
    const notifier = fakeNotifier();
    const view = render(<Harness notifier={notifier} level="off" messages={{}} />);
    view.rerender(<Harness notifier={notifier} level="off" messages={{ dm_1: [message("a")] }} />);
    view.rerender(<Harness notifier={notifier} level="sender" messages={{ dm_1: [message("a")] }} />);
    expect(notifier.show).not.toHaveBeenCalled();
    view.rerender(<Harness notifier={notifier} level="sender" messages={{ dm_1: [message("a"), message("b")] }} />);
    expect(notifier.show).toHaveBeenCalledOnce();
  });

  it("clears notifications on lock and sign-out and stays silent while locked", () => {
    const notifier = fakeNotifier();
    const view = render(<Harness notifier={notifier} messages={{}} />);
    view.rerender(<Harness notifier={notifier} locked messages={{ dm_1: [message("a")] }} />);
    expect(notifier.show).not.toHaveBeenCalled();
    expect(notifier.closeAll).toHaveBeenCalled();
    notifier.closeAll.mockClear();
    view.rerender(<Harness notifier={notifier} enabled={false} messages={{}} />);
    expect(notifier.closeAll).toHaveBeenCalled();
  });
});

describe("browser notifier", () => {
  function fakeApi(permission: NotificationPermission, requested: NotificationPermission = "granted") {
    const created: Array<{ title: string; options?: NotificationOptions; close: ReturnType<typeof vi.fn>; onclick: null | (() => void) }> = [];
    const Api = vi.fn(function (this: unknown, title: string, options?: NotificationOptions) {
      const instance = { title, options, close: vi.fn(), onclick: null as null | (() => void), onclose: null };
      created.push(instance);
      return instance;
    }) as unknown as typeof Notification;
    Object.assign(Api, { permission, requestPermission: vi.fn(async () => requested) });
    return { Api, created };
  }

  it("asks for permission only when it is undecided", async () => {
    expect(await createBrowserNotifier(fakeApi("granted").Api).requestPermission()).toBe(true);
    expect(await createBrowserNotifier(fakeApi("denied").Api).requestPermission()).toBe(false);
    expect(await createBrowserNotifier(fakeApi("default", "denied").Api).requestPermission()).toBe(false);
    expect(await createBrowserNotifier(fakeApi("default", "granted").Api).requestPermission()).toBe(true);
    const unsupported = createBrowserNotifier(undefined);
    expect(unsupported.permission()).toBe("unsupported");
    expect(await unsupported.requestPermission()).toBe(false);
  });

  it("replaces a conversation's notification, opens it on click and closes all", () => {
    vi.spyOn(window, "focus").mockImplementation(() => undefined);
    const { Api, created } = fakeApi("granted");
    const notifier = createBrowserNotifier(Api);
    const onClick = vi.fn();
    notifier.show({ title: "A", body: "1", tag: "abyssal-dm_1" }, onClick);
    notifier.show({ title: "A", body: "2", tag: "abyssal-dm_1" }, onClick);
    expect(created[0].close).toHaveBeenCalled();
    expect(created[1].options).toMatchObject({ body: "2", tag: "abyssal-dm_1" });
    created[1].onclick!();
    expect(onClick).toHaveBeenCalledOnce();
    notifier.show({ title: "B", body: "3", tag: "abyssal-dm_2" }, onClick);
    notifier.closeAll();
    expect(created[2].close).toHaveBeenCalled();
  });

  it("shows nothing without permission", () => {
    const { Api, created } = fakeApi("default");
    createBrowserNotifier(Api).show({ title: "A", body: "1", tag: "t" }, vi.fn());
    expect(created).toHaveLength(0);
  });
});
