import type { NotificationContent } from "../domain/notificationPolicy";

export type NotifierPermission = NotificationPermission | "unsupported";

/** The OS notification surface, behind an interface so tests and other hosts can replace it. */
export interface Notifier {
  permission(): NotifierPermission;
  /** Asks the browser for permission; must run from a user gesture. Resolves true when granted. */
  requestPermission(): Promise<boolean>;
  show(content: NotificationContent, onClick: () => void): void;
  /** Removes every notification this tab raised, for example on lock or sign-out. */
  closeAll(): void;
}

type NotificationApi = Pick<typeof Notification, "permission" | "requestPermission"> &
  (new (title: string, options?: NotificationOptions) => Notification);

export function createBrowserNotifier(api: NotificationApi | undefined = globalThis.Notification): Notifier {
  const open = new Map<string, Notification>();
  return {
    permission: () => (api ? api.permission : "unsupported"),
    requestPermission: async () => {
      if (!api) return false;
      if (api.permission === "granted") return true;
      if (api.permission === "denied") return false;
      try {
        return (await api.requestPermission()) === "granted";
      } catch {
        return false;
      }
    },
    show: (content, onClick) => {
      if (!api || api.permission !== "granted") return;
      open.get(content.tag)?.close();
      let notification: Notification;
      try {
        notification = new api(content.title, { body: content.body, tag: content.tag, silent: false });
      } catch {
        // Some platforms only allow notifications from a service worker; stay quiet there.
        return;
      }
      open.set(content.tag, notification);
      notification.onclick = () => {
        window.focus();
        onClick();
        notification.close();
      };
      notification.onclose = () => {
        if (open.get(content.tag) === notification) open.delete(content.tag);
      };
    },
    closeAll: () => {
      for (const notification of open.values()) notification.close();
      open.clear();
    },
  };
}
