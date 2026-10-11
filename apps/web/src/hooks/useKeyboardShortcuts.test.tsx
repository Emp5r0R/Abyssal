import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useKeyboardShortcuts, type ShortcutHandlers } from "./useKeyboardShortcuts";

function Harness({ handlers, enabled = true }: { handlers: ShortcutHandlers; enabled?: boolean }) {
  useKeyboardShortcuts(handlers, enabled);
  return (
    <>
      <textarea aria-label="Message" />
      <div role="dialog"><input aria-label="Dialog field" /></div>
    </>
  );
}

afterEach(cleanup);

describe("useKeyboardShortcuts", () => {
  it("runs the matching handler and consumes the key", () => {
    const quick = vi.fn();
    render(<Harness handlers={{ "quick-switcher": quick }} />);
    const event = new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true, cancelable: true });
    window.dispatchEvent(event);
    expect(quick).toHaveBeenCalledOnce();
    expect(event.defaultPrevented).toBe(true);
  });

  it("leaves typing, dialogs, unhandled actions and disabled workspaces alone", () => {
    const focus = vi.fn();
    const quick = vi.fn();
    const { getByLabelText, rerender } = render(<Harness handlers={{ "focus-composer": focus, "quick-switcher": quick }} />);
    fireEvent.keyDown(getByLabelText("Message"), { key: "/" });
    expect(focus).not.toHaveBeenCalled();
    fireEvent.keyDown(document.body, { key: "/" });
    expect(focus).toHaveBeenCalledOnce();

    fireEvent.keyDown(getByLabelText("Dialog field"), { key: "k", ctrlKey: true });
    expect(quick).not.toHaveBeenCalled();

    const unhandled = new KeyboardEvent("keydown", { code: "KeyL", altKey: true, shiftKey: true, bubbles: true, cancelable: true });
    window.dispatchEvent(unhandled);
    expect(unhandled.defaultPrevented).toBe(false);

    rerender(<Harness handlers={{ "focus-composer": focus }} enabled={false} />);
    fireEvent.keyDown(document.body, { key: "/" });
    expect(focus).toHaveBeenCalledOnce();
  });
});
