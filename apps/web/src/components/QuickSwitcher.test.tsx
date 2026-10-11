import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ConversationEntry } from "../domain/displayLabels";
import { QuickSwitcher } from "./QuickSwitcher";
import { ShortcutsDialog } from "./ShortcutsDialog";

const conversations: ConversationEntry[] = [
  { id: "forum_ops", kind: "room", label: "Operations", searchText: "forum_ops" },
  { id: "dm_1", kind: "direct", label: "SilverComet", searchText: "acct_10ba" },
  { id: "dm_2", kind: "direct", label: "334a…9f94", searchText: "acct_334a" },
];

afterEach(cleanup);

describe("QuickSwitcher", () => {
  it("filters as you type and opens the highlighted conversation with Enter", () => {
    const onOpen = vi.fn();
    const onClose = vi.fn();
    render(<QuickSwitcher conversations={conversations} onOpen={onOpen} onClose={onClose} />);
    const search = screen.getByLabelText("Search conversations");
    expect(search).toHaveFocus();
    expect(screen.getAllByRole("option")).toHaveLength(3);

    fireEvent.change(search, { target: { value: "acct" } });
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["SilverCometDirect", "334a…9f94Direct"]);
    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(screen.getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(screen.getAllByRole("option")[0]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(search, { key: "ArrowUp" });
    fireEvent.keyDown(search, { key: "Enter" });
    expect(onOpen).toHaveBeenCalledWith("dm_2");
    expect(onClose).toHaveBeenCalled();
  });

  it("opens on click and explains an empty result", () => {
    const onOpen = vi.fn();
    render(<QuickSwitcher conversations={conversations} onOpen={onOpen} onClose={vi.fn()} />);
    fireEvent.click(screen.getByText("Operations"));
    expect(onOpen).toHaveBeenCalledWith("forum_ops");
    fireEvent.change(screen.getByLabelText("Search conversations"), { target: { value: "zzz" } });
    expect(screen.getByText("No conversations match.")).toBeVisible();
    fireEvent.keyDown(screen.getByLabelText("Search conversations"), { key: "Enter" });
    expect(onOpen).toHaveBeenCalledTimes(1);
  });
});

describe("ShortcutsDialog", () => {
  it("lists every shortcut with its keys", () => {
    render(<ShortcutsDialog onClose={vi.fn()} />);
    expect(screen.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    expect(screen.getByText("Jump to a conversation")).toBeVisible();
    expect(screen.getByText("Lock behind the calculator").nextElementSibling?.textContent).toBe("AltShiftL");
  });
});
