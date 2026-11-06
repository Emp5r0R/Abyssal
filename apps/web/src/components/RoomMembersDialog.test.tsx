import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RoomMembersDialog } from "./RoomMembersDialog";

afterEach(cleanup);

const owner = "acct_00000000000000000000000000000001";
const alice = "acct_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("room members", () => {
  it("lets only the owner remove other members, after confirming", async () => {
    const onRemove = vi.fn().mockResolvedValue(true);
    render(
      <RoomMembersDialog
        members={[alice, owner]}
        ownerUsername={owner}
        username={owner}
        displayNames={new Map([[alice, "Alice"]])}
        connected
        onRemove={onRemove}
        onClose={vi.fn()}
      />,
    );
    expect(screen.getByText("Members (2)")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /^Remove / })).toHaveLength(1);

    fireEvent.click(screen.getByRole("button", { name: "Remove Alice" }));
    expect(screen.getByText("Remove from room?")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(onRemove).toHaveBeenCalledWith(alice));
    await waitFor(() => expect(screen.getByText("Members (2)")).toBeInTheDocument());
  });

  it("shows no remove buttons to other members and reports a failed removal", async () => {
    const { unmount } = render(
      <RoomMembersDialog members={[alice, owner]} ownerUsername={owner} username={alice} displayNames={new Map()} connected onRemove={vi.fn()} onClose={vi.fn()} />,
    );
    expect(screen.queryAllByRole("button", { name: /^Remove / })).toHaveLength(0);
    unmount();

    render(
      <RoomMembersDialog
        members={[alice, owner]}
        ownerUsername={owner}
        username={owner}
        displayNames={new Map()}
        connected
        onRemove={vi.fn().mockResolvedValue(false)}
        onClose={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /^Remove / }));
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Could not remove");
  });
});
