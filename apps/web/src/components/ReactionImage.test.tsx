import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { REACTIONS } from "../domain/reactions";
import { VerifiedAssetLoader } from "../security/verifiedAssets";
import { ReactionImage } from "./ReactionImage";
import { VerifiedAssetContext } from "./verifiedAssetContext";

const reaction = REACTIONS[0];

function withLoader(objectUrl: VerifiedAssetLoader["objectUrl"]) {
  const loader = new VerifiedAssetLoader({ fetch: vi.fn<typeof fetch>(), origin: "https://abyssal.example" });
  vi.spyOn(loader, "objectUrl").mockImplementation(objectUrl);
  return loader;
}

describe("ReactionImage", () => {
  it("shows the image only from the verified blob URL", async () => {
    const loader = withLoader(async () => "blob:https://abyssal.example/1");
    const { container } = render(
      <VerifiedAssetContext.Provider value={loader}>
        <ReactionImage reaction={reaction} alt={reaction.label} />
      </VerifiedAssetContext.Provider>,
    );
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByRole("img", { name: reaction.label })).not.toHaveAttribute("src");
    await waitFor(() => expect(container.querySelector("img")).toHaveAttribute("src", "blob:https://abyssal.example/1"));
    expect(container.querySelector("img")).toHaveAccessibleName(reaction.label);
    expect(loader.objectUrl).toHaveBeenCalledWith(reaction);
  });

  it("waits until a lazy image is near the viewport before downloading it", async () => {
    const loader = withLoader(async () => "blob:https://abyssal.example/2");
    let notify: IntersectionObserverCallback = () => undefined;
    const observe = vi.fn();
    const disconnect = vi.fn();
    vi.stubGlobal("IntersectionObserver", vi.fn(function (this: unknown, callback: IntersectionObserverCallback) {
      notify = callback;
      return { observe, disconnect };
    }));
    try {
      const { container } = render(
        <VerifiedAssetContext.Provider value={loader}>
          <ReactionImage reaction={reaction} alt="" lazy />
        </VerifiedAssetContext.Provider>,
      );
      expect(observe).toHaveBeenCalledTimes(1);
      expect(loader.objectUrl).not.toHaveBeenCalled();
      act(() => notify([{ isIntersecting: true } as IntersectionObserverEntry], {} as IntersectionObserver));
      await waitFor(() => expect(container.querySelector("img")).toHaveAttribute("src", "blob:https://abyssal.example/2"));
      expect(loader.objectUrl).toHaveBeenCalledTimes(1);
      expect(disconnect).toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("falls back to the shortcode when verification fails", async () => {
    const loader = withLoader(async () => { throw new Error("Asset digest mismatch"); });
    const { container } = render(
      <VerifiedAssetContext.Provider value={loader}>
        <ReactionImage reaction={reaction} alt="" />
      </VerifiedAssetContext.Provider>,
    );
    expect(await screen.findByText(reaction.shortcode)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
