import { useEffect, useRef, useState } from "react";
import type { ReactionAsset } from "../domain/reactions";
import { useVerifiedAssetUrl } from "./verifiedAssetContext";

/**
 * Renders a bundled reaction only after its bytes match the digest compiled into the verified bundle.
 * A lazy image waits until it scrolls near the viewport before downloading.
 */
export function ReactionImage({ reaction, alt, lazy = false }: { reaction: ReactionAsset; alt: string; lazy?: boolean }) {
  const [visible, setVisible] = useState(() => !lazy || typeof IntersectionObserver === "undefined");
  const placeholderRef = useRef<HTMLSpanElement>(null);
  const state = useVerifiedAssetUrl(reaction, visible);

  useEffect(() => {
    const node = placeholderRef.current;
    if (visible || !node) return;
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      observer.disconnect();
      setVisible(true);
    }, { rootMargin: "200px" });
    observer.observe(node);
    return () => observer.disconnect();
  }, [visible]);

  if (state.status === "ready") return <img src={state.url} alt={alt} />;
  return (
    <span
      ref={placeholderRef}
      className={`reaction-placeholder${state.status === "failed" ? " is-failed" : ""}`}
      role={alt ? "img" : undefined}
      aria-label={alt || undefined}
      aria-hidden={alt ? undefined : true}
    >
      {state.status === "failed" ? reaction.shortcode : null}
    </span>
  );
}
