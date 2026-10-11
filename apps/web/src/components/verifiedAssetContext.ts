import { createContext, useContext, useEffect, useState } from "react";
import { VerifiedAssetLoader, type VerifiableAsset } from "../security/verifiedAssets";

/** Overrides the page-wide loader, for tests and isolated previews. */
export const VerifiedAssetContext = createContext<VerifiedAssetLoader | null>(null);

let sharedLoader: VerifiedAssetLoader | null = null;

export function useVerifiedAssets(): VerifiedAssetLoader {
  const injected = useContext(VerifiedAssetContext);
  if (injected) return injected;
  sharedLoader ??= new VerifiedAssetLoader();
  return sharedLoader;
}

export type VerifiedAssetState = { status: "loading" } | { status: "ready"; url: string } | { status: "failed" };

/** A `blob:` URL over the verified asset once its digest matches; never the raw served URL. */
export function useVerifiedAssetUrl(asset: VerifiableAsset, enabled = true): VerifiedAssetState {
  const loader = useVerifiedAssets();
  const [state, setState] = useState<{ key: string; value: VerifiedAssetState }>({ key: "", value: { status: "loading" } });
  const key = `${asset.path}\0${asset.sha256Hex}`;
  useEffect(() => {
    if (!enabled) return;
    let active = true;
    loader.objectUrl(asset).then(
      (url) => { if (active) setState({ key, value: { status: "ready", url } }); },
      () => { if (active) setState({ key, value: { status: "failed" } }); },
    );
    return () => { active = false; };
  }, [asset, enabled, key, loader]);
  return state.key === key ? state.value : { status: "loading" };
}
