export interface ReleaseBuildIdentity {
  buildId: string;
  buildSignatureB64: string;
  sourceCommit: string;
  configured: boolean;
}

export interface BuildAttestation {
  platform: "web";
  version: string;
  build_signature_b64: string;
}

export const RELEASE_BUILD_IDENTITY: Readonly<ReleaseBuildIdentity> = Object.freeze({
  buildId: __ABYSSAL_BUILD_ID__,
  buildSignatureB64: __ABYSSAL_BUILD_SIGNATURE_B64__,
  sourceCommit: __ABYSSAL_SOURCE_COMMIT__,
  configured: __ABYSSAL_BUILD_SIGNATURE_B64__.length > 0,
});

export function currentBuildAttestation(): BuildAttestation {
  const match = /^web@((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$/u
    .exec(RELEASE_BUILD_IDENTITY.buildId);
  if (!match || !RELEASE_BUILD_IDENTITY.configured ||
    !/^[A-Za-z0-9_-]{86}$/u.test(RELEASE_BUILD_IDENTITY.buildSignatureB64)) {
    return { platform: "web", version: "0.0.0", build_signature_b64: "" };
  }
  return {
    platform: "web",
    version: match[1],
    build_signature_b64: RELEASE_BUILD_IDENTITY.buildSignatureB64,
  };
}
