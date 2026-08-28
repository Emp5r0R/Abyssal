import initWasm from "../generated/abyssal_core/abyssal_core";

export interface SecurityRuntime {
  initialize(): Promise<void>;
}

export function createSecurityRuntime(loader: () => Promise<unknown>): SecurityRuntime {
  let ready: Promise<void> | null = null;
  return {
    initialize(): Promise<void> {
      ready ??= loader().then(
        () => undefined,
        (error: unknown) => {
          ready = null;
          throw error;
        },
      );
      return ready;
    },
  };
}

const runtime = createSecurityRuntime(initWasm);

export function initializeSecurityRuntime(): Promise<void> {
  return runtime.initialize();
}
