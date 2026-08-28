import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { initializeSecurityRuntime } from "../security/runtime";
import { SecurityVerificationDialog } from "./SecurityVerificationDialog";

type RuntimeStatus = "CHECKING" | "READY" | "UNAVAILABLE";

export function SecurityRuntimeGate({
  children,
  initialize = initializeSecurityRuntime,
}: {
  children: ReactNode;
  initialize?: () => Promise<void>;
}) {
  const [status, setStatus] = useState<RuntimeStatus>("CHECKING");
  const generationRef = useRef(0);

  const initializeGeneration = useCallback((generation: number) => {
    void initialize().then(
      () => {
        if (generationRef.current === generation) setStatus("READY");
      },
      () => {
        if (generationRef.current === generation) setStatus("UNAVAILABLE");
      },
    );
  }, [initialize]);

  useEffect(() => {
    const generation = ++generationRef.current;
    initializeGeneration(generation);
    return () => { generationRef.current += 1; };
  }, [initializeGeneration]);

  const retry = useCallback(() => {
    const generation = ++generationRef.current;
    setStatus("CHECKING");
    initializeGeneration(generation);
  }, [initializeGeneration]);

  if (status === "READY") return children;
  return (
    <SecurityVerificationDialog
      status={status}
      onRetry={retry}
    />
  );
}
