import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { SecurityRuntimeGate } from "./components/SecurityRuntimeGate";
import "./styles.css";

const root = document.getElementById("root");
if (!root) throw new Error("Abyssal root unavailable");

createRoot(root).render(
  <StrictMode>
    <SecurityRuntimeGate>
      <App />
    </SecurityRuntimeGate>
  </StrictMode>,
);
