import { useQuery } from "@tanstack/react-query";
import { api } from "./api/client";
import type { HostRoleResponse } from "./api/types";
import ConsoleShell from "./shells/ConsoleShell";
import DispatcherShell from "./shells/DispatcherShell";

/**
 * Root component. Probes /api/host-role to decide which shell to
 * mount. The SPA is the same binary asset embedded into the
 * dispatcher / relay / console binaries (plan §3.4), so the
 * decision is "what am I running on top of" and can only be
 * answered by the server.
 */
export default function App() {
  const { data: host, isLoading, error } = useQuery({
    queryKey: ["host-role"],
    queryFn: () => api<HostRoleResponse>("/api/host-role"),
  });

  if (isLoading) {
    return <CenterStatus text="Connecting…" />;
  }
  if (error || !host) {
    return (
      <CenterStatus
        text={`Cannot reach control plane: ${(error as Error | undefined)?.message ?? "unknown"}`}
        tone="error"
      />
    );
  }

  switch (host.role) {
    case "dispatcher":
      return <DispatcherShell host={host} />;
    case "relay":
      return (
        <CenterStatus text="Relay shell — implementation lands later in v1.1." />
      );
    case "console":
      return <ConsoleShell host={host} />;
    default: {
      const _exhaustive: never = host;
      void _exhaustive;
      return <CenterStatus text="Unknown host role" tone="error" />;
    }
  }
}

function CenterStatus({
  text,
  tone = "neutral",
}: {
  text: string;
  tone?: "neutral" | "error";
}) {
  const color = tone === "error" ? "text-red-300" : "text-zinc-400";
  return (
    <div className="grid min-h-screen place-items-center px-6">
      <p className={`font-mono text-sm ${color}`}>{text}</p>
    </div>
  );
}
