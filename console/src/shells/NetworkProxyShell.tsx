import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router";
import { ApiBaseProvider } from "../api/ApiContext";
import { createApi } from "../api/client";
import type { HostRoleResponse } from "../api/types";
import DispatcherShell, { type DispatcherHost } from "./DispatcherShell";

/**
 * Mount the dispatcher SPA over the federation proxy.
 *
 * `/networks/:id` lives on the SaaS console origin. Every request
 * the dispatcher shell makes goes through the console backend's
 * `/api/networks/:id/proxy/*` route (see
 * `crates/gnet-console/src/routes/proxy.rs`), which attaches the
 * deterministic federation Bearer token and forwards to the
 * dispatcher behind the network.
 *
 * Host detection: `App.tsx` already resolved we're on the console
 * binary. We probe the *dispatcher's* host-role separately, through
 * the proxy, so `DispatcherShell` gets a real `DispatcherHost`
 * (version, network_name, network_id) rather than a synthesized one.
 */
export default function NetworkProxyShell() {
  const { id } = useParams<{ id: string }>();
  if (!id) {
    return <FatalNotice text="missing network id" />;
  }
  const basePath = `/api/networks/${id}/proxy`;
  return (
    <ApiBaseProvider basePath={basePath}>
      <NetworkProxyShellInner basePath={basePath} networkId={id} />
    </ApiBaseProvider>
  );
}

function NetworkProxyShellInner({
  basePath,
  networkId,
}: {
  basePath: string;
  networkId: string;
}) {
  // Probe the dispatcher's host-role through the proxy. Done with a
  // fresh proxy-scoped client so this query's cache key can be
  // network-specific without leaking into the outer console's
  // ["host-role"] entry.
  const proxyApi = createApi(basePath);
  const host = useQuery({
    queryKey: ["proxy-host-role", networkId],
    queryFn: () => proxyApi<HostRoleResponse>("/api/host-role"),
  });

  if (host.isLoading) {
    return (
      <div className="grid min-h-screen place-items-center font-mono text-sm text-zinc-400">
        …
      </div>
    );
  }
  if (host.error || !host.data) {
    return (
      <FatalNotice
        text={`Cannot reach dispatcher: ${(host.error as Error | undefined)?.message ?? "unknown"}`}
        tone="error"
      />
    );
  }
  if (host.data.role !== "dispatcher") {
    return (
      <FatalNotice
        text={`Federation endpoint reports role=${host.data.role}, expected dispatcher.`}
        tone="error"
      />
    );
  }
  return <DispatcherShell host={host.data as DispatcherHost} mode="proxy" />;
}

function FatalNotice({
  text,
  tone = "neutral",
}: {
  text: string;
  tone?: "neutral" | "error";
}) {
  const color = tone === "error" ? "text-red-300" : "text-zinc-400";
  return (
    <div className="grid min-h-screen place-items-center px-6 font-mono text-sm">
      <div className="max-w-md space-y-3 text-center">
        <p className={color}>{text}</p>
        <p className="text-xs text-zinc-500">
          <Link to="/dashboard" className="underline hover:text-zinc-300">
            back to dashboard
          </Link>
        </p>
      </div>
    </div>
  );
}
