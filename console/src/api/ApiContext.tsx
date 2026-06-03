import { createContext, useContext, useMemo, type ReactNode } from "react";
import { api as defaultApi, createApi, type ApiClient } from "./client";

const ApiContext = createContext<ApiClient>(defaultApi);

/**
 * Override the API client used by `useApi()` for everything inside
 * `children`. Pass `basePath` to mount a sub-tree against the console
 * federation proxy (e.g. `/api/networks/:id/proxy`); leave it empty
 * and the default same-origin client is used.
 */
export function ApiBaseProvider({
  basePath,
  children,
}: {
  basePath: string;
  children: ReactNode;
}) {
  const client = useMemo(() => createApi(basePath), [basePath]);
  return <ApiContext.Provider value={client}>{children}</ApiContext.Provider>;
}

export function useApi(): ApiClient {
  return useContext(ApiContext);
}
