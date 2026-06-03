// Tiny fetch wrapper.
//
// - Same-origin: dev runs through the Vite proxy, prod runs on the
//   dispatcher itself, so cookies just work without CORS gymnastics.
// - Mutating methods auto-attach the CSRF token. The dispatcher sets
//   `gnet_csrf` as a JS-readable cookie on login; we mirror it into
//   the `X-Csrf-Token` header (double-submit; see dispatcher's
//   `admin/routes/csrf.rs`).
// - 204 No Content returns undefined; everything else .json()s.
// - Non-2xx throws `ApiError` carrying the status + body.

export class ApiError extends Error {
  status: number;
  body: string;
  constructor(status: number, body: string) {
    super(`${status}: ${body}`);
    this.status = status;
    this.body = body;
  }
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const CSRF_COOKIE = "gnet_csrf";
const CSRF_HEADER = "X-Csrf-Token";

export async function api<T = unknown>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers);
  const method = (init?.method ?? "GET").toUpperCase();

  if (!SAFE_METHODS.has(method)) {
    const csrf = readCookie(CSRF_COOKIE);
    if (csrf) headers.set(CSRF_HEADER, csrf);
  }
  if (init?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, {
    credentials: "same-origin",
    ...init,
    method,
    headers,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function readCookie(name: string): string | null {
  const pieces = document.cookie.split(";");
  for (const piece of pieces) {
    const trimmed = piece.trim();
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    if (trimmed.slice(0, eq) === name) {
      return decodeURIComponent(trimmed.slice(eq + 1));
    }
  }
  return null;
}
