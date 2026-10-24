import { useCallback, useEffect, useRef } from "react";
import { solveChallengeWorkers } from "altcha/lib";
import type { Challenge } from "altcha/lib";
import pbkdf2WorkerUrl from "altcha/workers/pbkdf2?url";

/**
 * Invisible proof-of-work for the endpoints that send mail.
 *
 * A challenge is fetched and solved in web workers as soon as the
 * form mounts, so by the time the user has typed an email the answer
 * is usually ready. `take()` hands out the answer (waiting for it if
 * needed) and immediately starts on the next one, since every answer
 * is single-use on the server.
 *
 * When the server has the check turned off, the challenge endpoint
 * answers 404 and `take()` resolves to `undefined`.
 */
export type HumanCheckScope = "register" | "resend" | "forgot";

// refetch this long before the server-side expiry
const EXPIRY_MARGIN_MS = 30_000;

async function solveOnce(
  scope: HumanCheckScope,
  controller: AbortController,
): Promise<{ payload?: string; expiresAt?: number }> {
  const res = await fetch(`/api/auth/challenge?scope=${scope}`, {
    credentials: "same-origin",
    signal: controller.signal,
  });
  if (res.status === 404) return {};
  if (!res.ok) throw new Error(`challenge: ${res.status}`);
  const challenge = (await res.json()) as Challenge;
  const solution = await solveChallengeWorkers({
    challenge,
    controller,
    // chrome runs webcrypto pbkdf2 serially across workers; measured
    // 1 vs 16 workers at the same ~2.5 s, so more buys nothing
    concurrency: 2,
    createWorker: () => new Worker(pbkdf2WorkerUrl),
  });
  if (!solution) throw new Error("challenge: not solved");
  const payload = btoa(
    JSON.stringify({
      challenge: {
        parameters: challenge.parameters,
        signature: challenge.signature,
      },
      solution,
    }),
  );
  const exp = challenge.parameters.expiresAt;
  return { payload, expiresAt: exp ? exp * 1000 : undefined };
}

type Attempt = { result: Promise<string | undefined>; controller: AbortController };

export function useHumanCheck(scope: HumanCheckScope) {
  const current = useRef<Attempt | null>(null);
  const live = useRef(new Set<AbortController>());
  const timer = useRef<number | undefined>(undefined);

  const begin = useCallback(() => {
    window.clearTimeout(timer.current);
    const controller = new AbortController();
    live.current.add(controller);
    const result = solveOnce(scope, controller)
      .then(({ payload, expiresAt }) => {
        if (expiresAt && current.current?.controller === controller) {
          // still unused near expiry: swap in a fresh one
          timer.current = window.setTimeout(
            () => {
              if (current.current?.controller !== controller) return;
              controller.abort();
              begin();
            },
            Math.max(expiresAt - Date.now() - EXPIRY_MARGIN_MS, 0),
          );
        }
        return payload;
      })
      .finally(() => live.current.delete(controller));
    // a failure surfaces through take(); don't report it twice
    result.catch(() => {});
    current.current = { result, controller };
  }, [scope]);

  useEffect(() => {
    const controllers = live.current;
    begin();
    return () => {
      window.clearTimeout(timer.current);
      controllers.forEach((c) => c.abort());
      current.current = null;
    };
  }, [begin]);

  /**
   * The next single-use answer. The one after it starts only once this
   * one is settled: solves share one serial pbkdf2 queue, so starting
   * early would double the wait for the answer the user is waiting on.
   */
  return useCallback(async (): Promise<string | undefined> => {
    if (!current.current) begin();
    const mine = current.current!;
    // detach so the expiry timer leaves it alone
    current.current = null;
    try {
      return await mine.result;
    } catch {
      begin();
      const retry = current.current!;
      current.current = null;
      return await retry.result;
    } finally {
      if (!current.current) begin();
    }
  }, [begin]);
}
