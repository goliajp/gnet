import { Link } from "react-router";
import type { ConsoleHost } from "../../shells/ConsoleShell";

/**
 * Public marketing landing for gnet.golia.jp.
 *
 * Three sections, all visible without sign-in:
 *
 *   - hero: what gnet is, in one sentence
 *   - three pillars: post-quantum, self-host-friendly, SaaS-managed
 *   - sign-in / sign-up CTAs (or "open dashboard" when already authed)
 *
 * Intentionally typographic — no images, no chrome — to keep
 * load light and the binary-embed size down.
 */
export default function Landing({
  host,
  authed,
}: {
  host: ConsoleHost;
  authed: boolean;
}) {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <Header />

      <main className="mx-auto max-w-4xl px-6 pb-24 pt-16 sm:pt-24">
        {/* Hero */}
        <section className="space-y-6">
          <p className="font-mono text-xs uppercase tracking-[0.2em] text-zinc-500">
            gnet · v{host.version}
          </p>
          <h1 className="text-4xl font-semibold leading-tight text-zinc-100 sm:text-5xl">
            A mesh overlay you actually own.
          </h1>
          <p className="max-w-2xl text-base leading-relaxed text-zinc-400 sm:text-lg">
            Post-quantum, hand-rolled, WireGuard-class. Self-host the entire
            control plane on your own boxes, or sign in here and let us run it
            for you. Either way, the daemons on your machines never depend on
            this site to keep talking.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            {authed ? (
              <PrimaryLink to="/dashboard">Open dashboard →</PrimaryLink>
            ) : (
              <>
                <PrimaryLink to="/signup">Create an account</PrimaryLink>
                <SecondaryLink to="/login">Sign in</SecondaryLink>
              </>
            )}
          </div>
        </section>

        {/* Three pillars */}
        <section className="mt-20 grid gap-10 sm:grid-cols-3">
          <Pillar
            title="Post-quantum"
            body="Noise_IK + ML-KEM-768 hybrid. Every primitive hand-written and KAT-validated against the published vectors."
          />
          <Pillar
            title="Self-host first"
            body="docker compose up brings up the dispatcher, relay, PG, and Valkey. No SaaS dependency. The open-source line is the whole product."
          />
          <Pillar
            title="Hybrid when you want it"
            body="Federate your self-host dispatcher with this console and operate it through a single SaaS UI. Revoke from either side; the path goes cold immediately."
          />
        </section>

        {/* Open source link */}
        <section className="mt-20 border-t border-zinc-800 pt-8">
          <p className="font-mono text-xs text-zinc-500">
            Source on{" "}
            <a
              className="text-zinc-300 underline-offset-4 hover:underline"
              href="https://github.com/goliajp/gnet"
              target="_blank"
              rel="noreferrer noopener"
            >
              github.com/goliajp/gnet
            </a>
            . MIT or Apache-2.0, your pick.
          </p>
        </section>
      </main>
    </div>
  );
}

function Header() {
  return (
    <header className="mx-auto flex max-w-4xl items-center justify-between px-6 pt-8 font-mono text-sm">
      <Link to="/" className="font-semibold text-zinc-100">
        gnet
      </Link>
      <nav className="flex items-center gap-5 text-zinc-400">
        <Link to="/login" className="hover:text-zinc-200">
          sign in
        </Link>
        <Link
          to="/signup"
          className="rounded-md bg-zinc-100 px-3 py-1.5 text-zinc-950 hover:bg-white"
        >
          sign up
        </Link>
      </nav>
    </header>
  );
}

function Pillar({ title, body }: { title: string; body: string }) {
  return (
    <div className="space-y-2">
      <h2 className="font-mono text-sm uppercase tracking-[0.18em] text-zinc-300">
        {title}
      </h2>
      <p className="text-sm leading-relaxed text-zinc-400">{body}</p>
    </div>
  );
}

function PrimaryLink({
  to,
  children,
}: {
  to: string;
  children: React.ReactNode;
}) {
  return (
    <Link
      to={to}
      className="inline-flex items-center rounded-md bg-zinc-100 px-4 py-2 font-mono text-sm font-medium text-zinc-950 transition hover:bg-white"
    >
      {children}
    </Link>
  );
}

function SecondaryLink({
  to,
  children,
}: {
  to: string;
  children: React.ReactNode;
}) {
  return (
    <Link
      to={to}
      className="inline-flex items-center rounded-md border border-zinc-700 bg-transparent px-4 py-2 font-mono text-sm font-medium text-zinc-200 transition hover:border-zinc-500 hover:text-zinc-100"
    >
      {children}
    </Link>
  );
}
