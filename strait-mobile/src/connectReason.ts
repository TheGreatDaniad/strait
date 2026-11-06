// Exact sentences from nat-tunnel/src/transport.rs `impl Display for ConnectError`.
// __tests__/rustContract.test.ts fails if the Rust wording drifts from these.
export const REASON_SYMMETRIC = 'Direct path unavailable - both networks are symmetric.';
export const REASON_UNREACHABLE = 'Host unreachable - check the invite or UDP reachability.';
export const REASON_NO_IPV6 = 'No IPv6 on this network; the host is IPv6-only.';
export const REASON_NO_RENDEZVOUS =
  'None of the ways listed in the invite to find the host are available on this device.';
// RendezvousFailed(s): the dynamic part `s` sits between these two fixed halves.
export const RV_FAILED_PREFIX = 'The host could not be found or reached through ';
export const RV_FAILED_SUFFIX =
  '. Check that they are sharing and that these services work from your network.';
export const KNOWN_REASONS = [REASON_SYMMETRIC, REASON_UNREACHABLE, REASON_NO_IPV6, REASON_NO_RENDEZVOUS];

// The full RendezvousFailed sentence (`...through trk: no peer; nostr: ...<suffix>`), if present.
const RV_FAILED = new RegExp(`${RV_FAILED_PREFIX}.*?${RV_FAILED_SUFFIX.replace(/[.]/g, '\\.')}`);

// Native messages are the Rust `error: <sentence>` line (or a bare sentence); anything
// that is not a known ConnectError sentence (e.g. an Io error) passes through as-is.
export function failureReason(message: string | undefined): string {
  const m = (message ?? '').trim().replace(/^error:\s*/i, '');
  const rv = RV_FAILED.exec(m);
  if (rv) return rv[0];
  return KNOWN_REASONS.find((r) => m.includes(r)) ?? (m || REASON_UNREACHABLE);
}

export type ClientPath = 'direct' | 'signal' | undefined;
export const pathLabel = (p: ClientPath) => (p === 'direct' ? 'Direct' : p === 'signal' ? 'Via signal' : undefined);

export type LogEvent =
  | { kind: 'ready'; path: 'direct' | 'signal' }
  | { kind: 'hosting'; max: number; port: number }
  | { kind: 'clients'; count: number }
  | { kind: 'rv'; role: 'host' | 'client'; id: string; status: string }
  | { kind: 'error'; message: string };

// TS mirror of LogStatus.kt (no Kotlin unit-test setup); keep both in sync.
// Rust guest: "<label> tun session ready (direct|relayed, raw packets)", "error: <sentence>".
// Rust host (run_host_mux): "hosting up to N clients on port P", "client A is IP (N connected)",
// "client IP left: reason (N connected)".
const READY = /session ready \((direct|relayed)[,)]/;
// Rust runner: "rendezvous host: trk -> Publishing" / "rendezvous client: nostr -> Failed(\"x\")".
const RV = /rendezvous (host|client): (\w+) -> (\w+(?:\(.*\))?)\s*$/;
const ERROR = /^error: (.+)$/;
const HOSTING = /hosting up to (\d+) clients on port (\d+)/;
const CLIENTS = /client \S+ (?:is \S+|left: .*) \((\d+) connected\)$/;
export function parseLogLine(line: string): LogEvent | undefined {
  const r = READY.exec(line);
  if (r) return { kind: 'ready', path: r[1] === 'direct' ? 'direct' : 'signal' };
  const h = HOSTING.exec(line);
  if (h) return { kind: 'hosting', max: Number(h[1]), port: Number(h[2]) };
  const c = CLIENTS.exec(line.trim());
  if (c) return { kind: 'clients', count: Number(c[1]) };
  const v = RV.exec(line);
  if (v) return { kind: 'rv', role: v[1] as 'host' | 'client', id: v[2], status: v[3] };
  const e = ERROR.exec(line.trim());
  if (e) return { kind: 'error', message: e[1] };
  return undefined;
}
