// TS mirror of nat-tunnel/src/preflight.rs `mod rvui` (stage logic, copy, chips, selection).
// __tests__/rustContract.test.ts reads the Rust source and fails if the shared texts drift.
import type { PreflightResult, RvProbe } from './native/strait';

export const KNOWN = ['sig', 'trk', 'nostr', 'dht', 'ntfy', 'mqtt'] as const;

const NAMES: Record<string, string> = {
  sig: 'Signal server',
  trk: 'Trackers',
  nostr: 'Nostr',
  dht: 'Mainline DHT',
  ntfy: 'ntfy',
  mqtt: 'MQTT (test-grade)',
};
const SHORT: Record<string, string> = {
  sig: 'Your own signal server',
  trk: 'Public BitTorrent trackers',
  nostr: 'Public Nostr relays',
  dht: 'BitTorrent Mainline DHT',
  ntfy: 'ntfy.sh push service',
  mqtt: 'Public MQTT brokers (testing only)',
};

export const isKnown = (id: string) => (KNOWN as readonly string[]).includes(id);
export const name = (id: string) => NAMES[id] ?? id;
export const short = (id: string) => SHORT[id] ?? 'Not supported by this version';
export const names = (ids: string[]) => ids.map(name).join(', ');
export const clientsWillTry = (ids: string[]) => `Clients will try: ${names(ids)}`;
export const pickerLabel = (id: string, signals: string[]) =>
  id === 'sig' && signals.length ? `Your signal server ${signals[0]}` : name(id);

export const TRAFFIC_LINE =
  'Your traffic goes only between you and the other device; these services never carry it.';
export const PICK_HEADING = 'Pick at least one way for the two devices to find each other:';
export const SEEN_MESSAGE =
  'What these services see:\n• Your public IP address and when you connect\n• A code only you and the other device can work out\n• The address you publish, sealed so only the other device can read it (trackers can read it, that is how trackers work)\nWhat they never see:\n• Your traffic\n• The invite key\n• Anything readable about what you are doing\nThey are public services run by others, with no promise of uptime. MQTT brokers are for testing and may reset at any time.';
export const DIRECT_TITLE = 'Connectable';
export const DIRECT_COPY = 'Clients can reach this device directly, so no extra service is needed.';

export const blockedCopy = (port: number) =>
  `This network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP ${port} to this device.\n3. Or add a signal server in Settings.`;

// ---- stage ----
export type Stage = 'check' | 'checking' | 'direct' | 'meeting';
export type NatKind = 'cone' | 'symmetric' | 'blocked';

const DIRECT_METHODS = ['public', 'upnp', 'natpmp', 'pcp', 'ipv6'];

export const isDirect = (r: PreflightResult) =>
  r.hostable === true && !!r.invite && DIRECT_METHODS.includes(r.method);

/** A verdict belongs to the port it probed; any other port is Stage A again. */
export function stage(check: PreflightResult | null, running: boolean, port: number | null): Stage {
  if (running) return 'checking';
  if (check && check.port === port) return isDirect(check) ? 'direct' : 'meeting';
  return 'check';
}

export function natKind(r: PreflightResult): NatKind {
  return r.nat === 'Symmetric' ? 'symmetric' : r.nat === 'Block' ? 'blocked' : 'cone';
}
export const offersPicker = (r: PreflightResult) => natKind(r) !== 'blocked';

export const MEETING_CONE =
  'Your router allows direct connections, but it does not open a port for clients, so the two devices need a meeting point (a signaling service) to find each other.';

export function meetingCopy(r: PreflightResult, port = r.port ?? 0): string {
  const kind = natKind(r);
  if (kind === 'blocked') {
    return `Your network seems to block incoming UDP, so these services cannot help.\n${blockedCopy(port)}`;
  }
  if (kind === 'cone') {
    return `${MEETING_CONE} You can also enable UPnP on your router, or forward UDP ${port} to this device, and check again.`;
  }
  return `${MEETING_CONE} Your network uses symmetric NAT: only clients that are public or behind full-cone / address-restricted routers can connect. You can also enable UPnP on your router, or forward UDP ${port} to this device, and check again.`;
}

const DIRECT_LABEL: Record<string, string> = {
  public: 'Public address',
  upnp: 'UPnP port mapping',
  natpmp: 'NAT-PMP port mapping',
  pcp: 'PCP port mapping',
  ipv6: 'IPv6 only',
};
export const directLabel = (method: string) => DIRECT_LABEL[method] ?? method;

// ---- picker ----
/** Methods offered in the Host list (`sig` only with a configured signal server). */
export const offered = (hasSignal: boolean, compiled: readonly string[] = KNOWN) =>
  compiled.filter(i => i !== 'sig' || hasSignal);

export type MethodState =
  | { kind: 'checking' }
  | { kind: 'reachable'; ms: number }
  | { kind: 'unreachable'; detail?: string };

export function methodState(p: RvProbe | undefined): MethodState {
  if (!p) return { kind: 'checking' };
  return p.status === 'reachable'
    ? { kind: 'reachable', ms: p.rtt_ms ?? 0 }
    : { kind: 'unreachable', detail: p.detail };
}

export function methodChip(s: MethodState): { text: string; tone: 'good' | 'bad' | 'neutral' } {
  if (s.kind === 'reachable') return { text: `reachable ${s.ms} ms`, tone: 'good' };
  if (s.kind === 'unreachable') return { text: 'not reachable from here', tone: 'bad' };
  return { text: 'checking...', tone: 'neutral' };
}

export const selectable = (s: MethodState) => s.kind === 'reachable';

export const reachableIds = (offeredIds: string[], results: Record<string, RvProbe>) =>
  offeredIds.filter(id => results[id]?.status === 'reachable');

/** The user's earlier explicit choice, limited to methods that are still reachable. */
export const restoreSelection = (prev: string[], reachable: string[]) =>
  reachable.filter(r => prev.includes(r));

export const startAllowed = (st: Stage, tickedReachable: number) =>
  st === 'direct' ? true : st === 'meeting' ? tickedReachable >= 1 : false;

/** Ticked ids that are still reachable, in registry order: what goes into the invite. */
export const selectionToRv = (selected: string[], results: Record<string, RvProbe>) =>
  KNOWN.filter(id => selected.includes(id) && results[id]?.status === 'reachable') as string[];

// ---- guest ----
export type GuestMethod = { id: string; supported: boolean; enabled: boolean };

export const guestMethods = (inviteRv: string[], disabled: string[], compiled: readonly string[] = KNOWN): GuestMethod[] =>
  inviteRv.map(id => {
    const supported = compiled.includes(id);
    return { id, supported, enabled: supported && !disabled.includes(id) };
  });

export const setDisabled = (disabled: string[], id: string, disable: boolean) => {
  const v = disabled.filter(d => d !== id);
  return disable ? [...v, id] : v;
};

export const guestChip = (m: GuestMethod, p: RvProbe | undefined) =>
  m.supported
    ? p
      ? methodChip(methodState(p))
      : { text: 'Not tested', tone: 'neutral' as const }
    : { text: 'not supported by this version', tone: 'neutral' as const };

// ---- probe JSON (`rv-test --json`: array of {id,status,rtt_ms?,detail?}) ----
export function parseProbeResults(raw: unknown): Record<string, RvProbe> {
  const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!Array.isArray(v)) throw new Error('Unexpected service test result.');
  const out: Record<string, RvProbe> = {};
  for (const r of v) {
    if (r && typeof r.id === 'string' && typeof r.status === 'string') {
      out[r.id] = { id: r.id, status: r.status, rtt_ms: r.rtt_ms ?? undefined, detail: r.detail ?? undefined };
    }
  }
  return out;
}

/** Host-side rendezvous results from a `check-host --json` verdict, keyed by id. */
export const checkProbes = (r: PreflightResult | null): Record<string, RvProbe> =>
  Object.fromEntries((r?.rendezvous ?? []).map(p => [p.id, p]));

// ---- live per-method status while sharing (log line `rendezvous host: trk -> Publishing`) ----
export function liveText(s: string): string {
  const m = /^(\w+)(?:\((.*)\))?$/.exec(s.trim());
  if (!m) return s;
  const [, k, d] = m;
  return k === 'GotPeer' ? 'Got peer' : d ? `${k}: ${d.replace(/^"|"$/g, '')}` : k;
}

/** Why a re-check with the ticked methods is not hostable (mirror of rvui::failure_copy). */
export function failureCopy(r: PreflightResult): string | undefined {
  const rows = (r.rendezvous ?? []).filter(Boolean);
  if (!rows.length) return undefined;
  const d = (p: RvProbe) =>
    p.rtt_ms !== undefined ? `reachable (${p.rtt_ms} ms)` : p.detail ? `${p.status} (${p.detail})` : p.status;
  return `None of the ways you chose could be reached from this network:${rows.map(p => `\n- ${name(p.id)}: ${d(p)}`).join('')}`;
}
