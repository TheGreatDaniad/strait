import { Strait } from './native/strait';

// Mirrors nat-tunnel/src/invite.rs. Grammar: STRAIT2|<key>|<hosts>|<signals>|<rv ids>
// `cr` (optional, host's preference order) keeps the raw `id[@host:port][;k=v]` entries so the invite round-trips verbatim.
export type Invite = { key: string; hosts: string[]; signals: string[]; rv: string[]; cr?: string[] };

const KEY_RE = /^[0-9a-fA-F]{32}$/;
const V4_OR_NAME = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;
const V6_RE = /^[0-9a-fA-F:.]+$/;

function checkEndpoint(ep: string): string {
  const m = ep.startsWith('[')
    ? /^\[([^\]]+)\]:(\d+)$/.exec(ep)
    : /^([^:]+):(\d+)$/.exec(ep);
  const port = m ? Number(m[2]) : 0;
  const hostOk = m && (ep.startsWith('[')
    ? m[1].includes(':') && V6_RE.test(m[1])
    : V4_OR_NAME.test(m[1]));
  if (!hostOk || port < 1 || port > 65535) {
    throw new Error(`Invalid address "${ep}". Use host:port or [ipv6]:port.`);
  }
  return ep;
}

function list(field: string | undefined): string[] {
  return (field ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(checkEndpoint);
}

const RV_ID = /^[a-z0-9]{1,12}$/;
const RV_KNOWN = ['sig', 'trk', 'nostr', 'dht', 'ntfy', 'mqtt'];

const CR_ENTRY = /^([a-z0-9]{1,12})(?:@([^;,|@]+))?(;[^,|]*)?$/;

// Mirrors invite.rs parse_cr loosely: `id[@host:port][;k=v...]`, at most 8. Unknown ids are kept (forward compat).
function crList(field: string | undefined): { entries: string[]; endpoints: string[] } {
  const entries: string[] = [];
  const endpoints: string[] = [];
  for (const p of (field ?? '').split(',').map(s => s.trim()).filter(Boolean)) {
    const m = CR_ENTRY.exec(p);
    if (!m) throw new Error(`Invalid invite: bad carrier entry "${p}".`);
    if (m[2]) endpoints.push(checkEndpoint(m[2]));
    entries.push(p);
  }
  if (entries.length > 8) throw new Error('Invalid invite: too many carriers.');
  return { entries, endpoints };
}

/** Carrier ids of an invite's `cr` field, in the host's order. */
export const carrierIds = (cr: string[] = []) => cr.map(e => e.split(/[@;]/)[0]);

// Comma list of method ids, deduplicated; unknown (but well-formed) ids are kept for forward compat.
function rvList(field: string | undefined): string[] {
  const out: string[] = [];
  for (const p of (field ?? '').split(',').map(s => s.trim()).filter(Boolean)) {
    if (!RV_ID.test(p)) throw new Error(`Invalid invite: bad rendezvous method "${p}".`);
    if (!out.includes(p)) out.push(p);
  }
  if (out.length > 8) throw new Error('Invalid invite: too many rendezvous methods.');
  return out;
}

// Mirrors invite.rs rv_shaped: a lone 4th field is rv (not a legacy room) if it is a list or a known id.
const rvShaped = (f: string) => !!f && f.split(',').every(p => RV_ID.test(p.trim())) && (f.includes(',') || RV_KNOWN.includes(f));

function checkKey(key: string): string {
  if (!KEY_RE.test(key)) {
    throw new Error('Invalid invite: key must be 32 hex characters.');
  }
  return key;
}

export function parseInvite(input: string): Invite {
  const value = input.trim();
  const bad = () => new Error('Invalid invite. Expected STRAIT2|key|hosts|signals.');
  if (!value) throw bad();
  const parts = value.split('|').map(s => s.trim());
  let invite: Invite;
  let hasCrEndpoint = false;
  if (parts[0] === 'STRAIT2') {
    // A 4th field (legacy room) is tolerated and ignored, as the room derives from the key.
    invite = {
      key: checkKey(parts[1] ?? ''),
      hosts: list(parts[2]),
      signals: list(parts[3]),
      rv: rvList(parts[5]),
    };
    const cr = crList(parts[6]);
    if (cr.entries.length) invite.cr = cr.entries;
    hasCrEndpoint = cr.endpoints.length > 0;
    if (parts[5] === undefined && rvShaped(parts[4] ?? '')) invite.rv = rvList(parts[4]);
  } else if (parts.length === 3 && !parts[1].includes(':')) {
    // Legacy `signal:port|room|key`. The room is not carried over.
    if (!parts[1]) throw bad();
    invite = { key: parts[2], hosts: [], signals: list(parts[0]), rv: [] };
    if (!invite.key) throw bad();
  } else {
    throw bad();
  }
  if (!invite.hosts.length && !invite.signals.length && !invite.rv.length && !hasCrEndpoint) {
    throw new Error('Invalid invite: needs at least one host, signal server or rendezvous method.');
  }
  return invite;
}

export function buildInvite({ key, hosts, signals, rv = [], cr = [] }: Omit<Invite, 'rv'> & { rv?: string[] }): string {
  let out = `STRAIT2|${checkKey(key)}|${hosts.join(',')}`;
  if (signals.length || rv.length || cr.length) out += `|${signals.join(',')}`;
  if (rv.length || cr.length) out += `||${rv.join(',')}`;
  if (cr.length) out += `|${cr.join(',')}`;
  return out;
}

// 128-bit key as 32 hex chars. Prefers the native SecureRandom (Hermes may lack
// crypto.getRandomValues). Never falls back to Math.random.
export async function generateKey(): Promise<string> {
  if (Strait.generateKey) return checkKey(await Strait.generateKey());
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (!c?.getRandomValues) {
    throw new Error('No secure random source available; cannot generate an invite key.');
  }
  const bytes = c.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}
