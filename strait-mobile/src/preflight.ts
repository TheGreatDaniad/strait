import type { PreflightResult } from './native/strait';

export const SYMMETRIC_WARNING =
  'This network uses symmetric NAT. Only clients that are public or behind a full-cone / address-restricted NAT will be able to connect. A signal server is recommended.';

export const blockedCopy = (port: number) =>
  `This network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP ${port} to this device.\n3. Or add a signal server in Settings.`;

const METHOD_LABEL: Record<string, string> = {
  public: 'Public address',
  upnp: 'UPnP port mapping',
  natpmp: 'NAT-PMP port mapping',
  ipv6: 'IPv6 only',
  signal: 'Signal server',
  symmetric: 'Symmetric NAT',
  blocked: 'Blocked',
};

const REQUIREMENT_TEXT: Record<string, string> = {
  any: 'Any client can connect.',
  ipv6: 'Clients must have IPv6.',
  'public-or-cone': 'Clients must be public or behind a cone NAT.',
  'public-or-restricted-cone': 'Clients must be public or behind a full-cone / address-restricted NAT.',
  none: 'No client can connect.',
};

const NAT_LABEL: Record<string, string> = {
  FullCone: 'Full cone',
  RestrictedCone: 'Restricted cone',
  Symmetric: 'Symmetric',
  Block: 'Blocked',
  Unknown: 'Unknown',
};

export type Verdict = {
  kind: 'hostable' | 'warning' | 'blocked';
  method: string;
  nat?: string;
  signalLatency?: string;
  clientRequirements?: string;
  message: string; // verbatim warning / blocked copy, or the tool's own note
  canStart: boolean;
  invite: string;
};

export function toVerdict(r: PreflightResult, port: number): Verdict {
  const invite = r.invite ?? '';
  const hostable = r.hostable === true && invite !== '';
  const symmetric = r.nat === 'Symmetric';
  const kind = !hostable ? 'blocked' : symmetric ? 'warning' : 'hostable';
  const req = r.client_requirements;
  return {
    kind,
    method: METHOD_LABEL[r.method] ?? r.method,
    nat: r.nat ? NAT_LABEL[r.nat] ?? r.nat : undefined,
    signalLatency: typeof r.signal_latency_ms === 'number' ? `${r.signal_latency_ms} ms` : undefined,
    clientRequirements: (req && REQUIREMENT_TEXT[req]) || r.client_note || undefined,
    message: kind === 'blocked' ? blockedCopy(port) : kind === 'warning' ? SYMMETRIC_WARNING : r.note ?? '',
    canStart: hostable,
    invite: hostable ? invite : '',
  };
}
