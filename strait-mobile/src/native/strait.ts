import { DeviceEventEmitter, NativeModules } from 'react-native';

export type Mode = 'client' | 'host';

export type StartOptions = {
  mode: Mode;
  invite: string;
  maxClients: number;
  rateKbps: number;
  killSwitch: boolean;
  blockIPv6: boolean;
  port?: number; // host: UDP port the check probed (NAT_TUNNEL_BIND_PORT)
  rvDisable?: string[]; // client: rendezvous ids switched off locally (--rv-disable)
  carrierDisable?: string[]; // client: carriers never used even if the invite lists them (--carrier-disable)
};

export type TunnelStatus = {
  state: 'idle' | 'connecting' | 'connected' | 'sharing' | 'failed';
  message?: string;
  blocked?: boolean; // kill switch is holding all traffic after the core died; only Disconnect releases it
  path?: 'direct' | 'signal';
  ip?: string;
  clients?: number; // host: peers currently connected
  bytesIn?: number;
  bytesOut?: number;
  carrier?: string; // client: carrier that carries the tunnel (udp, ss, ws, awg, xray)
  mtu?: number; // TUN MTU the core chose for that carrier (applied to the VpnService interface)
  carrierNotes?: string; // JSON text string[] of "<id>: <why it failed>" ladder lines
  rv?: string; // host: JSON text {"trk":"Publishing",...} from the live `rendezvous host:` lines
};

// One `rv-test --json` / `check-host --json` rendezvous row.
export type RvProbe = {
  id: string;
  status: 'reachable' | 'blocked' | 'error' | string;
  rtt_ms?: number;
  detail?: string;
};

export type PreflightMethod =
  | 'public' | 'upnp' | 'natpmp' | 'ipv6' | 'signal' | 'symmetric' | 'blocked';

// Mirrors `nat-tunnel check-host --json` (handoff section 7). Only hostable
// and method are relied upon; everything else may be absent or null.
export type PreflightResult = {
  hostable: boolean;
  method: PreflightMethod | string;
  nat?: 'FullCone' | 'RestrictedCone' | 'Symmetric' | 'Block' | 'Unknown' | string;
  port?: number;
  endpoint?: string | null;
  endpoints?: string[];
  signal?: string | null;
  signal_latency_ms?: number | null;
  client_requirements?: 'any' | 'ipv6' | 'public-or-cone' | 'public-or-restricted-cone' | 'none' | string;
  client_note?: string;
  invite?: string;
  note?: string;
  rendezvous?: RvProbe[];
};

export type CheckOptions = { port: number; signals: string[]; key?: string; rendezvous?: string[] };

export function parsePreflight(raw: unknown): PreflightResult {
  const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!v || typeof v !== 'object' || typeof (v as any).method !== 'string') {
    throw new Error('Unexpected network check result.');
  }
  return { hostable: false, ...(v as object) } as PreflightResult;
}

type StraitNativeModule = {
  checkNetwork?(options: CheckOptions): Promise<string>;
  probeServices?(ids: string[], signals: string[]): Promise<string>;
  start(options: StartOptions): Promise<void>;
  stop(): Promise<void>;
  // Absent on the dev fallback and in jest; JS then tries globalThis.crypto.
  generateKey?(): Promise<string>;
  getStatus(): Promise<TunnelStatus>;
};

const native = NativeModules.Strait as StraitNativeModule | undefined;

export const isNativeAvailable = !!native;

export const StraitEvents = native ? DeviceEventEmitter : null;

export const Strait: StraitNativeModule = native ?? {
  async start() {
    // The UI has a development fallback so the design can be exercised on a
    // simulator before the native service is installed.
    await new Promise<void>(resolve => setTimeout(resolve, 900));
  },
  async stop() {
    await Promise.resolve();
  },
  async getStatus() {
    return { state: 'idle' };
  },
};

export async function checkNetwork(options: CheckOptions): Promise<PreflightResult> {
  if (native?.checkNetwork) return parsePreflight(await native.checkNetwork(options));
  // Dev fallback (no native module): pretend a signal-less network is blocked.
  return { hostable: false, method: 'blocked', nat: 'Unknown', port: options.port, client_requirements: 'none' };
}

// Probes only `ids` (publishes nothing). Dev fallback: everything "not reachable".
export async function probeServices(ids: string[], signals: string[] = []): Promise<RvProbe[]> {
  if (native?.probeServices) {
    const v = JSON.parse(await native.probeServices(ids, signals));
    return Array.isArray(v) ? v : [];
  }
  return ids.map(id => ({ id, status: 'error', detail: 'unavailable in this build' }));
}
