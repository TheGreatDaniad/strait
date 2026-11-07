import AsyncStorage from '@react-native-async-storage/async-storage';
import { addSignal } from './validate';

export type Settings = {
  signals: string[];
  hostPort: number;
  killSwitch: boolean;
  blockIPv6: boolean;
  maxClients: number;
  rateKbps: number;
  rvDisabled: string[]; // client: rendezvous ids switched off locally
  rvSelected: string[]; // host: the user's last explicit choice in the picker
};

export const defaultSettings: Settings = {
  signals: [],
  hostPort: 7100,
  killSwitch: true,
  blockIPv6: true,
  maxClients: 1,
  rateKbps: 0,
  rvDisabled: [],
  rvSelected: [],
};

const SETTINGS_KEY = 'strait.settings.v1';
const HISTORY_KEY = 'strait.history.v1';
const LAST_KEY = 'strait.last.v1';

// Old builds stored a single `relay` string; fold it into `signals`.
// The old emulator default (10.0.2.2:7000) is dropped: signals now default to empty.
export function migrateSettings(stored: any): Settings {
  const { relay, ...rest } = stored ?? {};
  const out = { ...defaultSettings, ...rest } as Settings;
  if (!Array.isArray(out.signals)) out.signals = [];
  out.signals = out.signals.reduce<string[]>(
    (acc, x) => (typeof x === 'string' ? addSignal(acc, x).list : acc),
    [],
  );
  if (typeof relay === 'string' && relay.trim() && relay.trim() !== '10.0.2.2:7000' && !rest.signals?.length) {
    out.signals = [relay.trim()];
  }
  if (!Number.isInteger(out.hostPort) || out.hostPort < 1 || out.hostPort > 65535) {
    out.hostPort = defaultSettings.hostPort;
  }
  if (!Number.isInteger(out.maxClients) || out.maxClients < 1 || out.maxClients > 1024) {
    out.maxClients = defaultSettings.maxClients;
  }
  if (!Number.isFinite(out.rateKbps) || out.rateKbps < 0) out.rateKbps = 0;
  for (const k of ['rvDisabled', 'rvSelected'] as const) {
    const v: unknown = out[k];
    out[k] = Array.isArray(v) ? [...new Set(v.filter((x): x is string => typeof x === 'string'))] : [];
  }
  if (typeof out.killSwitch !== 'boolean') out.killSwitch = true;
  if (typeof out.blockIPv6 !== 'boolean') out.blockIPv6 = true;
  return out;
}

export async function loadSettings(): Promise<Settings> {
  try {
    const raw = await AsyncStorage.getItem(SETTINGS_KEY);
    if (!raw) return defaultSettings;
    return migrateSettings(JSON.parse(raw));
  } catch {
    return defaultSettings;
  }
}

export async function saveSettings(settings: Settings) {
  await AsyncStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}

export async function loadHistory(): Promise<string[]> {
  try {
    const raw = await AsyncStorage.getItem(HISTORY_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter(x => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

export async function loadLast(): Promise<string> {
  try {
    return (await AsyncStorage.getItem(LAST_KEY)) ?? '';
  } catch {
    return '';
  }
}

// shortcut: invites sit in plaintext AsyncStorage (no secure-storage module installed); the manifest excludes app data from backup, so they stay in the app sandbox. Upgrade to a keystore-backed store if rooted-device theft matters.
export async function rememberInvite(invite: string) {
  const trimmed = invite.trim();
  if (!trimmed) return;
  await AsyncStorage.setItem(LAST_KEY, trimmed);
  const history = await loadHistory();
  const next = [trimmed, ...history.filter(x => x !== trimmed)].slice(0, 5);
  await AsyncStorage.setItem(HISTORY_KEY, JSON.stringify(next));
}
