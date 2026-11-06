jest.mock('@react-native-async-storage/async-storage', () => ({ getItem: jest.fn(async () => null), setItem: jest.fn() }));
import { toVerdict, SYMMETRIC_WARNING, blockedCopy } from '../src/preflight';
import { addSignal, parsePort, validateSignal } from '../src/validate';
import { migrateSettings } from '../src/storage';

const base = { hostable: true, invite: 'STRAIT2|k|1.2.3.4:7100|', port: 7100 };

test.each([
  ['public', 'Public address', 'any', 'Any client can connect.'],
  ['upnp', 'UPnP port mapping', 'any', 'Any client can connect.'],
  ['natpmp', 'NAT-PMP port mapping', 'any', 'Any client can connect.'],
  ['ipv6', 'IPv6 only', 'ipv6', 'Clients must have IPv6.'],
  ['signal', 'Signal server', 'public-or-cone', 'Clients must be public or behind a cone NAT.'],
])('%s is hostable', (method, label, req, text) => {
  const v = toVerdict({ ...base, method, nat: 'FullCone', client_requirements: req, signal_latency_ms: 42 }, 7100);
  expect(v).toMatchObject({ kind: 'hostable', method: label, canStart: true, clientRequirements: text, nat: 'Full cone' });
  expect(v.invite).toBe(base.invite);
});

test('signal latency shown', () => {
  expect(toVerdict({ ...base, method: 'signal', signal_latency_ms: 42 }, 7100).signalLatency).toBe('42 ms');
});

test('symmetric with signal warns but can start', () => {
  const v = toVerdict({ ...base, method: 'signal', nat: 'Symmetric', client_requirements: 'public-or-restricted-cone' }, 7100);
  expect(v.kind).toBe('warning');
  expect(v.canStart).toBe(true);
  expect(v.message).toBe(SYMMETRIC_WARNING);
  expect(v.clientRequirements).toMatch(/restricted/);
});

test('symmetric without signal is blocked with verbatim copy and real port', () => {
  const v = toVerdict({ hostable: false, method: 'symmetric', nat: 'Symmetric', invite: '' }, 7200);
  expect(v.kind).toBe('blocked');
  expect(v.canStart).toBe(false);
  expect(v.invite).toBe('');
  expect(v.message).toBe(
    "This network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP 7200 to this device.\n3. Or add a signal server in Settings.",
  );
  expect(blockedCopy(7100)).toContain('forward UDP 7100 to');
});

test('blocked, and hostable without invite is not startable; missing fields tolerated', () => {
  expect(toVerdict({ hostable: false, method: 'blocked' }, 7100).canStart).toBe(false);
  expect(toVerdict({ hostable: true, method: 'public' }, 7100).canStart).toBe(false);
  expect(toVerdict({ ...base, method: 'weird', client_note: 'note' }, 7100)).toMatchObject({ method: 'weird', clientRequirements: 'note' });
});

test('validation', () => {
  expect(parsePort('7100')).toBe(7100);
  expect(['0', '65536', 'abc', ''].map(parsePort)).toEqual([null, null, null, null]);
  expect(validateSignal('signal.example.com:7000').ok).toBe(true);
  expect(validateSignal('1.2.3.4:7000').ok).toBe(true);
  expect(validateSignal('[::1]:7000').ok).toBe(true);
  expect(['nohost', 'a:0', 'a b:1', ':7000', '-x:1'].every(x => !validateSignal(x).ok)).toBe(true);
  const r = addSignal(['a.com:1'], 'A.com:1');
  expect(r.error).toBe('Already added.');
  expect(addSignal([], ' b.com:2 ').list).toEqual(['b.com:2']);
});

test('settings migration', () => {
  const m = migrateSettings({ relay: '10.0.2.2:7000', signals: ['a.com:1', 'a.com:1', 'bad'], maxClients: 0, rateKbps: -1 });
  expect(m.signals).toEqual(['a.com:1']);
  expect(m.maxClients).toBe(1);
  expect(m.rateKbps).toBe(0);
  expect(migrateSettings(null).signals).toEqual([]);
  expect(migrateSettings({ relay: 'r.com:7000' }).signals).toEqual(['r.com:7000']);
});
