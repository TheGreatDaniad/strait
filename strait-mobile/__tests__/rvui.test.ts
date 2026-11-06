import * as r from '../src/rvui';
import { parseInvite, buildInvite } from '../src/invite';
import { failureReason, parseLogLine } from '../src/connectReason';
import { migrateSettings } from '../src/storage';

jest.mock('@react-native-async-storage/async-storage', () => ({ getItem: jest.fn(async () => null), setItem: jest.fn() }));

const pf = (o: object = {}) => ({ hostable: false, method: 'blocked', nat: 'RestrictedCone', port: 7100, invite: '', ...o });
const ok = (id: string, ms = 20) => ({ id, status: 'reachable', rtt_ms: ms });

test('stage logic mirrors rvui::stage', () => {
  expect(r.stage(null, false, 7100)).toBe('check');
  expect(r.stage(null, true, 7100)).toBe('checking');
  expect(r.stage(pf(), false, 7100)).toBe('meeting');
  expect(r.stage(pf(), false, 7101)).toBe('check');
  for (const m of ['public', 'upnp', 'natpmp', 'pcp', 'ipv6']) {
    expect(r.stage(pf({ hostable: true, method: m, invite: 'STRAIT2|k|1.2.3.4:7100' }), false, 7100)).toBe('direct');
  }
  // hostable via a signal server is not "direct": it still needs the meeting stage
  expect(r.stage(pf({ hostable: true, method: 'signal', invite: 'STRAIT2|k||s:1' }), false, 7100)).toBe('meeting');
  // direct method without an invite is not direct
  expect(r.stage(pf({ hostable: true, method: 'public' }), false, 7100)).toBe('meeting');
});

test('nat copy', () => {
  expect(r.natKind(pf())).toBe('cone');
  expect(r.natKind(pf({ nat: 'Symmetric' }))).toBe('symmetric');
  expect(r.offersPicker(pf({ nat: 'Block' }))).toBe(false);
  expect(r.meetingCopy(pf())).toMatch(/^Your router allows direct connections.*forward UDP 7100 to this device, and check again\.$/);
  expect(r.meetingCopy(pf({ nat: 'Symmetric' }))).toContain('symmetric NAT: only clients that are public');
  expect(r.meetingCopy(pf({ nat: 'Block' }))).toBe(
    "Your network seems to block incoming UDP, so these services cannot help.\nThis network can't accept incoming connections.\n1. Enable UPnP on your router and check again.\n2. Or forward UDP 7100 to this device.\n3. Or add a signal server in Settings.",
  );
});

test('offered, labels, chips', () => {
  expect(r.offered(false)).toEqual(['trk', 'nostr', 'dht', 'ntfy', 'mqtt']);
  expect(r.offered(true)[0]).toBe('sig');
  expect(r.pickerLabel('sig', ['1.2.3.4:7000'])).toBe('Your signal server 1.2.3.4:7000');
  expect(r.pickerLabel('trk', [])).toBe('Trackers');
  expect(r.methodChip(r.methodState(undefined))).toEqual({ text: 'checking...', tone: 'neutral' });
  expect(r.methodChip(r.methodState(ok('trk', 31)))).toEqual({ text: 'reachable 31 ms', tone: 'good' });
  expect(r.methodChip(r.methodState({ id: 'x', status: 'error' }))).toEqual({ text: 'not reachable from here', tone: 'bad' });
  expect(r.selectable(r.methodState({ id: 'x', status: 'blocked' }))).toBe(false);
  expect(r.clientsWillTry(['trk', 'nostr'])).toBe('Clients will try: Trackers, Nostr');
});

test('gating and selection restore', () => {
  expect(r.startAllowed('check', 3)).toBe(false);
  expect(r.startAllowed('checking', 3)).toBe(false);
  expect(r.startAllowed('direct', 0)).toBe(true);
  expect(r.startAllowed('meeting', 0)).toBe(false);
  expect(r.startAllowed('meeting', 1)).toBe(true);
  const res = { trk: ok('trk'), nostr: { id: 'nostr', status: 'blocked' }, dht: ok('dht') };
  const reach = r.reachableIds(r.offered(false), res);
  expect(reach).toEqual(['trk', 'dht']);
  expect(r.restoreSelection(['nostr', 'dht', 'mqtt'], reach)).toEqual(['dht']);
  // invite order follows the registry, unreachable ticks are dropped
  expect(r.selectionToRv(['dht', 'nostr', 'trk'], res)).toEqual(['trk', 'dht']);
});

test('guest methods and disable list', () => {
  const rows = r.guestMethods(['trk', 'nostr', 'zzz'], ['nostr']);
  expect(rows).toEqual([
    { id: 'trk', supported: true, enabled: true },
    { id: 'nostr', supported: true, enabled: false },
    { id: 'zzz', supported: false, enabled: false },
  ]);
  expect(r.guestChip(rows[2], undefined).text).toBe('not supported by this version');
  expect(r.guestChip(rows[0], undefined).text).toBe('Not tested');
  expect(r.setDisabled([], 'trk', true)).toEqual(['trk']);
  expect(r.setDisabled(['trk', 'dht'], 'trk', false)).toEqual(['dht']);
});

test('probe JSON parsing (rv-test --json)', () => {
  const raw = '[{"id":"trk","status":"reachable","rtt_ms":57},{"id":"mqtt","status":"blocked","detail":"tcp: timeout"},{"bogus":1}]';
  const m = r.parseProbeResults(raw);
  expect(Object.keys(m)).toEqual(['trk', 'mqtt']);
  expect(m.trk).toMatchObject({ status: 'reachable', rtt_ms: 57 });
  expect(m.mqtt.detail).toBe('tcp: timeout');
  expect(r.parseProbeResults([])).toEqual({});
  expect(() => r.parseProbeResults('{}')).toThrow();
  expect(r.checkProbes(pf({ rendezvous: [ok('trk')] })).trk.rtt_ms).toBe(20);
});

test('failure copy and live text', () => {
  const c = r.failureCopy(pf({ rendezvous: [ok('trk', 5), { id: 'nostr', status: 'blocked', detail: 'dns' }] }));
  expect(c).toBe('None of the ways you chose could be reached from this network:\n- Trackers: reachable (5 ms)\n- Nostr: blocked (dns)');
  expect(r.failureCopy(pf())).toBeUndefined();
  expect(r.liveText('Publishing')).toBe('Publishing');
  expect(r.liveText('GotPeer(1.2.3.4:5)')).toBe('Got peer');
  expect(r.liveText('Failed("no route")')).toBe('Failed: no route');
});

test('invite rv field round trip and legacy forms', () => {
  const K = '0123456789abcdef0123456789abcdef';
  const inv = parseInvite(`STRAIT2|${K}||||trk,nostr,zzz`);
  expect(inv).toEqual({ key: K, hosts: [], signals: [], rv: ['trk', 'nostr', 'zzz'] });
  expect(buildInvite(inv)).toBe(`STRAIT2|${K}||||trk,nostr,zzz`);
  expect(parseInvite(buildInvite(inv))).toEqual(inv);
  expect(parseInvite(`STRAIT2|${K}|1.2.3.4:7100|s:7000|trk`).rv).toEqual(['trk']); // lone 4th field is rv
  expect(parseInvite(`STRAIT2|${K}|1.2.3.4:7100|s:7000|someroom`).rv).toEqual([]); // legacy room
  expect(parseInvite(`STRAIT2|${K}|1.2.3.4:7100`).rv).toEqual([]);
  expect(() => parseInvite(`STRAIT2|${K}|||||BAD ID`)).toThrow();
});

test('typed connect errors and live rv lines', () => {
  const rvFailed = 'The host could not be found or reached through trk: no peer; nostr: timeout. Check that they are sharing and that these services work from your network.';
  expect(failureReason(`error: ${rvFailed}`)).toBe(rvFailed);
  expect(failureReason('error: None of the ways listed in the invite to find the host are available on this device.'))
    .toBe('None of the ways listed in the invite to find the host are available on this device.');
  expect(parseLogLine('[2026-11-06T10:00:00Z INFO  nat_tunnel] rendezvous host: trk -> Publishing'))
    .toEqual({ kind: 'rv', role: 'host', id: 'trk', status: 'Publishing' });
  expect(parseLogLine('rendezvous client: nostr -> Failed("x y")')).toEqual({ kind: 'rv', role: 'client', id: 'nostr', status: 'Failed("x y")' });
});

test('settings: rv lists are sanitised', () => {
  expect(migrateSettings({ rvDisabled: ['trk', 'trk', 5], rvSelected: 'x' })).toMatchObject({ rvDisabled: ['trk'], rvSelected: [] });
  expect(migrateSettings(null)).toMatchObject({ rvDisabled: [], rvSelected: [] });
});
