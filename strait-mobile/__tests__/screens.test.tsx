jest.mock('@react-native-async-storage/async-storage', () => ({ getItem: jest.fn(async () => null), setItem: jest.fn() }));
import React from 'react';
import ReactTestRenderer, { act } from 'react-test-renderer';
import { HostScreen } from '../src/screens/HostScreen';
import { ConnectScreen } from '../src/screens/ConnectScreen';
import { SettingsScreen } from '../src/screens/SettingsScreen';
import { defaultSettings } from '../src/storage';

const noop = () => {};
const texts = (t: ReactTestRenderer.ReactTestRenderer) =>
  t.root.findAll(n => (n.type as unknown) === 'Text').map(n => [n.props.children].flat().join(''));
const mounted: ReactTestRenderer.ReactTestRenderer[] = [];
afterEach(() => { mounted.splice(0).forEach(t => act(() => t.unmount())); });
const render = (el: React.ReactElement) => {
  let t!: ReactTestRenderer.ReactTestRenderer;
  act(() => { t = ReactTestRenderer.create(el); });
  mounted.push(t);
  return t;
};
const button = (t: ReactTestRenderer.ReactTestRenderer, title: string) =>
  t.root.findAll(
    n =>
      n.props.accessibilityRole === 'button' &&
      n.findAll(c => (c.type as unknown) === 'Text' && [c.props.children].flat().join('') === title).length > 0,
  )[0];

const host = (over: object = {}) => (
  <HostScreen sharing={false} relay="" invite="" copied={false} maxClients={1} rateKbps={0}
    onStart={noop} onStop={noop} onChangeRelay={noop} onCopy={noop}
    portText="7100" checking={false} check={null} onChangePort={noop} onCheck={noop} {...over} />
);
const joined = (t: ReactTestRenderer.ReactTestRenderer) => texts(t).join('\n');
const reachable = (id: string, ms = 40) => ({ id, status: 'reachable', rtt_ms: ms });
const blocked = (id: string) => ({ id, status: 'blocked', detail: 'x' });
const cone = { hostable: false, method: 'blocked', nat: 'RestrictedCone', port: 7100, invite: '' };

test('host stage A: Check connectivity, Start visible but disabled, no list', () => {
  const t = render(host());
  expect(button(t, 'Check connectivity')).toBeTruthy();
  expect(button(t, 'Start sharing').props.disabled).toBe(true);
  expect(t.root.findAllByProps({ testID: 'seen-message' })).toHaveLength(0);
});

test('host stage B1: Connectable, no list, Start enabled', () => {
  const t = render(host({ check: { hostable: true, method: 'upnp', nat: 'RestrictedCone', port: 7100, invite: 'STRAIT2|k|1.2.3.4:7100' } }));
  const j = joined(t);
  expect(j).toContain('Connectable');
  expect(j).toContain('Clients can reach this device directly, so no extra service is needed.');
  expect(j).toContain('via UPnP port mapping');
  expect(j).not.toContain('Pick at least one way');
  expect(button(t, 'Start sharing').props.disabled).toBe(false);
});

test('host stage B2: copy, list, chips, gating, one shared message', () => {
  const onToggle = jest.fn();
  const probes = { trk: reachable('trk'), nostr: blocked('nostr'), dht: reachable('dht') };
  const props = { check: cone, probes, selected: [] as string[], onToggle };
  let t = render(host(props));
  const j = joined(t);
  expect(j).toContain('the two devices need a meeting point');
  expect(j).toContain('Pick at least one way for the two devices to find each other:');
  expect(j).toContain('reachable 40 ms');
  expect(j).toContain('not reachable from here');
  expect(j).toContain('checking...'); // ntfy / mqtt not yet probed
  expect(j).not.toContain('Your signal server'); // no signal configured
  expect(t.root.findAll(n => n.props.testID === 'seen-message' && (n.type as unknown) === 'Text')).toHaveLength(1);
  expect(button(t, 'Start sharing').props.disabled).toBe(true);
  expect(t.root.findByProps({ testID: 'pick-nostr' }).props.disabled).toBe(true);
  act(() => { t.root.findByProps({ testID: 'pick-trk' }).props.onPress(); });
  expect(onToggle).toHaveBeenCalledWith('trk');
  t = render(host({ ...props, selected: ['trk'] }));
  expect(button(t, 'Start sharing').props.disabled).toBe(false);
  // a ticked method that is no longer reachable does not count
  t = render(host({ ...props, selected: ['nostr'] }));
  expect(button(t, 'Start sharing').props.disabled).toBe(true);
});

test('host stage B2: sig row only with a signal server; symmetric copy; blocked UDP has no list', () => {
  expect(joined(render(host({ check: cone, signals: ['1.2.3.4:7000'], probes: {} })))).toContain('Your signal server 1.2.3.4:7000');
  expect(joined(render(host({ check: { ...cone, nat: 'Symmetric' } })))).toContain('symmetric NAT');
  const t = render(host({ check: { ...cone, nat: 'Block' } }));
  expect(joined(t)).toContain('Your network seems to block incoming UDP');
  expect(t.root.findAllByProps({ testID: 'seen-message' })).toHaveLength(0);
});

test('host stage resets when the port no longer matches the check', () => {
  const t = render(host({ check: { ...cone, port: 7200 } }));
  expect(joined(t)).not.toContain('Pick at least one way');
  expect(button(t, 'Start sharing').props.disabled).toBe(true);
});

test('host sharing: invite, clients will try, live status', () => {
  const inv = 'STRAIT2|k||||trk,nostr';
  const t = render(host({ sharing: true, invite: inv, live: { trk: 'Publishing', nostr: 'GotPeer(1.2.3.4:5)' } }));
  const j = joined(t);
  expect(j).toContain('Clients will try: Trackers, Nostr');
  expect(t.root.findByProps({ testID: 'live-trk' }).props.children).toBe('Publishing');
  expect(t.root.findByProps({ testID: 'live-nostr' }).props.children).toBe('Got peer');
});

test('host: invalid port disables Check', () => {
  const t = render(host({ portText: '70000', portError: 'Enter a port from 1 to 65535.' }));
  expect(button(t, 'Check connectivity').props.disabled).toBe(true);
  expect(texts(t)).toContain('Enter a port from 1 to 65535.');
});

const connect = (state: any, extra: object = {}) => (
  <ConnectScreen state={state} invite="x" bytes={0} history={[]} onChangeInvite={noop} onConnect={noop}
    onCancel={noop} onDisconnect={noop} onPaste={noop} onPickHistory={noop} {...extra} />
);

test.each([
  ['idle', 'Not connected'],
  ['connecting', 'Connecting…'],
  ['connected', 'Connected'],
  ['failed', "Couldn't connect"],
])('connect state %s', (state, title) => {
  expect(texts(render(connect(state))).join('\n')).toContain(title);
});

test('connect: path and failure reason', () => {
  expect(texts(render(connect('connected', { path: 'signal' }))).join('\n')).toContain('Via signal');
  expect(texts(render(connect('connected', { path: 'direct' }))).join('\n')).toContain('Direct');
  expect(texts(render(connect('failed', { error: 'Host unreachable - check the invite or UDP reachability.' }))).join('\n'))
    .toContain('Failed: Host unreachable');
});

test('connect: kill switch blocked shows Disconnect and how to unblock', () => {
  const onDisconnect = jest.fn();
  const t = render(connect('failed', { blocked: true, error: 'core crashed', onDisconnect }));
  const all = texts(t).join('\n');
  expect(all).toContain('Traffic blocked');
  expect(all).toContain('Tap Disconnect to unblock');
  expect(button(t, 'Try again')).toBeUndefined();
  act(() => { button(t, 'Disconnect').props.onPress(); });
  expect(onDisconnect).toHaveBeenCalled();
});

test('settings: list and remove signal', () => {
  const onChange = jest.fn();
  const t = render(<SettingsScreen settings={{ ...defaultSettings, signals: ['a.com:1'] }} onChange={onChange} version="x" />);
  expect(texts(t)).toContain('a.com:1');
  act(() => { t.root.findByProps({ accessibilityLabel: 'Remove a.com:1' }).props.onPress(); });
  expect(onChange).toHaveBeenCalledWith({ ...defaultSettings, signals: [] });
});

test('connect: invite rv methods with Use this toggle, chips, unknown id', () => {
  const onToggleRv = jest.fn();
  const onTestRv = jest.fn();
  const t = render(connect('idle', {
    rvIds: ['trk', 'nostr', 'zzz'], rvDisabled: ['nostr'], rvProbes: { trk: reachable('trk', 12) }, onToggleRv, onTestRv,
  }));
  const j = joined(t);
  expect(j).toContain('Trackers');
  expect(j).toContain('reachable 12 ms');
  expect(j).toContain('Not tested');
  expect(j).toContain('not supported by this version');
  expect(t.root.findByProps({ testID: 'use-nostr' }).props.accessibilityState.checked).toBe(false);
  expect(t.root.findByProps({ testID: 'use-trk' }).props.accessibilityState.checked).toBe(true);
  expect(t.root.findByProps({ testID: 'use-zzz' }).props.disabled).toBe(true);
  act(() => { t.root.findByProps({ testID: 'use-trk' }).props.onPress(); });
  expect(onToggleRv).toHaveBeenCalledWith('trk');
  act(() => { button(t, 'Test services').props.onPress(); });
  expect(onTestRv).toHaveBeenCalled();
  expect(t.root.findAllByProps({ testID: 'rv-guest' }).length).toBeGreaterThan(0);
  expect(joined(render(connect('idle')))).not.toContain('The host offers these ways');
});
