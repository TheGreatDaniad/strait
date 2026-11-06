jest.mock('@react-native-async-storage/async-storage', () => ({ getItem: jest.fn(async () => null), setItem: jest.fn() }));
import { Strait } from '../src/native/strait';
import { buildInvite, generateKey, parseInvite } from '../src/invite';
import { defaultSettings, migrateSettings } from '../src/storage';

const KEY = '0123456789abcdef0123456789abcdef';

describe('invite', () => {
  test('round trips', () => {
    for (const inv of [
      { key: KEY, hosts: ['203.0.113.10:7100'], signals: [], rv: [] },
      { key: KEY, hosts: [], signals: ['signal.example.com:7000'], rv: [] },
      { key: KEY, hosts: ['203.0.113.10:7100', '[2001:db8::1]:7100'], signals: ['1.2.3.4:7000'], rv: ['trk', 'nostr'] },
    ]) {
      expect(parseInvite(buildInvite(inv))).toEqual(inv);
    }
  });
  test('build omits trailing empty signals', () => {
    expect(buildInvite({ key: KEY, hosts: ['1.2.3.4:7100'], signals: [] })).toBe(`STRAIT2|${KEY}|1.2.3.4:7100`);
    expect(buildInvite({ key: KEY, hosts: [], signals: ['s:7000'] })).toBe(`STRAIT2|${KEY}||s:7000`);
  });
  test('ipv6', () => {
    expect(parseInvite(`STRAIT2|${KEY}|[::1]:7100`).hosts).toEqual(['[::1]:7100']);
    expect(() => parseInvite(`STRAIT2|${KEY}|[::1]:0`)).toThrow();
    expect(() => parseInvite(`STRAIT2|${KEY}|[::1]`)).toThrow();
  });
  test('legacy', () => {
    expect(parseInvite('10.0.2.2:7000|room1|secret')).toEqual({ key: 'secret', hosts: [], signals: ['10.0.2.2:7000'], rv: [] });
  });
  test('rejects garbage', () => {
    for (const bad of ['', 'hello', 'STRAIT2|', 'STRAIT2|abc|1.2.3.4:7100', `STRAIT2|${KEY}`, `STRAIT2|${KEY}|`, `STRAIT2|${KEY}|1.2.3.4`, `STRAIT2|${KEY}|1.2.3.4:99999`, 'a|b|c|d']) {
      expect(() => parseInvite(bad)).toThrow();
    }
    expect(() => buildInvite({ key: 'zz', hosts: ['1.2.3.4:1'], signals: [] })).toThrow(/32 hex/);
  });
  describe('generateKey', () => {
    const g = globalThis as any;
    const saved = g.crypto;
    afterEach(() => {
      g.crypto = saved;
      delete (Strait as any).generateKey;
    });
    test('uses native', async () => {
      g.crypto = undefined;
      (Strait as any).generateKey = jest.fn(async () => 'cd'.repeat(16));
      await expect(generateKey()).resolves.toBe('cd'.repeat(16));
    });
    test('rejects bad native length', async () => {
      (Strait as any).generateKey = jest.fn(async () => 'abcd');
      await expect(generateKey()).rejects.toThrow(/32 hex/);
    });
    test('falls back to crypto when native missing', async () => {
      g.crypto = { getRandomValues: (a: Uint8Array) => a.fill(0xab) };
      await expect(generateKey()).resolves.toBe('ab'.repeat(16));
    });
    test('no source throws', async () => {
      g.crypto = undefined;
      await expect(generateKey()).rejects.toThrow(/secure random/);
    });
  });
});

describe('settings migration', () => {
  test('relay folds into signals', () => {
    const s = migrateSettings({ relay: 'sig.example.com:7000', killSwitch: false });
    expect(s.signals).toEqual(['sig.example.com:7000']);
    expect(s.hostPort).toBe(7100);
    expect(s.killSwitch).toBe(false);
    expect('relay' in s).toBe(false);
  });
  test('old emulator default dropped', () => {
    expect(migrateSettings({ relay: '10.0.2.2:7000' }).signals).toEqual([]);
  });
  test('new settings untouched, junk repaired', () => {
    expect(migrateSettings({ signals: ['a:1'], hostPort: 7200 })).toMatchObject({ signals: ['a:1'], hostPort: 7200 });
    expect(migrateSettings({ signals: 'x', hostPort: 'no' })).toMatchObject({ signals: [], hostPort: 7100 });
    expect(migrateSettings(null)).toEqual(defaultSettings);
  });
});

describe('invite cr carriers', () => {
  const cr = ['ws@203.0.113.10:9443;sni=h.example', 'ss@203.0.113.10:9461', 'awg@203.0.113.10:9460'];
  test('round trips and keeps entries verbatim', () => {
    const inv = { key: KEY, hosts: ['203.0.113.10:7100'], signals: [], rv: [], cr };
    expect(parseInvite(buildInvite(inv))).toEqual(inv);
    expect(buildInvite(inv)).toBe(`STRAIT2|${KEY}|203.0.113.10:7100||||${cr.join(',')}`);
  });
  test('cr endpoint alone is a valid invite; bad entries are not', () => {
    expect(parseInvite(`STRAIT2|${KEY}|||||ss@1.2.3.4:8388`).cr).toEqual(['ss@1.2.3.4:8388']);
    expect(() => parseInvite(`STRAIT2|${KEY}|1.2.3.4:7100||||ss@1.2.3.4`)).toThrow();
    expect(() => parseInvite(`STRAIT2|${KEY}|1.2.3.4:7100||||WS`)).toThrow();
  });
});
