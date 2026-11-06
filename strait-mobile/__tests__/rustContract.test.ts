/// <reference types="node" />
import { readFileSync } from 'fs';
import { join } from 'path';
import { KNOWN_REASONS, RV_FAILED_PREFIX, RV_FAILED_SUFFIX } from '../src/connectReason';
import * as rvui from '../src/rvui';

const rust = (f: string) => readFileSync(join(__dirname, '../../nat-tunnel/src', f), 'utf8');

// A Rust wording change must fail here instead of silently breaking the UI mapping.
describe('Rust contract', () => {
  it.each(KNOWN_REASONS)('transport.rs still contains: %s', (s) => {
    expect(rust('transport.rs')).toContain(`"${s}"`);
  });
  it('main.rs prints failures as `error: {e}`', () => {
    expect(rust('main.rs')).toContain('eprintln!("error: {e}")');
  });
  it('app.rs keeps the guest and host log shapes', () => {
    const app = rust('app.rs');
    expect(app).toContain('session ready ({})');
    expect(app).toContain('tun session ready ({}, raw packets)');
    expect(app).toMatch(/"direct"[\s\S]*"relayed"/);
    expect(app).toContain('hosting up to {max} clients on port {port}');
    expect(app).toContain('client {from} is {ip} ({} connected)');
    expect(app).toContain('client {ip} left: {reason} ({} connected)');
  });
  it('app.rs keeps the carrier log lines LogStatus.kt reads', () => {
    const app = rust('app.rs');
    expect(app).toContain('client address {ip}/{prefix}, MTU {mtu}, carrier {}');
    expect(app).toContain('connected over the {id} carrier');
    expect(app).toContain('carrier {id}: {why}');
  });
  it('android fd protocol line matches between Rust and Kotlin', () => {
    expect(rust('android_fd_proto.rs')).toContain('"STRAIT-ADDR"');
    const kt = readFileSync(
      join(__dirname, '../android/app/src/main/java/com/straitmobile/FdProtocol.kt'), 'utf8');
    expect(kt).toContain('STRAIT-ADDR');
  });
  it('transport.rs RendezvousFailed sentence keeps its fixed halves', () => {
    expect(rust('transport.rs')).toContain(`"${RV_FAILED_PREFIX}{s}${RV_FAILED_SUFFIX}"`);
  });
  it('preflight.rs rvui texts match the TS mirror', () => {
    const src = rust('preflight.rs');
    // Rust string literal -> text: only \n and \" appear in these constants.
    const lit = (name: string) => {
      const m = new RegExp(`pub const ${name}: &str =\\s*"((?:[^"\\\\]|\\\\.)*)";`).exec(src);
      if (!m) throw new Error(`${name} not found in preflight.rs`);
      return m[1].replace(/\\n/g, '\n').replace(/\\"/g, '"');
    };
    expect(rvui.SEEN_MESSAGE).toBe(lit('SEEN_MESSAGE'));
    expect(rvui.PICK_HEADING).toBe(lit('PICK_HEADING'));
    expect(rvui.TRAFFIC_LINE).toBe(lit('TRAFFIC_LINE'));
    for (const id of rvui.KNOWN) {
      expect(src).toContain(`"${id}" => "${rvui.short(id)}"`);
      expect(src).toContain(`"${id}" => "${rvui.name(id)}"`);
    }
    expect(src).toContain('pub const KNOWN: &[&str] = &["sig", "trk", "nostr", "dht", "ntfy", "mqtt"];');
    expect(src).toContain(rvui.MEETING_CONE);
    expect(src).toContain('Your network uses symmetric NAT: only clients that are public or behind full-cone / address-restricted routers can connect.');
    expect(src).toContain('Your network seems to block incoming UDP, so these services cannot help.');
    expect(rust('gui.rs')).toContain(rvui.DIRECT_COPY);
    expect(rust('gui.rs')).toContain(`"${rvui.DIRECT_TITLE}"`);
  });
  it('main.rs rv-test has --json and check-host takes --rendezvous', () => {
    const m = rust('main.rs');
    expect(m).toContain('RvTest');
    expect(m).toMatch(/Machine-readable result: one JSON array/);
  });
});
