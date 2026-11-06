import { failureReason, parseLogLine, REASON_NO_IPV6, REASON_SYMMETRIC, REASON_UNREACHABLE } from '../src/connectReason';

// Literal strings as printed by nat-tunnel (app.rs log::info!, main.rs eprintln!).
describe('failureReason', () => {
  it('maps the exact Rust sentences, with or without the error: prefix', () => {
    expect(failureReason('error: No IPv6 on this network; the host is IPv6-only.')).toBe(REASON_NO_IPV6);
    expect(failureReason('error: Host unreachable - check the invite or UDP reachability.')).toBe(REASON_UNREACHABLE);
    expect(failureReason('Direct path unavailable - both networks are symmetric.')).toBe(REASON_SYMMETRIC);
  });
  it('passes unknown errors through and defaults empty', () => {
    expect(failureReason('error: tunnel probe failed')).toBe('tunnel probe failed');
    expect(failureReason(undefined)).toBe(REASON_UNREACHABLE);
  });
});

describe('parseLogLine', () => {
  it.each([
    ['host session ready (direct)', 'direct'],
    ['guest session ready (relayed)', 'signal'],
    ['[2026-01-01T00:00:00Z INFO  nat_tunnel::app] guest tun session ready (direct, raw packets)', 'direct'],
  ])('ready: %s', (line, path) => expect(parseLogLine(line)).toEqual({ kind: 'ready', path }));
  it('parses the host lines', () => {
    expect(parseLogLine('[INFO app] hosting up to 8 clients on port 7100')).toEqual({ kind: 'hosting', max: 8, port: 7100 });
    expect(parseLogLine('client 1.2.3.4:5555 is 10.7.0.3 (2 connected)')).toEqual({ kind: 'clients', count: 2 });
    expect(parseLogLine('client 10.7.0.3 left: idle timeout (1 connected)')).toEqual({ kind: 'clients', count: 1 });
  });
  it('parses the error line', () => {
    expect(parseLogLine('error: Host unreachable - check the invite or UDP reachability.')).toEqual({
      kind: 'error',
      message: REASON_UNREACHABLE,
    });
  });
  it('ignores other lines', () => {
    expect(parseLogLine('waiting for session ready')).toBeUndefined();
    expect(parseLogLine('tx=1B rx=2B')).toBeUndefined();
  });
});
