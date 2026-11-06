export const MAX_CLIENTS_UI = 8;

export function parsePort(text: string): number | null {
  if (!/^\d{1,5}$/.test(text.trim())) return null;
  const n = Number(text);
  return n >= 1 && n <= 65535 ? n : null;
}

const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;

// Accepts host:port, a.b.c.d:port and [v6]:port. Returns the trimmed entry or an error.
export function validateSignal(input: string): { ok: true; value: string } | { ok: false; error: string } {
  const v = input.trim();
  const m = v.startsWith('[') ? /^\[([0-9a-fA-F:.]+:[0-9a-fA-F:.]*)\]:(\d+)$/.exec(v) : /^([^:\s]+):(\d+)$/.exec(v);
  const hostOk = m && (v.startsWith('[') || HOST_RE.test(m[1]));
  if (!m || !hostOk || parsePort(m[2]) === null) {
    return { ok: false, error: 'Use host:port, e.g. signal.example.com:7000' };
  }
  return { ok: true, value: v };
}

export function addSignal(list: string[], input: string): { list: string[]; error?: string } {
  const r = validateSignal(input);
  if (!r.ok) return { list, error: r.error };
  if (list.some(x => x.toLowerCase() === r.value.toLowerCase())) return { list, error: 'Already added.' };
  return { list: [...list, r.value] };
}
