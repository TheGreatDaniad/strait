# Strait — UI design handoff

Strait is a desktop app that lets one peer use another peer's internet connection through a relay ("NAT tunnel"). This package is the complete visual design for the app's UI. Build the UI to match it; the backend/tunnel logic is out of scope here.

## What's in this folder

| Path | What it is |
|---|---|
| `screens/*.html` | **Source of truth.** One standalone HTML page per screen, exact markup and inline styles. Open in a browser; tabs and buttons link between screens. |
| `screens/*.png` | 2× renders of each screen (840×1120 px for a 420×560 window). |
| `screens/00-brand.html/.png` | Brand sheet: logo, app icon, lockup, type, palette. |
| `tokens/tokens.json` | All colours, type, spacing, radii, sizes, motion, with what each is used for. |
| `tokens/tokens.css` | Same tokens as CSS custom properties (`--st-*`). |
| `logo/` | Final mark and app icon (SVG + PNG at 1024–16 px). |

## Window

- Fixed size **420 × 560**, not resizable. Light theme only (no dark mode designed yet).
- Background `#F5F8FA`, 20 px padding on the sides.
- Vertical structure, top to bottom:
  1. **Header** (16 px top padding): logo (22 px) + wordmark "Strait" left, **status chip** right.
  2. **Tab bar** (12 px below): segmented control, 3 equal tabs — Connect · Host · Settings.
  3. **Status card** (16 px below): the route graphic + status title + subtitle. (Not on Settings.)
  4. **Content** (20 px below): the one field or info block for this state.
  5. **Primary action** pinned to the bottom (20 px padding), full width, 48 px tall.

## Screens and states

| File | Tab | State | Status chip | Route graphic | Content | Bottom action |
|---|---|---|---|---|---|---|
| `01-connect-idle` | Connect | Not connected | Idle (grey) | You → Host → Internet, grey nodes, dashed grey lines | Invite code input + **Paste** button | **Connect** (deep sea, primary) |
| `02-connect-connecting` | Connect | Connecting | Connecting (deep-sea tint) | "You" node pulses, first segment has marching dashes, rest grey dashed | Invite code shown, disabled | **Cancel** (secondary) |
| `03-connect-connected` | Connect | Connected | Connected (lagoon) | All nodes lagoon, solid lagoon lines with flowing packets | Stat pair: **Your IP**, **Data used** (mono) | **Disconnect** (danger outline) |
| `04-connect-failed` | Connect | Failed | Failed (ember) | First line grey with ember ✕ badge in the middle; host and internet greyed | Invite code with ember border + error helper text, **Paste** | **Try again** (deep sea, primary) |
| `05-host-not-sharing` | Host | Not sharing | Idle | Peer (dashed empty circle) → You → Internet, grey | Relay row: current relay address + **Change** link (→ Settings) | **Start sharing** (deep sea, primary) |
| `06-host-sharing` | Host | Sharing | Sharing (deep-sea tint) | Peer → **You** (solid deep-sea node) → Internet, deep-sea lines with packets | Invite code (masked key) + **Copy** button | **Stop sharing** (secondary) |
| `07-settings` | Settings | — | Reflects current state | none | Privacy group: **Kill switch**, **Block IPv6** toggles; **Relay server** input; version footer | none |

### State logic

```
Connect tab:  idle ──Connect──▶ connecting ──ok──▶ connected ──Disconnect──▶ idle
                                    │ fail/timeout
                                    ▼
                                  failed ──Try again──▶ connecting
              connecting ──Cancel──▶ idle
Host tab:     not sharing ──Start sharing──▶ sharing ──Stop sharing──▶ not sharing
```

- The **status chip in the header always reflects the app's global state** on every tab (e.g. Settings shows "Connected" while connected).
- The Connect tab and Host tab are mutually exclusive in practice: while connected as a client, Start sharing should be disabled, and vice versa (not drawn — use disabled button styling: 50% opacity, no hover).
- Paste fills the input from the clipboard. Copy copies the full invite code (the key is masked on screen as `••••••`); show a brief "Copied" label on the button for ~1.5 s.
- Invite code format: `relay-host:port|room|key`.
- The error helper text should say what actually failed (examples: timeout, room not found, bad key). Drawn example: "No host answered in this room after 15 s."

## Components

**Status chip** — 26 px tall, radius 13, padding 0 10, 12 px/600 text, 7 px dot.

| State | Fill | Text | Dot |
|---|---|---|---|
| Idle | `#E9EFF3` | `#576773` | `#8A9AA6` |
| Connecting / Sharing | `#E3EFF5` | `#0A4560` | `#0E5A7A` |
| Connected | `#E0F5F1` | `#0B7666` | `#0F9D8A` |
| Failed | `#FDEBE1` | `#9A3412` | `#C2410C` |

**Tabs** — track `#E9EFF3`, radius 12, padding 4, gap 4, 3 equal columns. Tab 36 px tall, radius 9. Active: white fill, shadow `0 1px 2px rgba(15,28,36,.1)`, text `#0F1C24` 600. Inactive: transparent, `#576773` 500; hover text `#0F1C24`.

**Status card** — white, 1 px border, radius 16, padding 24/20/20, gap 18. Border colour follows state: idle `#DFE7EC`, connecting/sharing `#C3DCE8`, connected `#BCE7DF`, failed `#F5CDB5`.

**Route graphic** (decorative, `aria-hidden`; the title below carries the meaning):
- Three nodes, each 64 px column: 52 px circle with 24 px stroke icon (laptop / router / globe), 12 px/500 label under it (`#576773`).
- Lines between nodes are aligned to node centre (25 px from top), flex-grow to fill.
- Idle: node fill `#EEF3F6`, icon `#576773`, line `2px dashed #B9C7D0`.
- Connected: node fill `#E0F5F1`, icon `#0F9D8A`, line solid 2 px `#8FD6CA` with 6 px `#0F9D8A` packets travelling left→right.
- Sharing: same but deep sea (`#E3EFF5` / `#0E5A7A` / line `#9CC3D6`); the "You" node is solid `#0E5A7A` with white icon. Peer → You → Internet.
- Connecting: "You" node deep-sea tint with pulse ring; first line is a deep-sea dashed pattern that scrolls; rest idle.
- Failed: first line solid `#B9C7D0` with a 24 px ember circle + white ✕ in its middle.
- Host not sharing: Peer node is an empty 2 px dashed `#B9C7D0` circle.
- Status title 17/600 (coloured per state: idle `#0F1C24`, deep sea `#083B52`, lagoon `#075E52`, ember `#9A3412`), subtitle 13 `#576773`, centred.

**Input** — 44 px, radius 10, border `#CCD7DE`, white, padding 0 14, JetBrains Mono 13. Focus: 2 px `#0E5A7A` outline, offset 2. Invalid: border `#C2410C` + `aria-invalid` + helper text 13 `#9A3412` linked via `aria-describedby`. Disabled/read-only: fill `#F6F9FB`, border `#DFE7EC`, text `#576773`. Label above: 13/600 `#33424D`, 8 px gap.

**Buttons** (radius 12, 48 px for bottom actions; inline Paste/Copy are 44 px, radius 10, padding 0 16–18, 14 px):
- Primary: `#0E5A7A` fill, white 15/600 text; hover `#0A4560`.
- Secondary: white, 1 px `#CCD7DE`, text `#0F1C24`; hover fill `#EEF3F6`.
- Danger (Disconnect): white, 1 px `#F1C2A6`, text `#B43C0D`; hover fill `#FDEBE1`.

**Stat pair** (Connected) — white card, 1 px border, radius 12, two equal columns split by a 1 px border. Label 12/500 `#576773`, value JetBrains Mono 14.

**Relay row** (Host idle) — white card, radius 12, padding 12 16: label "Relay" 12/500 muted, value mono 13 (ellipsis), "Change" link 13/500 deep sea on the right.

**Toggle switch** (Settings) — 40×24, radius 12, off `#B9C7D0`, on `#0E5A7A`, 18 px white knob with small shadow, 0.15 s slide. Whole row is the `<label>` (click target), title 14/500 + description 13 muted. Grouped in a white card with 1 px row dividers `#EEF3F6`.

## Brand

- **Name:** Strait — a narrow passage of water between two shores. The two shores are the two peers; the passage is the tunnel.
- **Mark ("S3 · Wave S"):** the S of Strait drawn as a wave, with a dot at each end. The deep-sea dot `#0E5A7A` (top) is you, the lagoon dot `#0F9D8A` (bottom) is the other peer; the stroke fades from deep sea to lagoon (vertical gradient) — the wave carrying traffic between you. Use `logo/strait-mark.svg` for large sizes (stroke 2.2) and `logo/strait-mark-small.svg` for 16–24 px (stroke 2.8).
- **Wordmark:** "Strait" in Fraunces **Italic** 600, letter-spacing −0.01em — set like water names on nautical charts. 19 px in the app header next to the 22 px mark, 8 px gap.
- **App icon:** `logo/strait-app-icon.svg` — deep-sea rounded tile with the wave in white fading to light lagoon (`#7FE3D3`). Transparent PNGs at 1024/512/256/128/64/32/16 in `logo/png/`. Generate `.icns` / `.ico` from these.
- **Tray / menu bar:** use `logo/strait-mark-mono.svg` as a template image on macOS (the system tints it). On Windows use `strait-mark-small.svg`. Suggested: idle = 50% opacity, connected/sharing = full.

## Fonts

All three are free Google Fonts (SIL Open Font License) — **bundle them with the app**; don't load from the web at runtime.
- Inter — 400, 500, 600, 700
- Fraunces — **Italic 600** only (wordmark)
- JetBrains Mono — 400, 500

## Motion

- Packets: two 6 px dots per line, `left: 0 → calc(100% - 6px)`, 1.6 s linear infinite, second dot delayed −0.8 s.
- Connecting: line background `repeating-linear-gradient(90deg, #0E5A7A 0 6px, transparent 6px 12px)`, background-position animates 0 → 12px over 0.6 s linear infinite; "You" node box-shadow pulse 0 → 8 px over 1.4 s.
- Respect `prefers-reduced-motion: reduce`: hide packets, stop pulse and march.

## Accessibility

- All text meets WCAG AA 4.5:1 on its background (checked for the muted greys and tinted chips).
- Use real `<button>`, `<a>`, `<input>`, `<label>`; tabs should be a proper tablist (`role="tablist"`/`tab`, arrow-key navigation) in the real build.
- Visible focus ring everywhere: 2 px `#0E5A7A`, offset 2 px.
- Status changes should be announced (`aria-live="polite"` on the status title).
- Never rely on colour alone: every state also changes the chip label and the status title text.

## Placeholders in the mockups

`203.0.113.24`, `00:12:43`, `13.5 MB`, `relay.example.com:7000`, `[ROOM]`, `[RELAY]`, `[VERSION]` are sample values — bind them to real data.

## Not designed yet

Dark mode · first-run / onboarding · multiple peers on Host (drawn as a single peer) · update / about dialog · tray menu contents · Windows/Linux window chrome differences.
