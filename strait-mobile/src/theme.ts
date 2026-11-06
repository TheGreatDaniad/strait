export const colors = {
  bg: '#F5F8FA',
  surface: '#FFFFFF',
  subtle: '#EEF3F6',
  track: '#E9EFF3',
  fieldDisabled: '#F6F9FB',
  border: '#DFE7EC',
  borderStrong: '#CCD7DE',
  line: '#B9C7D0',
  iconMuted: '#8A9AA6',
  textMuted: '#576773',
  textLabel: '#33424D',
  text: '#0F1C24',

  sea: '#0E5A7A',
  seaHover: '#0A4560',
  seaStrong: '#083B52',
  seaLine: '#9CC3D6',
  seaBorder: '#C3DCE8',
  seaTint: '#E3EFF5',

  lagoon: '#0F9D8A',
  lagoonText: '#0B7666',
  lagoonStrong: '#075E52',
  lagoonLine: '#8FD6CA',
  lagoonBorder: '#BCE7DF',
  lagoonTint: '#E0F5F1',
  lagoonOnSea: '#7FE3D3',

  ember: '#C2410C',
  emberText: '#9A3412',
  emberBorder: '#F5CDB5',
  emberTint: '#FDEBE1',
  dangerText: '#B43C0D',
  dangerBorder: '#F1C2A6',

  onPrimary: '#FFFFFF',
} as const;

export const fonts = {
  regular: 'Inter-400',
  medium: 'Inter-500',
  semibold: 'Inter-600',
  bold: 'Inter-700',
  brand: 'Fraunces-600',
  mono: 'JetBrainsMono-400',
  monoMedium: 'JetBrainsMono-500',
} as const;

export const radius = {
  tab: 9,
  input: 10,
  track: 12,
  button: 12,
  statCard: 12,
  chip: 13,
  card: 16,
} as const;

export type ConnectionState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'failed'
  | 'sharing';

export const statusMeta: Record<
  ConnectionState,
  { label: string; fg: string; bg: string; dot: string; border: string; title: string }
> = {
  idle: {
    label: 'Idle',
    fg: colors.textMuted,
    bg: colors.track,
    dot: colors.iconMuted,
    border: colors.border,
    title: colors.text,
  },
  connecting: {
    label: 'Connecting',
    fg: colors.seaHover,
    bg: colors.seaTint,
    dot: colors.sea,
    border: colors.seaBorder,
    title: colors.seaStrong,
  },
  connected: {
    label: 'Connected',
    fg: colors.lagoonText,
    bg: colors.lagoonTint,
    dot: colors.lagoon,
    border: colors.lagoonBorder,
    title: colors.lagoonStrong,
  },
  failed: {
    label: 'Failed',
    fg: colors.emberText,
    bg: colors.emberTint,
    dot: colors.ember,
    border: colors.emberBorder,
    title: colors.emberText,
  },
  sharing: {
    label: 'Sharing',
    fg: colors.seaHover,
    bg: colors.seaTint,
    dot: colors.sea,
    border: colors.seaBorder,
    title: colors.seaStrong,
  },
};
