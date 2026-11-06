import React from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { Button } from '../components/Button';
import { Field, InlineButton } from '../components/Field';
import type { PreflightResult, RvProbe } from '../native/strait';
import { RouteGraphic } from '../components/RouteGraphic';
import { parsePort } from '../validate';
import * as rv from '../rvui';
import { colors, fonts, statusMeta } from '../theme';

export function Chip({ text, tone }: { text: string; tone: 'good' | 'bad' | 'neutral' }) {
  const bg = tone === 'good' ? colors.lagoonTint : tone === 'bad' ? colors.emberTint : colors.subtle;
  const fg = tone === 'good' ? colors.lagoonText : tone === 'bad' ? colors.emberText : colors.textMuted;
  return (
    <View style={[styles.chip, { backgroundColor: bg }]}>
      <Text style={[styles.chipText, { color: fg }]}>{text}</Text>
    </View>
  );
}

export function HostScreen({
  sharing,
  clients = 0,
  relay,
  invite,
  copied,
  maxClients,
  rateKbps,
  onStart,
  onStop,
  onChangeRelay,
  onCopy,
  portText,
  portError,
  checking,
  checkError,
  check,
  signals = [],
  probes = {},
  probing = false,
  selected = [],
  onToggle = () => {},
  starting = false,
  live = {},
  onChangePort,
  onCheck,
}: {
  sharing: boolean;
  clients?: number;
  relay: string;
  invite: string;
  copied: boolean;
  maxClients: number;
  rateKbps: number;
  onStart: () => void;
  onStop: () => void;
  onChangeRelay: () => void;
  onCopy: () => void;
  portText: string;
  portError?: string;
  checking: boolean;
  checkError?: string;
  check: PreflightResult | null;
  signals?: string[];
  probes?: Record<string, RvProbe>;
  probing?: boolean;
  selected?: string[];
  onToggle?: (id: string) => void;
  starting?: boolean;
  live?: Record<string, string>;
  onChangePort: (v: string) => void;
  onCheck: () => void;
}) {
  const state = sharing ? 'sharing' : 'host-idle';
  const meta = statusMeta[sharing ? 'sharing' : 'idle'];
  const port = parsePort(portText);
  const st = rv.stage(check, checking, port);
  const ids = rv.offered(signals.length > 0);
  const ticked = ids.filter(id => selected.includes(id) && rv.selectable(rv.methodState(probes[id]))).length;
  const canStart = !starting && rv.startAllowed(st, ticked);
  const meeting = st === 'meeting' && check;
  const showList = !!meeting && rv.offersPicker(check);
  const sharedIds = invite.split('|')[5]?.split(',').filter(Boolean) ?? [];

  return (
    <View style={styles.root}>
      <ScrollView
        contentContainerStyle={styles.scroll}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}>
        <View style={[styles.card, { borderColor: meta.border }]}>
          <RouteGraphic state={state} host />
          <View style={styles.copy}>
            <Text accessibilityLiveRegion="polite" style={[styles.title, { color: meta.title }]}>
              {sharing ? 'Sharing your connection' : 'Not sharing'}
            </Text>
            <Text style={styles.subtitle}>
              {sharing
                ? `${clients} connected. A peer can join with this invite code.`
                : "Let someone else use this device's internet."}
            </Text>
          </View>
        </View>

        {!sharing ? (
          <View style={styles.inviteBlock}>
            <Field
              label="Port (UDP)"
              value={portText}
              onChangeText={onChangePort}
              keyboardType="number-pad"
              error={portError}
            />
            <Button
              title={checking ? 'Checking…' : 'Check connectivity'}
              variant="secondary"
              disabled={checking || !!portError}
              onPress={onCheck}
            />
            {checking ? <Text style={styles.verdictMsg}>Checking this network. This can take several seconds.</Text> : null}
            {!checking && st === 'check' && !checkError ? (
              <Text style={styles.verdictMsg}>Check whether clients can reach this device.</Text>
            ) : null}
            {checkError ? <Text testID="check-error" style={styles.warnText}>{checkError}</Text> : null}
          </View>
        ) : null}

        {!sharing && st === 'direct' && check ? (
          <View testID="stage-direct" style={[styles.verdict, { borderColor: colors.lagoonBorder }]}>
            <Text style={styles.directTitle}>{rv.DIRECT_TITLE}</Text>
            <Text style={styles.vValueLeft}>{rv.DIRECT_COPY}</Text>
            <Text style={styles.statLabel}>{`via ${rv.directLabel(check.method)}`}</Text>
          </View>
        ) : null}

        {!sharing && meeting ? (
          <View testID="stage-meeting" style={[styles.verdict, { borderColor: colors.emberBorder }]}>
            <Text style={[styles.verdictMsg, { color: colors.emberText }]}>{rv.meetingCopy(check, port ?? check.port)}</Text>
          </View>
        ) : null}

        {!sharing && showList ? (
          <View style={styles.inviteBlock}>
            <Text style={styles.label}>{rv.PICK_HEADING}</Text>
            {ids.map(id => {
              const ms = rv.methodState(probes[id]);
              const chip = rv.methodChip(ms);
              const usable = rv.selectable(ms);
              const on = usable && selected.includes(id);
              return (
                <Pressable
                  key={id}
                  testID={`pick-${id}`}
                  accessibilityRole="checkbox"
                  accessibilityState={{ checked: on, disabled: !usable }}
                  disabled={!usable}
                  onPress={() => onToggle(id)}
                  style={[styles.pickRow, !usable && { opacity: 0.55 }]}>
                  <View style={[styles.box, on && styles.boxOn]}>
                    {on ? <Text style={styles.tick}>✓</Text> : null}
                  </View>
                  <View style={styles.pickText}>
                    <Text style={styles.settingLabel}>{rv.pickerLabel(id, signals)}</Text>
                    <Text style={styles.statLabel}>{rv.short(id)}</Text>
                  </View>
                  <Chip text={chip.text} tone={chip.tone} />
                </Pressable>
              );
            })}
            {probing ? <Text style={styles.verdictMsg}>Checking which services this network can reach…</Text> : null}
            <Text testID="seen-message" style={styles.verdictMsg}>{rv.SEEN_MESSAGE}</Text>
          </View>
        ) : null}

        {sharing && invite ? (
          <View style={styles.inviteBlock}>
            <Text style={styles.label}>Invite code</Text>
            <View style={styles.inviteRow}>
              <View style={styles.inviteBox}>
                <Text numberOfLines={1} style={styles.inviteText}>
                  {invite}
                </Text>
              </View>
              <InlineButton title={copied ? 'Copied' : 'Copy'} onPress={onCopy} />
            </View>
            {sharedIds.length ? <Text style={styles.verdictMsg}>{rv.clientsWillTry(sharedIds)}</Text> : null}
            {sharedIds.map(id => (
              <View key={id} style={styles.vRow}>
                <Text style={styles.statLabel}>{rv.name(id)}</Text>
                <Text testID={`live-${id}`} style={styles.vValue}>{live[id] ? rv.liveText(live[id]) : 'Starting'}</Text>
              </View>
            ))}
          </View>
        ) : null}

        {!sharing ? (
          <View style={styles.relayCard}>
            <View style={styles.relayText}>
              <Text style={styles.statLabel}>Signal</Text>
              <Text numberOfLines={1} style={styles.relayValue}>
                {relay || 'None (direct only)'}
              </Text>
            </View>
            <Pressable onPress={onChangeRelay} accessibilityRole="link">
              <Text style={styles.link}>Change</Text>
            </Pressable>
          </View>
        ) : null}

        <View style={styles.settingsCard}>
          <View style={styles.settingRow}>
            <Text style={styles.settingLabel}>Max clients</Text>
            <Text style={styles.settingValue}>{maxClients}</Text>
          </View>
          <View style={styles.divider} />
          <View style={styles.settingRow}>
            <Text style={styles.settingLabel}>Per-client limit</Text>
            <Text style={styles.settingValue}>
              {rateKbps > 0 ? `${rateKbps} KB/s` : 'Unlimited'}
            </Text>
          </View>
        </View>
      </ScrollView>

      <View style={styles.action}>
        {sharing ? (
          <Button title="Stop sharing" variant="secondary" onPress={onStop} />
        ) : (
          <Button title={starting ? 'Starting…' : 'Start sharing'} onPress={onStart} disabled={!canStart} />
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  chip: { borderRadius: 8, paddingHorizontal: 8, paddingVertical: 2 },
  chipText: { fontFamily: fonts.medium, fontSize: 11.5 },
  directTitle: { color: colors.lagoonText, fontFamily: fonts.semibold, fontSize: 15 },
  vValueLeft: { color: colors.text, fontFamily: fonts.regular, fontSize: 13 },
  pickRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    padding: 12,
  },
  pickText: { flex: 1, gap: 2 },
  box: { width: 22, height: 22, borderRadius: 6, borderWidth: 1.5, borderColor: colors.borderStrong, alignItems: 'center', justifyContent: 'center' },
  boxOn: { backgroundColor: colors.sea, borderColor: colors.sea },
  tick: { color: colors.onPrimary, fontSize: 14, fontFamily: fonts.semibold },
  verdict: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    padding: 16,
    gap: 8,
  },
  vRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  vValue: { flex: 1, textAlign: 'right', color: colors.text, fontFamily: fonts.medium, fontSize: 13 },
  verdictMsg: { color: colors.textMuted, fontFamily: fonts.regular, fontSize: 13, marginTop: 4 },
  warnText: { color: colors.emberText, fontFamily: fonts.regular, fontSize: 13 },
  root: { flex: 1 },
  scroll: { paddingHorizontal: 20, paddingTop: 16, paddingBottom: 16, gap: 20 },
  card: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderRadius: 16,
    paddingTop: 24,
    paddingHorizontal: 20,
    paddingBottom: 20,
    gap: 18,
  },
  copy: { alignItems: 'center', gap: 2 },
  title: { fontFamily: fonts.semibold, fontSize: 17, textAlign: 'center' },
  subtitle: {
    color: colors.textMuted,
    fontFamily: fonts.regular,
    fontSize: 13,
    textAlign: 'center',
  },
  relayCard: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  relayText: { flex: 1, gap: 2 },
  statLabel: { color: colors.textMuted, fontFamily: fonts.medium, fontSize: 12 },
  relayValue: { color: colors.text, fontFamily: fonts.mono, fontSize: 13 },
  link: { color: colors.sea, fontFamily: fonts.medium, fontSize: 13 },
  inviteBlock: { gap: 8 },
  label: { color: colors.textLabel, fontFamily: fonts.semibold, fontSize: 13 },
  inviteRow: { flexDirection: 'row', gap: 8 },
  inviteBox: {
    flex: 1,
    height: 44,
    borderRadius: 10,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.fieldDisabled,
    paddingHorizontal: 14,
    justifyContent: 'center',
  },
  inviteText: { color: colors.textMuted, fontFamily: fonts.mono, fontSize: 13 },
  settingsCard: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    paddingHorizontal: 16,
  },
  settingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 12,
  },
  settingLabel: { color: colors.text, fontFamily: fonts.medium, fontSize: 14 },
  settingValue: { color: colors.textMuted, fontFamily: fonts.mono, fontSize: 13 },
  divider: { height: 1, backgroundColor: colors.subtle },
  action: { paddingHorizontal: 20, paddingTop: 4, paddingBottom: 20 },
});
