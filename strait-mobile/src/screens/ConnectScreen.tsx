import React from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { Button } from '../components/Button';
import { Field, InlineButton } from '../components/Field';
import { RouteGraphic } from '../components/RouteGraphic';
import { pathLabel, type ClientPath } from '../connectReason';
import type { RvProbe } from '../native/strait';
import * as rv from '../rvui';
import { Chip } from './HostScreen';
import { colors, fonts, statusMeta, type ConnectionState } from '../theme';

function formatBytes(bytes: number) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function ConnectScreen({
  state,
  invite,
  error,
  blocked = false,
  ip,
  path,
  carrier,
  bytes,
  history,
  onChangeInvite,
  onConnect,
  onCancel,
  onDisconnect,
  onPaste,
  onPickHistory,
  rvIds = [],
  rvDisabled = [],
  rvProbes = {},
  rvTesting = false,
  onToggleRv = () => {},
  onTestRv = () => {},
}: {
  state: ConnectionState;
  invite: string;
  error?: string;
  blocked?: boolean; // kill switch is holding traffic: only Disconnect releases it
  ip?: string;
  path?: ClientPath;
  carrier?: { id?: string; mtu?: number; notes: string[] };
  bytes: number;
  history: string[];
  onChangeInvite: (v: string) => void;
  onConnect: () => void;
  onCancel: () => void;
  onDisconnect: () => void;
  onPaste: () => void;
  onPickHistory: (value: string) => void;
  rvIds?: string[];
  rvDisabled?: string[];
  rvProbes?: Record<string, RvProbe>;
  rvTesting?: boolean;
  onToggleRv?: (id: string) => void;
  onTestRv?: () => void;
}) {
  const meta = statusMeta[state];
  const connected = state === 'connected';
  const connecting = state === 'connecting';
  const failed = state === 'failed';
  const isBlocked = failed && blocked;

  const title = connected
    ? 'Connected'
    : connecting
      ? 'Connecting…'
      : isBlocked
        ? 'Traffic blocked'
        : failed
        ? "Couldn't connect"
        : 'Not connected';
  const subtitle = connected
    ? `${pathLabel(path) ? `${pathLabel(path)}. ` : ''}Traffic is flowing through the host.`
    : connecting
      ? 'Looking for the host…'
      : isBlocked
        ? `Reason: ${(error || 'unknown').replace(/[.\s]+$/, '')}. The kill switch is blocking all network traffic on this device. Tap Disconnect to unblock.`
        : failed
        ? `Failed: ${error || 'Host unreachable - check the invite or UDP reachability.'}`
        : "Paste a host's invite code to get online.";

  return (
    <View style={styles.root}>
      <ScrollView
        contentContainerStyle={styles.scroll}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}>
        <View style={[styles.card, { borderColor: meta.border }]}>
          <RouteGraphic state={state} />
          <View style={styles.copy}>
            <Text accessibilityLiveRegion="polite" style={[styles.title, { color: meta.title }]}>
              {title}
            </Text>
            <Text style={styles.subtitle}>{subtitle}</Text>
            {connected && carrier?.id ? (
              <Text style={styles.subtitle}>
                {`Carrier: ${carrier.id}${carrier.mtu ? `, MTU ${carrier.mtu}` : ''}`}
              </Text>
            ) : null}
            {(connected || failed) && carrier?.notes.length ? (
              <Text style={styles.subtitle}>{`Carriers tried: ${carrier.notes.join('; ')}`}</Text>
            ) : null}
          </View>
        </View>

        {connected ? (
          <View style={styles.stats}>
            <View style={styles.statCell}>
              <Text style={styles.statLabel}>Public IP</Text>
              <Text style={styles.statValue}>{ip || '—'}</Text>
            </View>
            <View style={styles.statDivider} />
            <View style={styles.statCell}>
              <Text style={styles.statLabel}>Data used</Text>
              <Text style={styles.statValue}>{formatBytes(bytes)}</Text>
            </View>
          </View>
        ) : (
          <Field
            label="Invite code"
            value={invite}
            onChangeText={onChangeInvite}
            placeholder="STRAIT2|key|host:7100"
            autoCapitalize="none"
            autoCorrect={false}
            editable={!connecting}
            error={failed && !isBlocked ? error : undefined}
            right={
              <InlineButton
                title="Paste"
                onPress={onPaste}
                disabled={connecting}
              />
            }
          />
        )}

        {!connected && !connecting && rvIds.length > 0 ? (
          <View testID="rv-guest" style={styles.recent}>
            <Text style={styles.recentLabel}>The host offers these ways to connect</Text>
            {rv.guestMethods(rvIds, rvDisabled).map(m => {
              const chip = rv.guestChip(m, rvProbes[m.id]);
              return (
                <Pressable
                  key={m.id}
                  testID={`use-${m.id}`}
                  accessibilityRole="switch"
                  accessibilityState={{ checked: m.enabled, disabled: !m.supported }}
                  disabled={!m.supported}
                  onPress={() => onToggleRv(m.id)}
                  style={[styles.rvRow, !m.supported && { opacity: 0.6 }]}>
                  <View style={{ flex: 1, gap: 2 }}>
                    <Text style={styles.rvName}>{rv.name(m.id)}</Text>
                    <Text style={styles.statLabel}>{m.supported ? (m.enabled ? 'Use this: on' : 'Use this: off') : rv.short(m.id)}</Text>
                  </View>
                  <Chip text={chip.text} tone={chip.tone} />
                </Pressable>
              );
            })}
            <Button
              title={rvTesting ? 'Testing…' : 'Test services'}
              variant="secondary"
              disabled={rvTesting}
              onPress={onTestRv}
            />
            <Text style={styles.statLabel}>{rv.TRAFFIC_LINE}</Text>
          </View>
        ) : null}

        {!connected && !connecting && history.length > 0 ? (
          <View style={styles.recent}>
            <Text style={styles.recentLabel}>Recent</Text>
            {history.slice(0, 5).map(item => (
              <Pressable
                key={item}
                onPress={() => onPickHistory(item)}
                style={({ pressed }) => [
                  styles.recentRow,
                  pressed && { backgroundColor: colors.subtle },
                ]}>
                <Text numberOfLines={1} style={styles.recentText}>
                  {item}
                </Text>
              </Pressable>
            ))}
          </View>
        ) : null}
      </ScrollView>

      <View style={styles.action}>
        {connected || isBlocked ? (
          <Button title="Disconnect" variant="danger" onPress={onDisconnect} />
        ) : connecting ? (
          <Button title="Cancel" variant="secondary" onPress={onCancel} />
        ) : (
          <Button
            title={failed ? 'Try again' : 'Connect'}
            onPress={onConnect}
            disabled={!invite.trim()}
          />
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  rvRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    padding: 12,
  },
  rvName: { color: colors.text, fontFamily: fonts.semibold, fontSize: 13 },
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
  title: {
    fontFamily: fonts.semibold,
    fontSize: 17,
    textAlign: 'center',
  },
  subtitle: {
    color: colors.textMuted,
    fontFamily: fonts.regular,
    fontSize: 13,
    textAlign: 'center',
  },
  stats: {
    flexDirection: 'row',
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    overflow: 'hidden',
  },
  statCell: { flex: 1, padding: 14, gap: 4 },
  statDivider: { width: 1, backgroundColor: colors.border },
  statLabel: { color: colors.textMuted, fontFamily: fonts.medium, fontSize: 12 },
  statValue: { color: colors.text, fontFamily: fonts.mono, fontSize: 14 },
  recent: { gap: 4 },
  recentLabel: {
    color: colors.textLabel,
    fontFamily: fonts.semibold,
    fontSize: 13,
    marginBottom: 2,
  },
  recentRow: { paddingVertical: 9, paddingHorizontal: 10, borderRadius: 8 },
  recentText: { color: colors.textMuted, fontFamily: fonts.mono, fontSize: 12 },
  action: { paddingHorizontal: 20, paddingTop: 4, paddingBottom: 20 },
});
