import React, { useState } from 'react';
import {
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { Field, InlineButton } from '../components/Field';
import { addSignal, parsePort } from '../validate';
import { ToggleRow } from '../components/ToggleRow';
import { colors, fonts } from '../theme';
import type { Settings } from '../storage';

export function SettingsScreen({
  settings,
  onChange,
  version,
}: {
  settings: Settings;
  onChange: (next: Settings) => void;
  version: string;
}) {
  const [signalText, setSignalText] = useState('');
  const [signalError, setSignalError] = useState('');
  const [portText, setPortText] = useState(String(settings.hostPort));
  const addSig = () => {
    const r = addSignal(settings.signals, signalText);
    if (r.error) return setSignalError(r.error);
    onChange({ ...settings, signals: r.list });
    setSignalText('');
  };
  const set = <K extends keyof Settings>(key: K, value: Settings[K]) =>
    onChange({ ...settings, [key]: value });

  return (
    <ScrollView
      contentContainerStyle={styles.scroll}
      keyboardShouldPersistTaps="handled"
      showsVerticalScrollIndicator={false}>
      <View style={styles.group}>
        <ToggleRow
          title="Kill switch"
          description="If the tunnel process dies, block all traffic until you tap Disconnect. Does not protect before the tunnel is up, or if Android removes the VPN (force stop, revoked permission); for that use Always-on VPN + Block connections without VPN."
          value={settings.killSwitch}
          onChange={v => set('killSwitch', v)}
        />
        <View style={styles.divider} />
        <ToggleRow
          title="Block IPv6"
          description="Prevent IPv6 leaks outside the tunnel."
          value={settings.blockIPv6}
          onChange={v => set('blockIPv6', v)}
        />
      </View>

      <View style={styles.fieldGroup}>
        <Text style={styles.label}>Signal servers (optional)</Text>
        {settings.signals.map(sig => (
          <View key={sig} style={styles.sigRow}>
            <Text numberOfLines={1} style={styles.sigText}>{sig}</Text>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={`Remove ${sig}`}
              onPress={() => set('signals', settings.signals.filter(x => x !== sig))}>
              <Text style={styles.remove}>Remove</Text>
            </Pressable>
          </View>
        ))}
        <Field
          label="Add server"
          value={signalText}
          onChangeText={v => { setSignalText(v); setSignalError(''); }}
          autoCapitalize="none"
          autoCorrect={false}
          placeholder="signal.example.com:7000"
          error={signalError}
          right={<InlineButton title="Add" onPress={addSig} />}
        />
        <Text style={styles.helper}>Signaling only. Payload goes directly peer-to-peer.</Text>
      </View>

      <Field
        label="Host port (UDP)"
        value={portText}
        onChangeText={v => {
          setPortText(v);
          const n = parsePort(v);
          if (n !== null) set('hostPort', n);
        }}
        keyboardType="number-pad"
        error={parsePort(portText) === null ? 'Enter a port from 1 to 65535.' : undefined}
      />

      <View style={styles.fieldGroup}>
        <Text style={styles.label}>Sharing</Text>
        <View style={styles.group}>
          <View style={styles.row}>
            <View style={styles.rowText}>
              <Text style={styles.rowTitle}>Max clients</Text>
              <Text style={styles.rowDesc}>Concurrent clients (1–8 here; server limit 1024).</Text>
            </View>
            <View style={styles.stepper}>
              <Pressable
                accessibilityRole="button"
                onPress={() => set('maxClients', Math.max(1, settings.maxClients - 1))}
                style={styles.stepBtn}>
                <Text style={styles.stepText}>−</Text>
              </Pressable>
              <Text style={styles.stepValue}>{settings.maxClients}</Text>
              <Pressable
                accessibilityRole="button"
                onPress={() => set('maxClients', Math.min(8, settings.maxClients + 1))}
                style={styles.stepBtn}>
                <Text style={styles.stepText}>+</Text>
              </Pressable>
            </View>
          </View>
          <View style={styles.divider} />
          <View style={styles.row}>
            <View style={styles.rowText}>
              <Text style={styles.rowTitle}>Per-client limit</Text>
              <Text style={styles.rowDesc}>KB/s, 0 means unlimited.</Text>
            </View>
            <TextInput
              value={String(settings.rateKbps)}
              onChangeText={v => {
                const n = Number(v.replace(/[^0-9]/g, ''));
                set('rateKbps', Number.isFinite(n) ? n : 0);
              }}
              keyboardType="number-pad"
              style={styles.numberInput}
            />
          </View>
        </View>
      </View>

      <Text style={styles.version}>Strait {version} · Android</Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  scroll: { padding: 20, gap: 20 },
  group: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 12,
    paddingHorizontal: 16,
  },
  divider: { height: 1, backgroundColor: colors.subtle },
  fieldGroup: { gap: 8 },
  label: { color: colors.textLabel, fontFamily: fonts.semibold, fontSize: 13 },
  input: {
    height: 44,
    borderWidth: 1,
    borderColor: colors.borderStrong,
    borderRadius: 10,
    backgroundColor: colors.surface,
    paddingHorizontal: 14,
    color: colors.text,
    fontFamily: fonts.mono,
    fontSize: 13,
  },
  sigRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    paddingHorizontal: 14,
    height: 44,
  },
  sigText: { flex: 1, color: colors.text, fontFamily: fonts.mono, fontSize: 13 },
  remove: { color: colors.sea, fontFamily: fonts.medium, fontSize: 13 },
  helper: { color: colors.textMuted, fontFamily: fonts.regular, fontSize: 13 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    paddingVertical: 12,
  },
  rowText: { flex: 1, gap: 2 },
  rowTitle: { color: colors.text, fontFamily: fonts.medium, fontSize: 14 },
  rowDesc: { color: colors.textMuted, fontFamily: fonts.regular, fontSize: 13 },
  stepper: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  stepBtn: {
    width: 30,
    height: 30,
    borderRadius: 8,
    backgroundColor: colors.subtle,
    alignItems: 'center',
    justifyContent: 'center',
  },
  stepText: { color: colors.text, fontFamily: fonts.semibold, fontSize: 18 },
  stepValue: {
    minWidth: 24,
    textAlign: 'center',
    color: colors.text,
    fontFamily: fonts.mono,
    fontSize: 14,
  },
  numberInput: {
    width: 84,
    height: 38,
    borderWidth: 1,
    borderColor: colors.borderStrong,
    borderRadius: 8,
    paddingHorizontal: 10,
    color: colors.text,
    fontFamily: fonts.mono,
    fontSize: 13,
    textAlign: 'right',
  },
  version: {
    color: colors.textMuted,
    fontFamily: fonts.regular,
    fontSize: 12,
    textAlign: 'center',
    marginTop: 4,
  },
});
