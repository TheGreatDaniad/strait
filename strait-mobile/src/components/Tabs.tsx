import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { colors, fonts } from '../theme';

export type TabKey = 'connect' | 'host' | 'settings';

const tabs: { key: TabKey; label: string }[] = [
  { key: 'connect', label: 'Connect' },
  { key: 'host', label: 'Host' },
  { key: 'settings', label: 'Settings' },
];

export function Tabs({
  active,
  onChange,
}: {
  active: TabKey;
  onChange: (tab: TabKey) => void;
}) {
  return (
    <View style={styles.track} accessibilityRole="tablist">
      {tabs.map(tab => {
        const selected = active === tab.key;
        return (
          <Pressable
            key={tab.key}
            accessibilityRole="tab"
            accessibilityState={{ selected }}
            onPress={() => onChange(tab.key)}
            style={({ pressed }) => [
              styles.tab,
              selected && styles.active,
              pressed && !selected && { backgroundColor: colors.bg },
            ]}>
            <Text style={[styles.label, selected && styles.activeLabel]}>
              {tab.label}
            </Text>
          </Pressable>
        );
      })}
    </View>
  );
}

const styles = StyleSheet.create({
  track: {
    flexDirection: 'row',
    gap: 4,
    padding: 4,
    borderRadius: 12,
    backgroundColor: colors.track,
  },
  tab: {
    flex: 1,
    height: 36,
    borderRadius: 9,
    alignItems: 'center',
    justifyContent: 'center',
  },
  active: {
    backgroundColor: colors.surface,
    shadowColor: '#14141E',
    shadowOpacity: 0.1,
    shadowRadius: 2,
    shadowOffset: { width: 0, height: 1 },
    elevation: 2,
  },
  label: {
    color: colors.textMuted,
    fontFamily: fonts.medium,
    fontSize: 14,
  },
  activeLabel: { color: colors.text, fontFamily: fonts.semibold },
});
