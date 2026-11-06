import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { colors, fonts, statusMeta, type ConnectionState } from '../theme';

export function StatusChip({ state }: { state: ConnectionState }) {
  const meta = statusMeta[state];
  return (
    <View style={[styles.chip, { backgroundColor: meta.bg }]}>
      <View style={[styles.dot, { backgroundColor: meta.dot }]} />
      <Text style={[styles.text, { color: meta.fg }]}>{meta.label}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  chip: {
    height: 26,
    paddingHorizontal: 10,
    borderRadius: 13,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  dot: { width: 7, height: 7, borderRadius: 4 },
  text: { fontFamily: fonts.semibold, fontSize: 12 },
});
