import React from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { colors, fonts } from '../theme';

export function ToggleRow({
  title,
  description,
  value,
  onChange,
}: {
  title: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <Pressable
      accessibilityRole="switch"
      accessibilityState={{ checked: value }}
      onPress={() => onChange(!value)}
      style={styles.row}>
      <View style={styles.textCol}>
        <Text style={styles.title}>{title}</Text>
        <Text style={styles.desc}>{description}</Text>
      </View>
      <View style={[styles.track, value && styles.on]}>
        <View style={[styles.knob, value && styles.knobOn]} />
      </View>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  row: {
    minHeight: 58,
    paddingVertical: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  textCol: { flex: 1, gap: 2 },
  title: { color: colors.text, fontFamily: fonts.medium, fontSize: 14 },
  desc: { color: colors.textMuted, fontFamily: fonts.regular, fontSize: 13 },
  track: {
    width: 40,
    height: 24,
    borderRadius: 12,
    backgroundColor: colors.line,
    padding: 3,
    justifyContent: 'center',
  },
  on: { backgroundColor: colors.sea },
  knob: {
    width: 18,
    height: 18,
    borderRadius: 9,
    backgroundColor: colors.surface,
    shadowColor: '#14141E',
    shadowOpacity: 0.2,
    shadowRadius: 2,
    shadowOffset: { width: 0, height: 1 },
    elevation: 1,
  },
  knobOn: { alignSelf: 'flex-end' },
});
