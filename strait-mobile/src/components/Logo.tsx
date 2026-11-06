import React from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Svg, { Circle, Defs, LinearGradient, Path, Stop } from 'react-native-svg';
import { colors, fonts } from '../theme';

// The wave "S": deep-sea dot = you, lagoon dot = the other peer, the stroke fades between them.
// Stroke 2.8 at 16-24 px, 2.2 larger (design handoff).
export function Mark({ size = 22 }: { size?: number }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <Defs>
        <LinearGradient id="strait-wave" x1="0" y1="0" x2="0" y2="1">
          <Stop offset="0" stopColor={colors.sea} />
          <Stop offset="1" stopColor={colors.lagoon} />
        </LinearGradient>
      </Defs>
      <Path
        d="M17 5.5C13 3.5 7 5 7.5 9S16.5 13 16.5 16.5 10 21 6.5 18.5"
        stroke="url(#strait-wave)"
        strokeWidth={size <= 24 ? 2.8 : 2.2}
        strokeLinecap="round"
      />
      <Circle cx={17.5} cy={5.6} r={2.5} fill={colors.sea} />
      <Circle cx={6.3} cy={18.4} r={2.5} fill={colors.lagoon} />
    </Svg>
  );
}

export function Logo() {
  return (
    <View style={styles.row}>
      <View style={styles.markBox}>
        <Mark size={20} />
      </View>
      <Text style={styles.wordmark}>trait</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  // The mark is the "S" of Strait, so it sits tight against "trait".
  row: { flexDirection: 'row', alignItems: 'center' },
  markBox: { width: 13, height: 26, alignItems: 'center', justifyContent: 'center', overflow: 'visible' },
  wordmark: {
    color: colors.text,
    fontFamily: fonts.brand,
    fontStyle: 'italic',
    fontSize: 19,
    letterSpacing: -0.19,
  },
});
