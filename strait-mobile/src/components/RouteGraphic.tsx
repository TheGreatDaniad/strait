import React, { useEffect, useRef, useState } from 'react';
import { Animated, Easing, StyleSheet, Text, View } from 'react-native';
import Svg, { Circle, Path, Rect } from 'react-native-svg';
import { colors, fonts } from '../theme';

export type RouteState =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'failed'
  | 'host-idle'
  | 'sharing';

type Kind = 'laptop' | 'router' | 'globe' | 'peer';

function Icon({ kind, color }: { kind: Kind; color: string }) {
  if (kind === 'laptop') {
    return (
      <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
        <Rect
          x={4}
          y={5}
          width={16}
          height={11}
          rx={1.5}
          stroke={color}
          strokeWidth={2}
        />
        <Path d="M2 19h20" stroke={color} strokeWidth={2} strokeLinecap="round" />
      </Svg>
    );
  }
  if (kind === 'router') {
    return (
      <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
        <Rect
          x={3}
          y={13}
          width={18}
          height={7}
          rx={2}
          stroke={color}
          strokeWidth={2}
        />
        <Path
          d="M7 16.5h.01M11 16.5h.01"
          stroke={color}
          strokeWidth={2}
          strokeLinecap="round"
        />
        <Path
          d="M8.5 9.5a5 5 0 0 1 7 0M6 7a8.5 8.5 0 0 1 12 0"
          stroke={color}
          strokeWidth={2}
          strokeLinecap="round"
        />
      </Svg>
    );
  }
  if (kind === 'globe') {
    return (
      <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
        <Circle cx={12} cy={12} r={9} stroke={color} strokeWidth={2} />
        <Path
          d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"
          stroke={color}
          strokeWidth={2}
          strokeLinecap="round"
        />
      </Svg>
    );
  }
  return (
    <Svg width={24} height={24} viewBox="0 0 24 24" fill="none">
      <Circle cx={9} cy={8} r={3} stroke={color} strokeWidth={2} />
      <Path
        d="M3.5 19c.5-3.2 2.6-5 5.5-5s5 1.8 5.5 5"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
      />
      <Circle cx={17} cy={9} r={2.4} stroke={color} strokeWidth={2} />
      <Path
        d="M15.5 14.2c2.3.1 3.9 1.6 4.3 4.1"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
      />
    </Svg>
  );
}

function Packet({ width, color, delay }: { width: number; color: string; delay: number }) {
  const x = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    if (!width) return;
    const loop = Animated.loop(
      Animated.sequence([
        Animated.delay(delay),
        Animated.timing(x, {
          toValue: width - 6,
          duration: 1600,
          easing: Easing.linear,
          useNativeDriver: true,
        }),
        Animated.timing(x, {
          toValue: 0,
          duration: 0,
          useNativeDriver: true,
        }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [width, delay, x]);
  if (!width) return null;
  return (
    <Animated.View
      style={[
        styles.packet,
        { backgroundColor: color, transform: [{ translateX: x }] },
      ]}
    />
  );
}

function Line({
  state,
  first,
  onWidth,
}: {
  state: RouteState;
  first: boolean;
  onWidth: (width: number) => void;
}) {
  const [width, setWidth] = useState(0);
  const connected = state === 'connected';
  const sharing = state === 'sharing';
  const connecting = state === 'connecting' && first;
  const failed = state === 'failed' && first;
  const color = connected
    ? colors.lagoonLine
    : sharing
      ? colors.seaLine
      : connecting
        ? colors.sea
        : colors.line;

  return (
    <View
      style={styles.lineWrap}
      onLayout={e => {
        const w = e.nativeEvent.layout.width;
        setWidth(w);
        onWidth(w);
      }}>
      {connecting ? (
        <View style={styles.marchClip}>
          <Animated.View style={styles.marchRow}>
            {Array.from({ length: 24 }).map((_, i) => (
              <View key={i} style={[styles.marchDash, { backgroundColor: color }]} />
            ))}
          </Animated.View>
        </View>
      ) : (
        <View
          style={{
            borderTopWidth: 2,
            borderTopColor: color,
            borderStyle:
              failed || (!connected && !sharing)
                ? 'dashed'
                : 'solid',
            width: '100%',
          }}
        />
      )}
      {(connected || sharing) && (
        <>
          <Packet width={width} color={connected ? colors.lagoon : colors.sea} delay={0} />
          <Packet
            width={width}
            color={connected ? colors.lagoon : colors.sea}
            delay={800}
          />
        </>
      )}
      {failed && (
        <View style={styles.failBadge}>
          <Text style={styles.failGlyph}>×</Text>
        </View>
      )}
    </View>
  );
}

export function RouteGraphic({ state, host = false }: { state: RouteState; host?: boolean }) {
  const pulse = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    if (state !== 'connecting') return;
    const loop = Animated.loop(
      Animated.sequence([
        Animated.timing(pulse, {
          toValue: 1,
          duration: 1400,
          easing: Easing.inOut(Easing.ease),
          useNativeDriver: true,
        }),
        Animated.timing(pulse, {
          toValue: 0,
          duration: 0,
          useNativeDriver: true,
        }),
      ]),
    );
    loop.start();
    return () => loop.stop();
  }, [state, pulse]);

  const labels = host ? ['Peer', 'You', 'Internet'] : ['You', 'Host', 'Internet'];
  const kinds: Kind[] = host
    ? ['peer', 'laptop', 'globe']
    : ['laptop', 'router', 'globe'];

  const connected = state === 'connected';
  const sharing = state === 'sharing';
  const connecting = state === 'connecting';
  const hostIdle = state === 'host-idle';
  const failed = state === 'failed';

  const nodeFill = (index: number) => {
    if (sharing) return index === 1 ? colors.sea : colors.seaTint;
    if (connected) return colors.lagoonTint;
    if (connecting) return index === 0 ? colors.seaTint : colors.subtle;
    return colors.subtle;
  };
  const nodeIcon = (index: number) => {
    if (sharing) return index === 1 ? colors.onPrimary : colors.sea;
    if (connected) return colors.lagoon;
    if (connecting) return index === 0 ? colors.sea : colors.iconMuted;
    return colors.iconMuted;
  };

  return (
    <View style={styles.route} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
      {labels.map((label, index) => (
        <React.Fragment key={label}>
          {index > 0 && <Line state={state} first={index === 1} onWidth={() => {}} />}
          <View style={styles.nodeCol}>
            <View>
              {connecting && index === 0 && (
                <Animated.View
                  pointerEvents="none"
                  style={[
                    styles.pulse,
                    {
                      opacity: pulse.interpolate({
                        inputRange: [0, 1],
                        outputRange: [0.55, 0],
                      }),
                      transform: [
                        {
                          scale: pulse.interpolate({
                            inputRange: [0, 1],
                            outputRange: [1, 1.18],
                          }),
                        },
                      ],
                    },
                  ]}
                />
              )}
              <View
                style={[
                  styles.node,
                  { backgroundColor: nodeFill(index) },
                  hostIdle && index === 0 && styles.peerEmpty,
                ]}>
                {!(hostIdle && index === 0) && (
                  <Icon kind={kinds[index]} color={nodeIcon(index)} />
                )}
              </View>
            </View>
            <Text style={styles.nodeLabel}>{label}</Text>
          </View>
        </React.Fragment>
      ))}
    </View>
  );
}

const styles = StyleSheet.create({
  route: { flexDirection: 'row', alignItems: 'flex-start' },
  nodeCol: { width: 64, alignItems: 'center', gap: 8 },
  node: {
    width: 52,
    height: 52,
    borderRadius: 26,
    alignItems: 'center',
    justifyContent: 'center',
  },
  peerEmpty: {
    borderWidth: 2,
    borderStyle: 'dashed',
    borderColor: colors.line,
    backgroundColor: 'transparent',
  },
  nodeLabel: { color: colors.textMuted, fontFamily: fonts.medium, fontSize: 12 },
  lineWrap: {
    flex: 1,
    height: 2,
    marginTop: 25,
    justifyContent: 'center',
  },
  packet: {
    position: 'absolute',
    width: 6,
    height: 6,
    borderRadius: 3,
    left: 0,
  },
  failBadge: {
    position: 'absolute',
    alignSelf: 'center',
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: colors.ember,
    alignItems: 'center',
    justifyContent: 'center',
  },
  failGlyph: {
    color: colors.onPrimary,
    fontFamily: fonts.semibold,
    fontSize: 16,
    lineHeight: 18,
  },
  marchClip: { height: 2, overflow: 'hidden' },
  marchRow: { flexDirection: 'row', width: 600 },
  marchDash: { width: 6, height: 2, marginRight: 6 },
  pulse: {
    position: 'absolute',
    width: 52,
    height: 52,
    borderRadius: 26,
    backgroundColor: colors.sea,
  },
});
