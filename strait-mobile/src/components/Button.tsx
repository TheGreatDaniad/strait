import React from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  type StyleProp,
  type ViewStyle,
} from 'react-native';
import { colors, fonts } from '../theme';

type Variant = 'primary' | 'secondary' | 'danger';

export function Button({
  title,
  onPress,
  variant = 'primary',
  disabled,
  style,
}: {
  title: string;
  onPress: () => void;
  variant?: Variant;
  disabled?: boolean;
  style?: StyleProp<ViewStyle>;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!disabled }}
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.base,
        variant === 'primary' && styles.primary,
        variant === 'secondary' && styles.secondary,
        variant === 'danger' && styles.danger,
        pressed &&
          !disabled &&
          (variant === 'primary'
            ? { backgroundColor: colors.seaHover }
            : variant === 'danger'
              ? { backgroundColor: colors.emberTint }
              : { backgroundColor: colors.subtle }),
        disabled && styles.disabled,
        style,
      ]}>
      <Text
        style={[
          styles.label,
          variant === 'danger' && { color: colors.dangerText },
          variant !== 'primary' && { color: colors.text },
        ]}>
        {title}
      </Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  base: {
    height: 48,
    borderRadius: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  primary: { backgroundColor: colors.sea },
  secondary: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.borderStrong,
  },
  danger: {
    backgroundColor: colors.surface,
    borderWidth: 1,
    borderColor: colors.dangerBorder,
  },
  disabled: { opacity: 0.5 },
  label: {
    color: colors.onPrimary,
    fontFamily: fonts.semibold,
    fontSize: 15,
  },
});
