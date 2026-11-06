import React, { useState } from 'react';
import {
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
  type TextInputProps,
} from 'react-native';
import { colors, fonts } from '../theme';

export function InlineButton({
  title,
  onPress,
  disabled,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable
      accessibilityRole="button"
      disabled={disabled}
      onPress={onPress}
      style={({ pressed }) => [
        styles.inline,
        pressed && !disabled && { backgroundColor: colors.subtle },
        disabled && { opacity: 0.5 },
      ]}>
      <Text style={styles.inlineText}>{title}</Text>
    </Pressable>
  );
}

export function Field({
  label,
  error,
  right,
  style,
  ...props
}: TextInputProps & {
  label: string;
  error?: string;
  right?: React.ReactNode;
  style?: object;
}) {
  const [focused, setFocused] = useState(false);
  return (
    <View style={styles.wrap}>
      <Text style={styles.label}>{label}</Text>
      <View style={styles.row}>
        <TextInput
          {...props}
          onFocus={e => {
            setFocused(true);
            props.onFocus?.(e);
          }}
          onBlur={e => {
            setFocused(false);
            props.onBlur?.(e);
          }}
          placeholderTextColor={colors.iconMuted}
          style={[
            styles.input,
            focused && styles.focused,
            error && styles.invalid,
            props.editable === false && styles.readonly,
            style,
          ]}
        />
        {right}
      </View>
      {error ? (
        <Text accessibilityLiveRegion="polite" style={styles.error}>
          {error}
        </Text>
      ) : null}
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { gap: 8 },
  label: { color: colors.textLabel, fontFamily: fonts.semibold, fontSize: 13 },
  row: { flexDirection: 'row', gap: 8 },
  input: {
    flex: 1,
    minWidth: 0,
    height: 44,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: colors.borderStrong,
    borderRadius: 10,
    backgroundColor: colors.surface,
    color: colors.text,
    fontFamily: fonts.mono,
    fontSize: 13,
  },
  focused: { borderColor: colors.sea, borderWidth: 2, paddingHorizontal: 13 },
  invalid: { borderColor: colors.ember },
  readonly: {
    backgroundColor: colors.fieldDisabled,
    borderColor: colors.border,
    color: colors.textMuted,
  },
  inline: {
    height: 44,
    paddingHorizontal: 16,
    borderWidth: 1,
    borderColor: colors.borderStrong,
    borderRadius: 10,
    backgroundColor: colors.surface,
    alignItems: 'center',
    justifyContent: 'center',
  },
  inlineText: { color: colors.text, fontFamily: fonts.medium, fontSize: 14 },
  error: { color: colors.emberText, fontFamily: fonts.regular, fontSize: 13 },
});
