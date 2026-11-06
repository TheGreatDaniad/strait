import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Platform,
  StatusBar,
  StyleSheet,
  View,
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { Logo } from './src/components/Logo';
import { StatusChip } from './src/components/StatusChip';
import { Tabs, type TabKey } from './src/components/Tabs';
import { ConnectScreen } from './src/screens/ConnectScreen';
import { HostScreen } from './src/screens/HostScreen';
import { SettingsScreen } from './src/screens/SettingsScreen';
import { colors } from './src/theme';
import {
  defaultSettings,
  loadHistory,
  loadLast,
  loadSettings,
  rememberInvite,
  saveSettings,
  type Settings,
} from './src/storage';
import {
  Strait,
  StraitEvents,
  isNativeAvailable,
  checkNetwork,
  probeServices,
  type PreflightResult,
  type RvProbe,
  type StartOptions,
  type TunnelStatus,
} from './src/native/strait';

import { generateKey, parseInvite } from './src/invite';
import * as rvui from './src/rvui';
import { failureReason } from './src/connectReason';
import { parsePort } from './src/validate';

const VERSION = '0.4.0';

function StraitApp() {
  const [tab, setTab] = useState<TabKey>('connect');
  const [settings, setSettings] = useState<Settings>(defaultSettings);
  const [history, setHistory] = useState<string[]>([]);
  const [invite, setInvite] = useState('');
  const [clientState, setClientState] = useState<
    'idle' | 'connecting' | 'connected' | 'failed'
  >('idle');
  const [error, setError] = useState('');
  const [blocked, setBlocked] = useState(false);
  const [ip, setIp] = useState('');
  const [bytes, setBytes] = useState(0);
  const [sharing, setSharing] = useState(false);
  const [clients, setClients] = useState(0);
  const [hostInvite, setHostInvite] = useState('');
  const [copied, setCopied] = useState(false);
  const [path, setPath] = useState<'direct' | 'signal' | undefined>();
  const [carrier, setCarrier] = useState<{ id?: string; mtu?: number; notes: string[] }>({ notes: [] });
  const [portText, setPortText] = useState(String(defaultSettings.hostPort));
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState('');
  const [check, setCheck] = useState<PreflightResult | null>(null);
  const [probes, setProbes] = useState<Record<string, RvProbe>>({});
  const [probing, setProbing] = useState(false);
  const [selected, setSelected] = useState<string[]>([]);
  const [starting, setStarting] = useState(false);
  const [live, setLive] = useState<Record<string, string>>({});
  const [rvProbes, setRvProbes] = useState<Record<string, RvProbe>>({});
  const [rvTesting, setRvTesting] = useState(false);
  const checkKey = useRef('');
  const loaded = useRef(false);
  const shareBusy = useRef(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      const [s, h, last] = await Promise.all([
        loadSettings(),
        loadHistory(),
        loadLast(),
      ]);
      if (!alive) return;
      setSettings(s);
      setPortText(String(s.hostPort));
      setHistory(h);
      setInvite(last);
      setSelected(s.rvSelected);
      loaded.current = true;
    })();
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (!loaded.current) return;
    saveSettings(settings).catch(() => {});
  }, [settings]);

  useEffect(() => {
    if (!StraitEvents) return;
    const sub = StraitEvents.addListener('StraitStatus', (raw: unknown) => {
      const status = raw as TunnelStatus;
      if (status.state === 'connected' || status.state === 'failed' || status.state === 'connecting') {
        let notes: string[] = [];
        try {
          notes = status.carrierNotes ? JSON.parse(status.carrierNotes) : [];
        } catch {}
        setCarrier({ id: status.carrier, mtu: status.mtu, notes });
      }
      if (status.state === 'connected') {
        setClientState('connected');
        setPath(status.path);
        if (typeof status.bytesIn === 'number' || typeof status.bytesOut === 'number') {
          setBytes((status.bytesIn ?? 0) + (status.bytesOut ?? 0));
        }
      } else if (status.state === 'failed') {
        setClientState('failed');
        setBlocked(!!status.blocked);
        setSharing(false);
        setError(failureReason(status.message) || 'The tunnel stopped unexpectedly.');
      } else if (status.state === 'sharing') {
        setBlocked(false);
        setSharing(true);
        setClients(status.clients ?? 0);
      } else if (status.state === 'idle') {
        setBlocked(false);
        setSharing(false);
        setClients(0);
        setLive({});
      }
      if (status.rv) {
        try {
          setLive(JSON.parse(status.rv));
        } catch {}
      }
    });
    return () => sub.remove();
  }, []);

  // The emulator/UI fallback has no native counters yet; keep the stat alive
  // so the connected state is visibly working.
  useEffect(() => {
    // Only the development mock needs simulated counters. The native service
    // reports real tunnel bytes from the Rust process every second.
    if (clientState !== 'connected' || isNativeAvailable) return;
    const timer = setInterval(() => {
      setBytes(v => v + 2400 + Math.floor(Math.random() * 6800));
    }, 1000);
    return () => clearInterval(timer);
  }, [clientState]);

  // The native status carries the tunnel address (10.7.0.2). What the user
  // wants to see is the public address of the exit, so ask an IP echo service
  // through the tunnel and fall back to the signal host.
  useEffect(() => {
    if (clientState !== 'connected') return;
    let cancelled = false;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    (async () => {
      try {
        const res = await fetch('https://api.ipify.org?format=json', {
          signal: controller.signal,
        });
        const data = (await res.json()) as { ip?: string };
        if (!cancelled && data.ip) setIp(data.ip);
      } catch {
        try {
          const first = parseInvite(invite);
          const ep = first.hosts[0] ?? first.signals[0];
          if (!cancelled && ep) setIp(ep.replace(/^\[?([^\]]*?)\]?:\d+$/, '$1'));
        } catch {}
      } finally {
        clearTimeout(timer);
      }
    })();
    return () => {
      cancelled = true;
      clearTimeout(timer);
      controller.abort();
    };
  }, [clientState, invite]);

  const globalState =
    sharing ? 'sharing' : clientState;

  const updateSettings = useCallback((next: Settings) => {
    setSettings(next);
  }, []);

  const connect = useCallback(async () => {
    try {
      parseInvite(invite);
    } catch (e) {
      setClientState('failed');
      setError(e instanceof Error ? e.message : 'Invalid invite.');
      return;
    }
    setError('');
    setBlocked(false);
    setClientState('connecting');
    const options: StartOptions = {
      mode: 'client',
      invite: invite.trim(),
      maxClients: settings.maxClients,
      rateKbps: settings.rateKbps,
      killSwitch: settings.killSwitch,
      blockIPv6: settings.blockIPv6,
      rvDisable: settings.rvDisabled,
    };
    try {
      await Strait.start(options);
      if (!isNativeAvailable) {
        // Development fallback only; the native service reports Connected
        // when the Rust session is actually ready.
        setClientState('connected');
        setIp(prev => prev || '10.7.0.2');
      }
      await rememberInvite(invite.trim());
      setHistory(await loadHistory());
    } catch (e) {
      setClientState('failed');
      setError(failureReason(e instanceof Error ? e.message : undefined));
    }
  }, [invite, settings]);

  const disconnect = useCallback(async () => {
    try {
      await Strait.stop();
    } catch {}
    setClientState('idle');
    setBlocked(false);
    setPath(undefined);
    setBytes(0);
    setIp('');
  }, []);

  const cancel = useCallback(async () => {
    try {
      await Strait.stop();
    } catch {}
    setClientState('idle');
  }, []);

  const changePort = useCallback((v: string) => {
    setPortText(v);
    setCheck(null);
    setProbes({});
    setCheckError('');
    const n = parsePort(v);
    if (n !== null) setSettings(prev => ({ ...prev, hostPort: n }));
  }, []);

  const hasSignal = settings.signals.length > 0;

  const check_ = useCallback(async () => {
    const port = parsePort(portText);
    if (port === null || checking) return;
    setChecking(true);
    setCheckError('');
    setCheck(null);
    setProbes({});
    try {
      checkKey.current = await generateKey();
      const r = await checkNetwork({ port, signals: settings.signals, key: checkKey.current });
      setCheck(r);
      // Stage B2: the list appears, so probe its services right away.
      if (!rvui.isDirect(r) && rvui.offersPicker(r)) {
        const ids = rvui.offered(hasSignal);
        setProbing(true);
        try {
          const res = rvui.parseProbeResults(await probeServices(ids, settings.signals));
          setProbes(res);
          setSelected(rvui.restoreSelection(settings.rvSelected, rvui.reachableIds(ids, res)));
        } catch (e) {
          setCheckError(e instanceof Error ? e.message : 'Could not test the services.');
        } finally {
          setProbing(false);
        }
      }
    } catch (e) {
      setCheckError(e instanceof Error ? e.message : 'Network check failed.');
    } finally {
      setChecking(false);
    }
  }, [portText, checking, settings.signals, settings.rvSelected, hasSignal]);

  const toggleMethod = useCallback((id: string) => {
    setSelected(prev => {
      const next = prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id];
      setSettings(s => ({ ...s, rvSelected: next }));
      return next;
    });
  }, []);

  const startSharing = useCallback(async () => {
    const port = parsePort(portText);
    if (shareBusy.current || !check || port === null) return;
    shareBusy.current = true;
    setStarting(true);
    setCheckError('');
    try {
      let next = check.invite ?? '';
      if (!rvui.isDirect(check)) {
        // The invite is built with the ticked methods: check-host --rendezvous ids --json.
        const ids = rvui.selectionToRv(selected, probes);
        if (!rvui.startAllowed('meeting', ids.length)) return;
        const r = await checkNetwork({ port, signals: settings.signals, key: checkKey.current, rendezvous: ids });
        if (!r.hostable || !r.invite) {
          setCheckError(rvui.failureCopy(r) ?? r.note ?? 'Could not start sharing.');
          return;
        }
        next = r.invite;
      }
      parseInvite(next);
      setHostInvite(next);
      setSharing(true);
      await Strait.start({
        mode: 'host',
        invite: next,
        maxClients: settings.maxClients,
        rateKbps: settings.rateKbps,
        killSwitch: settings.killSwitch,
        blockIPv6: settings.blockIPv6,
        port,
      });
    } catch (e) {
      setSharing(false);
      setHostInvite('');
      setCheckError(e instanceof Error ? e.message : 'Could not start sharing.');
    } finally {
      shareBusy.current = false;
      setStarting(false);
    }
  }, [settings, check, selected, probes, portText]);

  const stopSharing = useCallback(async () => {
    try {
      await Strait.stop();
    } catch {}
    setSharing(false);
    setHostInvite('');
  }, []);

  const copyHostInvite = useCallback(() => {
    Clipboard.setString(hostInvite);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [hostInvite]);

  const inviteRv = (() => {
    try {
      return parseInvite(invite);
    } catch {
      return null;
    }
  })();
  const rvIds = inviteRv?.rv ?? [];

  const toggleRv = useCallback((id: string) => {
    setSettings(s => ({ ...s, rvDisabled: rvui.setDisabled(s.rvDisabled, id, !s.rvDisabled.includes(id)) }));
  }, []);

  const testRv = useCallback(async () => {
    const ids = rvui.guestMethods(rvIds, []).filter(m => m.supported).map(m => m.id);
    setRvTesting(true);
    try {
      setRvProbes(rvui.parseProbeResults(await probeServices(ids, inviteRv?.signals ?? [])));
    } catch {
      setRvProbes(Object.fromEntries(ids.map(id => [id, { id, status: 'error', detail: 'test failed' }])));
    } finally {
      setRvTesting(false);
    }
  }, [rvIds.join(','), inviteRv]);

  const paste = useCallback(async () => {
    const value = await Clipboard.getString();
    if (value) setInvite(value.trim());
  }, []);

  return (
    <SafeAreaView style={styles.safe} edges={['top', 'left', 'right', 'bottom']}>
      <StatusBar barStyle="dark-content" />
      <View style={styles.frame}>
        <View style={styles.header}>
          <Logo />
          <StatusChip state={globalState} />
        </View>
        <View style={styles.tabs}>
          <Tabs active={tab} onChange={setTab} />
        </View>
        <View style={styles.body}>
          {tab === 'connect' ? (
            <ConnectScreen
              state={clientState}
              invite={invite}
              error={error}
              blocked={blocked}
              ip={ip}
              path={path}
              carrier={carrier}
              bytes={bytes}
              history={history}
              onChangeInvite={setInvite}
              onConnect={connect}
              onCancel={cancel}
              onDisconnect={disconnect}
              onPaste={paste}
              onPickHistory={v => setInvite(v)}
              rvIds={rvIds}
              rvDisabled={settings.rvDisabled}
              rvProbes={rvProbes}
              rvTesting={rvTesting}
              onToggleRv={toggleRv}
              onTestRv={testRv}
            />
          ) : tab === 'host' ? (
            <HostScreen
              sharing={sharing}
              clients={clients}
              relay={settings.signals.join(', ')}
              invite={hostInvite}
              copied={copied}
              maxClients={settings.maxClients}
              rateKbps={settings.rateKbps}
              onStart={startSharing}
              onStop={stopSharing}
              onChangeRelay={() => setTab('settings')}
              onCopy={copyHostInvite}
              portText={portText}
              portError={parsePort(portText) === null ? 'Enter a port from 1 to 65535.' : undefined}
              checking={checking}
              checkError={checkError}
              check={check}
              signals={settings.signals}
              probes={probes}
              probing={probing}
              selected={selected}
              onToggle={toggleMethod}
              starting={starting}
              live={live}
              onChangePort={changePort}
              onCheck={check_}
            />
          ) : (
            <SettingsScreen
              settings={settings}
              onChange={updateSettings}
              version={VERSION}
            />
          )}
        </View>
      </View>
    </SafeAreaView>
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <StraitApp />
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.bg },
  frame: {
    flex: 1,
    width: '100%',
    maxWidth: Platform.OS === 'web' ? 420 : 520,
    alignSelf: 'center',
  },
  header: {
    paddingTop: 16,
    paddingHorizontal: 20,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  tabs: { paddingTop: 12, paddingHorizontal: 20 },
  body: { flex: 1, paddingTop: 16 },
});
