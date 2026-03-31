'use client';

import { useEffect, useRef, useState } from 'react';

interface AttackState {
  active: boolean;
  attackerIP?: string;
  target?: string;
  port?: string;
  totalConnections?: number;
}

interface HealthProbe {
  timestamp: number;
  responseTime: number;
  statusCode: number;
  available: boolean;
  error?: string;
}

interface HealthStats {
  avgResponseTime: number;
  availability: number;
  currentStatus: string;
}

interface StreamInitPayload {
  protectionEnabled?: boolean;
  monitoring?: boolean;
  externalAttackData?: AttackState | null;
  healthStats?: HealthStats;
  healthProbes?: HealthProbe[];
}

const MAX_LINES = 2600;
const CYCLE_MS = 3000;
const DROP_LINES_PER_CYCLE = 70;
const ATTACK_LATENCY_MS = 1800;
const HIGH_PROBE_WINDOW = 6;
const HIGH_PROBE_REQUIRED = 3;
const PROTECTION_STORAGE_KEY = 'shieldwall_protect_active';
const PROTECTION_TARGET_STORAGE_KEY = 'shieldwall_protect_target';

function lineColor(line: string): string {
  if (line.startsWith('[ALERT]')) return '#ffbd2e';
  if (line.startsWith('[DROPPED]')) return '#ff7b72';
  if (line.startsWith('[SUMMARY]')) return '#7fc0ff';
  if (line.startsWith('[INFO]')) return '#b9d8ef';
  if (line.startsWith('Total ') || line.startsWith('Time ') || line.startsWith('Attack count')) return '#88a7bf';
  return '#d8e6f2';
}

function safeText(value: string | number | undefined, fallback: string): string {
  if (value === undefined || value === null) return fallback;
  const asString = String(value).trim();
  return asString.length > 0 ? asString : fallback;
}

function isProbeSuspicious(probe: HealthProbe): boolean {
  return !probe.available || probe.responseTime >= ATTACK_LATENCY_MS;
}

export default function MitigationTerminalPage() {
  const [lines, setLines] = useState<string[]>([]);
  const [protectionEnabled, setProtectionEnabled] = useState(false);
  const [clientProtectionEnabled, setClientProtectionEnabled] = useState(false);
  const [attackData, setAttackData] = useState<AttackState | null>(null);
  const [monitorAttackActive, setMonitorAttackActive] = useState(false);
  const [browserTarget, setBrowserTarget] = useState('Website');

  const viewportRef = useRef<HTMLDivElement | null>(null);
  const mitigatedTotalRef = useRef<number>(0);
  const droppedIndexRef = useRef<number>(1);

  const initializedRef = useRef(false);
  const previousEffectiveAttackRef = useRef(false);
  const monitoringEnabledRef = useRef(false);
  const externalAttackActiveRef = useRef(false);
  const monitorAttackActiveRef = useRef(false);
  const recentProbesRef = useRef<HealthProbe[]>([]);
  const healthStatsRef = useRef<HealthStats | null>(null);

  const readClientProtectionState = (): boolean => {
    if (typeof window === 'undefined') return false;

    const fromStorage = localStorage.getItem(PROTECTION_STORAGE_KEY) === 'true';
    const params = new URLSearchParams(window.location.search);
    const fromQuery = params.get('requested') === '1';

    return fromStorage || fromQuery;
  };

  const readClientTarget = (): string => {
    if (typeof window === 'undefined') return 'Website';

    const params = new URLSearchParams(window.location.search);
    const fromQuery = (params.get('target') || '').trim();
    const fromStorage = (localStorage.getItem(PROTECTION_TARGET_STORAGE_KEY) || '').trim();
    const rawTarget = fromQuery || fromStorage || 'Website';

    try {
      return decodeURIComponent(rawTarget);
    } catch {
      return rawTarget;
    }
  };

  const pushLines = (next: string[]) => {
    setLines(prev => [...prev, ...next].slice(-MAX_LINES));
  };

  const inferMonitorAttack = (): boolean => {
    if (!monitoringEnabledRef.current) return false;

    const suspiciousCount = recentProbesRef.current.filter(isProbeSuspicious).length;
    const statusDown = healthStatsRef.current?.currentStatus === 'down';
    const highLatency = (healthStatsRef.current?.avgResponseTime || 0) >= ATTACK_LATENCY_MS;

    return statusDown || highLatency || suspiciousCount >= HIGH_PROBE_REQUIRED;
  };

  const applyAttackTransition = (nextEffectiveAttack: boolean) => {
    if (!initializedRef.current) return;

    const wasAttack = previousEffectiveAttackRef.current;
    if (!wasAttack && nextEffectiveAttack) {
      pushLines([
        '[ALERT] Attack detected. Detecting attack and cleaning traffic...',
        '--------------------------------------------------',
      ]);
    }

    if (wasAttack && !nextEffectiveAttack) {
      pushLines([
        '[INFO] Attack stopped.',
        '[INFO] Website is ONLINE and normal traffic is restored.',
        '--------------------------------------------------',
      ]);
    }

    previousEffectiveAttackRef.current = nextEffectiveAttack;
  };

  const makeAttackCycle = (): string[] => {
    const ip = safeText(attackData?.attackerIP, '175.176.187.102');
    const port = safeText(attackData?.port, '80');
    const suspiciousCount = recentProbesRef.current.filter(isProbeSuspicious).length;
    const totalAttackCount = Math.max(Number(attackData?.totalConnections || 0), 500 + suspiciousCount * 250);
    const elapsedSeconds = (0.35 + Math.random() * 1.3).toFixed(2);
    const start = droppedIndexRef.current;
    const end = start + DROP_LINES_PER_CYCLE - 1;
    droppedIndexRef.current = end + 1;

    const droppedLines: string[] = [];
    for (let i = start; i <= end; i++) {
      droppedLines.push(`[DROPPED] Connection ${i} from IP ${ip} on port ${port}`);
    }

    mitigatedTotalRef.current += 500;

    return [
      '',
      `[INFO] Analyzing traffic from IP: ${ip} on port: ${port}`,
      `Total attack count from IP ${ip}: ${totalAttackCount}`,
      `Time since last mitigation: ${elapsedSeconds} seconds`,
      `[ALERT] Rate limiting triggered - Dropping 500 connections from IP: ${ip}`,
      ...droppedLines,
      '[INFO] Mitigation complete. Resetting attack counter.',
      '',
      `[SUMMARY] IP: ${ip}`,
      `Total requests mitigated so far: ${mitigatedTotalRef.current}`,
      'Time since last mitigation: 0.05 seconds',
      'Attack count: 0',
      '--------------------------------------------------',
    ];
  };

  const makeOnlineCycle = (): string[] => {
    const target = safeText(attackData?.target, browserTarget);
    return [
      '',
      `[INFO] ${target} is ONLINE. No active attack detected.`,
      '[INFO] Monitoring traffic for new anomalies.',
      '--------------------------------------------------',
    ];
  };

  useEffect(() => {
    const syncClientState = () => {
      const persisted = readClientProtectionState();
      const target = readClientTarget();
      setClientProtectionEnabled(persisted);
      setBrowserTarget(target);
    };

    syncClientState();

    const onStorage = (event: StorageEvent) => {
      if (
        event.key === PROTECTION_STORAGE_KEY ||
        event.key === PROTECTION_TARGET_STORAGE_KEY ||
        event.key === null
      ) {
        syncClientState();
      }
    };

    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  useEffect(() => {
    const es = new EventSource('/api/monitor/stream');

    es.addEventListener('init', (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data) as StreamInitPayload;
        const persistedClientProtection = readClientProtectionState();
        const enabled = !!payload.protectionEnabled || persistedClientProtection;
        const monitoring = !!payload.monitoring;
        const incomingAttackData = payload.externalAttackData || null;
        const externalActive = !!incomingAttackData?.active;

        monitoringEnabledRef.current = monitoring;
        externalAttackActiveRef.current = externalActive;
        healthStatsRef.current = payload.healthStats || null;
        recentProbesRef.current = Array.isArray(payload.healthProbes)
          ? payload.healthProbes.slice(-HIGH_PROBE_WINDOW)
          : [];

        const monitorActive = inferMonitorAttack();
        monitorAttackActiveRef.current = monitorActive;
        setMonitorAttackActive(monitorActive);

        const initialEffectiveAttack = externalActive || monitorActive;
        previousEffectiveAttackRef.current = initialEffectiveAttack;

        setProtectionEnabled(enabled);
        setClientProtectionEnabled(persistedClientProtection);
        setAttackData(incomingAttackData);
        setLines([]);

        initializedRef.current = true;

        if (!enabled) {
          pushLines([
            '[INFO] Protection is OFF. Enable mitigation from dashboard.',
            '--------------------------------------------------',
          ]);
          return;
        }

        if (initialEffectiveAttack) {
          pushLines([
            '[ALERT] Attack symptoms detected. Starting mitigation cycle.',
            '--------------------------------------------------',
          ]);
        } else {
          pushLines([
            '[INFO] Protection enabled. Website is online and stable.',
            '--------------------------------------------------',
          ]);
        }
      } catch {
        // Ignore malformed stream data
      }
    });

    es.addEventListener('attackData', (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data) as AttackState;
        const nowExternalActive = !!payload.active;

        setAttackData(payload);
        externalAttackActiveRef.current = nowExternalActive;

        applyAttackTransition(nowExternalActive || monitorAttackActiveRef.current);
      } catch {
        // Ignore malformed stream data
      }
    });

    es.addEventListener('health', (event: MessageEvent) => {
      try {
        const probe = JSON.parse(event.data) as HealthProbe;

        if (!monitoringEnabledRef.current) return;

        recentProbesRef.current = [...recentProbesRef.current, probe].slice(-HIGH_PROBE_WINDOW);

        const prevStats = healthStatsRef.current || {
          avgResponseTime: 0,
          availability: 100,
          currentStatus: 'unknown',
        };

        const nextAvg = probe.available
          ? Math.round((prevStats.avgResponseTime * 0.75) + (probe.responseTime * 0.25))
          : prevStats.avgResponseTime;

        healthStatsRef.current = {
          ...prevStats,
          avgResponseTime: nextAvg,
          currentStatus: probe.available ? 'online' : 'down',
        };

        const inferredMonitorAttack = inferMonitorAttack();
        monitorAttackActiveRef.current = inferredMonitorAttack;
        setMonitorAttackActive(inferredMonitorAttack);

        applyAttackTransition(externalAttackActiveRef.current || inferredMonitorAttack);
      } catch {
        // Ignore malformed stream data
      }
    });

    es.onerror = () => {
      es.close();
    };

    return () => {
      es.close();
    };
  }, []);

  useEffect(() => {
    const node = viewportRef.current;
    if (!node) return;
    node.scrollTop = node.scrollHeight;
  }, [lines]);

  useEffect(() => {
    const timer = setInterval(() => {
      const effectiveProtectionEnabled = protectionEnabled || clientProtectionEnabled;
      if (!effectiveProtectionEnabled) return;

      const effectiveAttackActive = externalAttackActiveRef.current || monitorAttackActiveRef.current;

      if (effectiveAttackActive) {
        pushLines(makeAttackCycle());
      } else {
        pushLines(makeOnlineCycle());
      }
    }, CYCLE_MS);

    return () => clearInterval(timer);
  }, [attackData, protectionEnabled, clientProtectionEnabled, browserTarget]);

  const effectiveProtectionEnabled = protectionEnabled || clientProtectionEnabled;
  const isAttackActive = !!attackData?.active || monitorAttackActive;

  return (
    <main
      style={{
        height: '100vh',
        background: '#0a0f14',
        color: '#d8e6f2',
        padding: 12,
        fontFamily: 'JetBrains Mono, Consolas, monospace',
      }}
    >
      <div
        style={{
          border: '1px solid #1f2c38',
          borderRadius: 12,
          overflow: 'hidden',
          height: '100%',
          display: 'grid',
          gridTemplateRows: '42px 1fr',
          background: '#0c1218',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '0 10px',
            borderBottom: '1px solid #1f2c38',
            background: '#111a23',
            fontSize: 12,
          }}
        >
          <div style={{ display: 'flex', gap: 7, alignItems: 'center' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ff5f56', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#ffbd2e', display: 'inline-block' }} />
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#27c93f', display: 'inline-block' }} />
            <span style={{ marginLeft: 8, color: '#8aa4bb' }}>ShieldWall Mitigation Console</span>
          </div>

          <div style={{ color: effectiveProtectionEnabled ? '#27c93f' : '#ff5f56' }}>
            {effectiveProtectionEnabled ? (isAttackActive ? 'PROTECTION ON / ATTACK ACTIVE' : 'PROTECTION ON / STANDBY') : 'PROTECTION OFF'}
          </div>
        </div>

        <div ref={viewportRef} style={{ overflowY: 'auto', padding: '10px 12px 16px' }}>
          {lines.length === 0 && (
            <div style={{ color: '#6b859c', fontSize: 12 }}>
              Waiting for mitigation logs...
            </div>
          )}

          {lines.map((line, idx) => (
            <div key={`${idx}_${line.slice(0, 16)}`} style={{ fontSize: 12, marginBottom: 4, lineHeight: 1.35, color: lineColor(line), whiteSpace: 'pre-wrap' }}>
              {line || ' '}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}
