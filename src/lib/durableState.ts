import {
  store,
  type AlertEntry,
  type BlockedIP,
  type EngineLogEntry,
  type ExternalAttackData,
  type FirewallConfig,
  type HealthProbe,
} from './store';

interface PersistedRuntimeState {
  version: 1;
  updatedAt: number;
  targetUrl: string;
  monitoring: boolean;
  protectionEnabled: boolean;
  protectionLockedOn: boolean;
  proxyPort: number;
  totalProxyForwarded: number;
  totalProxyBlocked: number;
  emailSentForCurrentAttack: boolean;
  healthProbes: HealthProbe[];
  blockedIPs: BlockedIP[];
  alerts: AlertEntry[];
  engineLogs: EngineLogEntry[];
  externalAttackData: ExternalAttackData | null;
  config: FirewallConfig;
}

const REDIS_STATE_KEY = 'shieldwall:runtime:v1';
const MAX_PERSIST_PROBES = 180;
const MAX_PERSIST_ALERTS = 120;
const MAX_PERSIST_ENGINE_LOGS = 180;

let memorySnapshot: PersistedRuntimeState | null = null;
let hydrationInFlight: Promise<void> | null = null;

function normalizeBaseUrl(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

function getRedisRestConfig(): { url: string; token: string } | null {
  const rawUrl = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
  const rawToken = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;

  if (!rawUrl || !rawToken) {
    return null;
  }

  return {
    url: normalizeBaseUrl(rawUrl),
    token: rawToken,
  };
}

export function isDurableStateConfigured(): boolean {
  return getRedisRestConfig() !== null;
}

async function runRedisCommand(command: Array<string>): Promise<unknown> {
  const config = getRedisRestConfig();
  if (!config) {
    return null;
  }

  const response = await fetch(config.url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(command),
    cache: 'no-store',
  });

  if (!response.ok) {
    throw new Error(`Redis command failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as { result?: unknown; error?: string };

  if (payload.error) {
    throw new Error(payload.error);
  }

  return payload.result ?? null;
}

function buildSnapshotFromStore(): PersistedRuntimeState {
  return {
    version: 1,
    updatedAt: Date.now(),
    targetUrl: store.targetUrl,
    monitoring: store.monitoring,
    protectionEnabled: store.protectionEnabled,
    protectionLockedOn: store.protectionLockedOn,
    proxyPort: store.proxyPort,
    totalProxyForwarded: store.totalProxyForwarded,
    totalProxyBlocked: store.totalProxyBlocked,
    emailSentForCurrentAttack: store.emailSentForCurrentAttack,
    healthProbes: store.getRecentProbes(MAX_PERSIST_PROBES),
    blockedIPs: store.getBlockedIPs(),
    alerts: store.getAlerts(MAX_PERSIST_ALERTS),
    engineLogs: store.getEngineLogs(MAX_PERSIST_ENGINE_LOGS),
    externalAttackData: store.externalAttackData,
    config: { ...store.config },
  };
}

function applySnapshotToStore(snapshot: PersistedRuntimeState): void {
  store.targetUrl = snapshot.targetUrl || '';
  store.monitoring = !!snapshot.monitoring;
  store.protectionEnabled = !!snapshot.protectionEnabled;
  store.protectionLockedOn = !!snapshot.protectionLockedOn;
  store.proxyPort = Number(snapshot.proxyPort) || 80;
  store.totalProxyForwarded = Number(snapshot.totalProxyForwarded) || 0;
  store.totalProxyBlocked = Number(snapshot.totalProxyBlocked) || 0;
  store.emailSentForCurrentAttack = !!snapshot.emailSentForCurrentAttack;

  store.healthProbes = Array.isArray(snapshot.healthProbes) ? snapshot.healthProbes.slice(-600) : [];
  store.blockedIPs = new Map((snapshot.blockedIPs || []).map((entry) => [entry.ip, entry]));
  store.alerts = Array.isArray(snapshot.alerts) ? snapshot.alerts.slice(-500) : [];
  store.engineLogs = Array.isArray(snapshot.engineLogs) ? snapshot.engineLogs.slice(-300) : [];

  store.externalAttackData = snapshot.externalAttackData || null;

  if (snapshot.config) {
    Object.assign(store.config, snapshot.config);
  }
}

async function loadSnapshotFromRedis(): Promise<PersistedRuntimeState | null> {
  try {
    const result = await runRedisCommand(['GET', REDIS_STATE_KEY]);
    if (typeof result !== 'string' || result.trim().length === 0) {
      return null;
    }

    const parsed = JSON.parse(result) as PersistedRuntimeState;
    if (parsed.version !== 1) {
      return null;
    }

    return parsed;
  } catch (err) {
    console.error('[DurableState] Failed to read state:', err);
    return null;
  }
}

async function saveSnapshotToRedis(snapshot: PersistedRuntimeState): Promise<void> {
  try {
    await runRedisCommand(['SET', REDIS_STATE_KEY, JSON.stringify(snapshot)]);
  } catch (err) {
    console.error('[DurableState] Failed to write state:', err);
  }
}

export async function hydrateStoreFromDurableState(): Promise<void> {
  if (hydrationInFlight) {
    await hydrationInFlight;
    return;
  }

  hydrationInFlight = (async () => {
    const redisSnapshot = await loadSnapshotFromRedis();
    const snapshot = redisSnapshot || memorySnapshot;
    if (snapshot) {
      applySnapshotToStore(snapshot);
    }
  })().finally(() => {
    hydrationInFlight = null;
  });

  await hydrationInFlight;
}

export async function persistStoreToDurableState(): Promise<void> {
  const snapshot = buildSnapshotFromStore();
  memorySnapshot = snapshot;
  await saveSnapshotToRedis(snapshot);
}
