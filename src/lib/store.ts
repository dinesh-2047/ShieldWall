/**
 * In-memory store for the ShieldWall firewall dashboard.
 * Tracks: target website, health probes, attack process state,
 * blocked IPs, traffic through reverse proxy, alerts,
 * self-healing state, fault events, attack classifications,
 * multi-node monitoring, and data persistence.
 */

import { AttackClassification } from './attackClassifier';
import { loadState, saveState, startAutoSave, type PersistedState } from './persistence';

// ============ Existing Interfaces (unchanged) ============

export interface HealthProbe {
  timestamp: number;
  responseTime: number;    // ms, -1 if failed
  statusCode: number;      // HTTP status, 0 if failed
  available: boolean;
  error?: string;
}

export interface BlockedIP {
  ip: string;
  reason: string;
  blockedAt: number;
  requestCount: number;
  autoBlocked: boolean;
}

export interface AlertEntry {
  id: string;
  timestamp: number;
  type: 'attack_detected' | 'site_down' | 'high_latency' | 'ip_blocked' | 'attack_started' | 'attack_stopped' | 'email_alert' | 'self_healing' | 'fault_detected' | 'node_isolated' | 'node_restored';
  message: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface ProxyRequest {
  timestamp: number;
  ip: string;
  method: string;
  path: string;
  status: 'forwarded' | 'blocked' | 'rate_limited';
}

export interface FirewallConfig {
  rateLimit: number;            // max requests per IP per window
  rateLimitWindow: number;      // seconds
  autoBlockThreshold: number;   // violations before auto-block
  alertEmailEnabled: boolean;
  alertEmail: string;
  alertTrafficThreshold: number;
  smtpHost: string;
  smtpPort: number;
  smtpUser: string;
  smtpPass: string;
}

interface IPTracker {
  count: number;
  firstSeen: number;
  lastSeen: number;
  violations: number;
}

export interface ExternalAttackData {
  active: boolean;
  target: string;
  port: string;
  totalVolleys: number;
  totalConnections: number;
  totalFailed: number;
  attackerIP: string;
  lastUpdate: number;
}

export interface EngineLogEntry {
  id: string;
  timestamp: number;
  source: 'system' | 'proxy' | 'python' | 'fallback' | 'healer';
  level: 'info' | 'warning' | 'critical';
  message: string;
  simulated: boolean;
}

// ============ NEW Interfaces for Self-Healing ============

export type FaultType =
  | 'SERVICE_DOWN'
  | 'HIGH_LATENCY'
  | 'DDOS_ATTACK'
  | 'PARTIAL_OUTAGE'
  | 'RATE_LIMIT_BREACH';

export interface FaultEvent {
  id: string;
  timestamp: number;
  type: FaultType;
  affectedNode: string;
  severity: 'warning' | 'critical';
  details: string;
  resolved: boolean;
  resolvedAt?: number;
}

export interface HealingAction {
  id: string;
  timestamp: number;
  faultId: string;
  faultType: FaultType;
  actions: string[];
  result: 'success' | 'partial' | 'failed';
  recoveryTimeMs: number;
  verificationProbe?: { available: boolean; responseTime: number };
}

export interface MonitoredNode {
  id: string;
  url: string;
  label: string;
  status: 'online' | 'down' | 'degraded' | 'isolated' | 'unknown';
  lastProbe?: HealthProbe;
  avgResponseTime: number;
  availability: number;
  probeHistory: HealthProbe[];
  failoverUrl?: string;
  addedAt: number;
  isolated: boolean;
}

export interface RecoveryPlaybook {
  faultType: FaultType;
  name: string;
  steps: string[];
  cooldownMs: number;
}

// ============ Store Class ============

class FirewallStore {
  // ---- Target website (primary — existing) ----
  targetUrl: string = '';
  monitoring: boolean = false;

  // ---- Health probes (keep last 600 = 10 min at 1 probe/sec) ----
  healthProbes: HealthProbe[] = [];
  private readonly MAX_PROBES = 600;

  // ---- Attack process ----
  attackRunning: boolean = false;
  attackPid: number | null = null;
  attackTarget: string = '';
  attackPort: string = '';
  attackStartedAt: number | null = null;
  attackLogs: string[] = [];

  // ---- Reverse proxy (protection mode) ----
  protectionEnabled: boolean = false;
  protectionLockedOn: boolean = false;
  proxyPort: number = 80;
  proxyRequests: ProxyRequest[] = [];
  private readonly MAX_PROXY_REQUESTS = 5000;
  totalProxyForwarded: number = 0;
  totalProxyBlocked: number = 0;

  // ---- External attack data (from dos.cpp via API) ----
  externalAttackData: ExternalAttackData | null = null;
  emailSentForCurrentAttack: boolean = false;

  // ---- Engine logs (for terminal view + popup) ----
  engineLogs: EngineLogEntry[] = [];
  private readonly MAX_ENGINE_LOGS = 300;

  // ---- Blocked IPs ----
  blockedIPs: Map<string, BlockedIP> = new Map();

  // ---- IP tracking for rate limiting ----
  ipTrackers: Map<string, IPTracker> = new Map();

  // ---- Alerts ----
  alerts: AlertEntry[] = [];
  private readonly MAX_ALERTS = 500;

  // ---- SSE clients ----
  private sseClients: Set<ReadableStreamDefaultController> = new Set();

  // ---- Config ----
  config: FirewallConfig = {
    rateLimit: 50,
    rateLimitWindow: 10,
    autoBlockThreshold: 5,
    alertEmailEnabled: false,
    alertEmail: '',
    alertTrafficThreshold: 100,
    smtpHost: 'smtp.gmail.com',
    smtpPort: 587,
    smtpUser: '',
    smtpPass: '',
  };

  // ============ NEW: Self-Healing State ============
  selfHealingEnabled: boolean = true;
  faultEvents: FaultEvent[] = [];
  private readonly MAX_FAULT_EVENTS = 200;
  healingActions: HealingAction[] = [];
  private readonly MAX_HEALING_ACTIONS = 200;
  isolatedNodes: Set<string> = new Set();
  failoverTargets: Map<string, string> = new Map();  // primary URL → backup URL

  // ---- Multi-node monitoring ----
  monitoredNodes: MonitoredNode[] = [];

  // ---- Attack classifications ----
  attackClassifications: AttackClassification[] = [];
  private readonly MAX_CLASSIFICATIONS = 100;

  // ---- Recovery playbooks ----
  readonly playbooks: RecoveryPlaybook[] = [
    {
      faultType: 'SERVICE_DOWN',
      name: 'Service Recovery',
      steps: [
        'Verify service status with probe',
        'Attempt connection retry (3x)',
        'Enable protection proxy if not active',
        'Switch to failover target if configured',
        'Isolate faulty node from topology',
        'Send critical alert notification',
      ],
      cooldownMs: 30000,
    },
    {
      faultType: 'HIGH_LATENCY',
      name: 'Latency Mitigation',
      steps: [
        'Measure baseline response time',
        'Enable protection proxy for traffic filtering',
        'Increase rate limiting aggressiveness (÷2)',
        'Reroute through protection proxy',
        'Monitor for improvement over 10s window',
      ],
      cooldownMs: 20000,
    },
    {
      faultType: 'DDOS_ATTACK',
      name: 'DDoS Defense',
      steps: [
        'Auto-enable firewall protection',
        'Classify attack type from telemetry',
        'Auto-block attacking IP addresses',
        'Activate mitigation engine',
        'Send incident alert email',
        'Generate attack classification report',
      ],
      cooldownMs: 15000,
    },
    {
      faultType: 'PARTIAL_OUTAGE',
      name: 'Partial Outage Recovery',
      steps: [
        'Identify affected vs healthy nodes',
        'Isolate affected nodes',
        'Reroute traffic to healthy nodes',
        'Attempt recovery of isolated nodes',
        'Verify restored connectivity',
      ],
      cooldownMs: 25000,
    },
    {
      faultType: 'RATE_LIMIT_BREACH',
      name: 'Rate Limit Enforcement',
      steps: [
        'Identify offending IP addresses',
        'Tighten rate limit thresholds',
        'Auto-block repeat offenders',
        'Log violation details',
      ],
      cooldownMs: 10000,
    },
  ];

  // Track last playbook execution time per fault type to enforce cooldowns
  private lastPlaybookRun: Map<string, number> = new Map();

  constructor() {
    // Load persisted state on creation
    this.loadPersistedState();
  }

  // ============ Persistence ============
  private loadPersistedState(): void {
    const saved = loadState();
    if (!saved) return;

    // Restore config
    if (saved.config) {
      this.config = { ...this.config, ...saved.config } as FirewallConfig;
    }

    // Restore blocked IPs
    if (Array.isArray(saved.blockedIPs)) {
      for (const ip of saved.blockedIPs) {
        this.blockedIPs.set(ip.ip, ip);
      }
    }

    // Restore alerts (last 100 only)
    if (Array.isArray(saved.alerts)) {
      this.alerts = saved.alerts.slice(-100) as unknown as AlertEntry[];
    }

    // Restore healing data
    if (Array.isArray(saved.healingActions)) {
      this.healingActions = saved.healingActions as unknown as HealingAction[];
    }
    if (Array.isArray(saved.faultEvents)) {
      this.faultEvents = saved.faultEvents as unknown as FaultEvent[];
    }
    if (Array.isArray(saved.attackClassifications)) {
      this.attackClassifications = saved.attackClassifications as unknown as AttackClassification[];
    }
    if (typeof saved.selfHealingEnabled === 'boolean') {
      this.selfHealingEnabled = saved.selfHealingEnabled;
    }

    // Restore multi-node
    if (Array.isArray(saved.monitoredNodes)) {
      this.monitoredNodes = saved.monitoredNodes as unknown as MonitoredNode[];
    }

    // Restore failover targets
    if (saved.failoverTargets && typeof saved.failoverTargets === 'object') {
      for (const [k, v] of Object.entries(saved.failoverTargets)) {
        this.failoverTargets.set(k, v);
      }
    }

    // Restore isolated nodes
    if (Array.isArray(saved.isolatedNodes)) {
      for (const n of saved.isolatedNodes) {
        this.isolatedNodes.add(n);
      }
    }

    console.log('[Store] Persisted state restored successfully');
  }

  getPersistedState(): PersistedState {
    return {
      savedAt: Date.now(),
      config: this.config as unknown as Record<string, unknown>,
      blockedIPs: this.getBlockedIPs(),
      alerts: this.alerts.slice(-100) as unknown as Array<Record<string, unknown>>,
      healingActions: this.healingActions as unknown as Array<Record<string, unknown>>,
      faultEvents: this.faultEvents as unknown as Array<Record<string, unknown>>,
      attackClassifications: this.attackClassifications as unknown as Array<Record<string, unknown>>,
      selfHealingEnabled: this.selfHealingEnabled,
      monitoredNodes: this.monitoredNodes as unknown as Array<Record<string, unknown>>,
      failoverTargets: Object.fromEntries(this.failoverTargets),
      isolatedNodes: Array.from(this.isolatedNodes),
    };
  }

  startPersistence(): void {
    startAutoSave(() => this.getPersistedState(), 30000);
  }

  persistNow(): void {
    saveState(this.getPersistedState());
  }

  // ============ SSE ============
  addSSEClient(controller: ReadableStreamDefaultController) {
    this.sseClients.add(controller);
  }

  removeSSEClient(controller: ReadableStreamDefaultController) {
    this.sseClients.delete(controller);
  }

  broadcastSSE(eventType: string, data: unknown) {
    const message = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
    const encoder = new TextEncoder();
    for (const client of this.sseClients) {
      try {
        client.enqueue(encoder.encode(message));
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  // ============ Health Probes ============
  addHealthProbe(probe: HealthProbe) {
    this.healthProbes.push(probe);
    if (this.healthProbes.length > this.MAX_PROBES) {
      this.healthProbes = this.healthProbes.slice(-this.MAX_PROBES);
    }
    this.broadcastSSE('health', probe);

    // Also update the primary node in monitoredNodes if it exists
    const primaryNode = this.monitoredNodes.find(n => n.url === this.targetUrl);
    if (primaryNode) {
      primaryNode.lastProbe = probe;
      primaryNode.status = probe.available
        ? (probe.responseTime > 3000 ? 'degraded' : 'online')
        : 'down';
      primaryNode.probeHistory.push(probe);
      if (primaryNode.probeHistory.length > 120) {
        primaryNode.probeHistory = primaryNode.probeHistory.slice(-120);
      }
      // Recalculate stats
      const recent = primaryNode.probeHistory.slice(-30);
      const up = recent.filter(p => p.available);
      primaryNode.avgResponseTime = up.length > 0
        ? Math.round(up.reduce((s, p) => s + p.responseTime, 0) / up.length)
        : 0;
      primaryNode.availability = recent.length > 0
        ? Math.round((up.length / recent.length) * 100)
        : 100;
    }

    // Alert if site goes down
    if (!probe.available && this.healthProbes.length >= 2) {
      const prev = this.healthProbes[this.healthProbes.length - 2];
      if (prev.available) {
        this.addAlert({
          type: 'site_down',
          message: `⚠️ ${this.targetUrl} is DOWN! Status: ${probe.statusCode}, Error: ${probe.error || 'Timeout'}`,
          severity: 'critical',
        });
      }
    }

    // Alert if response time is very high (possible attack)
    if (probe.available && probe.responseTime > 3000) {
      this.addAlert({
        type: 'high_latency',
        message: `🐢 High latency detected on ${this.targetUrl}: ${probe.responseTime}ms (possible DDoS)`,
        severity: 'warning',
      });
    }
  }

  getRecentProbes(limit: number = 120): HealthProbe[] {
    return this.healthProbes.slice(-limit);
  }

  getHealthStats() {
    const recent = this.healthProbes.slice(-30);
    if (recent.length === 0) {
      return { avgResponseTime: 0, availability: 100, currentStatus: 'unknown', lastProbe: null };
    }
    const available = recent.filter(p => p.available);
    const avgResponseTime = available.length > 0
      ? Math.round(available.reduce((s, p) => s + p.responseTime, 0) / available.length)
      : 0;
    const availability = Math.round((available.length / recent.length) * 100);
    const last = recent[recent.length - 1];
    const staleMs = Date.now() - last.timestamp;
    const isStaleWhileMonitoring = this.monitoring && staleMs > 12000;
    return {
      avgResponseTime,
      availability,
      currentStatus: isStaleWhileMonitoring ? 'down' : (last.available ? 'online' : 'down'),
      lastProbe: last,
    };
  }

  // ============ Proxy Traffic ============
  recordProxyRequest(ip: string, method: string, path: string): 'forwarded' | 'blocked' | 'rate_limited' {
    const now = Date.now();

    // Check blocked
    if (this.blockedIPs.has(ip)) {
      this.totalProxyBlocked++;
      this.addProxyEntry({ timestamp: now, ip, method, path, status: 'blocked' });
      return 'blocked';
    }

    // Rate limit check
    if (this.protectionEnabled) {
      const tracker = this.getOrCreateTracker(ip, now);
      const windowMs = this.config.rateLimitWindow * 1000;

      if (now - tracker.firstSeen > windowMs) {
        tracker.count = 1;
        tracker.firstSeen = now;
        tracker.lastSeen = now;
      } else {
        tracker.count++;
        tracker.lastSeen = now;
      }

      const elapsed = Math.max((now - tracker.firstSeen) / 1000, 1);
      const rate = tracker.count / elapsed;

      if (rate > this.config.rateLimit) {
        tracker.violations++;
        this.totalProxyBlocked++;

        if (tracker.violations >= this.config.autoBlockThreshold) {
          this.blockIP(ip, `Auto-blocked: ${tracker.violations} rate limit violations (${Math.round(rate)} req/s)`, tracker.count, true);
        }

        this.addProxyEntry({ timestamp: now, ip, method, path, status: 'rate_limited' });
        return 'rate_limited';
      }
    }

    this.totalProxyForwarded++;
    this.addProxyEntry({ timestamp: now, ip, method, path, status: 'forwarded' });
    return 'forwarded';
  }

  private getOrCreateTracker(ip: string, now: number): IPTracker {
    let tracker = this.ipTrackers.get(ip);
    if (!tracker) {
      tracker = { count: 0, firstSeen: now, lastSeen: now, violations: 0 };
      this.ipTrackers.set(ip, tracker);
    }
    return tracker;
  }

  private addProxyEntry(entry: ProxyRequest) {
    this.proxyRequests.push(entry);
    if (this.proxyRequests.length > this.MAX_PROXY_REQUESTS) {
      this.proxyRequests = this.proxyRequests.slice(-this.MAX_PROXY_REQUESTS);
    }
  }

  // ============ Blocked IPs ============
  blockIP(ip: string, reason: string, requestCount: number = 0, autoBlocked: boolean = false) {
    this.blockedIPs.set(ip, {
      ip, reason, blockedAt: Date.now(), requestCount, autoBlocked,
    });
    this.addAlert({
      type: 'ip_blocked',
      message: `🚫 IP ${ip} blocked: ${reason}`,
      severity: 'warning',
    });
    this.broadcastSSE('blocked', { ip, reason });
  }

  unblockIP(ip: string): boolean {
    const deleted = this.blockedIPs.delete(ip);
    if (deleted) {
      const tracker = this.ipTrackers.get(ip);
      if (tracker) tracker.violations = 0;
    }
    return deleted;
  }

  getBlockedIPs(): BlockedIP[] {
    return Array.from(this.blockedIPs.values());
  }

  // ============ Alerts ============
  addAlert(params: { type: AlertEntry['type']; message: string; severity: AlertEntry['severity'] }) {
    const alert: AlertEntry = {
      id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      timestamp: Date.now(),
      ...params,
    };
    this.alerts.push(alert);
    if (this.alerts.length > this.MAX_ALERTS) {
      this.alerts = this.alerts.slice(-this.MAX_ALERTS);
    }
    this.broadcastSSE('alert', alert);
    return alert;
  }

  getAlerts(limit: number = 50): AlertEntry[] {
    return this.alerts.slice(-limit).reverse();
  }

  // ============ Engine logs ============
  addEngineLog(params: {
    source: EngineLogEntry['source'];
    level: EngineLogEntry['level'];
    message: string;
    simulated?: boolean;
  }) {
    const log: EngineLogEntry = {
      id: `eng_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      timestamp: Date.now(),
      simulated: params.simulated ?? false,
      ...params,
    };

    this.engineLogs.push(log);
    if (this.engineLogs.length > this.MAX_ENGINE_LOGS) {
      this.engineLogs = this.engineLogs.slice(-this.MAX_ENGINE_LOGS);
    }

    this.broadcastSSE('engineLog', log);
    return log;
  }

  getEngineLogs(limit: number = 120): EngineLogEntry[] {
    return this.engineLogs.slice(-limit);
  }

  // ============ NEW: Fault Events ============
  addFaultEvent(params: {
    type: FaultType;
    affectedNode: string;
    severity: 'warning' | 'critical';
    details: string;
  }): FaultEvent {
    const fault: FaultEvent = {
      id: `fault_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      timestamp: Date.now(),
      resolved: false,
      ...params,
    };
    this.faultEvents.push(fault);
    if (this.faultEvents.length > this.MAX_FAULT_EVENTS) {
      this.faultEvents = this.faultEvents.slice(-this.MAX_FAULT_EVENTS);
    }
    this.addAlert({
      type: 'fault_detected',
      message: `🔍 Fault detected: ${params.type} on ${params.affectedNode} — ${params.details}`,
      severity: params.severity,
    });
    this.broadcastSSE('fault', fault);
    return fault;
  }

  resolveFault(faultId: string): void {
    const fault = this.faultEvents.find(f => f.id === faultId);
    if (fault) {
      fault.resolved = true;
      fault.resolvedAt = Date.now();
    }
  }

  getUnresolvedFaults(): FaultEvent[] {
    return this.faultEvents.filter(f => !f.resolved);
  }

  getFaultHistory(limit: number = 50): FaultEvent[] {
    return this.faultEvents.slice(-limit).reverse();
  }

  // ============ NEW: Healing Actions ============
  addHealingAction(action: HealingAction): void {
    this.healingActions.push(action);
    if (this.healingActions.length > this.MAX_HEALING_ACTIONS) {
      this.healingActions = this.healingActions.slice(-this.MAX_HEALING_ACTIONS);
    }
    this.addAlert({
      type: 'self_healing',
      message: `🧬 Self-healing: ${action.faultType} → ${action.actions.join(', ')} [${action.result.toUpperCase()}]`,
      severity: action.result === 'failed' ? 'critical' : 'info',
    });
    this.broadcastSSE('healing', action);
    this.addEngineLog({
      source: 'healer',
      level: action.result === 'failed' ? 'critical' : 'info',
      message: `Playbook "${action.faultType}" executed: ${action.actions.join(' → ')} | Result: ${action.result} | Recovery: ${action.recoveryTimeMs}ms`,
    });
  }

  getHealingHistory(limit: number = 50): HealingAction[] {
    return this.healingActions.slice(-limit).reverse();
  }

  getHealingStats() {
    const total = this.healingActions.length;
    const success = this.healingActions.filter(a => a.result === 'success').length;
    const partial = this.healingActions.filter(a => a.result === 'partial').length;
    const failed = this.healingActions.filter(a => a.result === 'failed').length;
    const avgRecovery = total > 0
      ? Math.round(this.healingActions.reduce((s, a) => s + a.recoveryTimeMs, 0) / total)
      : 0;
    return { total, success, partial, failed, avgRecoveryMs: avgRecovery };
  }

  // ============ NEW: Node Isolation ============
  isolateNode(nodeUrl: string): void {
    this.isolatedNodes.add(nodeUrl);
    const node = this.monitoredNodes.find(n => n.url === nodeUrl);
    if (node) {
      node.isolated = true;
      node.status = 'isolated';
    }
    this.addAlert({
      type: 'node_isolated',
      message: `🔒 Node isolated: ${nodeUrl} — removed from active traffic routing`,
      severity: 'warning',
    });
    this.broadcastSSE('nodeStatus', { url: nodeUrl, status: 'isolated' });
  }

  restoreNode(nodeUrl: string): void {
    this.isolatedNodes.delete(nodeUrl);
    const node = this.monitoredNodes.find(n => n.url === nodeUrl);
    if (node) {
      node.isolated = false;
      node.status = 'unknown'; // Will be updated on next probe
    }
    this.addAlert({
      type: 'node_restored',
      message: `🔓 Node restored: ${nodeUrl} — back in active routing`,
      severity: 'info',
    });
    this.broadcastSSE('nodeStatus', { url: nodeUrl, status: 'restored' });
  }

  // ============ NEW: Multi-Node ============
  addMonitoredNode(url: string, label?: string, failoverUrl?: string): MonitoredNode {
    // Avoid duplicates
    const existing = this.monitoredNodes.find(n => n.url === url);
    if (existing) return existing;

    const node: MonitoredNode = {
      id: `node_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
      url,
      label: label || new URL(url.startsWith('http') ? url : `https://${url}`).hostname,
      status: 'unknown',
      avgResponseTime: 0,
      availability: 100,
      probeHistory: [],
      failoverUrl,
      addedAt: Date.now(),
      isolated: false,
    };
    this.monitoredNodes.push(node);
    if (failoverUrl) {
      this.failoverTargets.set(url, failoverUrl);
    }
    return node;
  }

  removeMonitoredNode(nodeId: string): boolean {
    const idx = this.monitoredNodes.findIndex(n => n.id === nodeId);
    if (idx === -1) return false;
    const node = this.monitoredNodes[idx];
    this.failoverTargets.delete(node.url);
    this.isolatedNodes.delete(node.url);
    this.monitoredNodes.splice(idx, 1);
    return true;
  }

  // ============ NEW: Attack Classifications ============
  addAttackClassification(classification: AttackClassification): void {
    this.attackClassifications.push(classification);
    if (this.attackClassifications.length > this.MAX_CLASSIFICATIONS) {
      this.attackClassifications = this.attackClassifications.slice(-this.MAX_CLASSIFICATIONS);
    }
    this.broadcastSSE('attackClassification', classification);
  }

  getAttackClassifications(limit: number = 30): AttackClassification[] {
    return this.attackClassifications.slice(-limit).reverse();
  }

  // ============ Playbook Cooldown ============
  canRunPlaybook(faultType: FaultType): boolean {
    const playbook = this.playbooks.find(p => p.faultType === faultType);
    if (!playbook) return false;
    const lastRun = this.lastPlaybookRun.get(faultType) || 0;
    return Date.now() - lastRun > playbook.cooldownMs;
  }

  markPlaybookRun(faultType: FaultType): void {
    this.lastPlaybookRun.set(faultType, Date.now());
  }

  // ============ Full state snapshot ============
  getFullState() {
    return {
      targetUrl: this.targetUrl,
      monitoring: this.monitoring,
      healthStats: this.getHealthStats(),
      healthProbes: this.getRecentProbes(120),
      attackRunning: this.attackRunning,
      attackTarget: this.attackTarget,
      attackPort: this.attackPort,
      attackStartedAt: this.attackStartedAt,
      attackLogs: this.attackLogs.slice(-20),
      protectionEnabled: this.protectionEnabled,
      proxyPort: this.proxyPort,
      totalProxyForwarded: this.totalProxyForwarded,
      totalProxyBlocked: this.totalProxyBlocked,
      blockedIPs: this.getBlockedIPs(),
      externalAttackData: this.externalAttackData,
      engineLogs: this.getEngineLogs(200),
      alerts: this.getAlerts(30),
      config: this.config,
      ipStats: this.getIPStats(),
      // NEW fields
      selfHealingEnabled: this.selfHealingEnabled,
      faultEvents: this.getFaultHistory(20),
      healingActions: this.getHealingHistory(20),
      healingStats: this.getHealingStats(),
      monitoredNodes: this.monitoredNodes,
      attackClassifications: this.getAttackClassifications(10),
      isolatedNodes: Array.from(this.isolatedNodes),
    };
  }

  getIPStats() {
    const stats = [];
    for (const [ip, tracker] of this.ipTrackers) {
      const elapsed = Math.max((Date.now() - tracker.firstSeen) / 1000, 1);
      stats.push({
        ip,
        requests: tracker.count,
        rate: Math.round((tracker.count / elapsed) * 100) / 100,
        violations: tracker.violations,
        blocked: this.blockedIPs.has(ip),
      });
    }
    return stats.sort((a, b) => b.requests - a.requests).slice(0, 50);
  }

  // ============ Analytics ============
  getAnalytics() {
    // Attack type distribution
    const attackTypeCounts: Record<string, number> = {};
    for (const c of this.attackClassifications) {
      attackTypeCounts[c.type] = (attackTypeCounts[c.type] || 0) + 1;
    }

    // Healing success rates
    const healingStats = this.getHealingStats();

    // Recent attack timeline (group by 10-minute buckets)
    const attackTimeline: { time: string; count: number }[] = [];
    const now = Date.now();
    for (let i = 11; i >= 0; i--) {
      const bucketStart = now - (i + 1) * 600000;
      const bucketEnd = now - i * 600000;
      const count = this.attackClassifications.filter(
        c => c.timestamp >= bucketStart && c.timestamp < bucketEnd,
      ).length;
      attackTimeline.push({
        time: new Date(bucketEnd).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        count,
      });
    }

    // Fault distribution
    const faultTypeCounts: Record<string, number> = {};
    for (const f of this.faultEvents) {
      faultTypeCounts[f.type] = (faultTypeCounts[f.type] || 0) + 1;
    }

    // Uptime per node
    const nodeUptime = this.monitoredNodes.map(n => ({
      label: n.label,
      url: n.url,
      availability: n.availability,
      avgResponseTime: n.avgResponseTime,
      status: n.status,
    }));

    return {
      attackTypeCounts,
      healingStats,
      attackTimeline,
      faultTypeCounts,
      nodeUptime,
      totalAlerts: this.alerts.length,
      totalBlockedIPs: this.blockedIPs.size,
      totalFaults: this.faultEvents.length,
      totalHealingActions: this.healingActions.length,
    };
  }
}

// Singleton
const g = globalThis as typeof globalThis & { __firewallStore?: FirewallStore };
if (!g.__firewallStore) {
  g.__firewallStore = new FirewallStore();
  // Start persistence
  g.__firewallStore.startPersistence();
}
export const store = g.__firewallStore;
