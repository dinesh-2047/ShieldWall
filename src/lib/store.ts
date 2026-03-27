/**
 * In-memory store for the ShieldWall firewall dashboard.
 * Tracks: target website, health probes, attack process state,
 * blocked IPs, traffic through reverse proxy, and alerts.
 */

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
  type: 'attack_detected' | 'site_down' | 'high_latency' | 'ip_blocked' | 'attack_started' | 'attack_stopped' | 'email_alert';
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

class FirewallStore {
  // ---- Target website ----
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
  protectionLockedOn: boolean = false; // When true, protection stays ON despite serverless restarts
  proxyPort: number = 80;
  proxyRequests: ProxyRequest[] = [];
  private readonly MAX_PROXY_REQUESTS = 5000;
  totalProxyForwarded: number = 0;
  totalProxyBlocked: number = 0;

  // ---- External attack data (from dos.cpp via API) ----
  externalAttackData: ExternalAttackData | null = null;

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
    return {
      avgResponseTime,
      availability,
      currentStatus: last.available ? 'online' : 'down',
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
      alerts: this.getAlerts(30),
      config: this.config,
      ipStats: this.getIPStats(),
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
}

// Singleton
const g = globalThis as typeof globalThis & { __firewallStore?: FirewallStore };
if (!g.__firewallStore) {
  g.__firewallStore = new FirewallStore();
}
export const store = g.__firewallStore;
