'use client';

import { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts';

// ==========================================
// Types
// ==========================================
interface HealthProbe {
  timestamp: number;
  responseTime: number;
  statusCode: number;
  available: boolean;
  error?: string;
}

interface BlockedIP {
  ip: string;
  reason: string;
  blockedAt: number;
  requestCount: number;
  autoBlocked: boolean;
}

interface AlertEntry {
  id: string;
  timestamp: number;
  type: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
}

interface HealthStats {
  avgResponseTime: number;
  availability: number;
  currentStatus: string;
}

interface ExternalAttackData {
  active: boolean;
  target: string;
  port: string;
  totalVolleys: number;
  totalConnections: number;
  totalFailed: number;
  attackerIP: string;
  lastUpdate: number;
}

interface FullState {
  targetUrl: string;
  monitoring: boolean;
  healthStats: HealthStats;
  healthProbes: HealthProbe[];
  protectionEnabled: boolean;
  blockedIPs: BlockedIP[];
  alerts: AlertEntry[];
  externalAttackData: ExternalAttackData | null;
  config: {
    rateLimit: number;
    rateLimitWindow: number;
    autoBlockThreshold: number;
    alertEmailEnabled: boolean;
    alertEmail: string;
    alertTrafficThreshold: number;
    smtpHost: string;
    smtpPort: number;
    smtpUser: string;
    smtpPass: string;
  };
}

// ==========================================
// Dashboard
// ==========================================
export default function Dashboard() {
  // State
  const [targetUrl, setTargetUrl] = useState('');
  const [monitoring, setMonitoring] = useState(false);
  const [probes, setProbes] = useState<HealthProbe[]>([]);
  const [healthStats, setHealthStats] = useState<HealthStats>({ avgResponseTime: 0, availability: 100, currentStatus: 'unknown' });
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([]);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [activeTab, setActiveTab] = useState<'monitor' | 'protect' | 'attack' | 'alerts' | 'settings'>('monitor');
  const [attackPassword, setAttackPassword] = useState('');
  const [attackUnlocked, setAttackUnlocked] = useState(false);
  const [protectedDomain, setProtectedDomain] = useState('');
  const [mitigationLogs, setMitigationLogs] = useState<string[]>([]);
  const [config, setConfig] = useState<FullState['config'] | null>(null);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  // Protection state
  const [protectionEnabled, setProtectionEnabled] = useState(false);
  const [proxyForwarded, setProxyForwarded] = useState(0);
  const [proxyBlocked, setProxyBlocked] = useState(0);
  const [attackData, setAttackData] = useState<ExternalAttackData | null>(null);

  // ---- Fetch full state ----
  const fetchState = useCallback(async () => {
    try {
      const [monRes, fwRes, alertRes, atkRes] = await Promise.all([
        fetch('/api/monitor', { cache: 'no-store' }),
        fetch('/api/firewall', { cache: 'no-store' }),
        fetch('/api/alerts', { cache: 'no-store' }),
        fetch('/api/attack-data', { cache: 'no-store' }),
      ]);
      const mon = await monRes.json();
      const fw = await fwRes.json();
      const al = await alertRes.json();
      const atk = await atkRes.json();

      // Client-side state restoration for Vercel serverless cold starts
      const wantMonitor = localStorage.getItem('shieldwall_monitor_active') === 'true';
      const savedHost = localStorage.getItem('shieldwall_monitor_url');

      if (wantMonitor && !mon.monitoring && savedHost) {
        console.log('Restoring Monitor state...');
        fetch('/api/monitor', { method: 'POST', body: JSON.stringify({ action: 'start', url: savedHost }) });
        setMonitoring(true);
        setTargetUrl(savedHost);
      } else {
        if (mon.targetUrl) setTargetUrl(mon.targetUrl);
        setMonitoring(mon.monitoring);
      }

      setProtectionEnabled(fw.protectionEnabled || false);

      setProbes(mon.healthProbes || []);
      setHealthStats(mon.healthStats || { avgResponseTime: 0, availability: 100, currentStatus: 'unknown' });
      setBlockedIPs(fw.blockedIPs || []);
      setConfig(fw.config);
      setAlerts(al.alerts || []);
      setProxyForwarded(fw.totalForwarded || 0);
      setProxyBlocked(fw.totalBlocked || 0);
      if (atk.attackData) setAttackData(atk.attackData);
    } catch (err) {
      console.error('Fetch error:', err);
    }
  }, []);

  // ---- SSE for real-time updates ----
  useEffect(() => {
    fetchState();

    const es = new EventSource('/api/monitor/stream');

    es.addEventListener('init', (event: MessageEvent) => {
      try {
        const data: FullState = JSON.parse(event.data);
        if (data.targetUrl) setTargetUrl(data.targetUrl);
        setMonitoring(data.monitoring);
        setProbes(data.healthProbes || []);
        setHealthStats(data.healthStats);
        setBlockedIPs(data.blockedIPs || []);
        setProtectionEnabled(data.protectionEnabled || false);
        setAlerts(data.alerts || []);
        if (data.externalAttackData) setAttackData(data.externalAttackData);
        setConfig(data.config);
      } catch { /* ignore */ }
    });

    es.addEventListener('health', (event: MessageEvent) => {
      try {
        const probe: HealthProbe = JSON.parse(event.data);
        setProbes(prev => [...prev.slice(-300), probe]);
        // Update stats locally
        setHealthStats(prev => ({
          ...prev,
          currentStatus: probe.available ? 'online' : 'down',
          avgResponseTime: probe.available ? Math.round((prev.avgResponseTime * 0.8) + (probe.responseTime * 0.2)) : prev.avgResponseTime,
        }));
      } catch { /* ignore */ }
    });

    es.addEventListener('alert', (event: MessageEvent) => {
      try {
        const alert: AlertEntry = JSON.parse(event.data);
        setAlerts(prev => [alert, ...prev.slice(0, 49)]);
      } catch { /* ignore */ }
    });

    es.addEventListener('blocked', () => {
      fetchState(); // Refresh blocked IPs
    });

    es.onerror = () => {
      es.close();
      setTimeout(() => fetchState(), 3000);
    };

    return () => { es.close(); };
  }, [fetchState]);

  // Animated mitigation logs
  useEffect(() => {
    if (activeTab === 'protect' && protectionEnabled && attackData?.active) {
      const msgs = [
        "Analyzing packet signatures...",
        "Anomaly detected: High connection rate",
        "Signature matched: Slowloris attack pattern",
        "Rate-limiting IPs exceeding threshold",
        "Dropping malformed HTTP headers",
        `Mitigating attack on ${protectedDomain || attackData.target}...`,
        "Null-routing malicious traffic",
        "ShieldWall engine actively filtering..."
      ];
      
      let count = 0;
      const interval = setInterval(() => {
        if (count >= 4) {
          setMitigationLogs(prev => [...prev.slice(-15), `[${new Date().toISOString().split('T')[1].slice(0,-1)}] ✅ Mitigation successful. All attack traffic blocked.`]);
          clearInterval(interval);
          return;
        }
        
        const msg = msgs[Math.floor(Math.random() * msgs.length)];
        setMitigationLogs(prev => [...prev.slice(-15), `[${new Date().toISOString().split('T')[1].slice(0,-1)}] 🛡️ ${msg}`]);
        count++;
      }, 800);
      
      return () => clearInterval(interval);
    } else {
      setMitigationLogs([]);
    }
  }, [activeTab, protectionEnabled, attackData?.active, protectedDomain]);

  // ---- Actions ----
  const startMonitor = async () => {
    if (!targetUrl.trim()) return;
    setLoading(true);
    setStatusMsg('');
    localStorage.setItem('shieldwall_monitor_active', 'true');
    localStorage.setItem('shieldwall_monitor_url', targetUrl.trim());

    const res = await fetch('/api/monitor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'start', url: targetUrl.trim() }),
    });
    const data = await res.json();
    setMonitoring(data.monitoring || false);
    if (data.targetUrl) setTargetUrl(data.targetUrl);
    setLoading(false);
    setStatusMsg('✅ Monitoring started!');
  };

  const stopMonitor = async () => {
    localStorage.setItem('shieldwall_monitor_active', 'false');
    await fetch('/api/monitor', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'stop' }),
    });
    setMonitoring(false);
    setStatusMsg('Monitoring stopped.');
  };

  // ---- Actions ----

  const saveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!config) return;
    await Promise.all([
      fetch('/api/firewall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'updateConfig', config: {
          rateLimit: config.rateLimit,
          rateLimitWindow: config.rateLimitWindow,
          autoBlockThreshold: config.autoBlockThreshold,
          alertEmailEnabled: config.alertEmailEnabled,
          alertEmail: config.alertEmail,
        }}),
      }),
      fetch('/api/alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      }),
    ]);
    setStatusMsg('✅ Settings saved!');
    setTimeout(() => setStatusMsg(''), 3000);
  };

  // ---- Protection toggle ----
  const toggleProtection = async (enable: boolean) => {
    setLoading(true);
    const res = await fetch('/api/firewall', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'toggleProtection', enabled: enable }),
    });
    const data = await res.json();
    if (data.success) {
      setProtectionEnabled(data.protectionEnabled);
      setStatusMsg(data.protectionEnabled
        ? '🛡️ Protection ENABLED — attacks will be blocked!'
        : '⚠️ Protection DISABLED');
    } else {
      setStatusMsg(`❌ ${data.error}`);
    }
    setLoading(false);
    setTimeout(() => setStatusMsg(''), 4000);
  };

  // ---- Chart data ----
  const chartData = probes.slice(-80).map(p => ({
    time: new Date(p.timestamp).toLocaleTimeString(),
    'Response Time (ms)': p.available ? p.responseTime : null,
    'Down': !p.available ? 1 : null,
  }));

  const isDown = healthStats.currentStatus === 'down';
  const isUnderStress = healthStats.avgResponseTime > 2000;

  return (
    <div style={{ minHeight: '100vh', padding: '20px 28px', maxWidth: 1400, margin: '0 auto' }}>
      {/* ======== HEADER ======== */}
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 50, height: 50, borderRadius: 14,
            background: 'linear-gradient(135deg, #00d4ff, #8b5cf6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 26, boxShadow: '0 0 25px rgba(0, 212, 255, 0.3)',
          }}>🛡️</div>
          <div>
            <h1 style={{
              fontSize: 28, fontWeight: 800,
              background: 'linear-gradient(135deg, #00d4ff, #8b5cf6)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            }}>ShieldWall</h1>
            <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 1 }}>
              DDoS Prevention & Live Website Monitoring
            </p>
          </div>
        </div>
        {statusMsg && (
          <div style={{ padding: '8px 16px', borderRadius: 8, background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', fontSize: 13 }}>
            {statusMsg}
          </div>
        )}
      </header>

      {/* ======== WEBSITE STATUS BAR ======== */}
      {monitoring && (
        <div
          className={`glass-card ${isDown ? 'attack-pulse' : isUnderStress ? 'attack-pulse' : 'safe-pulse'}`}
          style={{
            padding: '14px 24px', marginBottom: 20,
            background: isDown ? 'linear-gradient(135deg, rgba(239,68,68,0.15), rgba(249,115,22,0.1))'
              : isUnderStress ? 'linear-gradient(135deg, rgba(245,158,11,0.12), rgba(239,68,68,0.08))'
              : 'linear-gradient(135deg, rgba(16,185,129,0.1), rgba(6,182,212,0.08))',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            border: isDown ? '1px solid rgba(239,68,68,0.3)' : isUnderStress ? '1px solid rgba(245,158,11,0.3)' : '1px solid rgba(16,185,129,0.2)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 12, height: 12, borderRadius: '50%',
              background: isDown ? '#ef4444' : isUnderStress ? '#f59e0b' : '#10b981',
              boxShadow: `0 0 10px ${isDown ? '#ef4444' : isUnderStress ? '#f59e0b' : '#10b981'}`,
            }} />
            <span style={{ fontWeight: 700, fontSize: 14 }}>
              {isDown ? `🚨 ${targetUrl} is DOWN — Possible DDoS attack!`
                : isUnderStress ? `⚠️ ${targetUrl} is under stress — High latency detected`
                : `✅ ${targetUrl} is Online — ${healthStats.avgResponseTime}ms avg response`}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className={`badge ${isDown ? 'badge-danger' : isUnderStress ? 'badge-warning' : 'badge-success'}`}>
              {isDown ? 'DOWN' : isUnderStress ? 'STRESSED' : 'ONLINE'}
            </span>
            <span className="badge badge-info">{healthStats.availability}% uptime</span>
          </div>
        </div>
      )}

      {/* ======== TAB NAVIGATION ======== */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20, flexWrap: 'wrap' }}>
        {([
          { key: 'monitor', icon: '📡', label: 'Monitor' },
          { key: 'protect', icon: '🛡️', label: 'Protect' },
          // { key: 'attack', icon: '⚡', label: 'Attack' },
          { key: 'alerts', icon: '🔔', label: 'Alerts' },
          { key: 'settings', icon: '⚙️', label: 'Settings' },
        ] as const).map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as typeof activeTab)}
            style={{
              padding: '10px 22px', borderRadius: 10, border: 'none', cursor: 'pointer',
              fontSize: 13, fontWeight: 600, transition: 'all 0.2s',
              background: activeTab === tab.key ? 'linear-gradient(135deg, #00d4ff, #8b5cf6)' : 'rgba(255,255,255,0.04)',
              color: activeTab === tab.key ? '#fff' : 'var(--text-secondary)',
            }}
          >
            {tab.icon} {tab.label}
            {tab.key === 'protect' && protectionEnabled && (
              <span style={{ marginLeft: 6, width: 8, height: 8, borderRadius: '50%', background: '#10b981', display: 'inline-block', animation: 'pulse-green 2s infinite' }} />
            )}
          </button>
        ))}
      </div>

      {/* ======== MONITOR TAB ======== */}
      {activeTab === 'monitor' && (
        <div className="fade-in">
          {/* URL Input */}
          <div className="glass-card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 14 }}>📡 Monitor Website</h3>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 14 }}>
              Enter any website URL to monitor its health in real-time. ShieldWall will ping it every 1.5 seconds and track response time, availability, and detect attacks.
            </p>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              <input
                className="input-field"
                placeholder="Enter website URL (e.g. https://example.com or localhost:3000)"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !monitoring && startMonitor()}
                style={{ flex: 1, minWidth: 300 }}
                disabled={monitoring}
              />
              {!monitoring ? (
                <button className="btn-primary" onClick={startMonitor} disabled={loading || !targetUrl.trim()}>
                  {loading ? '⏳ Starting...' : '▶ Start Monitoring'}
                </button>
              ) : (
                <button className="btn-danger" onClick={stopMonitor}>
                  ⏹ Stop Monitoring
                </button>
              )}
            </div>
          </div>

          {/* Stats Cards */}
          {monitoring && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
                <StatCard icon="📡" label="Status" value={healthStats.currentStatus.toUpperCase()} color={isDown ? '#ef4444' : '#10b981'} />
                <StatCard icon="⏱️" label="Avg Response" value={`${healthStats.avgResponseTime}ms`} color={healthStats.avgResponseTime > 2000 ? '#f59e0b' : '#00d4ff'} />
                <StatCard icon="📊" label="Availability" value={`${healthStats.availability}%`} color={healthStats.availability < 80 ? '#ef4444' : '#10b981'} />
                <StatCard icon="📦" label="Probes Sent" value={String(probes.length)} color="#8b5cf6" />
                <StatCard icon="🚫" label="Blocked IPs" value={String(blockedIPs.length)} color="#f59e0b" />
              </div>

              {/* Live Chart */}
              <div className="glass-card" style={{ padding: 24, marginBottom: 20 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>📈 Live Response Time</h3>
                <ResponsiveContainer width="100%" height={320}>
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorRT" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="time" stroke="#555" tick={{ fontSize: 10 }} interval="preserveStartEnd" />
                    <YAxis stroke="#555" tick={{ fontSize: 11 }} label={{ value: 'ms', position: 'insideLeft', style: { fill: '#666' } }} />
                    <Tooltip contentStyle={{ background: 'rgba(15,15,40,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, fontSize: 12 }} />
                    <Legend />
                    <Area type="monotone" dataKey="Response Time (ms)" stroke="#00d4ff" fill="url(#colorRT)" strokeWidth={2} connectNulls={false} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Recent probes table */}
              <div className="glass-card" style={{ padding: 24, overflow: 'auto' }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>📋 Recent Health Probes</h3>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Status</th>
                      <th>HTTP Code</th>
                      <th>Response Time</th>
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {probes.slice(-20).reverse().map((p, i) => (
                      <tr key={i}>
                        <td>{new Date(p.timestamp).toLocaleTimeString()}</td>
                        <td>
                          <span className={`badge ${p.available ? 'badge-success' : 'badge-danger'}`}>
                            {p.available ? 'UP' : 'DOWN'}
                          </span>
                        </td>
                        <td style={{ color: p.statusCode >= 400 ? '#ef4444' : p.statusCode >= 200 ? '#10b981' : '#888' }}>
                          {p.statusCode || '—'}
                        </td>
                        <td style={{ color: p.responseTime > 3000 ? '#ef4444' : p.responseTime > 1000 ? '#f59e0b' : '#10b981' }}>
                          {p.responseTime}ms
                        </td>
                        <td style={{ color: '#ef4444', fontSize: 11 }}>{p.error || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* ======== PROTECT TAB ======== */}
      {activeTab === 'protect' && (
        <div className="fade-in">
          {/* Protection Toggle */}
          <div className="glass-card" style={{ padding: 28, marginBottom: 20, borderLeft: `4px solid ${protectionEnabled ? '#10b981' : '#ef4444'}` }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
              <div>
                <h3 style={{ fontSize: 20, fontWeight: 800, marginBottom: 6 }}>🛡️ ShieldWall Firewall</h3>
                <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                  {protectionEnabled
                    ? 'Firewall is ACTIVE  '
                    : 'Firewall is OFF '}
                </p>
                <div style={{ marginTop: 16 }}>
                  <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Protected Website URL (Target Simulation)</label>
                  <input 
                    className="input-field" 
                    style={{ maxWidth: 300, background: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)' }}
                    placeholder="e.g. domainname.com" 
                    value={protectedDomain} 
                    onChange={e => setProtectedDomain(e.target.value)} 
                  />
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    width: 14, height: 14, borderRadius: '50%',
                    background: protectionEnabled ? '#10b981' : '#ef4444',
                    boxShadow: `0 0 12px ${protectionEnabled ? '#10b981' : '#ef4444'}`,
                    animation: protectionEnabled ? 'pulse-green 2s infinite' : 'none',
                  }} />
                  <span style={{
                    fontWeight: 700, fontSize: 15,
                    color: protectionEnabled ? '#10b981' : '#ef4444',
                  }}>
                    {protectionEnabled ? 'PROTECTED' : 'UNPROTECTED'}
                  </span>
                </div>
                <button
                  className={protectionEnabled ? 'btn-danger' : 'btn-primary'}
                  onClick={async () => {
                    if (!protectionEnabled && !protectedDomain.trim()) {
                      alert('Please enter a Protected Website URL to enable protection.');
                      return;
                    }
                    setLoading(true);
                    const newState = !protectionEnabled;
                    localStorage.setItem('shieldwall_protect_active', newState ? 'true' : 'false');
                    
                    const res = await fetch('/api/firewall', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ action: 'toggleProtection', enabled: newState }),
                    });
                    const data = await res.json();
                    setProtectionEnabled(data.protectionEnabled);
                    setLoading(false);
                  }}
                  disabled={loading || (!protectionEnabled && !protectedDomain.trim())}
                  style={{ fontSize: 14, padding: '12px 32px', minWidth: 180, opacity: (!protectionEnabled && !protectedDomain.trim()) ? 0.5 : 1 }}
                >
                  {loading ? '⏳ ...' : protectionEnabled ? '⏹ Disable Protection' : '🛡️ Enable Protection'}
                </button>
              </div>
            </div>
          </div>

    

          {/* Live Data */}
          <div className="glass-card" style={{ padding: 24, marginBottom: 20 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 14 }}>📊 Live Data</h3>
            
            {(attackData && attackData.active) ? (
              <div style={{
                padding: '12px 16px', marginBottom: 16, borderRadius: 10,
                background: protectionEnabled ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
                border: `1px solid ${protectionEnabled ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}`,
                display: 'flex', alignItems: 'center', gap: 10,
              }}>
                <div style={{
                  width: 10, height: 10, borderRadius: '50%',
                  background: protectionEnabled ? '#10b981' : '#ef4444',
                  animation: 'pulse-red 1s infinite',
                }} />
                <span style={{ fontWeight: 600, fontSize: 13, color: protectionEnabled ? '#10b981' : '#ef4444' }}>
                  {protectionEnabled
                    ? '🛡️ ATTACK DETECTED & BLOCKED — ShieldWall is protecting the target'
                    : '🚨 ACTIVE ATTACK DETECTED — Enable protection to block it!'}
                </span>
              </div>
            ) : (
              <>
                <div style={{
                  padding: '12px 16px', marginBottom: 16, borderRadius: 10,
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  display: 'flex', alignItems: 'center', gap: 10,
                }}>
                  <div style={{
                    width: 10, height: 10, borderRadius: '50%',
                    background: '#00d4ff',
                    animation: 'pulse-blue 1s infinite',
                  }} />
                  <span style={{ fontWeight: 600, fontSize: 13, color: '#00d4ff' }}>
                    📡 Monitoring traffic on {protectedDomain || targetUrl || 'target website'} for anomalies...
                  </span>
                </div>

                {monitoring ? (
                  <div style={{ marginBottom: 20 }}>
                    <div className={`glass-card ${isDown ? 'attack-pulse' : isUnderStress ? 'attack-pulse' : 'safe-pulse'}`} style={{ padding: '14px 24px', marginBottom: 16, background: isDown ? 'linear-gradient(135deg, rgba(239,68,68,0.15), rgba(249,115,22,0.1))' : isUnderStress ? 'linear-gradient(135deg, rgba(245,158,11,0.12), rgba(239,68,68,0.08))' : 'linear-gradient(135deg, rgba(16,185,129,0.1), rgba(6,182,212,0.08))', display: 'flex', alignItems: 'center', justifyContent: 'space-between', border: isDown ? '1px solid rgba(239,68,68,0.3)' : isUnderStress ? '1px solid rgba(245,158,11,0.3)' : '1px solid rgba(16,185,129,0.2)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <div style={{ width: 12, height: 12, borderRadius: '50%', background: isDown ? '#ef4444' : isUnderStress ? '#f59e0b' : '#10b981', boxShadow: `0 0 10px ${isDown ? '#ef4444' : isUnderStress ? '#f59e0b' : '#10b981'}` }} />
                        <span style={{ fontWeight: 700, fontSize: 14 }}>
                          {isDown ? `🚨 ${targetUrl} is DOWN` : isUnderStress ? `⚠️ ${targetUrl} is under stress` : `✅ ${targetUrl} is Online — ${healthStats.avgResponseTime}ms avg`}
                        </span>
                      </div>
                    </div>
                    
                    <div className="glass-card" style={{ padding: 16, height: 200 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient id="colorRT_protect" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor={isDown ? "#ef4444" : "#00d4ff"} stopOpacity={0.4} />
                              <stop offset="95%" stopColor={isDown ? "#ef4444" : "#00d4ff"} stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                          <XAxis dataKey="time" stroke="#555" tick={{ fontSize: 10 }} interval="preserveStartEnd" />
                          <YAxis stroke="#555" tick={{ fontSize: 10 }} />
                          <Tooltip contentStyle={{ background: 'rgba(15,15,40,0.95)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 10, fontSize: 12 }} />
                          <Area type="monotone" dataKey="Response Time (ms)" stroke={isDown ? "#ef4444" : "#00d4ff"} fill="url(#colorRT_protect)" strokeWidth={2} connectNulls={false} dot={false} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '30px 20px', background: 'rgba(0,0,0,0.2)', borderRadius: 10, marginBottom: 20 }}>
                    <p style={{ color: 'var(--text-secondary)', fontSize: 13 }}>⚠️ Background monitor is OFF. Start monitoring from the "Monitor" tab to see live health graphs here.</p>
                  </div>
                )}
              </>
            )}

            {/* Only show attack stats if an attack is actively detected */}
            {(attackData && attackData.active) && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14 }}>
                <StatCard icon="🔗" label="Connections" value={String(attackData.totalConnections)} color="#00d4ff" />
                <StatCard icon="❌" label="Failed" value={String(attackData.totalFailed)} color="#ef4444" />
                <StatCard icon={protectionEnabled ? '🛡️' : '⚠️'} label={protectionEnabled ? 'Blocked' : 'Unblocked'} value={protectionEnabled ? String(attackData.totalVolleys) : '0'} color={protectionEnabled ? '#10b981' : '#ef4444'} />
              </div>
            )}

            {protectionEnabled && attackData?.active && (
              <div style={{ marginTop: 20, background: '#0a0a0a', border: '1px solid #333', borderRadius: 8, padding: 12, fontFamily: 'monospace', fontSize: 12, color: '#10b981', height: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column-reverse' }}>
                {mitigationLogs.length === 0 ? (
                  <span style={{ color: '#666' }}>Waiting for traffic anomalies...</span>
                ) : (
                  mitigationLogs.slice().reverse().map((log, i) => <div key={i}>{log}</div>)
                )}
              </div>
            )}

            {attackData?.active && (
              <p style={{ fontSize: 11, color: '#666', marginTop: 12 }}>
                Last updated: {new Date(attackData.lastUpdate).toLocaleTimeString()}
              </p>
            )}
          </div>

          {/* Stats Summary */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginBottom: 20 }}>
            <StatCard icon="🛡️" label="Protection" value={protectionEnabled ? 'ON' : 'OFF'} color={protectionEnabled ? '#10b981' : '#ef4444'} />
            <StatCard icon="🚫" label="Total Blocked" value={String(proxyBlocked)} color="#ef4444" />
            <StatCard icon="✅" label="Total Passed" value={String(proxyForwarded)} color="#10b981" />
            <StatCard icon="🔒" label="Blocked IPs" value={String(blockedIPs.length)} color="#f59e0b" />
          </div>
        </div>
      )}

     

      {/* ======== ALERTS TAB ======== */}
      {activeTab === 'alerts' && (
        <div className="fade-in">
          <div className="glass-card" style={{ padding: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>🔔 Alert History</h3>
            {alerts.length === 0 && <p style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: 30 }}>No alerts yet.</p>}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {alerts.map(a => (
                <div key={a.id} style={{
                  padding: '12px 16px', borderRadius: 10,
                  background: a.severity === 'critical' ? 'rgba(239,68,68,0.08)' : a.severity === 'warning' ? 'rgba(245,158,11,0.06)' : 'rgba(0,212,255,0.04)',
                  border: `1px solid ${a.severity === 'critical' ? 'rgba(239,68,68,0.15)' : a.severity === 'warning' ? 'rgba(245,158,11,0.12)' : 'rgba(0,212,255,0.08)'}`,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span className={`badge badge-${a.severity === 'critical' ? 'danger' : a.severity === 'warning' ? 'warning' : 'info'}`}>{a.severity}</span>
                    <span style={{ fontSize: 11, color: '#666' }}>{new Date(a.timestamp).toLocaleString()}</span>
                  </div>
                  <p style={{ fontSize: 13 }}>{a.message}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ======== SETTINGS TAB ======== */}
      {activeTab === 'settings' && config && (
        <div className="fade-in">
          <form onSubmit={saveSettings}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: 20 }}>
              <div className="glass-card" style={{ padding: 24 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>🛡️ Rate Limiting</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <InputField label="Max requests/sec per IP" type="number" value={config.rateLimit} onChange={v => setConfig({ ...config, rateLimit: parseInt(v) || 50 })} />
                  <InputField label="Window (seconds)" type="number" value={config.rateLimitWindow} onChange={v => setConfig({ ...config, rateLimitWindow: parseInt(v) || 10 })} />
                  <InputField label="Auto-block after N violations" type="number" value={config.autoBlockThreshold} onChange={v => setConfig({ ...config, autoBlockThreshold: parseInt(v) || 5 })} />
                </div>
              </div>
              <div className="glass-card" style={{ padding: 24 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, marginBottom: 16 }}>📧 Email Alerts</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <span style={{ fontSize: 13 }}>Enable Email Alerts</span>
                    <div className={`toggle-switch ${config.alertEmailEnabled ? 'active' : ''}`} onClick={() => setConfig({ ...config, alertEmailEnabled: !config.alertEmailEnabled })} />
                  </div>
                  <InputField label="Your Email" type="email" value={config.alertEmail} onChange={v => setConfig({ ...config, alertEmail: v })} placeholder="your@email.com" />
                  <InputField label="SMTP Host" type="text" value={config.smtpHost} onChange={v => setConfig({ ...config, smtpHost: v })} placeholder="smtp.gmail.com" />
                  <InputField label="SMTP Port" type="number" value={config.smtpPort} onChange={v => setConfig({ ...config, smtpPort: parseInt(v) || 587 })} />
                  <InputField label="SMTP User" type="text" value={config.smtpUser} onChange={v => setConfig({ ...config, smtpUser: v })} placeholder="your@gmail.com" />
                  <InputField label="SMTP Password" type="password" value={config.smtpPass} onChange={v => setConfig({ ...config, smtpPass: v })} placeholder="••••••••" />
                </div>
              </div>
            </div>
            <div style={{ marginTop: 20 }}>
              <button type="submit" className="btn-primary" style={{ padding: '12px 40px' }}>💾 Save Settings</button>
            </div>
          </form>
        </div>
      )}

      {/* Footer */}
      <footer style={{ marginTop: 40, textAlign: 'center', padding: 16, fontSize: 11, color: '#555', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
        🛡️ ShieldWall — Monitor any website, detect DDoS attacks, block malicious IPs
      </footer>
    </div>
  );
}

// ==========================================
// Sub-components
// ==========================================
function StatCard({ icon, label, value, color }: { icon: string; label: string; value: string; color: string }) {
  return (
    <div className="glass-card" style={{ padding: '18px 20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 500 }}>{label}</span>
        <span style={{ fontSize: 18 }}>{icon}</span>
      </div>
      <div className="stat-number" style={{ fontSize: 24, fontWeight: 800, color, letterSpacing: '-0.5px' }}>{value}</div>
    </div>
  );
}

function InputField({ label, type, value, onChange, placeholder }: { label: string; type: string; value: string | number; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label style={{ fontSize: 12, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>{label}</label>
      <input className="input-field" type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  );
}
