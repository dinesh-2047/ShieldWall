/**
 * Attack Classifier
 * 
 * Classifies incoming attack patterns into known categories based on
 * traffic telemetry. Feeds into the self-healing engine for targeted
 * playbook selection.
 */

export type AttackType =
  | 'SYN_FLOOD'
  | 'HTTP_FLOOD'
  | 'SLOWLORIS'
  | 'UDP_FLOOD'
  | 'PORT_SCAN'
  | 'BRUTE_FORCE'
  | 'UNKNOWN';

export interface AttackClassification {
  id: string;
  timestamp: number;
  type: AttackType;
  confidence: number;       // 0 – 1
  indicators: string[];     // human-readable reasons
  sourceIP?: string;
  target: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  mitigationHint: string;
}

export interface TrafficSignature {
  totalVolleys: number;
  totalConnections: number;
  totalFailed: number;
  avgResponseTime: number;      // ms
  requestRate: number;           // req/s (from IP trackers)
  uniquePathCount: number;       // how many different paths were hit
  authEndpointHits: number;      // hits to /login, /auth, /api/auth etc.
  activeConnections: number;     // concurrent open connections
}

/**
 * Classify an attack from traffic signals.
 */
export function classifyAttack(
  sig: TrafficSignature,
  target: string,
  sourceIP?: string,
): AttackClassification | null {
  const indicators: string[] = [];
  let type: AttackType = 'UNKNOWN';
  let confidence = 0;
  let severity: AttackClassification['severity'] = 'low';
  let mitigationHint = '';

  const connectionBase = Math.max(sig.totalConnections, 1);
  const failureRatio = sig.totalFailed / connectionBase;

  // ---------- SYN FLOOD ----------
  // High connections, very high failure rate
  if (sig.totalConnections > 500 && failureRatio > 0.6) {
    type = 'SYN_FLOOD';
    confidence = Math.min(0.5 + failureRatio * 0.4 + (sig.totalConnections / 5000) * 0.1, 0.98);
    indicators.push(`High connection count: ${sig.totalConnections}`);
    indicators.push(`Very high failure ratio: ${(failureRatio * 100).toFixed(1)}%`);
    severity = sig.totalConnections > 2000 ? 'critical' : 'high';
    mitigationHint = 'Enable SYN cookies, drop half-open connections, enable firewall proxy';
  }

  // ---------- HTTP FLOOD ----------
  // High volleys, lower failure rate — many successful requests meant to overwhelm
  else if (sig.totalVolleys > 300 && failureRatio < 0.3 && sig.requestRate > 50) {
    type = 'HTTP_FLOOD';
    confidence = Math.min(0.5 + (sig.totalVolleys / 3000) * 0.3 + (sig.requestRate / 500) * 0.2, 0.95);
    indicators.push(`High volley count: ${sig.totalVolleys}`);
    indicators.push(`Request rate: ${sig.requestRate.toFixed(1)} req/s`);
    indicators.push(`Low failure ratio: ${(failureRatio * 100).toFixed(1)}%`);
    severity = sig.requestRate > 200 ? 'critical' : 'high';
    mitigationHint = 'Rate-limit per IP, enable CAPTCHA challenge, enable proxy filtering';
  }

  // ---------- SLOWLORIS ----------
  // Moderate connections but very high response times
  else if (sig.avgResponseTime > 4000 && sig.totalConnections > 50 && sig.totalConnections < 500) {
    type = 'SLOWLORIS';
    confidence = Math.min(0.5 + (sig.avgResponseTime / 10000) * 0.3 + 0.15, 0.92);
    indicators.push(`Very high avg response time: ${sig.avgResponseTime}ms`);
    indicators.push(`Moderate connection count: ${sig.totalConnections}`);
    severity = sig.avgResponseTime > 8000 ? 'critical' : 'high';
    mitigationHint = 'Set connection timeout limits, limit connections per IP, enable keep-alive limits';
  }

  // ---------- UDP FLOOD ----------
  // High volleys with high failure
  else if (sig.totalVolleys > 500 && failureRatio > 0.4) {
    type = 'UDP_FLOOD';
    confidence = Math.min(0.45 + (sig.totalVolleys / 5000) * 0.3 + failureRatio * 0.2, 0.90);
    indicators.push(`High volley count: ${sig.totalVolleys}`);
    indicators.push(`Elevated failure ratio: ${(failureRatio * 100).toFixed(1)}%`);
    severity = sig.totalVolleys > 2000 ? 'critical' : 'medium';
    mitigationHint = 'Enable UDP rate limiting, null-route suspicious sources';
  }

  // ---------- PORT SCAN ----------
  // Many unique paths — probing different endpoints
  else if (sig.uniquePathCount > 20 && sig.requestRate > 10) {
    type = 'PORT_SCAN';
    confidence = Math.min(0.5 + (sig.uniquePathCount / 100) * 0.3, 0.88);
    indicators.push(`Many unique paths probed: ${sig.uniquePathCount}`);
    indicators.push(`Request rate: ${sig.requestRate.toFixed(1)} req/s`);
    severity = 'medium';
    mitigationHint = 'Block scanning IP, enable port-knocking, hide service banners';
  }

  // ---------- BRUTE FORCE ----------
  // High auth endpoint hits
  else if (sig.authEndpointHits > 30 && sig.requestRate > 5) {
    type = 'BRUTE_FORCE';
    confidence = Math.min(0.5 + (sig.authEndpointHits / 200) * 0.35, 0.92);
    indicators.push(`Auth endpoint hit ${sig.authEndpointHits} times`);
    indicators.push(`Request rate: ${sig.requestRate.toFixed(1)} req/s`);
    severity = sig.authEndpointHits > 100 ? 'high' : 'medium';
    mitigationHint = 'Lock account after N attempts, enable CAPTCHA, block IP';
  }

  // ---------- GENERIC ANOMALY ----------
  else if (sig.requestRate > 100 || sig.totalVolleys > 200) {
    type = 'UNKNOWN';
    confidence = 0.4;
    indicators.push(`Elevated request rate: ${sig.requestRate.toFixed(1)} req/s`);
    if (sig.totalVolleys > 200) indicators.push(`High volley count: ${sig.totalVolleys}`);
    severity = 'medium';
    mitigationHint = 'Enable firewall protection, monitor closely';
  }

  // No attack detected
  else {
    return null;
  }

  return {
    id: `atk_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
    timestamp: Date.now(),
    type,
    confidence,
    indicators,
    sourceIP,
    target,
    severity,
    mitigationHint,
  };
}

/**
 * Human-readable attack type labels.
 */
export const ATTACK_TYPE_LABELS: Record<AttackType, string> = {
  SYN_FLOOD: 'SYN Flood',
  HTTP_FLOOD: 'HTTP Flood',
  SLOWLORIS: 'Slowloris',
  UDP_FLOOD: 'UDP Flood',
  PORT_SCAN: 'Port Scan',
  BRUTE_FORCE: 'Brute Force',
  UNKNOWN: 'Unknown Attack',
};
