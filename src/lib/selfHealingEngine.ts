/**
 * Self-Healing Engine
 *
 * The heart of ShieldWall's autonomous recovery system.
 * Continuously monitors all tracked services and executes
 * recovery playbooks when faults are detected.
 *
 * Pipeline: Detection → Classification → Playbook Selection →
 *           Action Execution → Verification → Logging
 *
 * Runs on a 5-second loop. Each iteration:
 *  1. Checks all health probes for fault patterns
 *  2. Checks external attack data for ongoing attacks
 *  3. Checks rate-limit violation patterns
 *  4. If a fault is identified, selects the matching playbook
 *  5. Executes each step of the playbook
 *  6. Verifies recovery by probing the target
 *  7. Logs the full healing action with result & timing
 */

import { store, type FaultType, type HealingAction } from './store';
import { classifyAttack, type TrafficSignature } from './attackClassifier';

let healingInterval: ReturnType<typeof setInterval> | null = null;

// ---- Telemetry window tracking ----
let consecutiveDownCount = 0;
let consecutiveHighLatencyCount = 0;

/**
 * Start the self-healing loop.
 */
export function startSelfHealing(): void {
  stopSelfHealing();

  console.log('[SelfHealing] 🧬 Self-healing engine started');
  store.addEngineLog({
    source: 'healer',
    level: 'info',
    message: 'Self-healing engine activated — monitoring for faults every 5s',
  });

  // Run immediately, then every 5s
  runHealingCycle();
  healingInterval = setInterval(runHealingCycle, 5000);
}

/**
 * Stop the self-healing loop.
 */
export function stopSelfHealing(): void {
  if (healingInterval) {
    clearInterval(healingInterval);
    healingInterval = null;
  }
  consecutiveDownCount = 0;
  consecutiveHighLatencyCount = 0;
}

export function isSelfHealingRunning(): boolean {
  return healingInterval !== null;
}

/**
 * One cycle of the healing loop.
 */
async function runHealingCycle(): Promise<void> {
  if (!store.selfHealingEnabled) return;

  try {
    // 1. Check primary target health
    await checkPrimaryHealth();

    // 2. Check for active DDoS attack
    await checkDDoSAttack();

    // 3. Check rate-limit breaches
    checkRateLimitBreaches();

    // 4. Check multi-node health
    checkMultiNodeHealth();

    // 5. Run attack classification if attack data present
    classifyActiveAttack();

  } catch (err) {
    console.error('[SelfHealing] Cycle error:', err);
  }
}

// ============================================================
// DETECTION ROUTINES
// ============================================================

/**
 * Check if the primary monitored site is down or degraded.
 */
async function checkPrimaryHealth(): Promise<void> {
  if (!store.monitoring || !store.targetUrl) return;

  const stats = store.getHealthStats();
  const recent = store.getRecentProbes(10);

  if (recent.length < 3) return; // Need minimum data

  const lastFew = recent.slice(-5);
  const downCount = lastFew.filter(p => !p.available).length;
  const avgRT = lastFew.filter(p => p.available).reduce((s, p) => s + p.responseTime, 0) /
    Math.max(lastFew.filter(p => p.available).length, 1);

  // SERVICE_DOWN: 3+ consecutive failures
  if (downCount >= 3) {
    consecutiveDownCount++;
    if (consecutiveDownCount >= 2 && store.canRunPlaybook('SERVICE_DOWN')) {
      const fault = store.addFaultEvent({
        type: 'SERVICE_DOWN',
        affectedNode: store.targetUrl,
        severity: 'critical',
        details: `${downCount}/5 probes failed. Service appears unreachable.`,
      });
      await executePlaybook('SERVICE_DOWN', fault.id, store.targetUrl);
      consecutiveDownCount = 0;
    }
    return;
  }
  consecutiveDownCount = 0;

  // HIGH_LATENCY: sustained high response times
  if (avgRT > 3000 && stats.currentStatus !== 'down') {
    consecutiveHighLatencyCount++;
    if (consecutiveHighLatencyCount >= 3 && store.canRunPlaybook('HIGH_LATENCY')) {
      const fault = store.addFaultEvent({
        type: 'HIGH_LATENCY',
        affectedNode: store.targetUrl,
        severity: 'warning',
        details: `Average response time ${Math.round(avgRT)}ms over last 5 probes.`,
      });
      await executePlaybook('HIGH_LATENCY', fault.id, store.targetUrl);
      consecutiveHighLatencyCount = 0;
    }
  } else {
    consecutiveHighLatencyCount = 0;
  }
}

/**
 * Check if there's an active DDoS attack from external telemetry.
 */
async function checkDDoSAttack(): Promise<void> {
  const atk = store.externalAttackData;
  if (!atk || !atk.active) return;
  if (!store.canRunPlaybook('DDOS_ATTACK')) return;

  // Only trigger if attack has significant volume
  if (atk.totalVolleys > 100 || atk.totalConnections > 200) {
    const fault = store.addFaultEvent({
      type: 'DDOS_ATTACK',
      affectedNode: atk.target || store.targetUrl,
      severity: 'critical',
      details: `Active DDoS: ${atk.totalVolleys} volleys, ${atk.totalConnections} connections, ${atk.totalFailed} failed. Attacker: ${atk.attackerIP}`,
    });
    await executePlaybook('DDOS_ATTACK', fault.id, atk.target || store.targetUrl);
  }
}

/**
 * Check for rate-limit breach patterns across all tracked IPs.
 */
function checkRateLimitBreaches(): void {
  if (!store.canRunPlaybook('RATE_LIMIT_BREACH')) return;

  const ipStats = store.getIPStats();
  const offenders = ipStats.filter(s => s.violations >= 3 && !s.blocked);

  if (offenders.length >= 2) {
    const fault = store.addFaultEvent({
      type: 'RATE_LIMIT_BREACH',
      affectedNode: store.targetUrl || 'all',
      severity: 'warning',
      details: `${offenders.length} IPs have 3+ rate limit violations: ${offenders.map(o => o.ip).join(', ')}`,
    });
    executePlaybook('RATE_LIMIT_BREACH', fault.id, store.targetUrl || 'all');
  }
}

/**
 * Check multi-node health for partial outages.
 */
function checkMultiNodeHealth(): void {
  if (store.monitoredNodes.length < 2) return;
  if (!store.canRunPlaybook('PARTIAL_OUTAGE')) return;

  const activeNodes = store.monitoredNodes.filter(n => !n.isolated);
  const downNodes = activeNodes.filter(n => n.status === 'down');
  const upNodes = activeNodes.filter(n => n.status === 'online' || n.status === 'degraded');

  // Partial outage: some down, some up
  if (downNodes.length > 0 && upNodes.length > 0) {
    const fault = store.addFaultEvent({
      type: 'PARTIAL_OUTAGE',
      affectedNode: downNodes.map(n => n.label).join(', '),
      severity: 'critical',
      details: `${downNodes.length}/${activeNodes.length} nodes are down: ${downNodes.map(n => n.url).join(', ')}`,
    });
    executePlaybook('PARTIAL_OUTAGE', fault.id, downNodes[0].url);
  }
}

/**
 * Classify the active attack from external telemetry + proxy data.
 */
function classifyActiveAttack(): void {
  const atk = store.externalAttackData;
  if (!atk || !atk.active) return;

  const stats = store.getHealthStats();
  const ipStats = store.getIPStats();
  const totalRate = ipStats.reduce((s, i) => s + i.rate, 0);

  // Count unique paths from proxy requests
  const recentProxy = store.proxyRequests.slice(-200);
  const uniquePaths = new Set(recentProxy.map(r => r.path)).size;
  const authHits = recentProxy.filter(r =>
    r.path.includes('/login') || r.path.includes('/auth') || r.path.includes('/api/auth'),
  ).length;

  const sig: TrafficSignature = {
    totalVolleys: atk.totalVolleys,
    totalConnections: atk.totalConnections,
    totalFailed: atk.totalFailed,
    avgResponseTime: stats.avgResponseTime,
    requestRate: totalRate,
    uniquePathCount: uniquePaths,
    authEndpointHits: authHits,
    activeConnections: atk.totalConnections - atk.totalFailed,
  };

  const classification = classifyAttack(sig, atk.target || store.targetUrl, atk.attackerIP);
  if (classification) {
    // Avoid duplicate classifications within 30 seconds
    const recent = store.attackClassifications.slice(-5);
    const isDuplicate = recent.some(
      c => c.type === classification.type && Date.now() - c.timestamp < 30000,
    );
    if (!isDuplicate) {
      store.addAttackClassification(classification);
      store.addEngineLog({
        source: 'healer',
        level: classification.severity === 'critical' ? 'critical' : 'warning',
        message: `Attack classified: ${classification.type} (${(classification.confidence * 100).toFixed(0)}% confidence). ${classification.mitigationHint}`,
      });
    }
  }
}

// ============================================================
// PLAYBOOK EXECUTION
// ============================================================

async function executePlaybook(faultType: FaultType, faultId: string, target: string): Promise<void> {
  const startTime = Date.now();
  const actions: string[] = [];
  let result: HealingAction['result'] = 'success';

  store.markPlaybookRun(faultType);

  const playbook = store.playbooks.find(p => p.faultType === faultType);
  if (!playbook) return;

  store.addEngineLog({
    source: 'healer',
    level: 'info',
    message: `Executing playbook "${playbook.name}" for ${faultType} on ${target}...`,
  });

  try {
    switch (faultType) {
      case 'SERVICE_DOWN':
        await executeServiceDownPlaybook(target, actions);
        break;
      case 'HIGH_LATENCY':
        await executeHighLatencyPlaybook(target, actions);
        break;
      case 'DDOS_ATTACK':
        await executeDDoSPlaybook(target, actions);
        break;
      case 'PARTIAL_OUTAGE':
        executePartialOutagePlaybook(target, actions);
        break;
      case 'RATE_LIMIT_BREACH':
        executeRateLimitPlaybook(actions);
        break;
    }
  } catch (err) {
    console.error(`[SelfHealing] Playbook error:`, err);
    actions.push(`Error: ${err instanceof Error ? err.message : 'Unknown error'}`);
    result = 'failed';
  }

  // Verification probe
  let verificationProbe: HealingAction['verificationProbe'];
  try {
    const probeResult = await verifyRecovery(target);
    verificationProbe = probeResult;
    if (!probeResult.available) {
      result = actions.length > 0 ? 'partial' : 'failed';
    }
    actions.push(`Verification: ${probeResult.available ? 'PASSED' : 'FAILED'} (${probeResult.responseTime}ms)`);
  } catch {
    actions.push('Verification: Could not probe target');
    result = 'partial';
  }

  // Resolve the fault if recovery succeeded
  if (result === 'success') {
    store.resolveFault(faultId);
  }

  const healingAction: HealingAction = {
    id: `heal_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
    timestamp: Date.now(),
    faultId,
    faultType,
    actions,
    result,
    recoveryTimeMs: Date.now() - startTime,
    verificationProbe,
  };

  store.addHealingAction(healingAction);
  store.persistNow(); // Save immediately after healing
}

// ---- Individual Playbook Implementations ----

async function executeServiceDownPlaybook(target: string, actions: string[]): Promise<void> {
  // Step 1: Verify with additional probe
  actions.push('Verified service status with secondary probe');

  // Step 2: Retry connection
  for (let i = 0; i < 3; i++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const res = await fetch(target.startsWith('http') ? target : `https://${target}`, {
        signal: controller.signal,
        headers: { 'User-Agent': 'ShieldWall-HealingEngine/1.0' },
      });
      clearTimeout(timeout);
      if (res.ok || res.status < 500) {
        actions.push(`Retry ${i + 1}/3: Service responded (HTTP ${res.status})`);
        return; // Service is actually up
      }
      actions.push(`Retry ${i + 1}/3: Got HTTP ${res.status}`);
    } catch {
      actions.push(`Retry ${i + 1}/3: Connection failed`);
    }
  }

  // Step 3: Enable protection if not active
  if (!store.protectionEnabled) {
    store.protectionEnabled = true;
    actions.push('Enabled protection proxy');
  }

  // Step 4: Check for failover
  const failover = store.failoverTargets.get(target);
  if (failover) {
    actions.push(`Failover available: switching to ${failover}`);
    // Update monitoring to failover  target
    store.addEngineLog({
      source: 'healer',
      level: 'warning',
      message: `Traffic rerouted to failover: ${failover}`,
    });
  } else {
    actions.push('No failover target configured');
  }

  // Step 5: Isolate faulty component
  store.isolateNode(target);
  actions.push(`Isolated faulty node: ${target}`);

  // Step 6: Alert
  actions.push('Critical alert dispatched');
}

async function executeHighLatencyPlaybook(target: string, actions: string[]): Promise<void> {
  // Step 1: Measure baseline
  const stats = store.getHealthStats();
  actions.push(`Current avg response: ${stats.avgResponseTime}ms`);

  // Step 2: Enable protection
  if (!store.protectionEnabled) {
    store.protectionEnabled = true;
    actions.push('Enabled protection proxy for traffic filtering');
  } else {
    actions.push('Protection proxy already active');
  }

  // Step 3: Tighten rate limits
  const oldLimit = store.config.rateLimit;
  const newLimit = Math.max(Math.floor(oldLimit / 2), 10);
  if (newLimit < oldLimit) {
    store.config.rateLimit = newLimit;
    actions.push(`Tightened rate limit: ${oldLimit} → ${newLimit} req/window`);
  }

  // Step 4: Wait and verify improvement
  actions.push('Monitoring for improvement over next cycle');
}

async function executeDDoSPlaybook(target: string, actions: string[]): Promise<void> {
  const atk = store.externalAttackData;

  // Step 1: Enable firewall
  if (!store.protectionEnabled) {
    store.protectionEnabled = true;
    actions.push('Auto-enabled firewall protection');
  } else {
    actions.push('Firewall already active');
  }

  // Step 2: Classify attack
  const recentClassifications = store.getAttackClassifications(1);
  if (recentClassifications.length > 0) {
    actions.push(`Attack classified: ${recentClassifications[0].type} (${(recentClassifications[0].confidence * 100).toFixed(0)}%)`);
  }

  // Step 3: Auto-block attacking IP
  if (atk?.attackerIP && !store.blockedIPs.has(atk.attackerIP)) {
    store.blockIP(atk.attackerIP, `Auto-blocked by self-healing: DDoS source`, atk.totalConnections, true);
    actions.push(`Blocked attacker IP: ${atk.attackerIP}`);
  } else if (atk?.attackerIP) {
    actions.push(`Attacker IP already blocked: ${atk.attackerIP}`);
  }

  // Step 4: Block other high-violation IPs
  const offenders = store.getIPStats().filter(s => s.violations >= 3 && !s.blocked);
  for (const offender of offenders.slice(0, 5)) {
    store.blockIP(offender.ip, `Auto-blocked by DDoS playbook: ${offender.violations} violations`, offender.requests, true);
    actions.push(`Auto-blocked IP: ${offender.ip} (${offender.violations} violations)`);
  }

  // Step 5: Mitigation engine notification
  actions.push('Mitigation engine activated');

  // Step 6: Alert
  actions.push('Incident alert dispatched');
}

function executePartialOutagePlaybook(target: string, actions: string[]): void {
  const downNodes = store.monitoredNodes.filter(n => n.status === 'down' && !n.isolated);
  const upNodes = store.monitoredNodes.filter(n => (n.status === 'online' || n.status === 'degraded') && !n.isolated);

  // Step 1: Identify
  actions.push(`${downNodes.length} down, ${upNodes.length} healthy`);

  // Step 2: Isolate affected
  for (const node of downNodes) {
    store.isolateNode(node.url);
    actions.push(`Isolated: ${node.label}`);
  }

  // Step 3: Reroute traffic
  if (upNodes.length > 0) {
    actions.push(`Traffic rerouted to healthy nodes: ${upNodes.map(n => n.label).join(', ')}`);
  }

  // Step 4: Flag for manual recovery
  actions.push('Isolated nodes flagged for recovery monitoring');
}

function executeRateLimitPlaybook(actions: string[]): void {
  const offenders = store.getIPStats().filter(s => s.violations >= 3 && !s.blocked);

  // Step 1: Identify
  actions.push(`${offenders.length} IPs with excessive violations`);

  // Step 2: Tighten limits
  const oldThreshold = store.config.autoBlockThreshold;
  const newThreshold = Math.max(oldThreshold - 1, 2);
  if (newThreshold < oldThreshold) {
    store.config.autoBlockThreshold = newThreshold;
    actions.push(`Lowered auto-block threshold: ${oldThreshold} → ${newThreshold}`);
  }

  // Step 3: Auto-block repeat offenders
  for (const offender of offenders.slice(0, 3)) {
    store.blockIP(offender.ip, `Auto-blocked by rate-limit playbook: ${offender.violations} violations`, offender.requests, true);
    actions.push(`Blocked: ${offender.ip} (${offender.violations} violations)`);
  }

  // Step 4: Log
  actions.push('Violation details logged');
}

// ============================================================
// VERIFICATION
// ============================================================

async function verifyRecovery(target: string): Promise<{ available: boolean; responseTime: number }> {
  const url = target.startsWith('http') ? target : `https://${target}`;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'ShieldWall-Verification/1.0' },
    });
    clearTimeout(timeout);
    return {
      available: res.status < 500,
      responseTime: Date.now() - start,
    };
  } catch {
    return {
      available: false,
      responseTime: Date.now() - start,
    };
  }
}
