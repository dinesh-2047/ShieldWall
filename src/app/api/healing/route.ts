/**
 * Self-Healing Control API
 *
 * Endpoints:
 *   GET  /api/healing — Get healing state, history, stats
 *   POST /api/healing — Toggle self-healing, view history
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';
import { startSelfHealing, stopSelfHealing, isSelfHealingRunning } from '@/lib/selfHealingEngine';

export const dynamic = 'force-dynamic';

export async function GET() {
  return NextResponse.json({
    selfHealingEnabled: store.selfHealingEnabled,
    running: isSelfHealingRunning(),
    healingStats: store.getHealingStats(),
    healingActions: store.getHealingHistory(50),
    faultEvents: store.getFaultHistory(50),
    unresolvedFaults: store.getUnresolvedFaults(),
    attackClassifications: store.getAttackClassifications(30),
    monitoredNodes: store.monitoredNodes,
    isolatedNodes: Array.from(store.isolatedNodes),
    failoverTargets: Object.fromEntries(store.failoverTargets),
    playbooks: store.playbooks.map(p => ({
      faultType: p.faultType,
      name: p.name,
      steps: p.steps,
      cooldownMs: p.cooldownMs,
    })),
  }, {
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache',
    },
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action } = body;

    switch (action) {
      case 'toggle': {
        const enabled = !!body.enabled;
        store.selfHealingEnabled = enabled;

        if (enabled) {
          startSelfHealing();
        } else {
          stopSelfHealing();
        }

        store.persistNow();
        return NextResponse.json({
          success: true,
          selfHealingEnabled: store.selfHealingEnabled,
          running: isSelfHealingRunning(),
        });
      }

      case 'isolateNode': {
        const { nodeUrl } = body;
        if (!nodeUrl) return NextResponse.json({ error: 'nodeUrl required' }, { status: 400 });
        store.isolateNode(nodeUrl);
        store.persistNow();
        return NextResponse.json({ success: true, isolated: true });
      }

      case 'restoreNode': {
        const { nodeUrl } = body;
        if (!nodeUrl) return NextResponse.json({ error: 'nodeUrl required' }, { status: 400 });
        store.restoreNode(nodeUrl);
        store.persistNow();
        return NextResponse.json({ success: true, isolated: false });
      }

      case 'setFailover': {
        const { primaryUrl, failoverUrl } = body;
        if (!primaryUrl) return NextResponse.json({ error: 'primaryUrl required' }, { status: 400 });
        if (failoverUrl) {
          store.failoverTargets.set(primaryUrl, failoverUrl);
        } else {
          store.failoverTargets.delete(primaryUrl);
        }
        store.persistNow();
        return NextResponse.json({ success: true, failoverTargets: Object.fromEntries(store.failoverTargets) });
      }

      case 'addNode': {
        const { url, label, failoverUrl } = body;
        if (!url) return NextResponse.json({ error: 'url required' }, { status: 400 });
        const node = store.addMonitoredNode(url, label, failoverUrl);
        store.persistNow();
        return NextResponse.json({ success: true, node });
      }

      case 'removeNode': {
        const { nodeId } = body;
        if (!nodeId) return NextResponse.json({ error: 'nodeId required' }, { status: 400 });
        const removed = store.removeMonitoredNode(nodeId);
        store.persistNow();
        return NextResponse.json({ success: true, removed });
      }

      case 'clearHistory': {
        store.healingActions.length = 0;
        store.faultEvents.length = 0;
        store.attackClassifications.length = 0;
        store.persistNow();
        return NextResponse.json({ success: true });
      }

      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
