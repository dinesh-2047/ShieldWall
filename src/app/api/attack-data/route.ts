/**
 * Attack Data API — Receives live attack stats from dos.cpp (Google Cloud Shell)
 * dos.cpp POSTs stats here every 3 seconds so the dashboard can show live attack data.
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';

export async function GET() {
  return NextResponse.json({
    attackData: store.externalAttackData,
    protectionEnabled: store.protectionEnabled,
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action } = body;

    if (action === 'report') {
      // dos.cpp sends attack stats
      const { target, port, totalVolleys, totalConnections, totalFailed, attackerIP, status } = body;

      store.externalAttackData = {
        active: status === 'running',
        target: target || '',
        port: port || '',
        totalVolleys: totalVolleys || 0,
        totalConnections: totalConnections || 0,
        totalFailed: totalFailed || 0,
        attackerIP: attackerIP || 'Unknown',
        lastUpdate: Date.now(),
      };

      // If protection is enabled, count this as a blocked attack
      if (store.protectionEnabled) {
        store.totalProxyBlocked = store.externalAttackData.totalVolleys;
        store.totalProxyForwarded = 0; // All traffic blocked when protected
      } else {
        store.totalProxyForwarded = store.externalAttackData.totalVolleys;
        store.totalProxyBlocked = 0;
      }

      // Broadcast to SSE clients
      store.broadcastSSE('attackData', store.externalAttackData);

      return NextResponse.json({
        received: true,
        protectionEnabled: store.protectionEnabled,
        shouldStop: store.protectionEnabled, // tell dos.cpp to stop if firewall is on
      });
    }

    if (action === 'stopped') {
      // dos.cpp reports attack has stopped
      if (store.externalAttackData) {
        store.externalAttackData.active = false;
      }
      store.addAlert({
        type: 'attack_stopped',
        message: `✅ External attack has stopped`,
        severity: 'info',
      });
      return NextResponse.json({ received: true });
    }

    return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
