/**
 * Firewall API — Manage blocked IPs, update config, get state
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';

export async function GET() {
  return NextResponse.json({
    config: store.config,
    blockedIPs: store.getBlockedIPs(),
    protectionEnabled: store.protectionEnabled,
    totalForwarded: store.totalProxyForwarded,
    totalBlocked: store.totalProxyBlocked,
    ipStats: store.getIPStats(),
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action } = body;

    switch (action) {
      case 'blockIP': {
        const { targetIP, reason } = body;
        if (!targetIP) return NextResponse.json({ error: 'targetIP required' }, { status: 400 });
        store.blockIP(targetIP, reason || 'Manually blocked', 0, false);
        return NextResponse.json({ success: true, blockedIPs: store.getBlockedIPs() });
      }
      case 'unblockIP': {
        const { targetIP } = body;
        if (!targetIP) return NextResponse.json({ error: 'targetIP required' }, { status: 400 });
        store.unblockIP(targetIP);
        return NextResponse.json({ success: true, blockedIPs: store.getBlockedIPs() });
      }
      case 'updateConfig': {
        const { config } = body;
        if (config) Object.assign(store.config, config);
        return NextResponse.json({ success: true, config: store.config });
      }
      case 'toggleProtection': {
        const newState = body.enabled !== undefined ? body.enabled : !store.protectionEnabled;
        store.protectionEnabled = newState;
        store.protectionLockedOn = newState;
        store.addAlert({
          type: newState ? 'attack_stopped' : 'attack_detected',
          message: newState
            ? '🛡️ Protection ENABLED — ShieldWall firewall is now active. Attacks will be blocked.'
            : '⚠️ Protection DISABLED — ShieldWall firewall is now off.',
          severity: newState ? 'info' : 'warning',
        });
        return NextResponse.json({ success: true, protectionEnabled: store.protectionEnabled });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
