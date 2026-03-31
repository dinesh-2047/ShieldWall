/**
 * Firewall API — Manage blocked IPs, update config, get state
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';
import { startPythonMitigation, stopPythonMitigation } from '@/lib/pythonEngineBridge';
import { hydrateStoreFromDurableState, persistStoreToDurableState } from '@/lib/durableState';

export async function GET() {
  await hydrateStoreFromDurableState();

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
    await hydrateStoreFromDurableState();

    const body = await request.json();
    const { action } = body;

    switch (action) {

      case 'updateConfig': {
        const { config } = body;
        if (config) Object.assign(store.config, config);
        await persistStoreToDurableState();
        return NextResponse.json({ success: true, config: store.config });
      }
      case 'toggleProtection': {
        const newState = body.enabled !== undefined ? body.enabled : !store.protectionEnabled;
        const requestedTarget = typeof body.targetUrl === 'string' ? body.targetUrl.trim() : '';

        store.protectionEnabled = newState;
        store.protectionLockedOn = newState;

        const engineResult = newState
          ? await startPythonMitigation(requestedTarget || store.targetUrl || 'localhost')
          : await stopPythonMitigation();

        store.addEngineLog({
          source: engineResult.mode === 'python' ? 'python' : 'fallback',
          level: newState
            ? (engineResult.connected ? 'info' : 'warning')
            : 'info',
          message: engineResult.message,
          simulated: !!engineResult.simulated,
        });

        store.addEngineLog({
          source: 'proxy',
          level: newState ? 'info' : 'warning',
          message: newState
            ? 'Reverse proxy mitigation is active in Next.js runtime.'
            : 'Reverse proxy mitigation is now disabled.',
          simulated: false,
        });

        store.addAlert({
          type: newState ? 'attack_stopped' : 'attack_detected',
          message: newState
            ? '🛡️ Protection ENABLED — ShieldWall firewall is now active. Attacks will be blocked.'
            : '⚠️ Protection DISABLED — ShieldWall firewall is now off.',
          severity: newState ? 'info' : 'warning',
        });

        await persistStoreToDurableState();

        return NextResponse.json({
          success: true,
          protectionEnabled: store.protectionEnabled,
          engine: engineResult,
        });
      }
      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
