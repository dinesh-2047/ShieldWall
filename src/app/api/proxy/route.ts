/**
 * Proxy API — Start/stop the reverse proxy protection server
 */

import { NextRequest, NextResponse } from 'next/server';
import { startProxyServer, stopProxyServer, isProxyRunning } from '@/lib/proxyServer';
import { store } from '@/lib/store';

export async function GET() {
  return NextResponse.json({
    running: isProxyRunning(),
    port: store.proxyPort,
    targetUrl: store.targetUrl,
    protectionEnabled: store.protectionEnabled,
    totalForwarded: store.totalProxyForwarded,
    totalBlocked: store.totalProxyBlocked,
    blockedIPs: store.getBlockedIPs().length,
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, targetUrl, port } = body;

    switch (action) {
      case 'start': {
        if (!targetUrl) {
          return NextResponse.json({ error: 'targetUrl is required (e.g., http://example.com)' }, { status: 400 });
        }
        const listenPort = port || 80;
        const result = startProxyServer(targetUrl, listenPort);
        return NextResponse.json({ ...result, port: listenPort, running: isProxyRunning() });
      }
      case 'stop': {
        const result = stopProxyServer();
        return NextResponse.json({ ...result, running: isProxyRunning() });
      }
      default:
        return NextResponse.json({ error: 'Unknown action. Use "start" or "stop".' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
