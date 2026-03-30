/**
 * Monitor API — Start/stop monitoring a website URL, get health data
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';
import { startMonitoring, stopMonitoring } from '@/lib/websiteMonitor';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

export async function GET() {
  return NextResponse.json(
    {
      targetUrl: store.targetUrl,
      monitoring: store.monitoring,
      healthStats: store.getHealthStats(),
      healthProbes: store.getRecentProbes(120),
    },
    {
      headers: {
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        Pragma: 'no-cache',
        Expires: '0',
      },
    }
  );
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { action, url } = body;

    switch (action) {
      case 'start': {
        if (!url) return NextResponse.json({ error: 'URL is required' }, { status: 400 });
        await startMonitoring(url);
        return NextResponse.json({ success: true, monitoring: true, targetUrl: store.targetUrl });
      }
      case 'stop': {
        stopMonitoring();
        return NextResponse.json({ success: true, monitoring: false });
      }
      default:
        return NextResponse.json({ error: 'Unknown action. Use "start" or "stop".' }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: 'Invalid request body' }, { status: 400 });
  }
}
