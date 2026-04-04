/**
 * Analytics API
 *
 * Returns aggregated analytics data for the dashboard:
 *   - Attack type distribution
 *   - Healing success rates
 *   - Attack timeline
 *   - Fault distribution
 *   - Node uptime
 */

import { NextResponse } from 'next/server';
import { store } from '@/lib/store';

export const dynamic = 'force-dynamic';

export async function GET() {
  const analytics = store.getAnalytics();

  return NextResponse.json(analytics, {
    headers: {
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache',
    },
  });
}
