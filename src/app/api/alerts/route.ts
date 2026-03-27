/**
 * Alerts API — Get alert history, configure email alerts
 */

import { NextRequest, NextResponse } from 'next/server';
import { store } from '@/lib/store';

export async function GET() {
  return NextResponse.json({
    alerts: store.getAlerts(50),
    emailConfig: {
      enabled: store.config.alertEmailEnabled,
      email: store.config.alertEmail,
      threshold: store.config.alertTrafficThreshold,
    },
  });
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { alertEmail, alertEmailEnabled, alertTrafficThreshold, smtpHost, smtpPort, smtpUser, smtpPass } = body;

    if (alertEmail !== undefined) store.config.alertEmail = alertEmail;
    if (alertEmailEnabled !== undefined) store.config.alertEmailEnabled = alertEmailEnabled;
    if (alertTrafficThreshold !== undefined) store.config.alertTrafficThreshold = alertTrafficThreshold;
    if (smtpHost !== undefined) store.config.smtpHost = smtpHost;
    if (smtpPort !== undefined) store.config.smtpPort = smtpPort;
    if (smtpUser !== undefined) store.config.smtpUser = smtpUser;
    if (smtpPass !== undefined) store.config.smtpPass = smtpPass;

    return NextResponse.json({ success: true, config: store.config });
  } catch {
    return NextResponse.json({ error: 'Invalid body' }, { status: 400 });
  }
}
