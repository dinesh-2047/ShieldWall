/**
 * Website Health Monitor
 * Pings a target URL every second, measures response time, status, availability.
 * Detects when a site is under attack (slow responses, timeouts, errors).
 */

import { store } from './store';
import { checkAndSendAlerts } from './alertService';

let monitorInterval: ReturnType<typeof setInterval> | null = null;
let probeInFlight = false;

async function runProbe(url: string) {
  if (probeInFlight || !store.monitoring) return;
  probeInFlight = true;
  try {
    await probeWebsite(url);
  } finally {
    probeInFlight = false;
  }
}

export async function startMonitoring(url: string) {
  stopMonitoring();

  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    // Prefer HTTPS when protocol is not provided.
    url = 'https://' + url;
  }

  store.targetUrl = url;
  store.monitoring = true;
  store.healthProbes = [];

  console.log(`[Monitor] Starting health monitoring for ${url}`);

  // Probe every 1.5 seconds
  monitorInterval = setInterval(() => {
    void runProbe(url);
  }, 1500);

  // First probe immediately and wait for it so UI has an initial status quickly.
  await runProbe(url);
}

export function stopMonitoring() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
  probeInFlight = false;
  store.monitoring = false;
  console.log('[Monitor] Stopped monitoring.');
}

async function probeWebsite(url: string) {
  const start = Date.now();
  let timeout: ReturnType<typeof setTimeout> | null = null;

  try {
    const controller = new AbortController();
    timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'ShieldWall-Monitor/1.0',
        'Accept': 'text/html',
      },
      redirect: 'follow',
    });

    const responseTime = Date.now() - start;

    store.addHealthProbe({
      timestamp: Date.now(),
      responseTime,
      statusCode: response.status,
      available: response.status < 500,
    });

    // Run alert evaluation on each probe so downtime emails work without proxy mode.
    checkAndSendAlerts();
  } catch (err: unknown) {
    const responseTime = Date.now() - start;
    const errorMessage = err instanceof Error ? err.message : 'Unknown error';

    store.addHealthProbe({
      timestamp: Date.now(),
      responseTime,
      statusCode: 0,
      available: false,
      error: errorMessage.includes('abort') ? 'Timeout (8s)' : errorMessage,
    });

    // Evaluate alerts on failed probes as well.
    checkAndSendAlerts();
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

export function isMonitoring(): boolean {
  return store.monitoring;
}
