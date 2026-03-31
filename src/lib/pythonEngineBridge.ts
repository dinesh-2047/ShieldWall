/**
 * Optional bridge to a Python mitigation/detection service.
 *
 * If PY_ENGINE_URL is not configured or unavailable, the dashboard
 * falls back to built-in JS logic so the app remains fully usable.
 */

export type EngineMode = 'python' | 'fallback';

export interface EngineBridgeResult {
  connected: boolean;
  mode: EngineMode;
  message: string;
  anomaly?: boolean;
  simulated?: boolean;
}

export interface DetectionTelemetry {
  totalVolleys: number;
  totalConnections: number;
  totalFailed: number;
  target?: string;
  port?: string;
}

const ENGINE_TIMEOUT_MS = 2000;

function getPythonEngineUrl(): string | null {
  const raw = process.env.PY_ENGINE_URL?.trim();
  if (!raw) return null;
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
}

function fallbackDetection(telemetry: DetectionTelemetry, reason: string): EngineBridgeResult {
  const connectionBase = Math.max(telemetry.totalConnections, 1);
  const failureRatio = telemetry.totalFailed / connectionBase;
  const anomaly = telemetry.totalVolleys > 800 || failureRatio > 0.35;

  const summary = anomaly
    ? `Fallback detector flagged suspicious traffic (volleys=${telemetry.totalVolleys}, failureRatio=${failureRatio.toFixed(2)}).`
    : `Fallback detector sees stable traffic (volleys=${telemetry.totalVolleys}, failureRatio=${failureRatio.toFixed(2)}).`;

  return {
    connected: false,
    mode: 'fallback',
    anomaly,
    simulated: true,
    message: `${summary} Reason: ${reason}`,
  };
}

async function fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ENGINE_TIMEOUT_MS);

  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(init?.headers || {}),
      },
      cache: 'no-store',
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function parseJsonSafe(response: Response): Promise<Record<string, unknown>> {
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export async function startPythonMitigation(target: string, port: number = 80): Promise<EngineBridgeResult> {
  const engineUrl = getPythonEngineUrl();
  if (!engineUrl) {
    return {
      connected: false,
      mode: 'fallback',
      simulated: true,
      message: 'Python engine URL is not configured. Using built-in Next.js mitigation only.',
    };
  }

  try {
    const response = await fetchWithTimeout(`${engineUrl}/mitigation/start`, {
      method: 'POST',
      body: JSON.stringify({ target, port }),
    });

    const body = await parseJsonSafe(response);
    if (!response.ok) {
      const errorMessage = typeof body.error === 'string' ? body.error : 'Python mitigation start returned non-200 status.';
      throw new Error(errorMessage);
    }

    return {
      connected: true,
      mode: 'python',
      simulated: false,
      message: typeof body.message === 'string'
        ? body.message
        : `Python mitigation started for ${target || 'target'}.`,
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown bridge error';
    return {
      connected: false,
      mode: 'fallback',
      simulated: true,
      message: `Python mitigation unavailable (${message}). Using built-in Next.js mitigation.`,
    };
  }
}

export async function stopPythonMitigation(): Promise<EngineBridgeResult> {
  const engineUrl = getPythonEngineUrl();
  if (!engineUrl) {
    return {
      connected: false,
      mode: 'fallback',
      simulated: true,
      message: 'Python engine URL is not configured. Built-in mitigation disabled only.',
    };
  }

  try {
    const response = await fetchWithTimeout(`${engineUrl}/mitigation/stop`, {
      method: 'POST',
      body: JSON.stringify({}),
    });

    const body = await parseJsonSafe(response);
    if (!response.ok) {
      const errorMessage = typeof body.error === 'string' ? body.error : 'Python mitigation stop returned non-200 status.';
      throw new Error(errorMessage);
    }

    return {
      connected: true,
      mode: 'python',
      simulated: false,
      message: typeof body.message === 'string'
        ? body.message
        : 'Python mitigation stopped.',
    };
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Unknown bridge error';
    return {
      connected: false,
      mode: 'fallback',
      simulated: true,
      message: `Could not notify Python engine to stop (${message}). Continuing with dashboard shutdown flow.`,
    };
  }
}

export async function analyzeAttackTelemetry(telemetry: DetectionTelemetry): Promise<EngineBridgeResult> {
  const engineUrl = getPythonEngineUrl();
  const packetCount = Math.max(telemetry.totalVolleys, telemetry.totalConnections, 0);

  if (!engineUrl) {
    return fallbackDetection(telemetry, 'PY_ENGINE_URL not set');
  }

  try {
    const response = await fetchWithTimeout(`${engineUrl}/detect`, {
      method: 'POST',
      body: JSON.stringify({
        packetCount,
        totalVolleys: telemetry.totalVolleys,
        totalConnections: telemetry.totalConnections,
        totalFailed: telemetry.totalFailed,
        target: telemetry.target,
        port: telemetry.port,
      }),
    });

    const body = await parseJsonSafe(response);
    if (!response.ok) {
      const errorMessage = typeof body.error === 'string' ? body.error : 'Python detector returned non-200 status.';
      throw new Error(errorMessage);
    }

    const anomaly = !!body.anomaly;
    const message = typeof body.message === 'string'
      ? body.message
      : (anomaly ? `Python detector flagged anomaly for packetCount=${packetCount}.` : `Python detector reports normal traffic for packetCount=${packetCount}.`);

    return {
      connected: true,
      mode: 'python',
      anomaly,
      simulated: !!body.simulated,
      message,
    };
  } catch (err: unknown) {
    const reason = err instanceof Error ? err.message : 'Unknown detector bridge error';
    return fallbackDetection(telemetry, reason);
  }
}
