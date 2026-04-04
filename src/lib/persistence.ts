/**
 * Data Persistence Layer
 * 
 * Periodically saves critical store state to a JSON file so that
 * healing history, fault events, alerts, blocked IPs, and config
 * survive server restarts.
 */

import fs from 'fs';
import path from 'path';

const DATA_DIR = path.join(process.cwd(), 'data');
const STATE_FILE = path.join(DATA_DIR, 'shieldwall_state.json');

export interface PersistedState {
  savedAt: number;
  config: Record<string, unknown>;
  blockedIPs: Array<{ ip: string; reason: string; blockedAt: number; requestCount: number; autoBlocked: boolean }>;
  alerts: Array<Record<string, unknown>>;
  healingActions: Array<Record<string, unknown>>;
  faultEvents: Array<Record<string, unknown>>;
  attackClassifications: Array<Record<string, unknown>>;
  selfHealingEnabled: boolean;
  monitoredNodes: Array<Record<string, unknown>>;
  failoverTargets: Record<string, string>;
  isolatedNodes: string[];
}

function ensureDataDir(): void {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch (err) {
    console.error('[Persistence] Could not create data directory:', err);
  }
}

/**
 * Save state to disk.
 */
export function saveState(state: PersistedState): boolean {
  try {
    ensureDataDir();
    const json = JSON.stringify(state, null, 2);
    fs.writeFileSync(STATE_FILE, json, 'utf-8');
    return true;
  } catch (err) {
    console.error('[Persistence] Save failed:', err);
    return false;
  }
}

/**
 * Load state from disk. Returns null if no saved state exists.
 */
export function loadState(): PersistedState | null {
  try {
    if (!fs.existsSync(STATE_FILE)) return null;
    const raw = fs.readFileSync(STATE_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as PersistedState;
    console.log(`[Persistence] Loaded state from ${STATE_FILE} (saved at ${new Date(parsed.savedAt).toISOString()})`);
    return parsed;
  } catch (err) {
    console.error('[Persistence] Load failed:', err);
    return null;
  }
}

/**
 * Delete saved state.
 */
export function clearState(): boolean {
  try {
    if (fs.existsSync(STATE_FILE)) {
      fs.unlinkSync(STATE_FILE);
    }
    return true;
  } catch (err) {
    console.error('[Persistence] Clear failed:', err);
    return false;
  }
}

let saveInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start auto-saving state every `intervalMs` milliseconds.
 * Accepts a function that returns the current state to save.
 */
export function startAutoSave(getState: () => PersistedState, intervalMs: number = 30000): void {
  stopAutoSave();
  // Save on start
  saveState(getState());
  saveInterval = setInterval(() => {
    saveState(getState());
  }, intervalMs);
  console.log(`[Persistence] Auto-save started (every ${intervalMs / 1000}s)`);
}

export function stopAutoSave(): void {
  if (saveInterval) {
    clearInterval(saveInterval);
    saveInterval = null;
  }
}
