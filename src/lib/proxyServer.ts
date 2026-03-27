/**
 * Reverse Proxy Protection Server
 * 
 * This is the CORE protection engine. It creates an HTTP server that:
 * 1. Listens on a configurable port (e.g., 8080)
 * 2. Receives ALL incoming traffic meant for the target website
 * 3. Checks each request against rate limits and blocked IP list
 * 4. BLOCKS malicious requests (returns 403)
 * 5. FORWARDS clean requests to the real target website
 * 
 * How it stops attacks:
 * - Attackers must go through ShieldWall (point DNS/routing here)
 * - ShieldWall rate-limits each IP: if an IP sends too many requests, it gets blocked
 * - Blocked IPs get instant 403 responses without touching the real server
 * - The real website only receives filtered, clean traffic
 * 
 * This is exactly how Cloudflare, AWS Shield, etc. work.
 */

import http from 'http';
import https from 'https';
import { store } from './store';
import { checkAndSendAlerts } from './alertService';

let proxyServer: http.Server | null = null;
let statsInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start the reverse proxy protection server.
 * @param targetUrl - The real website URL to protect (e.g., "http://example.com")
 * @param listenPort - Port this proxy listens on (e.g., 8080)
 */
export function startProxyServer(targetUrl: string, listenPort: number = 8080): { success: boolean; error?: string } {
  if (proxyServer) {
    return { success: false, error: 'Proxy server already running. Stop it first.' };
  }

  // Parse target URL
  let targetHost: string;
  let targetPort: number;
  let targetProtocol: string;

  try {
    const url = new URL(targetUrl.startsWith('http') ? targetUrl : `http://${targetUrl}`);
    targetHost = url.hostname;
    targetPort = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);
    targetProtocol = url.protocol;
  } catch {
    return { success: false, error: `Invalid target URL: ${targetUrl}` };
  }

  try {
    proxyServer = http.createServer((req, res) => {
      // Get client IP
      const clientIP = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
        || req.socket.remoteAddress
        || '0.0.0.0';

      // Clean the IP (remove IPv6 prefix)
      const ip = clientIP.replace('::ffff:', '');

      const method = req.method || 'GET';
      const path = req.url || '/';

      // ==========================================
      // FIREWALL CHECK — This is where attacks get stopped
      // ==========================================
      const decision = store.recordProxyRequest(ip, method, path);

      if (decision === 'blocked') {
        // IP is on the blocklist — DROP the request
        res.writeHead(403, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body style="background:#1a1a2e;color:#ef4444;text-align:center;padding:50px;font-family:Arial">
            <h1>🛡️ 403 — Blocked by ShieldWall</h1>
            <p>Your IP (${ip}) has been blocked due to suspicious activity.</p>
            <p style="color:#888">If you believe this is an error, contact the site administrator.</p>
          </body></html>
        `);
        return;
      }

      if (decision === 'rate_limited') {
        // Rate limit exceeded — return 429
        res.writeHead(429, {
          'Content-Type': 'text/html',
          'Retry-After': '10',
        });
        res.end(`
          <html><body style="background:#1a1a2e;color:#f59e0b;text-align:center;padding:50px;font-family:Arial">
            <h1>🛡️ 429 — Rate Limited</h1>
            <p>Too many requests from your IP (${ip}). Please slow down.</p>
            <p style="color:#888">Try again in a few seconds.</p>
          </body></html>
        `);
        return;
      }

      // ==========================================
      // FORWARD — Request is clean, proxy it to the real server
      // ==========================================
      const proxyOptions: http.RequestOptions = {
        hostname: targetHost,
        port: targetPort,
        path: path,
        method: method,
        headers: {
          ...req.headers,
          host: targetHost,
          'x-forwarded-for': ip,
          'x-real-ip': ip,
          'x-forwarded-proto': 'http',
        },
        timeout: 10000,
      };

      const transport = targetProtocol === 'https:' ? https : http;

      const proxyReq = transport.request(proxyOptions, (proxyRes) => {
        // Add ShieldWall header to show it's protected
        const headers = { ...proxyRes.headers, 'x-protected-by': 'ShieldWall' };
        res.writeHead(proxyRes.statusCode || 200, headers);
        proxyRes.pipe(res, { end: true });
      });

      proxyReq.on('error', (err) => {
        console.error(`[Proxy] Error forwarding to ${targetHost}: ${err.message}`);
        res.writeHead(502, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body style="background:#1a1a2e;color:#ef4444;text-align:center;padding:50px;font-family:Arial">
            <h1>🛡️ 502 — Bad Gateway</h1>
            <p>ShieldWall could not reach the target server (${targetHost}:${targetPort}).</p>
            <p style="color:#888">${err.message}</p>
          </body></html>
        `);
      });

      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        res.writeHead(504, { 'Content-Type': 'text/html' });
        res.end(`
          <html><body style="background:#1a1a2e;color:#f59e0b;text-align:center;padding:50px;font-family:Arial">
            <h1>🛡️ 504 — Gateway Timeout</h1>
            <p>The target server (${targetHost}) took too long to respond.</p>
          </body></html>
        `);
      });

      // Forward request body
      req.pipe(proxyReq, { end: true });
    });

    proxyServer.listen(listenPort, '0.0.0.0', () => {
      console.log(`[Proxy] 🛡️ ShieldWall proxy running on port ${listenPort}`);
      console.log(`[Proxy] Proxying to ${targetProtocol}//${targetHost}:${targetPort}`);
      console.log(`[Proxy] All traffic through port ${listenPort} is now filtered`);
    });

    proxyServer.on('error', (err: NodeJS.ErrnoException) => {
      console.error(`[Proxy] Server error: ${err.message}`);
      if (err.code === 'EADDRINUSE') {
        store.addAlert({
          type: 'attack_detected',
          message: `❌ Port ${listenPort} is already in use. Choose another port.`,
          severity: 'critical',
        });
      }
    });

    store.protectionEnabled = true;
    store.proxyPort = listenPort;

    store.addAlert({
      type: 'attack_stopped',
      message: `🛡️ Protection ENABLED — Proxy running on port ${listenPort}, filtering traffic to ${targetHost}:${targetPort}`,
      severity: 'info',
    });

    // Periodic stats check for email alerts
    statsInterval = setInterval(() => {
      checkAndSendAlerts();
      // Broadcast proxy stats
      store.broadcastSSE('proxyStats', {
        forwarded: store.totalProxyForwarded,
        blocked: store.totalProxyBlocked,
        blockedIPs: store.getBlockedIPs().length,
      });
    }, 3000);

    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    return { success: false, error: msg };
  }
}

/**
 * Stop the reverse proxy server.
 */
export function stopProxyServer(): { success: boolean; error?: string } {
  if (!proxyServer) {
    return { success: false, error: 'No proxy server running.' };
  }

  try {
    proxyServer.close();
    proxyServer = null;
    store.protectionEnabled = false;

    if (statsInterval) {
      clearInterval(statsInterval);
      statsInterval = null;
    }

    store.addAlert({
      type: 'attack_detected',
      message: '⚠️ Protection DISABLED — Proxy server stopped. Website is no longer protected.',
      severity: 'warning',
    });

    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    return { success: false, error: msg };
  }
}

export function isProxyRunning(): boolean {
  return proxyServer !== null && store.protectionEnabled;
}
