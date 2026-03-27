/**
 * Email Alert Service using Nodemailer
 */

import nodemailer from 'nodemailer';
import { store } from './store';

let lastEmailTime = 0;
const EMAIL_COOLDOWN = 60000; // 1 minute between emails

export async function sendAlertEmail(subject: string, htmlContent: string): Promise<boolean> {
  const config = store.config;

  if (!config.alertEmailEnabled || !config.alertEmail) {
    return false;
  }

  // Throttle emails
  if (Date.now() - lastEmailTime < EMAIL_COOLDOWN) {
    return false;
  }

  try {
    const transporter = nodemailer.createTransport({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpPort === 465,
      auth: { user: config.smtpUser, pass: config.smtpPass },
    });

    await transporter.sendMail({
      from: `"ShieldWall Firewall" <${config.smtpUser}>`,
      to: config.alertEmail,
      subject: `🛡️ ShieldWall: ${subject}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0a1a;color:#eee;padding:24px;border-radius:12px;">
          <h2 style="color:#00d4ff;border-bottom:1px solid #333;padding-bottom:10px;">🛡️ ShieldWall Alert</h2>
          <h3 style="color:#ff6b6b;">${subject}</h3>
          ${htmlContent}
          <p style="font-size:11px;color:#666;margin-top:20px;">Sent at ${new Date().toISOString()}</p>
        </div>
      `,
    });

    lastEmailTime = Date.now();
    store.addAlert({ type: 'email_alert', message: `📧 Email sent: ${subject}`, severity: 'info' });
    return true;
  } catch (err) {
    console.error('[AlertService] Email failed:', err);
    return false;
  }
}

/**
  * Check alerts and send emails if needed. Called periodically.
  */
export function checkAndSendAlerts() {
  if (!store.config.alertEmailEnabled || !store.config.alertEmail) return;
  
  const stats = store.getHealthStats();
  
  if (stats.currentStatus === 'down') {
    sendAlertEmail(
      `${store.targetUrl} is DOWN!`,
      `<p style="color:#ef4444;font-size:18px;">Your monitored website is not responding.</p>
       <p>Response time: ${stats.avgResponseTime}ms</p>
       <p>Availability: ${stats.availability}%</p>`
    );
  } else if (stats.avgResponseTime > 3000) {
    sendAlertEmail(
      `High Latency on ${store.targetUrl}`,
      `<p style="color:#f59e0b;">Average response time: <strong>${stats.avgResponseTime}ms</strong></p>
       <p>This could indicate a DDoS attack in progress.</p>`
    );
  }
}
