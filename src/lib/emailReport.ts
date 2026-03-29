import nodemailer from 'nodemailer';
import { jsPDF } from 'jspdf';
import { ExternalAttackData } from './store';

export async function sendAttackReportEmail(config: any, attackData: ExternalAttackData, blockedCount: number) {
  if (!config.alertEmail || !config.smtpHost || !config.smtpUser || !config.smtpPass) {
    console.log('Email or SMTP settings not fully configured. Skipping email alert.');
    return;
  }

  try {
    // 1. Generate PDF Report using jsPDF
    const doc = new jsPDF();
    
    // Header
    doc.setFontSize(22);
    doc.setTextColor(220, 38, 38); // Red color
    doc.text('ShieldWall - Attack Incident Report', 20, 30);
    
    // Summary Text
    doc.setFontSize(12);
    doc.setTextColor(50, 50, 50);
    doc.text(`An attack was detected and automatically blocked by ShieldWall.`, 20, 50);
    doc.text(`Date & Time: ${new Date().toLocaleString()}`, 20, 60);
    
    // Details
    doc.setFontSize(14);
    doc.setTextColor(0, 0, 0);
    doc.text('Attack Details:', 20, 80);
    
    doc.setFontSize(12);
    doc.text(`Target: ${attackData.target}:${attackData.port}`, 30, 95);
    doc.text(`Attacker IP: ${attackData.attackerIP}`, 30, 105);
    doc.text(`Total Volleys Sent: ${attackData.totalVolleys}`, 30, 115);
    doc.text(`Total Connections Attempted: ${attackData.totalConnections}`, 30, 125);
    doc.text(`Total Failed Connections: ${attackData.totalFailed}`, 30, 135);
    
    // Highlighted blocked stat
    doc.setFontSize(14);
    doc.setTextColor(16, 185, 129); // Green color
    doc.text(`Total Malicious Requests Blocked: ${blockedCount}`, 20, 155);
    
    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    doc.text('Generated automatically by ShieldWall Firewall System.', 20, 280);

    // Convert PDF to Buffer
    const pdfBuffer = Buffer.from(doc.output('arraybuffer'));

    // 2. Send via Nodemailer
    const transporter = nodemailer.createTransport({
      host: config.smtpHost,
      port: config.smtpPort,
      secure: config.smtpPort === 465, // usually true for 465, false for 587
      auth: {
        user: config.smtpUser,
        pass: config.smtpPass, // Can be an app password
      },
    });

    const info = await transporter.sendMail({
      from: `"ShieldWall Alerts" <${config.smtpUser}>`,
      to: config.alertEmail,
      subject: `🚨 ShieldWall Alert: DoS Attack Blocked on ${attackData.target}`,
      text: `ShieldWall has successfully blocked a DoS attack on ${attackData.target}.\n\nAttacker IP: ${attackData.attackerIP}\nRequests Blocked: ${blockedCount}\n\nPlease find the attached PDF incident report for more details.`,
      attachments: [
        {
          filename: `ShieldWall_Incident_${new Date().toISOString().replace(/:/g, '-')}.pdf`,
          content: pdfBuffer,
          contentType: 'application/pdf',
        },
      ],
    });

    console.log('Incident report email sent successfully:', info.messageId);

  } catch (err) {
    console.error('Failed to generate PDF or send email:', err);
  }
}
