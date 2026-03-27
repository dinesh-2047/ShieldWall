import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ShieldWall - DDoS Prevention Firewall",
  description: "Real-time DDoS attack prevention and traffic monitoring dashboard. Monitor, detect, and block malicious traffic with intelligent rate limiting and email alerts.",
  keywords: ["ddos", "firewall", "security", "traffic monitoring", "rate limiting"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
      </head>
      <body style={{ position: 'relative', zIndex: 1 }}>
        {children}
      </body>
    </html>
  );
}
