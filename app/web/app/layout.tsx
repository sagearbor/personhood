import type { Metadata, Viewport } from 'next';
import { JetBrains_Mono, Plus_Jakarta_Sans } from 'next/font/google';
import { ServiceWorkerRegister } from '@/components/ServiceWorkerRegister';
import './globals.css';

const mono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--f-mono-var',
  weight: ['400', '500', '600'],
  display: 'swap',
});

// Body font: Plus Jakarta Sans is a humanist sans with subtle character —
// slightly geometric without feeling utilitarian. Picked over Inter/Geist
// to dodge the "generic AI-tech" aesthetic. (Mona Sans was the first
// choice but `next/font/google` in Next 14.2.x does not ship it yet.)
const sans = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--f-sans-var',
  weight: ['400', '500', '600', '700'],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Personhood — proof you are a person',
  description:
    'A pluggable proof-of-personhood credential. Verify once on your device and reuse anywhere — without proving who you are.',
  applicationName: 'Personhood',
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'Personhood',
  },
  formatDetection: {
    telephone: false,
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
  themeColor: '#08090c',
  viewportFit: 'cover',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${mono.variable} ${sans.variable}`}>
      <head>
        <link rel="manifest" href="/manifest.webmanifest" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
        <meta name="apple-mobile-web-app-title" content="Personhood" />
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="theme-color" content="#08090c" />
      </head>
      <body>
        {children}
        <ServiceWorkerRegister />
      </body>
    </html>
  );
}
