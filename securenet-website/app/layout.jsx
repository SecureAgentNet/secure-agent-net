import { Inter } from 'next/font/google';
import Navbar from '../components/Navbar';
import Footer from '../components/Footer';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export const metadata = {
  title: 'SecureAgentNet — Zero-Trust AI Agent Security',
  description: 'Open-source security orchestration for autonomous AI agents. ITCD pipeline: Identify, Track, Decide, Contain.',
  icons: { icon: '/images/favicon.svg' },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        {/* Google Analytics */}
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
        <script dangerouslySetInnerHTML={{ __html: `
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());
          gtag('config', 'G-XXXXXXXXXX');
        `}}></script>
      </head>
      <body className={inter.className + ' bg-gray-900 text-gray-100 antialiased'}>
        <Navbar />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
