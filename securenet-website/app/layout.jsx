import { Inter } from 'next/font/google';
import Nav from '@/components/Nav';
import Footer from '@/components/Footer';
import './globals.css';

const inter = Inter({ subsets: ['latin'] });

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.className} bg-white dark:bg-dark-bg text-gray-900 dark:text-dark-text`}>
        <Nav />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  );
}
