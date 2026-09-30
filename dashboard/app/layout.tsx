import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import Navbar from '@/components/Navbar';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'JOCKY // Forensic Central Dashboard',
  description:
    'In-memory digital forensics and incident response central management interface.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} dark h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[#08090d] text-zinc-100 cyber-grid selection:bg-[#00ff66]/20 selection:text-[#00ff66]">
        {/* Fixed / Sticky Navigation Header */}
        <Navbar />

        {/* Main Content Area */}
        <main className="flex-1">{children}</main>

        {/* Forensic Footer */}
        <footer className="border-t border-[#18202e] bg-[#07080b] py-6 font-mono text-xs text-zinc-500">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 sm:flex-row sm:px-6 lg:px-8">
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-[#00ff66]"></span>
              <span className="text-zinc-400 font-semibold">JOCKY v0.1-FORENSIC</span>
              <span>//</span>
              <span>SIH26148 NTRO In-Memory Analysis</span>
            </div>
            <div className="flex items-center gap-4 text-zinc-400 text-[11px]">
              <span>JYCRYPT1 Protected</span>
              <span>•</span>
              <span>Polymorphic Bytecode</span>
              <span>•</span>
              <span className="text-[#00ff66]">Zero-Disk RAM Execution</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
