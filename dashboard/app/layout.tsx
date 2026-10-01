import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import Navbar from '@/components/Navbar';
import { ThemeProvider } from '@/components/ThemeProvider';
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
    'Enterprise in-memory digital forensics and incident response management dashboard.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground selection:bg-primary/20 selection:text-primary">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          {/* Top Navigation Header */}
          <Navbar />

          {/* Main Content Area */}
          <main className="flex-1">{children}</main>

          {/* Enterprise Footer */}
          <footer className="border-t border-border bg-card/50 py-6 text-xs text-muted-foreground">
            <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-4 sm:flex-row sm:px-6 lg:px-8">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-primary"></span>
                <span className="font-semibold text-foreground">JOCKY v0.1-FORENSIC</span>
                <span>•</span>
                <span>Central Management Controller</span>
              </div>
              <div className="flex items-center gap-4 text-[11px]">
                <span>JYCRYPT1 Protected</span>
                <span>•</span>
                <span>Polymorphic Bytecode</span>
                <span>•</span>
                <span className="text-primary font-medium">In-Memory Triage</span>
              </div>
            </div>
          </footer>
        </ThemeProvider>
      </body>
    </html>
  );
}
