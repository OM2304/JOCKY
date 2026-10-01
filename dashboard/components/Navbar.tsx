'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useTheme } from 'next-themes';
import {
  Shield,
  Clock,
  RefreshCw,
  Sun,
  Moon,
  Laptop,
  LayoutDashboard,
  ShieldAlert,
  Dna,
} from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
    setMounted(true);
    const updateTime = () => {
      const now = new Date();
      setTimeStr(
        now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const toggleTheme = () => {
    if (theme === 'system') {
      setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
    } else if (theme === 'dark') {
      setTheme('light');
    } else {
      setTheme('dark');
    }
  };

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md transition-colors">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand & Framework Title */}
        <div className="flex items-center gap-3">
          <Link href="/" className="group flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/20 bg-primary/10 text-primary transition-colors group-hover:bg-primary/20">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-foreground">
                  JOCKY
                </span>
                <span className="rounded-md bg-primary/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-primary border border-primary/20">
                  ENTERPRISE FORENSICS
                </span>
              </div>
              <span className="text-xs text-muted-foreground">
                In-Memory Sensor Central Controller
              </span>
            </div>
          </Link>
        </div>

        {/* Live Controller Status & Navigation */}
        <div className="flex items-center gap-3 sm:gap-5">
          {/* Status Badge */}
          <div className="hidden md:flex items-center gap-2 rounded-full border border-border bg-muted/50 px-3 py-1 text-xs">
            <span className="h-2 w-2 rounded-full bg-primary" />
            <span className="text-muted-foreground text-[11px] font-medium">
              Controller: <span className="text-foreground font-semibold">Active</span>
            </span>
          </div>

          {/* UTC Clock */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
            <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="tabular-nums">{timeStr || 'INITIALIZING...'}</span>
          </div>

          {/* Navigation Links - Segmented Control */}
          <nav className="flex items-center space-x-1 bg-secondary/40 p-1 rounded-lg border border-border/50">
            <Link
              href="/"
              className={`flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-all duration-200 ${
                pathname === '/'
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:bg-secondary/80 hover:text-foreground'
              }`}
            >
              <LayoutDashboard className="h-4 w-4" />
              <span>Dashboard</span>
            </Link>

            {/* Threat Scanners Nav Link */}
            <Link
              href="/scanners"
              className={`flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-all duration-200 ${
                pathname?.startsWith('/scanners')
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:bg-secondary/80 hover:text-foreground'
              }`}
            >
              <ShieldAlert className="h-4 w-4 text-amber-500" />
              <span>Scanners</span>
            </Link>

            {/* Polymorphism Showcase Nav Link */}
            <Link
              href="/poly"
              className={`flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md transition-all duration-200 ${
                pathname?.startsWith('/poly')
                  ? 'bg-background text-foreground shadow-sm'
                  : 'text-muted-foreground hover:bg-secondary/80 hover:text-foreground'
              }`}
            >
              <Dna className="h-4 w-4 text-purple-500" />
              <span>Polymorphism</span>
            </Link>
          </nav>

          {/* Quick Actions (Theme & Refresh) */}
          <div className="flex items-center gap-1.5">
            {/* Light / Dark Mode Toggle */}
            <button
              onClick={toggleTheme}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition-colors cursor-pointer"
              title={`Current theme: ${theme || 'system'}. Click to toggle.`}
              aria-label="Toggle theme"
            >
              {mounted ? (
                resolvedTheme === 'dark' ? (
                  <Sun className="h-4 w-4 text-amber-400" />
                ) : (
                  <Moon className="h-4 w-4 text-slate-700" />
                )
              ) : (
                <Laptop className="h-4 w-4" />
              )}
            </button>

            {/* Refresh telemetry */}
            <button
              onClick={() => window.location.reload()}
              title="Refresh telemetry"
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground transition-colors cursor-pointer"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
