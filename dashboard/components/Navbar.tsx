'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Radio, Terminal, Cpu, Clock, RefreshCw } from 'lucide-react';

export default function Navbar() {
  const pathname = usePathname();
  const [timeStr, setTimeStr] = useState<string>('');

  useEffect(() => {
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

  return (
    <header className="sticky top-0 z-50 border-b border-[#1e2638] bg-[#08090d]/90 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand & Framework Title */}
        <div className="flex items-center gap-3">
          <Link href="/" className="group flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66] transition-all duration-300 group-hover:border-[#00ff66] group-hover:shadow-[0_0_15px_rgba(0,255,102,0.4)]">
              <Shield className="h-5 w-5" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <span className="font-mono text-lg font-bold tracking-wider text-white">
                  JOCKY
                </span>
                <span className="rounded bg-[#00ff66]/10 px-1.5 py-0.5 text-[10px] font-mono font-semibold tracking-wider text-[#00ff66] border border-[#00ff66]/30">
                  FORENSIC CORE
                </span>
              </div>
              <span className="text-[11px] text-zinc-400 font-mono tracking-tight">
                In-Memory RAM Inspection // Central Controller
              </span>
            </div>
          </Link>
        </div>

        {/* Live Controller Status & Navigation */}
        <div className="flex items-center gap-4 sm:gap-6">
          {/* Status Pulse */}
          <div className="hidden md:flex items-center gap-2 rounded-full border border-[#1e2638] bg-[#0d1117] px-3 py-1 text-xs">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#00ff66] opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[#00ff66]"></span>
            </span>
            <span className="font-mono text-zinc-300 text-[11px] tracking-wide">
              CONTROLLER: <span className="text-[#00ff66] font-semibold">ONLINE</span>
            </span>
          </div>

          {/* UTC Clock */}
          <div className="hidden lg:flex items-center gap-1.5 text-xs text-zinc-400 font-mono">
            <Clock className="h-3.5 w-3.5 text-zinc-500" />
            <span className="tabular-nums">{timeStr || 'INITIALIZING CLOCK...'}</span>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1">
            <Link
              href="/"
              className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-mono transition-colors ${
                pathname === '/'
                  ? 'border border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]'
                  : 'text-zinc-400 hover:bg-[#161b24] hover:text-zinc-200'
              }`}
            >
              <Terminal className="h-3.5 w-3.5" />
              <span>DASHBOARD</span>
            </Link>

            <button
              onClick={() => window.location.reload()}
              title="Refresh telemetry"
              className="flex h-8 w-8 items-center justify-center rounded-md border border-[#1e2638] bg-[#0d1117] text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
          </nav>
        </div>
      </div>
    </header>
  );
}
