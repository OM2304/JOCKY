import React from 'react';
import Link from 'next/link';
import { ShieldAlert, ArrowLeft, Terminal } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-24 text-center sm:px-6">
      <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-2xl border border-red-500/30 bg-red-500/10 text-red-400 shadow-[0_0_25px_rgba(239,68,68,0.2)]">
        <ShieldAlert className="h-10 w-10" />
      </div>

      <h1 className="mt-6 font-mono text-3xl font-bold tracking-tight text-white">
        404: Report Not Found
      </h1>

      <p className="mt-3 font-mono text-sm text-zinc-400 max-w-md mx-auto leading-relaxed">
        The requested forensic report ID was not found in the controller storage (
        <code className="text-[#00ff66]">../agents/var/reports</code>). It may have been purged or not yet ingested.
      </p>

      <div className="mt-8 flex justify-center">
        <Link
          href="/"
          className="flex items-center gap-2 rounded-xl border border-[#00ff66]/40 bg-[#00ff66]/10 px-5 py-2.5 font-mono text-xs font-semibold text-[#00ff66] hover:bg-[#00ff66]/20 transition-all shadow-[0_0_15px_rgba(0,255,102,0.15)]"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>RETURN TO DASHBOARD</span>
        </Link>
      </div>
    </div>
  );
}
