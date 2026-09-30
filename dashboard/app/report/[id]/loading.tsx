import React from 'react';
import { Terminal } from 'lucide-react';

export default function ReportLoading() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6 animate-pulse">
      {/* Breadcrumb Skeleton */}
      <div className="h-4 w-48 bg-[#18202e] rounded" />

      {/* Header Skeleton */}
      <div className="border-b border-[#1e2638] pb-6">
        <div className="h-4 w-40 bg-[#18202e] rounded mb-2" />
        <div className="h-8 w-64 bg-[#1f293d] rounded mb-3" />
        <div className="h-4 w-80 bg-[#18202e] rounded" />
      </div>

      {/* Metadata Card Skeleton */}
      <div className="rounded-2xl border border-[#1e2638] bg-[#0c0e14] p-6 space-y-4">
        <div className="h-6 w-52 bg-[#18202e] rounded" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="h-20 bg-[#121622] rounded-xl" />
          <div className="h-20 bg-[#121622] rounded-xl" />
          <div className="h-20 bg-[#121622] rounded-xl" />
        </div>
        <div className="h-16 bg-[#121622] rounded-xl" />
      </div>

      {/* Terminal Skeleton */}
      <div className="rounded-2xl border border-[#1e2638] bg-[#0e1117] h-96 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-zinc-500 font-mono text-xs">
          <Terminal className="h-8 w-8 text-[#00ff66] animate-pulse" />
          <span>DECRYPTING RAM TELEMETRY STREAM...</span>
        </div>
      </div>
    </div>
  );
}
