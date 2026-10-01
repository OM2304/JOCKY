import React from 'react';
import { Terminal } from 'lucide-react';

export default function ReportLoading() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6 animate-pulse">
      {/* Breadcrumb Skeleton */}
      <div className="h-4 w-40 bg-muted rounded" />

      {/* Header Skeleton */}
      <div className="border-b border-border pb-6">
        <div className="h-4 w-32 bg-muted rounded mb-2" />
        <div className="h-8 w-56 bg-muted rounded mb-3" />
        <div className="h-4 w-72 bg-muted rounded" />
      </div>

      {/* Metadata Card Skeleton */}
      <div className="rounded-xl border border-border bg-card p-6 space-y-4">
        <div className="h-6 w-48 bg-muted rounded" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="h-16 bg-muted/60 rounded-lg" />
          <div className="h-16 bg-muted/60 rounded-lg" />
          <div className="h-16 bg-muted/60 rounded-lg" />
        </div>
        <div className="h-14 bg-muted/60 rounded-lg" />
      </div>

      {/* Terminal Skeleton */}
      <div className="rounded-xl border border-slate-800 bg-slate-950 h-96 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-slate-500 font-mono text-xs">
          <Terminal className="h-6 w-6 text-emerald-500 animate-pulse" />
          <span>DECRYPTING FORENSIC STREAM...</span>
        </div>
      </div>
    </div>
  );
}
