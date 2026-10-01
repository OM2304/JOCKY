import React from 'react';
import Link from 'next/link';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export default function NotFound() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-24 text-center sm:px-6">
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-destructive/20 bg-destructive/10 text-destructive shadow-xs">
        <ShieldAlert className="h-8 w-8" />
      </div>

      <h1 className="mt-5 text-2xl font-bold tracking-tight text-foreground">
        Report Not Found
      </h1>

      <p className="mt-2 text-sm text-muted-foreground max-w-md mx-auto leading-relaxed">
        The requested forensic report ID was not found in the controller storage (
        <code className="text-foreground font-mono">../agents/var/reports</code>). It may have been purged or not yet ingested.
      </p>

      <div className="mt-6 flex justify-center">
        <Link
          href="/"
          className="flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-2 text-xs font-semibold text-foreground hover:bg-muted transition-colors shadow-xs"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Return to Dashboard</span>
        </Link>
      </div>
    </div>
  );
}
