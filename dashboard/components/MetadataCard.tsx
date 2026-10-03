'use client';

import React, { useState } from 'react';
import { ForensicReport } from '@/types/report';
import {
  Layers,
  Hash,
  Copy,
  Check,
  Calendar,
  Activity,
  Server,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  GitCommit,
} from 'lucide-react';

interface MetadataCardProps {
  report: ForensicReport;
}

export default function MetadataCard({ report }: MetadataCardProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const hasAnomalies = (report.parsedSummary?.anomaliesCount ?? 0) > 0;

  return (
    <div className="rounded-xl border border-border bg-card p-6 shadow-xs">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-muted text-primary">
            <Server className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-foreground flex items-center gap-2">
              <span>{report.agent}</span>
              <span className="text-xs font-normal text-muted-foreground font-mono">
                ({report.filename})
              </span>
            </h2>
            <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono mt-0.5">
              <Calendar className="h-3.5 w-3.5 text-muted-foreground" />
              <span>{report.ts}</span>
            </div>
          </div>
        </div>

        {/* Status Badge */}
        <div>
          {hasAnomalies ? (
            <div className="inline-flex items-center gap-1.5 rounded-md border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-xs font-semibold text-amber-700 dark:text-amber-400">
              <ShieldAlert className="h-4 w-4" />
              <span>{report.parsedSummary?.anomaliesCount} Anomalies Flagged</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-700 dark:text-emerald-400">
              <ShieldCheck className="h-4 w-4" />
              <span>Baseline Clean</span>
            </div>
          )}
        </div>
      </div>

      {/* Grid of Forensic Attributes */}
      <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-3">
        {/* Task ID */}
        <div className="rounded-lg border border-border bg-muted/30 p-3.5">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-muted-foreground" />
              Task Identifier
            </span>
            <button
              onClick={() => handleCopy('task', report.task)}
              className="text-muted-foreground hover:text-foreground transition-colors"
              title="Copy Task ID"
            >
              {copiedKey === 'task' ? (
                <Check className="h-3.5 w-3.5 text-primary" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-foreground break-all select-all">
            {report.task}
          </div>
        </div>

        {/* Build ID */}
        <div className="rounded-lg border border-border bg-muted/30 p-3.5">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <FileCode className="h-3.5 w-3.5 text-muted-foreground" />
              Polymorphic Build ID
            </span>
            <button
              onClick={() => handleCopy('build_id', report.build_id)}
              className="text-muted-foreground hover:text-foreground transition-colors"
              title="Copy Build ID"
            >
              {copiedKey === 'build_id' ? (
                <Check className="h-3.5 w-3.5 text-primary" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-foreground break-all select-all">
            {report.build_id || 'n/a'}
          </div>
        </div>

        {/* Execution Result */}
        <div className="rounded-lg border border-border bg-muted/30 p-3.5">
          <div className="flex items-center justify-between text-muted-foreground">
            <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-muted-foreground" />
              Execution Result
            </span>
          </div>
          <div className="mt-1.5 font-mono text-sm font-semibold text-primary">
            {String(report.result)}
          </div>
        </div>
      </div>

      {/* SHA-256 Payload Hash (Full Width) */}
      <div className="mt-4 rounded-lg border border-border bg-muted/30 p-3.5">
        <div className="flex items-center justify-between text-muted-foreground">
          <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5 text-primary" />
            SHA-256 Payload Container Hash
          </span>
          <button
            onClick={() => handleCopy('sha256', report.sha256_payload)}
            className="flex items-center gap-1 rounded bg-muted px-2 py-0.5 text-xs text-foreground hover:bg-accent transition-colors"
          >
            {copiedKey === 'sha256' ? (
              <>
                <Check className="h-3 w-3 text-primary" />
                <span className="text-primary font-medium">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3 text-muted-foreground" />
                <span>Copy Hash</span>
              </>
            )}
          </button>
        </div>
        <div className="mt-2 font-mono text-xs text-foreground tracking-wide break-all select-all bg-card p-2.5 rounded-md border border-border">
          {report.sha256_payload || 'No payload hash recorded'}
        </div>
      </div>

      {/* Cryptographic Merkle Chain of Custody Section */}
      <div className="mt-4 rounded-lg border border-primary/20 bg-primary/5 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-primary/10 pb-2.5">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <span className="text-xs font-bold uppercase tracking-wider text-foreground">
              Cryptographic Chain of Custody (Merkle Verification)
            </span>
          </div>
          <span className="rounded-full bg-primary/10 px-2.5 py-0.5 text-[10px] font-mono font-semibold text-primary border border-primary/20">
            {report.parent_hash === 'GENESIS' || !report.parent_hash ? 'GENESIS ROOT' : 'VERIFIED CHAIN'}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          {/* Parent Hash */}
          <div className="rounded-md border border-border bg-card p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
                <GitCommit className="h-3.5 w-3.5 text-muted-foreground" />
                Parent Hash (Previous Block)
              </span>
              {report.parent_hash && (
                <button
                  onClick={() => handleCopy('parent_hash', report.parent_hash!)}
                  className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                >
                  {copiedKey === 'parent_hash' ? (
                    <Check className="h-3 w-3 text-primary" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  <span>{copiedKey === 'parent_hash' ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>
            <div className="font-mono text-xs font-semibold text-foreground tracking-wide break-all select-all pt-0.5">
              {report.parent_hash || 'GENESIS (Initial Ingestion Node)'}
            </div>
          </div>

          {/* Merkle Root */}
          <div className="rounded-md border border-border bg-card p-3 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5">
                <Hash className="h-3.5 w-3.5 text-primary" />
                Current Merkle Root
              </span>
              {report.merkle_root && (
                <button
                  onClick={() => handleCopy('merkle_root', report.merkle_root!)}
                  className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                >
                  {copiedKey === 'merkle_root' ? (
                    <Check className="h-3 w-3 text-primary" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                  <span>{copiedKey === 'merkle_root' ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>
            <div className="font-mono text-xs font-semibold text-primary tracking-wide break-all select-all pt-0.5">
              {report.merkle_root || 'Awaiting Controller Ingestion Hash'}
            </div>
          </div>
        </div>

        <p className="text-[11px] text-muted-foreground font-mono leading-relaxed pt-0.5">
          SHA256(Parent Hash + Payload Hash) = Merkle Root • Tamper-evident ledger guarantees chronological non-repudiation for incident response and courtroom admissibility.
        </p>
      </div>
    </div>
  );
}
