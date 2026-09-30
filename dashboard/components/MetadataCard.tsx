'use client';

import React, { useState } from 'react';
import { ForensicReport } from '@/types/report';
import {
  Layers,
  Cpu,
  Hash,
  Copy,
  Check,
  Calendar,
  Activity,
  Server,
  FileCode,
  ShieldAlert,
  ShieldCheck,
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
    <div className="rounded-2xl border border-[#1e2638] bg-[#0c0e14] p-6 shadow-xl">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-[#18202e] pb-5">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#1e2638] bg-[#121622] text-[#00ff66]">
            <Server className="h-5 w-5" />
          </div>
          <div>
            <h2 className="font-mono text-base font-bold text-white flex items-center gap-2">
              <span>{report.agent}</span>
              <span className="text-xs font-normal text-zinc-500 font-mono">
                ({report.filename})
              </span>
            </h2>
            <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono mt-0.5">
              <Calendar className="h-3.5 w-3.5 text-zinc-500" />
              <span>{report.ts}</span>
            </div>
          </div>
        </div>

        {/* Status Badge */}
        <div>
          {hasAnomalies ? (
            <div className="inline-flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-1.5 font-mono text-xs font-semibold text-amber-400">
              <ShieldAlert className="h-4 w-4" />
              <span>{report.parsedSummary?.anomaliesCount} ANOMALIES DETECTED</span>
            </div>
          ) : (
            <div className="inline-flex items-center gap-2 rounded-xl border border-[#00ff66]/30 bg-[#00ff66]/10 px-3.5 py-1.5 font-mono text-xs font-semibold text-[#00ff66]">
              <ShieldCheck className="h-4 w-4" />
              <span>VERIFIED BASELINE CLEAN</span>
            </div>
          )}
        </div>
      </div>

      {/* Grid of Forensic Attributes */}
      <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Task ID */}
        <div className="rounded-xl border border-[#1a2232] bg-[#08090d] p-3.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="font-mono text-[11px] uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="h-3.5 w-3.5 text-zinc-500" />
              Task Identifier
            </span>
            <button
              onClick={() => handleCopy('task', report.task)}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Copy Task ID"
            >
              {copiedKey === 'task' ? (
                <Check className="h-3.5 w-3.5 text-[#00ff66]" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-zinc-100 break-all select-all">
            {report.task}
          </div>
        </div>

        {/* Build ID */}
        <div className="rounded-xl border border-[#1a2232] bg-[#08090d] p-3.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="font-mono text-[11px] uppercase tracking-wider flex items-center gap-1.5">
              <FileCode className="h-3.5 w-3.5 text-zinc-500" />
              Polymorphic Build ID
            </span>
            <button
              onClick={() => handleCopy('build_id', report.build_id)}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
              title="Copy Build ID"
            >
              {copiedKey === 'build_id' ? (
                <Check className="h-3.5 w-3.5 text-[#00ff66]" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
            </button>
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-zinc-100 break-all select-all">
            {report.build_id || 'n/a'}
          </div>
        </div>

        {/* Execution Result */}
        <div className="rounded-xl border border-[#1a2232] bg-[#08090d] p-3.5">
          <div className="flex items-center justify-between text-zinc-400">
            <span className="font-mono text-[11px] uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-zinc-500" />
              VM Return Result
            </span>
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-[#00ff66]">
            {String(report.result)}
          </div>
        </div>
      </div>

      {/* SHA-256 Payload Hash (Full Width) */}
      <div className="mt-4 rounded-xl border border-[#1a2232] bg-[#08090d] p-3.5">
        <div className="flex items-center justify-between text-zinc-400">
          <span className="font-mono text-[11px] uppercase tracking-wider flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5 text-[#00ff66]" />
            SHA-256 Payload Cryptographic Hash (JYCRYPT1 Container)
          </span>
          <button
            onClick={() => handleCopy('sha256', report.sha256_payload)}
            className="flex items-center gap-1 rounded bg-[#161c28] px-2 py-0.5 text-xs text-zinc-300 hover:bg-[#222a3d] hover:text-white transition-colors"
          >
            {copiedKey === 'sha256' ? (
              <>
                <Check className="h-3 w-3 text-[#00ff66]" />
                <span className="text-[#00ff66]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3 text-zinc-400" />
                <span>Copy Full Hash</span>
              </>
            )}
          </button>
        </div>
        <div className="mt-2 font-mono text-xs text-zinc-300 tracking-wider break-all select-all bg-[#0e121a] p-2.5 rounded-lg border border-[#161d2b]">
          {report.sha256_payload || 'No payload hash recorded'}
        </div>
      </div>
    </div>
  );
}
