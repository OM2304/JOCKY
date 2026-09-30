import React from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getReportById } from '@/lib/data';
import MetadataCard from '@/components/MetadataCard';
import TerminalWindow from '@/components/TerminalWindow';
import {
  ChevronLeft,
  Server,
  Clock,
  Terminal,
  Shield,
  FileText,
  CornerDownRight,
} from 'lucide-react';

export const dynamic = 'force-dynamic';

interface PageProps {
  params: Promise<{ id: string }>;
}

export default async function ReportDetailPage({ params }: PageProps) {
  const { id } = await params;
  const decodedId = decodeURIComponent(id);
  const report = await getReportById(decodedId);

  if (!report) {
    notFound();
  }

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }) + ' UTC';
    } catch {
      return ts;
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-6">
      {/* Top Breadcrumb Navigation */}
      <div className="flex items-center gap-2 font-mono text-xs text-zinc-400">
        <Link
          href="/"
          className="flex items-center gap-1.5 text-zinc-400 hover:text-[#00ff66] transition-colors"
        >
          <ChevronLeft className="h-4 w-4" />
          <span>BACK TO DASHBOARD</span>
        </Link>
        <span className="text-zinc-600">/</span>
        <span className="text-zinc-500">REPORTS</span>
        <span className="text-zinc-600">/</span>
        <span className="text-[#00ff66] font-semibold truncate max-w-[200px] sm:max-w-xs">
          {report.agent} [{report.task}]
        </span>
      </div>

      {/* Header showing Agent Name and Timestamp */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-[#1e2638] pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#00ff66]">
            <span className="h-2 w-2 rounded-full bg-[#00ff66] animate-pulse" />
            <span>AGENT TELEMETRY REPORT RECORD</span>
          </div>
          <h1 className="mt-1 font-mono text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Server className="h-7 w-7 text-cyan-400" />
            <span>{report.agent}</span>
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs font-mono text-zinc-400">
            <div className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-zinc-500" />
              <span>Timestamp: {formatTimestamp(report.ts)}</span>
            </div>
            {report.parsedSummary?.host && (
              <div className="flex items-center gap-1.5 text-zinc-300">
                <CornerDownRight className="h-3.5 w-3.5 text-zinc-500" />
                <span>Host: {report.parsedSummary.host}</span>
              </div>
            )}
            {report.parsedSummary?.os && (
              <div className="flex items-center gap-1.5 text-zinc-300">
                <span>OS: {report.parsedSummary.os}</span>
              </div>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3 font-mono text-xs">
          <div className="rounded-xl border border-[#1e2638] bg-[#0c0e14] px-3.5 py-2 text-zinc-300">
            TASK: <span className="text-[#00ff66] font-semibold">{report.task}</span>
          </div>
        </div>
      </div>

      {/* Metadata Card: Full Task ID, Build ID, SHA-256 Payload Hash */}
      <section aria-label="Report Metadata">
        <MetadataCard report={report} />
      </section>

      {/* Terminal Window Component: Raw Output Display */}
      <section aria-label="Terminal Execution Log" className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[#00ff66]" />
            <h2 className="font-mono text-xs font-bold uppercase tracking-wider text-zinc-300">
              Raw Triage Terminal Output
            </h2>
          </div>
          <span className="font-mono text-[11px] text-zinc-500">
            RAM Execution // In-Memory Console Stream
          </span>
        </div>

        <TerminalWindow
          output={report.output}
          agentName={report.agent}
          taskId={report.task}
        />
      </section>
    </div>
  );
}
