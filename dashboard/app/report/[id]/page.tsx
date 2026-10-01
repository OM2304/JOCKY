import React from 'react';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { getReportById } from '@/lib/data';
import MetadataCard from '@/components/MetadataCard';
import TerminalWindow from '@/components/TerminalWindow';
import ExportEvidenceButton from '@/components/ExportEvidenceButton';
import {
  ArrowLeft,
  Server,
  Clock,
  Terminal,
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
      {/* Prominent Back to Dashboard Navigation Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-secondary px-4 py-2 text-xs font-semibold text-secondary-foreground hover:bg-secondary/80 shadow-xs transition-all group"
        >
          <ArrowLeft className="h-4 w-4 transition-transform group-hover:-translate-x-1 text-primary" />
          <span>Back to Dashboard</span>
        </Link>

        {/* Breadcrumb Path Context */}
        <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
          <span>Reports Census</span>
          <span className="text-muted-foreground/60">/</span>
          <span className="text-foreground font-medium truncate max-w-[200px] sm:max-w-xs">
            {report.agent}
          </span>
          <span className="text-muted-foreground/60">•</span>
          <span className="text-muted-foreground font-mono">{report.task}</span>
        </div>
      </div>

      {/* Header showing Agent Name and Timestamp */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-primary uppercase">
            <span className="h-2 w-2 rounded-full bg-primary" />
            <span>Agent Telemetry Record</span>
          </div>
          <h1 className="mt-1 text-2xl sm:text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
            <Server className="h-6 w-6 text-primary" />
            <span>{report.agent}</span>
          </h1>
          <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-muted-foreground font-mono">
            <div className="flex items-center gap-1.5">
              <Clock className="h-3.5 w-3.5 text-muted-foreground" />
              <span>Timestamp: {formatTimestamp(report.ts)}</span>
            </div>
            {report.parsedSummary?.host && (
              <div className="flex items-center gap-1.5 text-foreground">
                <CornerDownRight className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Host: {report.parsedSummary.host}</span>
              </div>
            )}
            {report.parsedSummary?.os && (
              <div className="flex items-center gap-1.5 text-foreground">
                <span>OS: {report.parsedSummary.os}</span>
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <div className="rounded-lg border border-border bg-card px-3 py-1.5 text-muted-foreground shadow-xs">
            Task ID: <span className="text-foreground font-semibold">{report.task}</span>
          </div>

          <ExportEvidenceButton report={report} />
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
            <Terminal className="h-4 w-4 text-primary" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Raw Triage Terminal Output
            </h2>
          </div>
          <span className="font-mono text-[11px] text-muted-foreground">
            In-Memory Stream
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
