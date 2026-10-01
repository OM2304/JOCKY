import React from 'react';
import { getReports, getDashboardMetrics } from '@/lib/data';
import MetricsHeader from '@/components/MetricsHeader';
import ReportsTable from '@/components/ReportsTable';
import EmptyState from '@/components/EmptyState';
import DispatchTaskButton from '@/components/DispatchTaskButton';
import { Activity, FileSpreadsheet } from 'lucide-react';

export const dynamic = 'force-dynamic';

export default async function HomePage() {
  const reports = await getReports();
  const metrics = getDashboardMetrics(reports);
  const knownAgents = Array.from(new Set(reports.map((r) => r.agent).filter(Boolean)));

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Dashboard Header Banner */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold text-primary tracking-wide uppercase">
            <span className="inline-block h-2 w-2 rounded-full bg-primary" />
            Central Forensics Operations • Controller Ingest
          </div>
          <h1 className="mt-1 text-2xl sm:text-3xl font-bold tracking-tight text-foreground">
            Forensic Telemetry Dashboard
          </h1>
          <p className="mt-1 text-xs sm:text-sm text-muted-foreground">
            Real-time ingestion of RAM-only incident response triages and host anomaly sweep findings.
          </p>
        </div>

        {/* Top Right Action & Source Info */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="rounded-lg border border-border bg-card px-3 py-1.5 text-xs text-muted-foreground flex items-center gap-2 shadow-xs">
            <Activity className="h-4 w-4 text-primary" />
            <span>
              Source: <span className="text-foreground font-mono font-medium">../agents/var/reports</span>
            </span>
          </div>

          {/* Prominent Dispatch New Task Button */}
          <DispatchTaskButton knownAgents={knownAgents} />
        </div>
      </div>

      {/* High-Level Forensic Metrics */}
      <MetricsHeader metrics={metrics} />

      {/* Ingested Reports Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold tracking-wide text-foreground">
              Agent Findings Census
            </h2>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {reports.length} {reports.length === 1 ? 'Report Logged' : 'Reports Logged'}
          </span>
        </div>

        {reports.length === 0 ? (
          <EmptyState />
        ) : (
          <ReportsTable reports={reports} />
        )}
      </div>
    </div>
  );
}
