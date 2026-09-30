import React from 'react';
import { getReports, getDashboardMetrics } from '@/lib/data';
import MetricsHeader from '@/components/MetricsHeader';
import ReportsTable from '@/components/ReportsTable';
import EmptyState from '@/components/EmptyState';
import { Shield, Terminal, Activity, FileSpreadsheet } from 'lucide-react';

// Force dynamic server rendering so every page hit scans the filesystem
export const dynamic = 'force-dynamic';

export default async function HomePage() {
  const reports = await getReports();
  const metrics = getDashboardMetrics(reports);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Dashboard Header Banner */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-[#1e2638] pb-6">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-[#00ff66] tracking-wider uppercase">
            <span className="inline-block h-2 w-2 rounded-full bg-[#00ff66] animate-pulse" />
            Central Forensics Operations // Controller Ingest
          </div>
          <h1 className="mt-1 font-mono text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Forensic Telemetry Dashboard
          </h1>
          <p className="mt-1 font-mono text-xs sm:text-sm text-zinc-400">
            Real-time ingestion of RAM-only incident response triages and host anomaly sweep findings.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="rounded-xl border border-[#1e2638] bg-[#0c0e14] px-3.5 py-2 font-mono text-xs text-zinc-300 flex items-center gap-2">
            <Activity className="h-4 w-4 text-[#00ff66]" />
            <span>
              SOURCE: <span className="text-white font-semibold">../agents/var/reports</span>
            </span>
          </div>
        </div>
      </div>

      {/* High-Level Forensic Metrics */}
      <MetricsHeader metrics={metrics} />

      {/* Ingested Reports Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-4 w-4 text-[#00ff66]" />
            <h2 className="font-mono text-sm font-bold uppercase tracking-wider text-zinc-200">
              Agent Findings Census
            </h2>
          </div>
          <span className="font-mono text-xs text-zinc-500">
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
