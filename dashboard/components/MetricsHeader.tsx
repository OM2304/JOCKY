import React from 'react';
import { DashboardMetrics } from '@/types/report';
import { FileText, Cpu, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';

interface MetricsHeaderProps {
  metrics: DashboardMetrics;
}

export default function MetricsHeader({ metrics }: MetricsHeaderProps) {
  // Format the latest activity timestamp
  const formatTime = (isoString: string | null) => {
    if (!isoString) return 'NO ACTIVITY RECORDED';
    try {
      const date = new Date(isoString);
      return date.toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      }) + ' UTC';
    } catch {
      return isoString;
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* Metric 1: Total Reports */}
      <div className="relative overflow-hidden rounded-xl border border-[#1e2638] bg-[#0c0e14] p-5 transition-all hover:border-[#2d3a52] hover:bg-[#0f121a]">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-medium uppercase tracking-wider text-zinc-400">
            Total Reports Ingested
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1e2638] bg-[#121622] text-[#00ff66]">
            <FileText className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-4 flex items-baseline gap-2">
          <span className="font-mono text-3xl font-bold tracking-tight text-white">
            {metrics.totalReports}
          </span>
          <span className="font-mono text-xs text-zinc-500">
            {metrics.totalReports === 1 ? 'file' : 'reports in var/reports'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-zinc-400 font-mono">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-[#00ff66]"></span>
          <span>{metrics.totalTasks} distinct task IDs</span>
        </div>
        <div className="absolute -right-4 -bottom-4 h-16 w-16 rounded-full bg-[#00ff66]/5 blur-xl pointer-events-none" />
      </div>

      {/* Metric 2: Unique Agents Seen */}
      <div className="relative overflow-hidden rounded-xl border border-[#1e2638] bg-[#0c0e14] p-5 transition-all hover:border-[#2d3a52] hover:bg-[#0f121a]">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-medium uppercase tracking-wider text-zinc-400">
            Unique Agents Seen
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1e2638] bg-[#121622] text-cyan-400">
            <Cpu className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-4 flex items-baseline gap-2">
          <span className="font-mono text-3xl font-bold tracking-tight text-white">
            {metrics.uniqueAgents}
          </span>
          <span className="font-mono text-xs text-zinc-500">
            target machines
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-zinc-400 font-mono">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
          <span>In-memory RAM endpoints</span>
        </div>
        <div className="absolute -right-4 -bottom-4 h-16 w-16 rounded-full bg-cyan-500/5 blur-xl pointer-events-none" />
      </div>

      {/* Metric 3: Latest Activity */}
      <div className="relative overflow-hidden rounded-xl border border-[#1e2638] bg-[#0c0e14] p-5 transition-all hover:border-[#2d3a52] hover:bg-[#0f121a]">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-medium uppercase tracking-wider text-zinc-400">
            Latest Activity
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#1e2638] bg-[#121622] text-emerald-400">
            <Clock className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-4">
          <span className="font-mono text-lg font-bold tracking-tight text-white block truncate" title={metrics.latestActivity || ''}>
            {formatTime(metrics.latestActivity)}
          </span>
          <span className="font-mono text-xs text-zinc-500 mt-1 block">
            {metrics.latestActivity ? 'Most recent telemetry report' : 'Awaiting incoming report'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-zinc-400 font-mono">
          <span className={`inline-block h-1.5 w-1.5 rounded-full ${metrics.latestActivity ? 'bg-[#00ff66]' : 'bg-zinc-600'}`}></span>
          <span>Status: {metrics.latestActivity ? 'Synchronized' : 'Idle'}</span>
        </div>
        <div className="absolute -right-4 -bottom-4 h-16 w-16 rounded-full bg-emerald-500/5 blur-xl pointer-events-none" />
      </div>

      {/* Metric 4: Triage Anomaly Status */}
      <div className="relative overflow-hidden rounded-xl border border-[#1e2638] bg-[#0c0e14] p-5 transition-all hover:border-[#2d3a52] hover:bg-[#0f121a]">
        <div className="flex items-center justify-between">
          <span className="font-mono text-xs font-medium uppercase tracking-wider text-zinc-400">
            Detected Anomalies
          </span>
          <div className={`flex h-8 w-8 items-center justify-center rounded-lg border ${
            metrics.anomaliesDetected > 0
              ? 'border-amber-500/40 bg-amber-500/10 text-amber-400'
              : 'border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]'
          }`}>
            {metrics.anomaliesDetected > 0 ? (
              <AlertTriangle className="h-4 w-4" />
            ) : (
              <ShieldCheck className="h-4 w-4" />
            )}
          </div>
        </div>
        <div className="mt-4 flex items-baseline gap-2">
          <span className={`font-mono text-3xl font-bold tracking-tight ${
            metrics.anomaliesDetected > 0 ? 'text-amber-400' : 'text-[#00ff66]'
          }`}>
            {metrics.anomaliesDetected}
          </span>
          <span className="font-mono text-xs text-zinc-500">
            {metrics.anomaliesDetected === 1 ? 'alert line' : 'alert flags'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-zinc-400 font-mono">
          <span className={`inline-block h-1.5 w-1.5 rounded-full ${
            metrics.anomaliesDetected > 0 ? 'bg-amber-400' : 'bg-[#00ff66]'
          }`}></span>
          <span>{metrics.anomaliesDetected > 0 ? 'Review flagged findings' : 'Zero host anomalies'}</span>
        </div>
        <div className="absolute -right-4 -bottom-4 h-16 w-16 rounded-full bg-amber-500/5 blur-xl pointer-events-none" />
      </div>
    </div>
  );
}
