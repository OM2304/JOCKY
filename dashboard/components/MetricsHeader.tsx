import React from 'react';
import { DashboardMetrics } from '@/types/report';
import { FileText, Cpu, Clock, AlertTriangle, ShieldCheck } from 'lucide-react';

interface MetricsHeaderProps {
  metrics: DashboardMetrics;
}

export default function MetricsHeader({ metrics }: MetricsHeaderProps) {
  const formatTime = (isoString: string | null) => {
    if (!isoString) return 'No activity recorded';
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
      <div className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-xs transition-shadow hover:shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Total Reports
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-muted text-primary">
            <FileText className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground">
            {metrics.totalReports}
          </span>
          <span className="text-xs text-muted-foreground">
            {metrics.totalReports === 1 ? 'file' : 'reports recorded'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
          <span className="inline-block h-2 w-2 rounded-full bg-primary"></span>
          <span>{metrics.totalTasks} distinct task {metrics.totalTasks === 1 ? 'queue' : 'queues'}</span>
        </div>
      </div>

      {/* Metric 2: Unique Agents */}
      <div className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-xs transition-shadow hover:shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Unique Agents
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-muted text-blue-600 dark:text-blue-400">
            <Cpu className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground">
            {metrics.uniqueAgents}
          </span>
          <span className="text-xs text-muted-foreground">
            target machines
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
          <span className="inline-block h-2 w-2 rounded-full bg-blue-500"></span>
          <span>In-memory RAM execution</span>
        </div>
      </div>

      {/* Metric 3: Latest Activity */}
      <div className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-xs transition-shadow hover:shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Latest Ingest
          </span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-muted text-emerald-600 dark:text-emerald-400">
            <Clock className="h-4 w-4" />
          </div>
        </div>
        <div className="mt-3">
          <span className="text-sm font-semibold tracking-tight text-foreground block truncate" title={metrics.latestActivity || ''}>
            {formatTime(metrics.latestActivity)}
          </span>
          <span className="text-xs text-muted-foreground mt-0.5 block">
            {metrics.latestActivity ? 'Synchronized with controller' : 'Awaiting incoming report'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
          <span className={`inline-block h-2 w-2 rounded-full ${metrics.latestActivity ? 'bg-emerald-500' : 'bg-slate-400'}`}></span>
          <span>Status: {metrics.latestActivity ? 'Live' : 'Standby'}</span>
        </div>
      </div>

      {/* Metric 4: Anomaly Status */}
      <div className="relative overflow-hidden rounded-xl border border-border bg-card p-5 shadow-xs transition-shadow hover:shadow-sm">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Detected Anomalies
          </span>
          <div className={`flex h-8 w-8 items-center justify-center rounded-lg border ${
            metrics.anomaliesDetected > 0
              ? 'border-amber-500/20 bg-amber-500/10 text-amber-600 dark:text-amber-400'
              : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
          }`}>
            {metrics.anomaliesDetected > 0 ? (
              <AlertTriangle className="h-4 w-4" />
            ) : (
              <ShieldCheck className="h-4 w-4" />
            )}
          </div>
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className={`text-2xl sm:text-3xl font-bold tracking-tight ${
            metrics.anomaliesDetected > 0
              ? 'text-amber-600 dark:text-amber-400'
              : 'text-emerald-600 dark:text-emerald-400'
          }`}>
            {metrics.anomaliesDetected}
          </span>
          <span className="text-xs text-muted-foreground">
            {metrics.anomaliesDetected === 1 ? 'alert line' : 'alert flags'}
          </span>
        </div>
        <div className="mt-3 flex items-center gap-1.5 text-xs text-muted-foreground font-mono">
          <span className={`inline-block h-2 w-2 rounded-full ${
            metrics.anomaliesDetected > 0 ? 'bg-amber-500' : 'bg-emerald-500'
          }`}></span>
          <span>{metrics.anomaliesDetected > 0 ? 'Flagged items require triage' : 'All endpoints verified clean'}</span>
        </div>
      </div>
    </div>
  );
}
