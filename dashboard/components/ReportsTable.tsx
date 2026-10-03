'use client';

import React, { useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { ForensicReport } from '@/types/report';
import {
  Search,
  Filter,
  Copy,
  Check,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  Cpu,
  Clock,
  Layers,
} from 'lucide-react';

interface ReportsTableProps {
  reports: ForensicReport[];
}

export default function ReportsTable({ reports }: ReportsTableProps) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedAgent, setSelectedAgent] = useState('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Extract unique agent list
  const uniqueAgents = useMemo(() => {
    const set = new Set<string>();
    reports.forEach((r) => {
      if (r.agent) set.add(r.agent);
    });
    return Array.from(set).sort();
  }, [reports]);

  // Filter reports
  const filteredReports = useMemo(() => {
    return reports.filter((report) => {
      const matchesAgent =
        selectedAgent === 'ALL' || report.agent.toLowerCase() === selectedAgent.toLowerCase();

      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        report.agent.toLowerCase().includes(q) ||
        report.task.toLowerCase().includes(q) ||
        report.sha256_payload.toLowerCase().includes(q) ||
        report.build_id.toLowerCase().includes(q) ||
        (report.merkle_root && report.merkle_root.toLowerCase().includes(q)) ||
        (report.parent_hash && report.parent_hash.toLowerCase().includes(q)) ||
        (report.parsedSummary?.host && report.parsedSummary.host.toLowerCase().includes(q)) ||
        report.output.toLowerCase().includes(q);

      return matchesAgent && matchesSearch;
    });
  }, [reports, searchQuery, selectedAgent]);

  const handleCopyHash = (e: React.MouseEvent, hash: string) => {
    e.stopPropagation();
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatTimestamp = (ts: string) => {
    try {
      const d = new Date(ts);
      return {
        formatted: d.toLocaleString('en-US', {
          month: 'short',
          day: '2-digit',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false,
        }),
        iso: ts,
      };
    } catch {
      return { formatted: ts, iso: ts };
    }
  };

  return (
    <div className="space-y-4">
      {/* Search and Filters Bar */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        {/* Search Input */}
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports by agent, task ID, hash, or host..."
            className="w-full rounded-lg border border-input bg-card py-2 pl-9 pr-12 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary shadow-xs transition-colors"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground hover:text-foreground"
            >
              Clear
            </button>
          )}
        </div>

        {/* Agent Filter Dropdown & Count */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="appearance-none rounded-lg border border-input bg-card py-2 pl-3 pr-8 text-xs text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary shadow-xs cursor-pointer transition-colors"
            >
              <option value="ALL">All Agents ({reports.length})</option>
              {uniqueAgents.map((agent) => (
                <option key={agent} value={agent}>
                  {agent}
                </option>
              ))}
            </select>
            <Filter className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          </div>

          <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs text-muted-foreground shadow-xs">
            Showing <span className="font-semibold text-foreground">{filteredReports.length}</span> of {reports.length}
          </div>
        </div>
      </div>

      {/* Reports Table Card */}
      <div className="overflow-hidden rounded-xl border border-border bg-card shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            {/* Table Header */}
            <thead className="border-b border-border bg-muted/40 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th scope="col" className="py-3 pl-6 pr-3">
                  Status
                </th>
                <th scope="col" className="px-3 py-3">
                  Timestamp (UTC)
                </th>
                <th scope="col" className="px-3 py-3">
                  Agent Name
                </th>
                <th scope="col" className="px-3 py-3">
                  Task ID
                </th>
                <th scope="col" className="px-3 py-3">
                  SHA-256 Payload Hash
                </th>
                <th scope="col" className="py-3 pl-3 pr-6 text-right">
                  Action
                </th>
              </tr>
            </thead>

            {/* Table Body */}
            <tbody className="divide-y divide-border">
              {filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-muted-foreground">
                    No reports match the current query &ldquo;{searchQuery}&rdquo;.
                  </td>
                </tr>
              ) : (
                filteredReports.map((report) => {
                  const time = formatTimestamp(report.ts);
                  const hasAnomalies = (report.parsedSummary?.anomaliesCount ?? 0) > 0;
                  const truncatedHash = report.sha256_payload
                    ? `${report.sha256_payload.substring(0, 14)}...`
                    : 'none';

                  return (
                    <tr
                      key={report.id}
                      onClick={() => router.push(`/report/${encodeURIComponent(report.id)}`)}
                      className="group cursor-pointer transition-colors hover:bg-muted/50"
                    >
                      {/* Status / Findings */}
                      <td className="py-3.5 pl-6 pr-3 whitespace-nowrap">
                        {hasAnomalies ? (
                          <div className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/20 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400">
                            <ShieldAlert className="h-3 w-3" />
                            <span>{report.parsedSummary?.anomaliesCount} Anomalies</span>
                          </div>
                        ) : (
                          <div className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-400">
                            <ShieldCheck className="h-3 w-3" />
                            <span>Clean</span>
                          </div>
                        )}
                      </td>

                      {/* Timestamp */}
                      <td className="px-3 py-3.5 whitespace-nowrap text-foreground">
                        <div className="flex items-center gap-1.5">
                          <Clock className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-medium">{time.formatted}</span>
                        </div>
                        <div className="text-[10px] text-muted-foreground font-mono">{time.iso}</div>
                      </td>

                      {/* Agent Name */}
                      <td className="px-3 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-muted text-muted-foreground">
                            <Cpu className="h-3.5 w-3.5" />
                          </div>
                          <div>
                            <span className="font-semibold text-foreground group-hover:text-primary transition-colors">
                              {report.agent}
                            </span>
                            {report.parsedSummary?.host && (
                              <div className="text-[10px] text-muted-foreground">
                                host: {report.parsedSummary.host}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Task ID */}
                      <td className="px-3 py-3.5 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 rounded-md border border-border bg-muted/60 px-2 py-0.5 text-[11px] font-mono text-foreground">
                          <Layers className="h-3 w-3 text-muted-foreground" />
                          {report.task}
                        </span>
                      </td>

                      {/* Truncated Hash with Copy & Merkle Chain */}
                      <td className="px-3 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span
                            className="font-mono text-muted-foreground group-hover:text-foreground transition-colors"
                            title={report.sha256_payload}
                          >
                            {truncatedHash}
                          </span>
                          {report.sha256_payload && (
                            <button
                              type="button"
                              onClick={(e) => handleCopyHash(e, report.sha256_payload)}
                              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                              title="Copy full SHA-256 payload hash"
                            >
                              {copiedHash === report.sha256_payload ? (
                                <Check className="h-3.5 w-3.5 text-primary" />
                              ) : (
                                <Copy className="h-3.5 w-3.5" />
                              )}
                            </button>
                          )}
                        </div>
                        {report.merkle_root && (
                          <div
                            className="mt-0.5 flex items-center gap-1 text-[10px] font-mono text-primary/80"
                            title={`Merkle Root: ${report.merkle_root}`}
                          >
                            <span className="text-muted-foreground font-sans text-[9px]">ROOT:</span>
                            <span className="truncate max-w-[120px]">{report.merkle_root.substring(0, 10)}...</span>
                          </div>
                        )}
                      </td>

                      {/* Action Link */}
                      <td className="py-3.5 pl-3 pr-6 text-right whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground group-hover:text-primary transition-colors">
                          <span>View Report</span>
                          <ChevronRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
