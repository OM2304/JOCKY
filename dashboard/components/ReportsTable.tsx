'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
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
  Key,
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
          <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search reports by agent, task ID, hash, or host..."
            className="w-full rounded-xl border border-[#1e2638] bg-[#0c0e14] py-2.5 pl-10 pr-4 font-mono text-xs text-zinc-200 placeholder:text-zinc-500 focus:border-[#00ff66] focus:outline-none focus:ring-1 focus:ring-[#00ff66]"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-zinc-500 hover:text-zinc-300"
            >
              Clear
            </button>
          )}
        </div>

        {/* Agent Filter Dropdown */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="appearance-none rounded-xl border border-[#1e2638] bg-[#0c0e14] py-2.5 pl-3.5 pr-8 font-mono text-xs text-zinc-300 focus:border-[#00ff66] focus:outline-none focus:ring-1 focus:ring-[#00ff66]"
            >
              <option value="ALL">All Agents ({reports.length})</option>
              {uniqueAgents.map((agent) => (
                <option key={agent} value={agent}>
                  {agent}
                </option>
              ))}
            </select>
            <Filter className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          </div>

          <div className="rounded-xl border border-[#1e2638] bg-[#0c0e14] px-3 py-2.5 font-mono text-xs text-zinc-400">
            Showing <span className="font-semibold text-[#00ff66]">{filteredReports.length}</span> of {reports.length}
          </div>
        </div>
      </div>

      {/* Reports Table Card */}
      <div className="overflow-hidden rounded-2xl border border-[#1e2638] bg-[#0c0e14] shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            {/* Table Header */}
            <thead className="border-b border-[#1e2638] bg-[#08090d] font-mono text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
              <tr>
                <th scope="col" className="py-3.5 pl-6 pr-3">
                  Status
                </th>
                <th scope="col" className="px-3 py-3.5">
                  Timestamp (UTC)
                </th>
                <th scope="col" className="px-3 py-3.5">
                  Agent Name
                </th>
                <th scope="col" className="px-3 py-3.5">
                  Task ID
                </th>
                <th scope="col" className="px-3 py-3.5">
                  SHA-256 Payload Hash
                </th>
                <th scope="col" className="py-3.5 pl-3 pr-6 text-right">
                  Action
                </th>
              </tr>
            </thead>

            {/* Table Body */}
            <tbody className="divide-y divide-[#18202e] font-mono">
              {filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-zinc-500 font-mono">
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
                      className="group cursor-pointer transition-colors hover:bg-[#121722]/80"
                    >
                      {/* Status / Findings */}
                      <td className="py-4 pl-6 pr-3 whitespace-nowrap">
                        {hasAnomalies ? (
                          <div className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-[11px] font-medium text-amber-400">
                            <ShieldAlert className="h-3 w-3" />
                            <span>{report.parsedSummary?.anomaliesCount} Anomalies</span>
                          </div>
                        ) : (
                          <div className="inline-flex items-center gap-1.5 rounded-full border border-[#00ff66]/30 bg-[#00ff66]/10 px-2.5 py-1 text-[11px] font-medium text-[#00ff66]">
                            <ShieldCheck className="h-3 w-3" />
                            <span>Verified Clean</span>
                          </div>
                        )}
                      </td>

                      {/* Timestamp */}
                      <td className="px-3 py-4 whitespace-nowrap text-zinc-300">
                        <div className="flex items-center gap-1.5">
                          <Clock className="h-3.5 w-3.5 text-zinc-500" />
                          <span>{time.formatted}</span>
                        </div>
                        <div className="text-[10px] text-zinc-500 font-mono">{time.iso}</div>
                      </td>

                      {/* Agent Name */}
                      <td className="px-3 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-[#161d2b] border border-[#232f46] text-cyan-400">
                            <Cpu className="h-3 w-3" />
                          </div>
                          <div>
                            <span className="font-semibold text-white group-hover:text-[#00ff66] transition-colors">
                              {report.agent}
                            </span>
                            {report.parsedSummary?.host && (
                              <div className="text-[10px] text-zinc-400">
                                host: {report.parsedSummary.host}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>

                      {/* Task ID */}
                      <td className="px-3 py-4 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 rounded-md border border-[#20293a] bg-[#121622] px-2 py-1 text-[11px] font-mono text-zinc-300">
                          <Layers className="h-3 w-3 text-zinc-500" />
                          {report.task}
                        </span>
                      </td>

                      {/* Truncated Hash with Copy */}
                      <td className="px-3 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span
                            className="text-zinc-400 hover:text-zinc-200 transition-colors"
                            title={report.sha256_payload}
                          >
                            {truncatedHash}
                          </span>
                          {report.sha256_payload && (
                            <button
                              type="button"
                              onClick={(e) => handleCopyHash(e, report.sha256_payload)}
                              className="rounded p-1 text-zinc-500 hover:bg-[#1f283a] hover:text-zinc-200 transition-colors"
                              title="Copy full SHA-256 payload hash"
                            >
                              {copiedHash === report.sha256_payload ? (
                                <Check className="h-3.5 w-3.5 text-[#00ff66]" />
                              ) : (
                                <Copy className="h-3.5 w-3.5" />
                              )}
                            </button>
                          )}
                        </div>
                      </td>

                      {/* Action Link */}
                      <td className="py-4 pl-3 pr-6 text-right whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-zinc-400 group-hover:text-[#00ff66] transition-colors">
                          <span>Inspect Report</span>
                          <ChevronRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
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
