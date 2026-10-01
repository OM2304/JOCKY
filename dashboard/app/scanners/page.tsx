'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Layers,
  ArrowLeft,
  Activity,
  FileCode,
  CheckCircle2,
  Terminal,
  ExternalLink,
  ChevronRight,
  Database,
  Radio,
} from 'lucide-react';

interface ByovdFinding {
  name: string;
  file: string;
  cve: string;
  cvss: number;
  vendor: string;
  capability: string;
  ioctl: string;
  note: string;
  confidence: string;
  path: string;
  sha256: string;
  detected_by: string;
  loaded_in_kernel: boolean;
  service?: Record<string, unknown>;
}

interface ByovdData {
  db_entries: number;
  loaded_driver_names: number;
  loaded_addresses: number;
  load_api_filtered: boolean;
  findings: ByovdFinding[];
  scan_time: number;
  host: string;
  stage_paths_tested: string[];
}

interface EdrEvidence {
  type: string;
  name: string;
  note?: string;
}

interface EdrProduct {
  name: string;
  vendor: string;
  category: string;
  evidence: EdrEvidence[];
  services?: string[];
  procs?: string[];
  dlls?: string[];
}

interface EdrHook {
  export: string;
  dll: string;
  hook_type: string;
  likely_hook: boolean;
  diff_offset: number;
  disk_hex: string;
  mem_hex: string;
  target?: string;
  target_module?: string | null;
  note?: string;
  synthetic?: boolean;
}

interface EdrData {
  host: string;
  products: EdrProduct[];
  security_center2: unknown[];
  hooks: Record<string, EdrHook[]>;
  hooks_list: EdrHook[];
  summary: {
    products: number;
    hook_diffs: number;
    likely_hooks: number;
  };
  mode?: string;
}

export default function ScannersPage() {
  const [byovdData, setByovdData] = useState<ByovdData | null>(null);
  const [edrData, setEdrData] = useState<EdrData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScanners = async () => {
    setLoading(true);
    setError(null);
    try {
      const [byovdRes, edrRes] = await Promise.all([
        fetch('/api/scanners/byovd'),
        fetch('/api/scanners/edr'),
      ]);

      if (!byovdRes.ok || !edrRes.ok) {
        throw new Error('Failed to retrieve scanner data from Python engine.');
      }

      const byovdJson = await byovdRes.json();
      const edrJson = await edrRes.json();

      if (!byovdJson.success || !edrJson.success) {
        throw new Error(byovdJson.error || edrJson.error || 'Scanner execution failed.');
      }

      setByovdData(byovdJson.data);
      setEdrData(edrJson.data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanners();
  }, []);

  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8 space-y-8">
      {/* Top Breadcrumb Navigation */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-secondary px-3.5 py-1.5 text-xs font-semibold text-secondary-foreground hover:bg-secondary/80 shadow-xs transition-colors group"
        >
          <ArrowLeft className="h-4 w-4 transition-transform group-hover:-translate-x-1 text-primary" />
          <span>Back to Dashboard</span>
        </Link>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchScanners}
            disabled={loading}
            className="flex items-center gap-1.5 rounded-lg border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground hover:bg-muted transition-colors shadow-xs disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Re-run Scanners</span>
          </button>
        </div>
      </div>

      {/* Header Banner */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold text-primary uppercase tracking-wide">
          <span className="h-2 w-2 rounded-full bg-primary" />
          <span>Kernel & Userland Threat Analysis Engine</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground">
          Host Threat & Sensor Scanners
        </h1>
        <p className="text-xs sm:text-sm text-muted-foreground max-w-3xl leading-relaxed">
          Automated discovery for Bring-Your-Own-Vulnerable-Driver (BYOVD) kernel primitives and live userland EDR API hook differentials (<code className="font-mono text-foreground font-medium">ntdll.dll</code> detours).
        </p>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-xl border border-destructive/20 bg-destructive/10 p-4 text-xs text-destructive">
          <div className="font-semibold flex items-center gap-1.5 mb-1">
            <AlertTriangle className="h-4 w-4" />
            <span>Scanner Execution Error</span>
          </div>
          <p className="font-mono text-[11px]">{error}</p>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading ? (
        <div className="space-y-8 animate-pulse">
          {/* Skeleton Metric Row */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 rounded-xl border border-border bg-card p-4" />
            ))}
          </div>

          {/* Skeleton BYOVD Cards */}
          <div className="rounded-xl border border-border bg-card p-6 space-y-4">
            <div className="h-5 w-48 bg-muted rounded" />
            <div className="h-28 bg-muted/40 rounded-lg" />
          </div>

          {/* Skeleton EDR Cards */}
          <div className="rounded-xl border border-border bg-card p-6 space-y-4">
            <div className="h-5 w-48 bg-muted rounded" />
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="h-32 bg-muted/40 rounded-lg" />
              <div className="h-32 bg-muted/40 rounded-lg" />
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-10">
          {/* Summary Metric Counters */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {/* Metric 1 */}
            <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                <span>BYOVD Database</span>
                <Database className="h-4 w-4 text-primary" />
              </div>
              <div className="mt-2 text-2xl font-bold text-foreground">
                {byovdData?.db_entries ?? 16} Drivers
              </div>
              <p className="text-[11px] text-muted-foreground font-mono mt-1">
                LOLDrivers catalogue signatures
              </p>
            </div>

            {/* Metric 2 */}
            <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                <span>Vulnerable Drivers</span>
                <AlertTriangle className="h-4 w-4 text-amber-500" />
              </div>
              <div className="mt-2 text-2xl font-bold text-amber-600 dark:text-amber-400">
                {byovdData?.findings.length ?? 0} Matched
              </div>
              <p className="text-[11px] text-muted-foreground font-mono mt-1">
                Identified in staging paths
              </p>
            </div>

            {/* Metric 3 */}
            <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                <span>EDR Sensors</span>
                <Radio className="h-4 w-4 text-blue-500" />
              </div>
              <div className="mt-2 text-2xl font-bold text-foreground">
                {edrData?.summary.products ?? 0} Discovered
              </div>
              <p className="text-[11px] text-muted-foreground font-mono mt-1">
                AV / EDR resident agents
              </p>
            </div>

            {/* Metric 4 */}
            <div className="rounded-xl border border-border bg-card p-4 shadow-xs">
              <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center justify-between">
                <span>Userland Hooks</span>
                <ShieldAlert className="h-4 w-4 text-destructive" />
              </div>
              <div className="mt-2 text-2xl font-bold text-destructive">
                {edrData?.summary.likely_hooks ?? 0} Intercepted
              </div>
              <p className="text-[11px] text-muted-foreground font-mono mt-1">
                Modified export trampolines
              </p>
            </div>
          </div>

          {/* ========================================================================= */}
          {/* SECTION 1: BYOVD (Bring Your Own Vulnerable Driver) Scanner */}
          {/* ========================================================================= */}
          <section className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-border pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-amber-500" />
                  <h2 className="text-lg font-bold tracking-tight text-foreground">
                    BYOVD (Vulnerable Driver) Analysis
                  </h2>
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Identification of signed drivers vulnerable to arbitrary kernel memory read/write.
                </p>
              </div>

              {byovdData?.load_api_filtered && (
                <div className="mt-2 sm:mt-0 inline-flex items-center gap-1.5 rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-700 dark:text-amber-400">
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>PSAPI Census Filtered (EDR Shim Active)</span>
                </div>
              )}
            </div>

            {/* BYOVD Findings Grid */}
            <div className="grid grid-cols-1 gap-4">
              {byovdData?.findings.length === 0 ? (
                <div className="rounded-xl border border-border bg-card p-8 text-center text-xs text-muted-foreground">
                  No vulnerable drivers matched in candidate staging paths.
                </div>
              ) : (
                byovdData?.findings.map((driver, idx) => {
                  const isHighCvss = driver.cvss >= 8.0;
                  return (
                    <div
                      key={idx}
                      className="rounded-xl border border-border bg-card p-5 shadow-xs space-y-4 hover:border-slate-400 dark:hover:border-slate-600 transition-colors"
                    >
                      {/* Driver Title Row */}
                      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted text-foreground font-mono font-bold text-xs">
                            .sys
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-bold text-foreground font-mono">
                                {driver.name || driver.file}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                • {driver.vendor}
                              </span>
                            </div>
                            <span className="text-xs text-muted-foreground font-mono">
                              {driver.cve}
                            </span>
                          </div>
                        </div>

                        {/* Badges: CVSS, Capability, Kernel Resident */}
                        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                          {/* CVSS Badge */}
                          <span
                            className={`rounded-md px-2.5 py-1 text-xs font-bold border ${
                              isHighCvss
                                ? 'bg-destructive/10 text-destructive border-destructive/20'
                                : 'bg-amber-500/10 text-amber-600 border-amber-500/20'
                            }`}
                          >
                            CVSS {driver.cvss}
                          </span>

                          {/* Capability Badge */}
                          <span className="rounded-md border border-border bg-muted px-2.5 py-1 text-xs font-semibold text-foreground">
                            Cap: {driver.capability}
                          </span>

                          {/* Kernel Resident Status */}
                          <span
                            className={`rounded-md px-2.5 py-1 text-xs font-semibold border ${
                              driver.loaded_in_kernel
                                ? 'bg-destructive/10 text-destructive border-destructive/20'
                                : 'bg-muted text-muted-foreground border-border'
                            }`}
                          >
                            {driver.loaded_in_kernel ? 'RESIDENT IN KERNEL' : 'STAGED ON DISK'}
                          </span>
                        </div>
                      </div>

                      {/* Technical Details Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
                        <div className="rounded-lg bg-muted/40 p-2.5 border border-border/60">
                          <span className="text-[11px] text-muted-foreground block">IOCTL Target</span>
                          <span className="text-foreground font-medium break-all">{driver.ioctl}</span>
                        </div>

                        <div className="rounded-lg bg-muted/40 p-2.5 border border-border/60">
                          <span className="text-[11px] text-muted-foreground block">Confidence Level</span>
                          <span className="text-foreground font-medium capitalize">{driver.confidence} ({driver.detected_by})</span>
                        </div>

                        <div className="rounded-lg bg-muted/40 p-2.5 border border-border/60 sm:col-span-2 lg:col-span-1">
                          <span className="text-[11px] text-muted-foreground block">Staged File Path</span>
                          <span className="text-foreground font-medium break-all">{driver.path}</span>
                        </div>
                      </div>

                      {/* Note / Context */}
                      <div className="rounded-lg bg-muted/20 p-3 text-xs text-muted-foreground border border-border/40">
                        <span className="font-semibold text-foreground mr-1.5">Forensic Context:</span>
                        {driver.note}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>

          {/* ========================================================================= */}
          {/* SECTION 2: EDR / AV Sensor Discovery */}
          {/* ========================================================================= */}
          <section className="space-y-4">
            <div className="border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <Radio className="h-5 w-5 text-blue-500" />
                <h2 className="text-lg font-bold tracking-tight text-foreground">
                  EDR & AV Endpoint Sensors
                </h2>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Active endpoint agents discovered via driver census, service registrations, DLL maps, and process trees.
              </p>
            </div>

            {/* Products Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {edrData?.products.map((product, idx) => (
                <div
                  key={idx}
                  className="rounded-xl border border-border bg-card p-5 shadow-xs flex flex-col justify-between space-y-3"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-bold text-foreground">
                          {product.name}
                        </h3>
                        <span className="text-xs text-muted-foreground">
                          {product.vendor}
                        </span>
                      </div>
                      <span className="rounded-md border border-border bg-muted px-2 py-0.5 text-[11px] font-mono font-semibold text-foreground">
                        {product.category}
                      </span>
                    </div>

                    {/* Discovered Evidence Items */}
                    <div className="mt-3 space-y-1.5 text-xs font-mono">
                      <span className="text-[11px] text-muted-foreground uppercase font-sans font-semibold tracking-wider block">
                        Sensor Evidence:
                      </span>
                      {product.evidence.map((ev, eIdx) => (
                        <div
                          key={eIdx}
                          className="rounded bg-muted/50 px-2 py-1 border border-border/50 text-[11px] text-foreground flex items-center justify-between"
                        >
                          <span className="text-primary font-medium">{ev.type}:</span>
                          <span className="truncate max-w-[200px]" title={ev.name}>
                            {ev.name}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-border/40 text-[11px] text-muted-foreground flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-primary" />
                    <span>Agent Confirmed Active</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* ========================================================================= */}
          {/* SECTION 3: Userland EDR Hook Differentials (ntdll.dll Detours) */}
          {/* ========================================================================= */}
          <section className="space-y-4">
            <div className="border-b border-border pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-destructive" />
                <h2 className="text-lg font-bold tracking-tight text-foreground">
                  Userland API Hook Differentials
                </h2>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Comparison of disk image bytes vs in-memory export stubs to detect API trampolines planted by security software.
              </p>
            </div>

            {/* Hooks Table Card */}
            <div className="overflow-hidden rounded-xl border border-border bg-card shadow-xs">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="border-b border-border bg-muted/40 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground font-sans">
                    <tr>
                      <th scope="col" className="py-3 pl-6 pr-3">
                        Status
                      </th>
                      <th scope="col" className="px-3 py-3">
                        Target Export (Function)
                      </th>
                      <th scope="col" className="px-3 py-3">
                        Hook Type
                      </th>
                      <th scope="col" className="px-3 py-3">
                        Diff Offset
                      </th>
                      <th scope="col" className="px-3 py-3">
                        Memory Stub (Hex)
                      </th>
                      <th scope="col" className="py-3 pl-3 pr-6 text-right">
                        Clean Disk Stub
                      </th>
                    </tr>
                  </thead>

                  <tbody className="divide-y divide-border">
                    {edrData?.hooks_list.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-muted-foreground font-sans">
                          No userland export hooks detected across resident system DLLs.
                        </td>
                      </tr>
                    ) : (
                      edrData?.hooks_list.map((hook, idx) => (
                        <tr key={idx} className="hover:bg-muted/40 transition-colors">
                          {/* Likely Hook Status */}
                          <td className="py-3.5 pl-6 pr-3 whitespace-nowrap">
                            <span className="inline-flex items-center gap-1.5 rounded-full border border-destructive/20 bg-destructive/10 px-2.5 py-0.5 text-[11px] font-bold text-destructive">
                              <ShieldAlert className="h-3 w-3" />
                              <span>LIKELY-HOOK</span>
                            </span>
                          </td>

                          {/* Function Name */}
                          <td className="px-3 py-3.5 whitespace-nowrap">
                            <span className="font-bold text-foreground">
                              {hook.dll}!{hook.export}
                            </span>
                            {hook.note && (
                              <div className="text-[10px] text-muted-foreground truncate max-w-xs font-sans">
                                {hook.note}
                              </div>
                            )}
                          </td>

                          {/* Hook Type */}
                          <td className="px-3 py-3.5 whitespace-nowrap">
                            <span className="rounded bg-muted px-2 py-0.5 border border-border text-foreground text-[11px]">
                              {hook.hook_type}
                            </span>
                          </td>

                          {/* Diff Offset */}
                          <td className="px-3 py-3.5 whitespace-nowrap text-muted-foreground">
                            Byte {hook.diff_offset ?? 0}
                          </td>

                          {/* Mem Hex */}
                          <td className="px-3 py-3.5 whitespace-nowrap">
                            <span className="text-destructive font-medium bg-destructive/10 px-1.5 py-0.5 rounded">
                              {hook.mem_hex.substring(0, 24)}...
                            </span>
                          </td>

                          {/* Disk Hex */}
                          <td className="py-3.5 pl-3 pr-6 text-right whitespace-nowrap text-muted-foreground">
                            <span className="bg-muted px-1.5 py-0.5 rounded">
                              {hook.disk_hex.substring(0, 24)}...
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
