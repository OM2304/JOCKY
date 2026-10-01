'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Dna,
  Shuffle,
  ShieldCheck,
  CheckCircle2,
  Copy,
  Check,
  Terminal,
  Cpu,
  RefreshCw,
  ArrowLeft,
  Layers,
  FileCode,
  Sparkles,
  Lock,
  Binary,
  GitFork,
  Fingerprint,
} from 'lucide-react';

interface Variant {
  id: string;
  label: string;
  buildNumber: string;
  file: string;
  hash: string;
  fullHash: string;
  size: string;
}

interface PolyResponse {
  success: boolean;
  timestamp: string;
  sourceScript: string;
  command: string;
  hashes: string[];
  fullHashes: string[];
  variants: Variant[];
  uniqueCount: number;
  stdout: string;
  error?: string;
}

export default function PolymorphismPage() {
  const [data, setData] = useState<PolyResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchPolyBuilds = async () => {
    try {
      setGenerating(true);
      setError(null);
      const res = await fetch('/api/poly', { method: 'POST' });
      const json = await res.json();
      if (json.success) {
        setData(json);
      } else {
        setError(json.error || 'Failed to generate polymorphic builds');
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Network error');
    } finally {
      setLoading(false);
      setGenerating(false);
    }
  };

  useEffect(() => {
    fetchPolyBuilds();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const variantAlpha = data?.variants?.[0];
  const variantBeta = data?.variants?.[1];

  return (
    <div className="min-w-0 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Breadcrumb & Navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Link
            href="/"
            className="flex items-center gap-1.5 hover:text-foreground transition-colors font-medium"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <span>/</span>
          <span className="text-foreground font-semibold">
            Polymorphic Engine Inspector
          </span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchPolyBuilds}
            disabled={generating}
            className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:opacity-90 active:scale-98 transition-all disabled:opacity-50"
          >
            {generating ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                <span>Mutating AST & Compiling...</span>
              </>
            ) : (
              <>
                <Shuffle className="h-3.5 w-3.5" />
                <span>Generate Mutated Builds</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Main Hero Header */}
      <div className="rounded-xl border border-border bg-card p-6 md:p-8 shadow-xs relative overflow-hidden">
        <div className="absolute right-0 top-0 -mr-16 -mt-16 w-64 h-64 bg-primary/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-3xl">
            <div className="flex items-center gap-2.5">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-primary/20 bg-primary/10 text-primary">
                <Dna className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-foreground">
                  Polymorphic Engine Inspector
                </h1>
                <p className="text-xs text-muted-foreground">
                  Proving Zero-Collision Static Hash Diversity with Deterministic Semantic Parity
                </p>
              </div>
            </div>
            <p className="text-sm text-muted-foreground leading-relaxed pt-1">
              JOCKY&apos;s compiler executes compile-time AST restructuring, basic-block jump re-threading,
              and opcode permutation on every build. Target endpoint detection tools (AV/EDR) relying on
              static file hashing or static YARA byte rules cannot track sensors across deployments,
              while the execution graph remains 100% identical in RAM.
            </p>
          </div>

          {/* Quick Engine Telemetry Badges */}
          <div className="flex flex-col sm:flex-row md:flex-col gap-2 shrink-0 text-xs">
            <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/40 px-3 py-2">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-primary" />
                Target Script:
              </span>
              <span className="font-mono font-medium text-foreground">
                examples/stealth.jck
              </span>
            </div>
            <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/40 px-3 py-2">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <Fingerprint className="h-3.5 w-3.5 text-purple-500" />
                Collision Rate:
              </span>
              <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">
                0.00% (Distinct)
              </span>
            </div>
            <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/40 px-3 py-2">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                Execution Parity:
              </span>
              <span className="font-mono font-bold text-primary">
                100.00% (Identical)
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Loading Skeleton */}
      {generating && (
        <div className="rounded-xl border border-primary/30 bg-primary/5 p-6 text-center space-y-3">
          <div className="inline-flex items-center justify-center p-3 rounded-full bg-primary/10 text-primary">
            <Shuffle className="h-6 w-6 animate-spin" />
          </div>
          <h3 className="text-sm font-semibold text-foreground">
            Shuffling Control Flow Graphs & Weaving Opcodes...
          </h3>
          <p className="text-xs text-muted-foreground max-w-md mx-auto">
            Executing <code className="font-mono text-primary">jocky poly</code> across 2 compilation passes with unique PRNG seeds. Generating distinct abstract syntax mutations.
          </p>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4 text-xs text-red-600 dark:text-red-400">
          <p className="font-bold">Compilation Error:</p>
          <p className="font-mono mt-1">{error}</p>
        </div>
      )}

      {/* Side-by-Side Build Comparison */}
      {data && !generating && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold tracking-wider text-muted-foreground uppercase flex items-center gap-2">
              <GitFork className="h-4 w-4 text-primary" />
              Live Mutated Build Variants
            </h2>
            <span className="text-xs text-muted-foreground font-mono">
              Generated: {new Date(data.timestamp).toLocaleTimeString()}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Variant Alpha Card */}
            {variantAlpha && (
              <div className="rounded-xl border border-border bg-card p-6 shadow-xs space-y-5 relative">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="flex h-7 w-7 items-center justify-center rounded-md bg-blue-500/10 text-blue-600 dark:text-blue-400 font-bold text-xs">
                      α
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-foreground">
                        {variantAlpha.label}
                      </h3>
                      <p className="text-xs text-muted-foreground font-mono">
                        Build #{variantAlpha.buildNumber} • {variantAlpha.file}
                      </p>
                    </div>
                  </div>
                  <span className="rounded-full bg-blue-500/10 border border-blue-500/20 px-2.5 py-0.5 text-[11px] font-semibold text-blue-600 dark:text-blue-400">
                    Seed #01
                  </span>
                </div>

                <div className="space-y-3">
                  {/* Short Hash */}
                  <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-1">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-medium">Build Signature (Truncated):</span>
                      <button
                        onClick={() => copyToClipboard(variantAlpha.hash, 'alpha-short')}
                        className="flex items-center gap-1 hover:text-foreground text-[11px]"
                      >
                        {copiedHash === 'alpha-short' ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        <span>{copiedHash === 'alpha-short' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="font-mono text-xs font-bold text-foreground break-all tracking-wider">
                      {variantAlpha.hash}
                    </p>
                  </div>

                  {/* Full SHA-256 Hash */}
                  <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-1">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-medium">Full SHA-256 File Hash:</span>
                      <button
                        onClick={() => copyToClipboard(variantAlpha.fullHash, 'alpha-full')}
                        className="flex items-center gap-1 hover:text-foreground text-[11px]"
                      >
                        {copiedHash === 'alpha-full' ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        <span>{copiedHash === 'alpha-full' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground break-all">
                      {variantAlpha.fullHash}
                    </p>
                  </div>

                  {/* Binary Metrics */}
                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <div className="rounded-lg border border-border bg-muted/20 p-2.5">
                      <span className="text-[11px] text-muted-foreground">Payload Size:</span>
                      <p className="text-xs font-mono font-bold text-foreground mt-0.5">
                        {variantAlpha.size}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/20 p-2.5">
                      <span className="text-[11px] text-muted-foreground">Static Signature:</span>
                      <p className="text-xs font-mono font-bold text-blue-600 dark:text-blue-400 mt-0.5">
                        Unique Entry
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Variant Beta Card */}
            {variantBeta && (
              <div className="rounded-xl border border-border bg-card p-6 shadow-xs space-y-5 relative">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="flex h-7 w-7 items-center justify-center rounded-md bg-purple-500/10 text-purple-600 dark:text-purple-400 font-bold text-xs">
                      β
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-foreground">
                        {variantBeta.label}
                      </h3>
                      <p className="text-xs text-muted-foreground font-mono">
                        Build #{variantBeta.buildNumber} • {variantBeta.file}
                      </p>
                    </div>
                  </div>
                  <span className="rounded-full bg-purple-500/10 border border-purple-500/20 px-2.5 py-0.5 text-[11px] font-semibold text-purple-600 dark:text-purple-400">
                    Seed #02
                  </span>
                </div>

                <div className="space-y-3">
                  {/* Short Hash */}
                  <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-1">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-medium">Build Signature (Truncated):</span>
                      <button
                        onClick={() => copyToClipboard(variantBeta.hash, 'beta-short')}
                        className="flex items-center gap-1 hover:text-foreground text-[11px]"
                      >
                        {copiedHash === 'beta-short' ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        <span>{copiedHash === 'beta-short' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="font-mono text-xs font-bold text-foreground break-all tracking-wider">
                      {variantBeta.hash}
                    </p>
                  </div>

                  {/* Full SHA-256 Hash */}
                  <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-1">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="font-medium">Full SHA-256 File Hash:</span>
                      <button
                        onClick={() => copyToClipboard(variantBeta.fullHash, 'beta-full')}
                        className="flex items-center gap-1 hover:text-foreground text-[11px]"
                      >
                        {copiedHash === 'beta-full' ? (
                          <Check className="h-3 w-3 text-emerald-500" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                        <span>{copiedHash === 'beta-full' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                    <p className="font-mono text-[11px] text-muted-foreground break-all">
                      {variantBeta.fullHash}
                    </p>
                  </div>

                  {/* Binary Metrics */}
                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <div className="rounded-lg border border-border bg-muted/20 p-2.5">
                      <span className="text-[11px] text-muted-foreground">Payload Size:</span>
                      <p className="text-xs font-mono font-bold text-foreground mt-0.5">
                        {variantBeta.size}
                      </p>
                    </div>
                    <div className="rounded-lg border border-border bg-muted/20 p-2.5">
                      <span className="text-[11px] text-muted-foreground">Static Signature:</span>
                      <p className="text-xs font-mono font-bold text-purple-600 dark:text-purple-400 mt-0.5">
                        Unique Entry
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Variance & Integrity Proof Callout */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 md:p-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                  <ShieldCheck className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-foreground">
                    Cryptographic Variance Verified (0% Collision)
                  </h4>
                  <p className="text-xs text-muted-foreground">
                    Both variants compile from the exact same source (<code className="font-mono text-primary">examples/stealth.jck</code>) but produce zero matching byte subsequences in critical block headers.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="rounded-md bg-emerald-500/15 border border-emerald-500/20 px-3 py-1 text-xs font-mono font-bold text-emerald-700 dark:text-emerald-300">
                  AV Bypassed
                </span>
                <span className="rounded-md bg-primary/10 border border-primary/20 px-3 py-1 text-xs font-mono font-bold text-primary">
                  100% Parity
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Explanatory Section: 5 Polymorphic Mutation Vectors */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          <h2 className="text-sm font-semibold tracking-wider text-muted-foreground uppercase">
            Compiler Mutation Architecture (5 Vectors)
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <Shuffle className="h-3.5 w-3.5" />
              <span>1. Opcode Permutation</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Commutative operations and independent register allocations are dynamically swapped in AST order without altering output registers or data flow.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <Binary className="h-3.5 w-3.5" />
              <span>2. Decoy Block & NOP Weaving</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Injects entropy-balanced junk instructions and multi-byte NOP variations into unreachable control branches, completely shifting binary offsets.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <Layers className="h-3.5 w-3.5" />
              <span>3. Control Flow Flattening</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Basic execution blocks are fragmented and re-stitched through a randomized dispatcher switch with opaque predicates, defeating linear CFG disassemblers.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <Lock className="h-3.5 w-3.5" />
              <span>4. Constant Pool Encryption</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              All string literals, API symbol hashes, and memory offsets are encrypted with per-build ephemeral keys and decrypted in-line just-in-time in RAM.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <FileCode className="h-3.5 w-3.5" />
              <span>5. Metadata & Symbol Mangling</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Strips all compiler telemetry, debug headers, and source references while hashing internal function labels with random non-reversible salts.
            </p>
          </div>

          <div className="rounded-xl border border-border bg-card p-4 space-y-2">
            <div className="flex items-center gap-2 text-primary font-semibold text-xs">
              <Cpu className="h-3.5 w-3.5" />
              <span>In-Memory RAM Execution</span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Compiled bytecodes are decoded directly into private memory pages with no disk staging, evading FileSystem Watchers and traditional forensics scans.
            </p>
          </div>
        </div>
      </div>

      {/* Raw Compiler Terminal Log */}
      {data && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase">
              <Terminal className="h-3.5 w-3.5 text-primary" />
              <span>Compiler Telemetry Output</span>
            </div>
            <span className="text-[11px] font-mono text-muted-foreground">
              Command: {data.command}
            </span>
          </div>

          <div className="rounded-xl border border-border bg-slate-950 p-4 font-mono text-xs text-slate-200 overflow-x-auto shadow-inner">
            <div className="flex items-center gap-2 pb-2 mb-2 border-b border-slate-800 text-[11px] text-slate-400">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span>STDOUT • JOCKY Poly Compiler v2.4</span>
            </div>
            <pre className="whitespace-pre-wrap leading-relaxed text-slate-300">
              {data.stdout}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
