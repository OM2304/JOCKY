'use client';

import React, { useState, useMemo } from 'react';
import {
  Terminal,
  Copy,
  Check,
  Search,
  WrapText,
  Download,
  Maximize2,
  Minimize2,
  Hash,
  Shield,
} from 'lucide-react';

interface TerminalWindowProps {
  output: string;
  agentName?: string;
  taskId?: string;
}

export default function TerminalWindow({ output, agentName, taskId }: TerminalWindowProps) {
  const [copied, setCopied] = useState(false);
  const [wordWrap, setWordWrap] = useState(true);
  const [showLineNumbers, setShowLineNumbers] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [isFullScreen, setIsFullScreen] = useState(false);

  const lines = useMemo(() => {
    if (!output) return [];
    return output.split('\n');
  }, [output]);

  const filteredLines = useMemo(() => {
    if (!searchFilter.trim()) {
      return lines.map((line, index) => ({ line, originalIndex: index + 1 }));
    }
    const q = searchFilter.toLowerCase();
    return lines
      .map((line, index) => ({ line, originalIndex: index + 1 }))
      .filter((item) => item.line.toLowerCase().includes(q));
  }, [lines, searchFilter]);

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([output], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `jocky-${agentName || 'agent'}-${taskId || 'output'}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Syntax highlighting renderer for individual terminal lines
  const renderLineContent = (line: string) => {
    const trimmed = line.trim();

    // Section headers: === JOCKY HOST TRIAGE ===
    if (trimmed.startsWith('===') && trimmed.endsWith('===')) {
      return (
        <span className="font-bold text-sky-400">
          {line}
        </span>
      );
    }

    // High severity / alert lines: starts with !
    if (trimmed.startsWith('!')) {
      return (
        <span className="font-medium text-amber-300 bg-amber-500/10 px-1 py-0.5 rounded-sm border-l-2 border-amber-400">
          {line}
        </span>
      );
    }

    // Bracketed categories: [procs], [persistence], [network], [arp], [dns]
    if (trimmed.startsWith('[')) {
      const tagMatch = line.match(/^(\s*\[[^\]]+\])(.*)$/);
      if (tagMatch) {
        return (
          <>
            <span className="font-semibold text-emerald-400">
              {tagMatch[1]}
            </span>
            <span className="text-slate-200">{tagMatch[2]}</span>
          </>
        );
      }
    }

    // Key-value headers: host :, time :, os :, cwd :
    const kvMatch = line.match(/^(\s*(?:host|time|os|cwd)\s*:)(.*)$/i);
    if (kvMatch) {
      return (
        <>
          <span className="text-sky-300 font-medium">{kvMatch[1]}</span>
          <span className="text-slate-200">{kvMatch[2]}</span>
        </>
      );
    }

    // Flagged / Anomaly keywords
    if (line.includes('flagged:') || line.includes('anomaly') || line.includes('scored>=')) {
      return <span className="text-amber-300 font-medium">{line}</span>;
    }

    // Standard output in clean, readable high-contrast slate text
    return <span className="text-slate-300">{line}</span>;
  };

  return (
    <div
      className={`overflow-hidden rounded-xl border border-slate-800 bg-slate-900 shadow-md transition-all ${
        isFullScreen ? 'fixed inset-4 z-50 flex flex-col' : 'relative'
      }`}
    >
      {/* Terminal Title Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-slate-950/80 px-4 py-2.5">
        {/* Window Controls & Status */}
        <div className="flex items-center gap-3">
          {/* Subtle Window Dots */}
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80 inline-block"></span>
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80 inline-block"></span>
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
          </div>

          <div className="h-3.5 w-px bg-slate-800" />

          {/* Terminal Session Header */}
          <div className="flex items-center gap-2 font-mono text-xs text-slate-300">
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span className="font-semibold text-slate-100">
              {agentName || 'agent'}@jocky-ram
            </span>
            <span className="hidden sm:inline rounded bg-slate-800 px-1.5 py-0.2 text-[10px] text-slate-400 border border-slate-700">
              IN-MEMORY LOG
            </span>
          </div>
        </div>

        {/* Terminal Controls Bar */}
        <div className="flex items-center gap-1.5">
          {/* Quick Line Search */}
          <div className="relative hidden sm:block">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter log..."
              className="h-7 w-32 rounded-md border border-slate-800 bg-slate-950 pl-7 pr-2 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none focus:w-44 transition-all"
            />
          </div>

          {/* Toggle Line Numbers */}
          <button
            onClick={() => setShowLineNumbers(!showLineNumbers)}
            className={`flex h-7 items-center gap-1 rounded-md px-2 font-mono text-[11px] border transition-colors ${
              showLineNumbers
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
            }`}
            title="Toggle line numbers"
          >
            <Hash className="h-3 w-3" />
            <span className="hidden md:inline">Lines</span>
          </button>

          {/* Toggle Wrap */}
          <button
            onClick={() => setWordWrap(!wordWrap)}
            className={`flex h-7 items-center gap-1 rounded-md px-2 font-mono text-[11px] border transition-colors ${
              wordWrap
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
            }`}
            title="Toggle word wrap"
          >
            <WrapText className="h-3 w-3" />
            <span className="hidden md:inline">Wrap</span>
          </button>

          {/* Download Raw Log */}
          <button
            onClick={handleDownload}
            className="flex h-7 items-center gap-1 rounded-md border border-slate-800 bg-slate-950 px-2 font-mono text-[11px] text-slate-300 hover:text-white transition-colors"
            title="Download log"
          >
            <Download className="h-3 w-3" />
            <span className="hidden md:inline">Save</span>
          </button>

          {/* Copy Output Button */}
          <button
            onClick={handleCopy}
            className="flex h-7 items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 font-mono text-[11px] font-medium text-slate-200 hover:bg-slate-750 hover:text-white transition-colors"
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5 text-slate-400" />
                <span>Copy</span>
              </>
            )}
          </button>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullScreen(!isFullScreen)}
            className="flex h-7 w-7 items-center justify-center rounded-md border border-slate-800 bg-slate-950 text-slate-400 hover:text-white transition-colors"
            title={isFullScreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullScreen ? (
              <Minimize2 className="h-3.5 w-3.5" />
            ) : (
              <Maximize2 className="h-3.5 w-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Terminal Body */}
      <div
        className={`relative bg-slate-950 p-4 sm:p-5 font-mono text-xs leading-relaxed selection:bg-slate-800 selection:text-white overflow-auto ${
          isFullScreen ? 'flex-1' : 'max-h-[640px]'
        }`}
        style={{
          fontFamily:
            'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
        }}
      >
        {filteredLines.length === 0 ? (
          <div className="py-8 text-center text-slate-500 font-mono">
            {lines.length === 0
              ? 'No execution output returned by agent.'
              : `No output matching "${searchFilter}".`}
          </div>
        ) : (
          <div className="space-y-0.5">
            {filteredLines.map(({ line, originalIndex }) => (
              <div
                key={originalIndex}
                className={`flex gap-3 font-mono ${
                  wordWrap ? 'break-all whitespace-pre-wrap' : 'whitespace-pre overflow-x-auto'
                }`}
              >
                {showLineNumbers && (
                  <span className="select-none text-slate-600 text-right w-8 shrink-0 tabular-nums">
                    {originalIndex}
                  </span>
                )}
                <div className="flex-1">{renderLineContent(line)}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Terminal Footer Status Bar */}
      <div className="flex items-center justify-between border-t border-slate-800 bg-slate-950/80 px-4 py-2 font-mono text-[10px] text-slate-400">
        <div className="flex items-center gap-3">
          <span>
            LINES: <span className="text-slate-200 font-semibold">{lines.length}</span>
          </span>
          <span>•</span>
          <span>
            BYTES: <span className="text-slate-200 font-semibold">{new Blob([output]).size}</span>
          </span>
          {searchFilter && (
            <>
              <span>•</span>
              <span className="text-emerald-400">
                MATCHING: {filteredLines.length}
              </span>
            </>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-slate-400">
          <Shield className="h-3 w-3 text-emerald-400" />
          <span>RAM Execution • Clean Footprint</span>
        </div>
      </div>
    </div>
  );
}
