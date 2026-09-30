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
        <span className="font-bold text-cyan-300 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]">
          {line}
        </span>
      );
    }

    // High severity / alert lines: starts with !
    if (trimmed.startsWith('!')) {
      return (
        <span className="font-semibold text-amber-300 bg-amber-500/10 px-1 py-0.5 rounded border-l-2 border-amber-400">
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
            <span className="font-bold text-[#00ff66] drop-shadow-[0_0_6px_rgba(0,255,102,0.4)]">
              {tagMatch[1]}
            </span>
            <span className="text-zinc-200">{tagMatch[2]}</span>
          </>
        );
      }
    }

    // Key-value headers: host :, time :, os :, cwd :
    const kvMatch = line.match(/^(\s*(?:host|time|os|cwd)\s*:)(.*)$/i);
    if (kvMatch) {
      return (
        <>
          <span className="text-cyan-400 font-semibold">{kvMatch[1]}</span>
          <span className="text-emerald-300">{kvMatch[2]}</span>
        </>
      );
    }

    // Flagged / Anomaly keywords
    if (line.includes('flagged:') || line.includes('anomaly') || line.includes('scored>=')) {
      return <span className="text-amber-300">{line}</span>;
    }

    // Standard output in classic neon-green/emerald terminal phosphor style
    return <span className="text-[#39ff14] text-opacity-90">{line}</span>;
  };

  return (
    <div
      className={`rounded-2xl border border-[#1e2638] bg-[#0e1117] shadow-2xl transition-all ${
        isFullScreen ? 'fixed inset-4 z-50 flex flex-col' : 'relative'
      }`}
    >
      {/* Terminal Title Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#1c2434] bg-[#090b10] px-4 py-3 rounded-t-2xl">
        {/* Window Controls & Status */}
        <div className="flex items-center gap-3">
          {/* Mac/Linux Terminal Dots */}
          <div className="flex items-center gap-1.5">
            <span className="h-3 w-3 rounded-full bg-[#ff5f56] inline-block shadow-[0_0_6px_rgba(255,95,86,0.6)]"></span>
            <span className="h-3 w-3 rounded-full bg-[#ffbd2e] inline-block shadow-[0_0_6px_rgba(255,189,46,0.6)]"></span>
            <span className="h-3 w-3 rounded-full bg-[#27c93f] inline-block shadow-[0_0_6px_rgba(39,201,63,0.6)]"></span>
          </div>

          <div className="h-4 w-[1px] bg-zinc-700" />

          {/* Terminal Session Header */}
          <div className="flex items-center gap-2 font-mono text-xs text-zinc-300">
            <Terminal className="h-4 w-4 text-[#00ff66]" />
            <span className="font-semibold text-white">
              tty0@jocky-vm: ~/{agentName || 'agent'}
            </span>
            <span className="hidden sm:inline rounded bg-[#00ff66]/10 px-1.5 py-0.5 text-[10px] font-mono text-[#00ff66] border border-[#00ff66]/30">
              IN-MEMORY PAYLOAD
            </span>
          </div>
        </div>

        {/* Terminal Controls Bar */}
        <div className="flex items-center gap-2">
          {/* Quick Line Search */}
          <div className="relative hidden sm:block">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter terminal..."
              className="h-7 w-36 rounded-md border border-[#1e2638] bg-[#121622] pl-8 pr-2 font-mono text-[11px] text-zinc-200 placeholder:text-zinc-500 focus:border-[#00ff66] focus:outline-none focus:w-48 transition-all"
            />
          </div>

          {/* Toggle Line Numbers */}
          <button
            onClick={() => setShowLineNumbers(!showLineNumbers)}
            className={`flex h-7 items-center gap-1 rounded-md px-2 font-mono text-[11px] border transition-colors ${
              showLineNumbers
                ? 'border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]'
                : 'border-[#1e2638] bg-[#121622] text-zinc-400 hover:text-zinc-200'
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
                ? 'border-[#00ff66]/40 bg-[#00ff66]/10 text-[#00ff66]'
                : 'border-[#1e2638] bg-[#121622] text-zinc-400 hover:text-zinc-200'
            }`}
            title="Toggle word wrap"
          >
            <WrapText className="h-3 w-3" />
            <span className="hidden md:inline">Wrap</span>
          </button>

          {/* Download Raw Log */}
          <button
            onClick={handleDownload}
            className="flex h-7 items-center gap-1 rounded-md border border-[#1e2638] bg-[#121622] px-2 font-mono text-[11px] text-zinc-300 hover:border-zinc-700 hover:text-white transition-colors"
            title="Download log"
          >
            <Download className="h-3 w-3" />
            <span className="hidden md:inline">Save</span>
          </button>

          {/* Copy Output Button */}
          <button
            onClick={handleCopy}
            className="flex h-7 items-center gap-1.5 rounded-md border border-[#00ff66]/40 bg-[#00ff66]/15 px-2.5 font-mono text-[11px] font-semibold text-[#00ff66] hover:bg-[#00ff66]/25 transition-colors shadow-[0_0_10px_rgba(0,255,102,0.15)]"
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Copy</span>
              </>
            )}
          </button>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsFullScreen(!isFullScreen)}
            className="flex h-7 w-7 items-center justify-center rounded-md border border-[#1e2638] bg-[#121622] text-zinc-400 hover:text-white transition-colors"
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
        className={`relative bg-[#0c0e14] p-4 sm:p-6 font-mono text-xs leading-relaxed selection:bg-[#00ff66]/30 selection:text-white overflow-auto ${
          isFullScreen ? 'flex-1' : 'max-h-[640px]'
        }`}
        style={{
          fontFamily:
            'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
        }}
      >
        {/* Subtle scanline effect overlay */}
        <div className="terminal-scanline absolute inset-0 pointer-events-none opacity-40" />

        {filteredLines.length === 0 ? (
          <div className="py-8 text-center text-zinc-500 font-mono">
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
                  <span className="select-none text-zinc-600 text-right w-8 shrink-0 tabular-nums">
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
      <div className="flex items-center justify-between border-t border-[#1c2434] bg-[#090b10] px-4 py-2 font-mono text-[10px] text-zinc-500 rounded-b-2xl">
        <div className="flex items-center gap-3">
          <span className="text-zinc-400">
            TOTAL LINES: <span className="text-zinc-200 font-semibold">{lines.length}</span>
          </span>
          <span>•</span>
          <span className="text-zinc-400">
            BYTES: <span className="text-zinc-200 font-semibold">{new Blob([output]).size}</span>
          </span>
          {searchFilter && (
            <>
              <span>•</span>
              <span className="text-[#00ff66]">
                MATCHING: {filteredLines.length}
              </span>
            </>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-[#00ff66]">
          <Shield className="h-3 w-3" />
          <span className="tracking-wide">ZERO ARTIFACTS PERSISTED ON AGENT</span>
        </div>
      </div>
    </div>
  );
}
