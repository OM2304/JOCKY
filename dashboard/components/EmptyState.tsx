'use client';

import React, { useState } from 'react';
import { Terminal, Shield, Copy, Check, Radar, RefreshCw, FolderSearch } from 'lucide-react';

export default function EmptyState() {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const commands = [
    {
      label: '1. Initialize controller storage',
      cmd: 'python -m agents.controller init',
    },
    {
      label: '2. Queue a triage payload task',
      cmd: 'python -m agents.controller add t.jxp --tag triage',
    },
    {
      label: '3. Run controller server on port 8177',
      cmd: 'python -m agents.controller serve --port 8177',
    },
    {
      label: '4. Execute target agent (RAM-only execution)',
      cmd: 'python -m agents.client --controller http://127.0.0.1:8177 --agent-name lab-node-01 --once',
    },
  ];

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="relative overflow-hidden rounded-2xl border border-[#1e2638] bg-[#0c0e14] p-8 text-center sm:p-12">
      {/* Radar Animation Graphic */}
      <div className="mx-auto flex h-24 w-24 items-center justify-center relative">
        <div className="absolute inset-0 rounded-full border border-[#00ff66]/20 animate-ping opacity-30" />
        <div className="absolute inset-2 rounded-full border border-dashed border-[#00ff66]/40 animate-spin" style={{ animationDuration: '10s' }} />
        <div className="flex h-16 w-16 items-center justify-center rounded-full border border-[#00ff66]/50 bg-[#00ff66]/10 text-[#00ff66]">
          <Radar className="h-8 w-8 animate-pulse text-[#00ff66]" />
        </div>
      </div>

      <div className="mt-6 max-w-lg mx-auto">
        <h3 className="font-mono text-xl font-bold tracking-tight text-white">
          Awaiting Agent Telemetry Reports
        </h3>
        <p className="mt-2 text-sm text-zinc-400 font-mono leading-relaxed">
          No forensic JSON reports were detected in{' '}
          <code className="rounded bg-[#121622] px-1.5 py-0.5 text-zinc-200 border border-[#1e2638]">
            ../agents/var/reports
          </code>
          . Once target machines complete their RAM triage scripts, findings will stream here in real time.
        </p>
      </div>

      {/* Quick Launch Instructions */}
      <div className="mt-8 max-w-2xl mx-auto rounded-xl border border-[#1e2638] bg-[#08090d] p-4 text-left">
        <div className="flex items-center justify-between border-b border-[#1e2638] pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-[#00ff66]" />
            <span className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-300">
              Quickstart: Dispatch A Forensic Task
            </span>
          </div>
          <span className="font-mono text-[10px] text-zinc-500">BASH / SHELL</span>
        </div>

        <div className="space-y-3 font-mono text-xs">
          {commands.map((item, idx) => (
            <div key={idx} className="group rounded-lg bg-[#0e121a] p-2.5 border border-[#1a2232] hover:border-[#2d3a52] transition-colors">
              <div className="text-[11px] text-zinc-400 mb-1">{item.label}</div>
              <div className="flex items-center justify-between gap-2">
                <code className="text-[#00ff66] break-all">{item.cmd}</code>
                <button
                  onClick={() => handleCopy(item.cmd, idx)}
                  className="shrink-0 flex items-center gap-1 rounded bg-[#161c28] px-2 py-1 text-[11px] text-zinc-300 hover:text-white hover:bg-[#20283a] transition-colors"
                  title="Copy command"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="h-3 w-3 text-[#00ff66]" />
                      <span className="text-[#00ff66]">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3 text-zinc-400" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-6 flex justify-center">
        <button
          onClick={() => window.location.reload()}
          className="flex items-center gap-2 rounded-lg border border-[#00ff66]/40 bg-[#00ff66]/10 px-4 py-2 font-mono text-xs font-semibold text-[#00ff66] hover:bg-[#00ff66]/20 transition-colors shadow-[0_0_15px_rgba(0,255,102,0.15)]"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>SCAN REPORTS DIRECTORY</span>
        </button>
      </div>
    </div>
  );
}
