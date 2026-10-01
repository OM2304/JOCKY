'use client';

import React, { useState } from 'react';
import { Terminal, Copy, Check, Radio, RefreshCw } from 'lucide-react';

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
    <div className="relative overflow-hidden rounded-xl border border-border bg-card p-8 text-center sm:p-12 shadow-xs">
      {/* Radar Graphic */}
      <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10 text-primary">
        <Radio className="h-8 w-8 text-primary" />
      </div>

      <div className="mt-5 max-w-lg mx-auto">
        <h3 className="text-lg font-bold tracking-tight text-foreground">
          Awaiting Agent Telemetry Reports
        </h3>
        <p className="mt-1.5 text-xs sm:text-sm text-muted-foreground leading-relaxed">
          No forensic JSON reports were found in{' '}
          <code className="rounded bg-muted px-1.5 py-0.5 text-foreground font-mono border border-border">
            ../agents/var/reports
          </code>
          . Once target machines complete their RAM triage scripts, findings will appear here automatically.
        </p>
      </div>

      {/* Quick Launch Instructions */}
      <div className="mt-7 max-w-2xl mx-auto rounded-xl border border-border bg-muted/30 p-4 text-left">
        <div className="flex items-center justify-between border-b border-border pb-3 mb-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <span className="text-xs font-semibold uppercase tracking-wider text-foreground">
              Dispatching Forensic Triage
            </span>
          </div>
          <span className="font-mono text-[10px] text-muted-foreground">CLI COMMANDS</span>
        </div>

        <div className="space-y-2.5 font-mono text-xs">
          {commands.map((item, idx) => (
            <div
              key={idx}
              className="rounded-lg bg-card p-2.5 border border-border hover:border-slate-400 dark:hover:border-slate-600 transition-colors shadow-2xs"
            >
              <div className="text-[11px] text-muted-foreground mb-1">{item.label}</div>
              <div className="flex items-center justify-between gap-2">
                <code className="text-foreground font-medium break-all">{item.cmd}</code>
                <button
                  onClick={() => handleCopy(item.cmd, idx)}
                  className="shrink-0 flex items-center gap-1 rounded bg-muted px-2 py-1 text-[11px] text-muted-foreground hover:text-foreground transition-colors"
                  title="Copy command"
                >
                  {copiedIndex === idx ? (
                    <>
                      <Check className="h-3 w-3 text-primary" />
                      <span className="text-primary font-medium">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
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
          className="flex items-center gap-2 rounded-lg border border-border bg-secondary px-4 py-2 text-xs font-semibold text-foreground hover:bg-accent transition-colors shadow-xs"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Scan Reports Directory</span>
        </button>
      </div>
    </div>
  );
}
