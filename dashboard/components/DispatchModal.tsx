'use client';

import React, { useState } from 'react';
import {
  X,
  Play,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Cpu,
  FileCode2,
  Layers,
  ShieldAlert,
  ArrowRight,
} from 'lucide-react';

interface DispatchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  knownAgents?: string[];
}

interface StepState {
  title: string;
  desc: string;
  status: 'pending' | 'in-progress' | 'completed' | 'error';
}

export interface ForensicScriptOption {
  slug: string;
  name: string;
  description: string;
}

export const FORENSIC_SCRIPTS: ForensicScriptOption[] = [
  {
    slug: 'triage',
    name: 'triage.jck',
    description: 'Full host triage, process census & persistence sweep',
  },
  {
    slug: 'netprobe',
    name: 'netprobe.jck',
    description: 'Network sockets, high-risk ports & C2 beacon hunt',
  },
  {
    slug: 'stealth',
    name: 'stealth.jck',
    description: 'Anti-forensics audit & mathematical timestomping detector',
  },
  {
    slug: 'ioc_sweep',
    name: 'ioc_sweep.jck',
    description: 'In-memory IoC sweep (Magic bytes & YARA-lite string hunt)',
  },
  {
    slug: 'lateral_recon',
    name: 'lateral_recon.jck',
    description: 'Lateral movement recon (ARP hypervisors & SSH/Cloud credential audit)',
  },
  {
    slug: 'sandbox_guard',
    name: 'sandbox_guard.jck',
    description: 'Anti-analysis gatekeeper (Debugger hunt & sandbox evasion)',
  },
];

const INITIAL_STEPS: StepState[] = [
  {
    title: 'Polymorphic Compilation & Keyed Encryption',
    desc: 'Applying Master Cipher Key and compiling byte container',
    status: 'pending',
  },
  {
    title: 'Task Queued to Central Controller',
    desc: 'Registering encrypted task blob in controller registry with unique tag',
    status: 'pending',
  },
  {
    title: 'In-Memory Execution (Zero-Disk Write)',
    desc: 'Target node pulls payload, verifies signature, and executes bytecode in RAM',
    status: 'pending',
  },
  {
    title: 'Telemetry Ingestion',
    desc: 'Encrypted findings ingested by controller and written to reports census',
    status: 'pending',
  },
];

export default function DispatchModal({
  isOpen,
  onClose,
  onSuccess,
  knownAgents = [],
}: DispatchModalProps) {
  const [targetNode, setTargetNode] = useState(
    knownAgents.length > 0 ? knownAgents[0] : 'local-workstation-01'
  );
  const [scriptName, setScriptName] = useState('triage');
  const [isRunning, setIsRunning] = useState(false);
  const [steps, setSteps] = useState<StepState[]>(INITIAL_STEPS);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);

  React.useEffect(() => {
    if (knownAgents.length > 0 && targetNode === 'local-workstation-01') {
      setTargetNode(knownAgents[0]);
    }
  }, [knownAgents]);

  if (!isOpen) return null;

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsRunning(true);
    setErrorMsg(null);
    setIsSuccess(false);

    // Reset steps
    setSteps(INITIAL_STEPS.map((s, idx) => ({ ...s, status: idx === 0 ? 'in-progress' : 'pending' })));

    // Sequential timing simulation for initial stages while API request processes
    const timer1 = setTimeout(() => {
      setSteps((prev) =>
        prev.map((s, idx) => {
          if (idx === 0) return { ...s, status: 'completed' };
          if (idx === 1) return { ...s, status: 'in-progress' };
          return s;
        })
      );
    }, 600);

    const timer2 = setTimeout(() => {
      setSteps((prev) =>
        prev.map((s, idx) => {
          if (idx <= 1) return { ...s, status: 'completed' };
          if (idx === 2) return { ...s, status: 'in-progress' };
          return s;
        })
      );
    }, 1300);

    try {
      const res = await fetch('/api/dispatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetNode, scriptName }),
      });

      const data = await res.json();

      clearTimeout(timer1);
      clearTimeout(timer2);

      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to dispatch task to target agent.');
      }

      // Step 2 & 3 marked complete, Step 4 in progress then complete
      setSteps((prev) =>
        prev.map((s, idx) => {
          if (idx < 3) return { ...s, status: 'completed' };
          if (idx === 3) return { ...s, status: 'in-progress' };
          return s;
        })
      );

      setTimeout(() => {
        setSteps((prev) => prev.map((s) => ({ ...s, status: 'completed' })));
        setIsSuccess(true);
        setTimeout(() => {
          onSuccess();
          onClose();
          // Reset modal state
          setIsRunning(false);
          setSteps(INITIAL_STEPS);
        }, 1200);
      }, 600);
    } catch (err: unknown) {
      clearTimeout(timer1);
      clearTimeout(timer2);
      const msg = err instanceof Error ? err.message : String(err);
      setErrorMsg(msg);
      setSteps((prev) =>
        prev.map((s) => (s.status === 'in-progress' ? { ...s, status: 'error' } : s))
      );
    }
  };

  const handleReset = () => {
    setIsRunning(false);
    setErrorMsg(null);
    setIsSuccess(false);
    setSteps(INITIAL_STEPS);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg rounded-2xl border border-border bg-card p-6 shadow-2xl text-foreground">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border pb-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-primary/20 bg-primary/10 text-primary">
              <Play className="h-4 w-4 fill-primary text-primary" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">Dispatch Forensic Task</h2>
              <p className="text-xs text-muted-foreground">In-Memory RAM Payload Execution</p>
            </div>
          </div>
          {!isRunning && (
            <button
              onClick={onClose}
              className="rounded-lg p-1 text-muted-foreground hover:bg-muted hover:text-foreground transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {/* Content Body */}
        {!isRunning ? (
          /* Form View */
          <form onSubmit={handleLaunch} className="mt-5 space-y-4">
            {/* Target Node Input */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Target Agent Node</span>
              </label>
              <input
                type="text"
                required
                list="known-agents"
                value={targetNode}
                onChange={(e) => setTargetNode(e.target.value)}
                placeholder="e.g. lab-node-01 or workstation-dmz"
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs font-mono text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary shadow-xs"
              />
              <datalist id="known-agents">
                {knownAgents.map((agent) => (
                  <option key={agent} value={agent} />
                ))}
              </datalist>
              <p className="text-[11px] text-muted-foreground">
                Designated computer hostname or identifier for telemetry ingestion.
                {knownAgents.length > 0 && ' Select a known reporting agent or enter a new target.'}
              </p>
            </div>

            {/* Script Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <FileCode2 className="h-3.5 w-3.5 text-muted-foreground" />
                <span>Forensic Script (.jck)</span>
              </label>
              <select
                value={scriptName}
                onChange={(e) => setScriptName(e.target.value)}
                className="w-full rounded-lg border border-input bg-background px-3 py-2 text-xs text-foreground focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary shadow-xs cursor-pointer font-mono"
              >
                {FORENSIC_SCRIPTS.map((script) => (
                  <option key={script.slug} value={script.slug} className="font-sans">
                    {script.name} — {script.description}
                  </option>
                ))}
              </select>
              <div className="rounded-md bg-muted/50 p-2 border border-border/60 text-[11px] text-muted-foreground flex items-center justify-between">
                <span>Selected Payload:</span>
                <span className="font-mono text-foreground font-semibold">
                  examples/{scriptName}.jck
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Payload will be compiled into polymorphic bytecode and encrypted with the synchronized Master Cipher Key.
              </p>
            </div>

            {/* Action Buttons */}
            <div className="mt-6 flex items-center justify-end gap-2.5 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-border bg-card px-4 py-2 text-xs font-medium text-foreground hover:bg-muted transition-colors shadow-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors shadow-xs"
              >
                <Play className="h-3.5 w-3.5 fill-primary-foreground" />
                <span>Launch In-Memory Triage</span>
              </button>
            </div>
          </form>
        ) : (
          /* Live Stepper View */
          <div className="mt-5 space-y-6">
            <div className="space-y-4">
              {steps.map((step, idx) => (
                <div key={idx} className="flex items-start gap-3.5">
                  {/* Status Indicator */}
                  <div className="mt-0.5 shrink-0">
                    {step.status === 'completed' && (
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                        <CheckCircle2 className="h-4 w-4" />
                      </div>
                    )}
                    {step.status === 'in-progress' && (
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-primary border border-primary/20">
                        <Loader2 className="h-4 w-4 animate-spin" />
                      </div>
                    )}
                    {step.status === 'error' && (
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-destructive/10 text-destructive border border-destructive/20">
                        <AlertCircle className="h-4 w-4" />
                      </div>
                    )}
                    {step.status === 'pending' && (
                      <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-muted-foreground border border-border text-[11px] font-mono">
                        {idx + 1}
                      </div>
                    )}
                  </div>

                  {/* Step Text */}
                  <div className="flex-1">
                    <h4
                      className={`text-xs font-semibold ${
                        step.status === 'completed'
                          ? 'text-foreground'
                          : step.status === 'in-progress'
                          ? 'text-primary'
                          : step.status === 'error'
                          ? 'text-destructive'
                          : 'text-muted-foreground'
                      }`}
                    >
                      {step.title}
                    </h4>
                    <p className="text-[11px] text-muted-foreground leading-normal mt-0.5">
                      {step.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Error Message if Failed */}
            {errorMsg && (
              <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-3 text-xs text-destructive">
                <div className="font-semibold flex items-center gap-1.5 mb-1">
                  <ShieldAlert className="h-4 w-4" />
                  <span>Execution Failed</span>
                </div>
                <div className="font-mono text-[11px] break-all">{errorMsg}</div>
                <div className="mt-3 flex justify-end">
                  <button
                    onClick={handleReset}
                    className="rounded-md border border-border bg-card px-3 py-1.5 text-xs font-medium text-foreground hover:bg-muted"
                  >
                    Try Again
                  </button>
                </div>
              </div>
            )}

            {/* Success Banner */}
            {isSuccess && (
              <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-emerald-700 dark:text-emerald-400 flex items-center justify-between animate-in fade-in">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" />
                  <span className="font-semibold">Triage Complete! Ingesting Telemetry...</span>
                </div>
                <span className="text-[11px] font-mono">Updating census...</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
