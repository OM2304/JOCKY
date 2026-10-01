'use client';

import React, { useState } from 'react';
import { ForensicReport } from '@/types/report';
import { Lock, Download, Check, ShieldCheck } from 'lucide-react';

interface ExportEvidenceButtonProps {
  report: ForensicReport;
}

export default function ExportEvidenceButton({ report }: ExportEvidenceButtonProps) {
  const [exporting, setExporting] = useState(false);
  const [exported, setExported] = useState(false);

  const handleExport = async () => {
    try {
      setExporting(true);

      const timestamp = new Date().toISOString();

      // Create base evidence bundle
      const baseEvidence = {
        metadata: {
          chain_of_custody_standard: 'NIST SP 800-86 / ISO 27037 Forensic Integrity',
          case_reference: 'SIH26148-JOCKY-LIVE',
          investigator_role: 'JOCKY Forensic Central Controller',
          export_timestamp: timestamp,
          agent_identifier: report.agent,
          task_identifier: report.task,
        },
        payload_record: {
          task: report.task,
          agent: report.agent,
          ts: report.ts,
          build_id: report.build_id,
          sha256_payload: report.sha256_payload,
          result: report.result,
          output: report.output,
          parsed_summary: report.parsedSummary,
        },
      };

      // Canonical JSON string for deterministic SHA-256 hashing
      const canonicalString = JSON.stringify(baseEvidence, Object.keys(baseEvidence).sort(), 2);

      // Compute cryptographic SHA-256 hash using browser native SubtleCrypto
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(canonicalString);
      const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const custodyHash = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

      // Final sealed evidence bundle containing chain_of_custody_hash
      const finalBundle = {
        ...baseEvidence,
        chain_of_custody_hash: custodyHash,
      };

      // Trigger browser download
      const blob = new Blob([JSON.stringify(finalBundle, null, 2)], {
        type: 'application/json;charset=utf-8',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `JOCKY_EVIDENCE_${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setExported(true);
      setTimeout(() => setExported(false), 2500);
    } catch (err) {
      console.error('[JOCKY] Failed to export evidence bundle:', err);
    } finally {
      setExporting(false);
    }
  };

  return (
    <button
      onClick={handleExport}
      disabled={exporting}
      className="inline-flex items-center gap-2 rounded-lg bg-primary px-3.5 py-2 text-xs font-semibold text-primary-foreground hover:bg-primary/90 transition-colors shadow-xs disabled:opacity-50"
      title="Export SHA-256 sealed forensic evidence bundle for judicial chain-of-custody"
    >
      {exported ? (
        <>
          <Check className="h-4 w-4" />
          <span>Evidence Bundle Exported</span>
        </>
      ) : (
        <>
          <Lock className="h-4 w-4" />
          <span>Export Evidence Bundle</span>
        </>
      )}
    </button>
  );
}
