# JOCKY Forensic Central Management Dashboard

A modern, cybersecurity-themed Next.js (App Router) dashboard for the **JOCKY** stealth in-memory digital forensics and incident response framework (SIH26148 NTRO).

## Features

- **Direct Filesystem Ingestion (`lib/data.ts`)**:
  - React Server Components read incoming agent reports directly from `../agents/var/reports` (with fallback to `./agents/var/reports` and `REPORTS_DIR`).
  - No database required; gracefully handles empty folders, missing directories, or malformed JSON.
  - Automatically sorts telemetry descending by timestamp.

- **Forensic Metrics Header (`components/MetricsHeader.tsx`)**:
  - **Total Reports Ingested**
  - **Unique Target Agents** seen in memory
  - **Latest Activity** timestamp with UTC synchronization
  - **Anomaly Alert Tracker** summarizing flagged processes and hot persistence hooks across all endpoints.

- **Reports Census Table (`components/ReportsTable.tsx`)**:
  - Fast search by Agent Name, Task ID, Payload SHA-256, or Host keyword.
  - Filter by target Agent dropdown.
  - Monospace cryptographic hashes with one-click copy.
  - Clickable rows routing to detailed report inspection.

- **Report Detail View & Hacker Terminal (`app/report/[id]/page.tsx` & `components/TerminalWindow.tsx`)**:
  - Agent header with host & OS details.
  - Metadata card displaying full Task ID, Polymorphic Build ID, SHA-256 Payload Hash, and VM return status.
  - Hacker/Forensic Terminal Window with:
    - Neon-green / phosphor syntax highlighting for JOCKY triage output (`=== HEADERS ===`, `[procs]`, `[persistence]`, `[network]`, `[arp]`, `[dns]`).
    - Alert and anomaly line highlighting (`!`, `flagged:`, `scored>=2`).
    - Interactive controls: Copy Raw Log, Toggle Word Wrap, Toggle Line Numbers, In-Terminal Search/Filter, and Download Log (`.log`).
    - Terminal status bar verifying RAM-only execution and artifact zero-footprint.

- **Empty States & Loading Skeletons**:
  - Beautiful radar scanner visual when `reports/` is empty, including copyable bash commands to dispatch triage tasks.
  - Fluid animated skeleton screens for instant visual feedback.

## Running the Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to view the dashboard.

To run a production build:
```bash
npm run build
npm start
```
