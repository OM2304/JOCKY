# JOCKY Forensic Central Management Dashboard

A modern, enterprise-grade Next.js (App Router) dashboard for the **JOCKY** stealth in-memory digital forensics and incident response framework (SIH26148 NTRO).

## Key Capabilities

- **Interactive Task Dispatcher (`POST /api/dispatch` & `DispatchModal.tsx`)**:
  - Live interactive modal to dispatch in-memory forensic triages (`triage`, `netprobe`, `stealth`, `ioc_sweep`, `lateral_recon`, `sandbox_guard`) directly from the dashboard.
  - Automatically executes the 4-stage pipeline:
    1. Generates 32-byte (64-char hex) JYCRYPT1 cipher key.
    2. Compiles script to polymorphic bytecode and encrypts container (`payload.jxp`).
    3. Queues task on the central controller (`agents.controller`).
    4. Target node executes in RAM via `agents.client` (with `JOCKY_KEY` in environment) and ingests findings back to the controller.
  - Real-time animated stepper UI with progress spinners and instant `router.refresh()` upon telemetry ingestion.

- **Chain-of-Custody Evidence Export (`components/ExportEvidenceButton.tsx`)**:
  - Available directly on the Forensic Report Detail page (`app/report/[id]/page.tsx`).
  - Computes a client-side SHA-256 cryptographic seal of the entire report payload using the browser's `window.crypto.subtle` API.
  - Generates a tamper-evident court/incident-response export bundle (`JOCKY_EVIDENCE_[timestamp].json`) embedding the `chain_of_custody_hash`, verifying forensic integrity from sensor execution to final courtroom export.

- **Polymorphic Engine Inspector (`/poly`, `POST /api/poly`)**:
  - Live inspection page proving the problem statement requirement that every compiled sensor instance exhibits zero hash collisions while preserving 100% semantic parity.
  - Interactive "Generate Mutated Builds" trigger that invokes `python -m jocky poly examples/stealth.jck -n 2 -o builds/` live on the host.
  - Compares Variant Alpha vs Variant Beta side-by-side with short signatures, full 64-char SHA-256 hashes, file sizes, and one-click copy.
  - Comprehensive documentation of the 5 compiler mutation vectors (Opcode Permutation, Decoy NOP Weaving, CFG Flattening, Constant Pool Encryption, and Symbol Mangling).
  - Embedded real-time compiler telemetry terminal.

- **Host Threat & Sensor Scanners (`/scanners`, `GET /api/scanners/byovd`, `GET /api/scanners/edr`)**:
  - **BYOVD Vulnerable Driver Hunter (`agents/byovd.py`)**:
    - Enumerates kernel driver staging paths against LOLDrivers database signatures.
    - Inspects arbitrary kernel read/write primitives, IOCTL handlers, and CVSS scores (> 8.0 highlighted in red).
    - Flags resident in-kernel vs staged driver states and detects PSAPI filtering / userland shims.
  - **EDR & AV Sensor Discovery (`agents/edr.py`)**:
    - Discovers active endpoint sensors (CrowdStrike Falcon, Sysmon, Defender, Carbon Black) across services, DLL maps, and process trees.
    - Inspects userland API hook differentials by comparing clean disk stubs against loaded memory export trampolines in `ntdll.dll` (e.g. `NtQuerySystemInformation` E9 jmp detours).

- **Enterprise Light & Dark Mode**:
  - Semantic CSS variable design system (`globals.css`) styled like Vercel, Stripe, and CrowdStrike Falcon.
  - Theme switching powered by `next-themes` with a Sun/Moon toggle in the navigation bar.
  - High-contrast accessible log terminal in dark slate (`bg-slate-950`).

- **Direct Filesystem Ingestion (`lib/data.ts`)**:
  - React Server Components read incoming agent reports directly from `../agents/var/reports` (with fallback to `./agents/var/reports` and `REPORTS_DIR`).
  - No database required; gracefully handles empty folders, missing directories, or malformed JSON.
  - Automatically sorts telemetry descending by timestamp.

- **Forensic Metrics Header (`components/MetricsHeader.tsx`)**:
  - **Total Reports Ingested**
  - **Unique Target Agents** seen in memory
  - **Latest Ingest** timestamp with UTC synchronization
  - **Anomaly Alert Tracker** summarizing flagged processes and hot persistence hooks across all endpoints.

- **Reports Census Table (`components/ReportsTable.tsx`)**:
  - Fast search by Agent Name, Task ID, Payload SHA-256, or Host keyword.
  - Filter by target Agent dropdown.
  - Monospace cryptographic hashes with one-click copy.
  - Clickable rows routing to detailed report inspection.

- **Report Detail View & Terminal Log Viewer (`app/report/[id]/page.tsx` & `components/TerminalWindow.tsx`)**:
  - Highly visible **"← Back to Dashboard"** navigation button with subtle hover animations.
  - Header with host & OS details and execution context.
  - Metadata card displaying full Task ID, Polymorphic Build ID, SHA-256 Payload Hash, and VM return status.
  - Enterprise log terminal with:
    - Syntax highlighting: section headers in sky blue, categories in emerald green, alerts in amber, standard logs in high-contrast slate.
    - Interactive controls: Copy Raw Log, Toggle Word Wrap, Toggle Line Numbers, In-Terminal Search/Filter, and Download Log (`.log`).

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
