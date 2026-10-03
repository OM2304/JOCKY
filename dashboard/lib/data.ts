import fs from 'fs';
import path from 'path';
import { ForensicReport, DashboardMetrics, RawReportData } from '@/types/report';

/**
 * Resolves the reports directory path.
 * Primary target is ../agents/var/reports relative to project root.
 * Fallbacks include ./agents/var/reports and process.env.REPORTS_DIR.
 */
export function getReportsDirectory(): string {
  if (process.env.REPORTS_DIR) {
    return path.resolve(/*turbopackIgnore: true*/ process.env.REPORTS_DIR);
  }

  // Primary: ../agents/var/reports relative to Next.js project root
  const primaryPath = path.resolve(/*turbopackIgnore: true*/ process.cwd(), '../agents/var/reports');
  if (fs.existsSync(/*turbopackIgnore: true*/ primaryPath)) {
    return primaryPath;
  }

  // Fallback for execution from repository root: ./agents/var/reports
  const rootFallback = path.resolve(/*turbopackIgnore: true*/ process.cwd(), 'agents/var/reports');
  if (fs.existsSync(/*turbopackIgnore: true*/ rootFallback)) {
    return rootFallback;
  }

  return primaryPath;
}

/**
 * Helper to parse quick summary information out of the raw forensic output string
 */
function parseOutputSummary(output: string) {
  if (!output || typeof output !== 'string') {
    return {
      anomaliesCount: 0,
      hasFlaggedProcs: false,
      hasSuspiciousPersistence: false,
    };
  }

  const hostMatch = output.match(/host\s*:\s*([^\r\n]+)/i);
  const osMatch = output.match(/os\s*:\s*([^\r\n]+)/i);

  // Look for flagged procs or scored persistence
  const flaggedProcsMatch = output.match(/\[procs\][^\r\n]*flagged:\s*([1-9]\d*)/i);
  const persistenceScoreMatch = output.match(/\[persistence\][^\r\n]*scored>=2:\s*([1-9]\d*)/i);

  // Count exclamation points used by triage.jck to denote alert lines
  const alertLines = output.split('\n').filter((l) => l.trim().startsWith('!'));

  const flaggedProcsCount = flaggedProcsMatch ? parseInt(flaggedProcsMatch[1], 10) : 0;
  const hotPersistenceCount = persistenceScoreMatch ? parseInt(persistenceScoreMatch[1], 10) : 0;

  const totalAnomalies = Math.max(alertLines.length, flaggedProcsCount + hotPersistenceCount);

  return {
    host: hostMatch ? hostMatch[1].trim() : undefined,
    os: osMatch ? osMatch[1].trim() : undefined,
    anomaliesCount: totalAnomalies,
    hasFlaggedProcs: flaggedProcsCount > 0,
    hasSuspiciousPersistence: hotPersistenceCount > 0,
  };
}

/**
 * Reads all forensic report JSON files from the reports directory,
 * parses each report gracefully, and returns an array sorted descending by timestamp.
 */
export async function getReports(): Promise<ForensicReport[]> {
  const dirPath = getReportsDirectory();

  if (!fs.existsSync(/*turbopackIgnore: true*/ dirPath)) {
    return [];
  }

  try {
    const fileEntries = await fs.promises.readdir(/*turbopackIgnore: true*/ dirPath, { withFileTypes: true });
    const jsonFiles = fileEntries.filter(
      (entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.json')
    );

    const reports: ForensicReport[] = [];

    for (const file of jsonFiles) {
      const fullPath = path.join(/*turbopackIgnore: true*/ dirPath, file.name);
      try {
        const fileContent = await fs.promises.readFile(/*turbopackIgnore: true*/ fullPath, 'utf-8');
        const rawJson: RawReportData = JSON.parse(fileContent);

        // Derive report ID from filename without .json extension
        const id = file.name.replace(/\.json$/i, '');

        reports.push({
          id,
          filename: file.name,
          task: rawJson.task || 'unknown-task',
          agent: rawJson.agent || 'unknown-agent',
          ts: rawJson.ts || new Date().toISOString(),
          build_id: rawJson.build_id || '',
          sha256_payload: rawJson.sha256_payload || '',
          result: rawJson.result ?? 'None',
          output: rawJson.output || '',
          parent_hash: rawJson.parent_hash,
          merkle_root: rawJson.merkle_root,
          parsedSummary: parseOutputSummary(rawJson.output || ''),
        });
      } catch (err) {
        console.error(`[JOCKY] Failed to parse report file: ${file.name}`, err);
        // Continue processing other files gracefully
      }
    }

    // Sort descending by timestamp (newest first)
    reports.sort((a, b) => {
      const timeA = new Date(a.ts).getTime();
      const timeB = new Date(b.ts).getTime();
      return (isNaN(timeB) ? 0 : timeB) - (isNaN(timeA) ? 0 : timeA);
    });

    return reports;
  } catch (error) {
    console.error('[JOCKY] Error reading reports directory:', error);
    return [];
  }
}

/**
 * Retrieves a single report by ID. Supports matching file ID or task ID.
 */
export async function getReportById(id: string): Promise<ForensicReport | null> {
  const reports = await getReports();
  // Exact match on file id or fallback to task id
  const report = reports.find((r) => r.id === id || r.task === id);
  return report || null;
}

/**
 * Calculates high-level aggregated metrics from report history.
 */
export function getDashboardMetrics(reports: ForensicReport[]): DashboardMetrics {
  const uniqueAgentsSet = new Set<string>();
  const uniqueTasksSet = new Set<string>();
  let totalAnomalies = 0;

  for (const report of reports) {
    if (report.agent) uniqueAgentsSet.add(report.agent);
    if (report.task) uniqueTasksSet.add(report.task);
    if (report.parsedSummary?.anomaliesCount) {
      totalAnomalies += report.parsedSummary.anomaliesCount;
    }
  }

  const latestActivity = reports.length > 0 ? reports[0].ts : null;

  return {
    totalReports: reports.length,
    uniqueAgents: uniqueAgentsSet.size,
    latestActivity,
    totalTasks: uniqueTasksSet.size,
    anomaliesDetected: totalAnomalies,
  };
}
