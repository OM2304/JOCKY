export interface RawReportData {
  task: string;
  agent: string;
  ts: string;
  build_id: string;
  sha256_payload: string;
  result: string;
  output: string;
  [key: string]: unknown;
}

export interface ForensicReport extends RawReportData {
  id: string;
  filename: string;
  parsedSummary?: {
    host?: string;
    os?: string;
    anomaliesCount: number;
    hasFlaggedProcs: boolean;
    hasSuspiciousPersistence: boolean;
  };
}

export interface DashboardMetrics {
  totalReports: number;
  uniqueAgents: number;
  latestActivity: string | null;
  totalTasks: number;
  anomaliesDetected: number;
}
