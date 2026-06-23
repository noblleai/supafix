export type Severity = 'critical' | 'warning' | 'info';

export interface Finding {
  severity: Severity;
  category: 'rls' | 'routes' | 'secrets' | 'storage' | 'injection' | 'auth';
  title: string;
  detail: string;
  file?: string;
  line?: number;
  fix?: string;
  autoFixable?: boolean;
}

export interface ScanStats {
  migrationFiles: number;
  tables: number;
  policies: number;
  routeFiles: number;
  handlers: number;
  sourceFiles: number;
  linesScanned: number;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface ScanResult {
  findings: Finding[];
  stats: ScanStats;
  ms: number;
  grade: Grade;
}
