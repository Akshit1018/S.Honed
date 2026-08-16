export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingKind = "security" | "polish" | "solution";
export type TargetType = "url" | "github" | "notes";
export type Effort = "low" | "medium" | "high";
export type Grade = "A" | "B" | "C" | "D" | "F";
export type WorkStatus = "open" | "doing" | "done";

export type Finding = {
  id: string;
  kind: FindingKind;
  severity: Severity;
  title: string;
  summary: string;
  detail: string;
  evidence?: string;
  location?: string;
  cwe?: string;
  owasp?: string;
  cvss?: number;
  effort: Effort;
  fixTitle: string;
  fix: string;
};

export type AgentNote = {
  name: string;
  role: string;
  note: string;
};

export type HeaderCheck = {
  name: string;
  present: boolean;
  note: string;
};

export type SurfaceCheck = {
  id: string;
  label: string;
  status: "found" | "missing" | "n/a";
  detail: string;
};

export type CookieCheck = {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  issues: string[];
};

export type Vendor = {
  host: string;
  kind: "script" | "style" | "iframe" | "pixel" | "font" | "connect";
  category: string;
  sri: boolean;
  sample: string;
};

export type DnsCheck = {
  id: string;
  label: string;
  status: "found" | "missing" | "warn" | "n/a";
  detail: string;
};

export type CompareDelta = {
  previousScore: number;
  previousGrade: string;
  delta: number;
  added?: string[];
  resolved?: string[];
};

export type Report = {
  target: string;
  targetType: TargetType;
  finalUrl?: string;
  statusCode?: number;
  pageTitle?: string;
  tech: string[];
  score: number;
  grade: Grade;
  summary: string;
  findings: Finding[];
  agents: AgentNote[];
  inspectedAt: string;
  headerNames?: string[];
  headers?: HeaderCheck[];
  surface?: SurfaceCheck[];
  cookies?: CookieCheck[];
  vendors?: Vendor[];
  dns?: DnsCheck[];
  playbook?: string[];
  compare?: CompareDelta;
  enriched: boolean;
};

export type ScanRow = {
  id: string;
  user_id: string;
  target: string;
  target_type: TargetType;
  mode: string;
  status: "queued" | "running" | "complete" | "failed";
  score: number | null;
  grade: string | null;
  summary: string | null;
  report_json: string;
  error: string | null;
  created_at: string;
  completed_at: string | null;
};

export type ScanSummary = {
  id: string;
  target: string;
  targetType: TargetType;
  status: ScanRow["status"];
  score: number | null;
  grade: string | null;
  summary: string | null;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  createdAt: string;
  completedAt: string | null;
};

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function gradeFromScore(score: number): Grade {
  if (score >= 90) return "A";
  if (score >= 78) return "B";
  if (score >= 64) return "C";
  if (score >= 48) return "D";
  return "F";
}

export function countBySeverity(findings: Finding[]) {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export function parseReport(json: string): Report | null {
  try {
    return JSON.parse(json) as Report;
  } catch {
    return null;
  }
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}
