import { createHash } from "node:crypto";
import type { Severity } from "@hcheck/core";

export interface AppanalyzerAdapterCapability {
  readonly available: boolean;
  readonly version?: string;
  readonly reason?: string;
}

export interface ImportedAppAnalyzerIssue {
  readonly id: string;
  readonly severity: Severity;
  readonly artifactUri: string;
  readonly message: string;
}

export interface ImportedAppAnalyzerReport {
  readonly parserVersion: "hcheck-appanalyzer-v1";
  readonly reportVersion?: string;
  readonly analyzerVersion?: string;
  readonly generatedAt?: string;
  readonly rawReportHash: `sha256:${string}`;
  readonly issues: readonly ImportedAppAnalyzerIssue[];
}

export const adapterStatus = "P1 正式导出报告导入合同已接入" as const;

export function parseAppAnalyzerReport(
  text: string,
): ImportedAppAnalyzerReport {
  const data = parseRecord(text);
  if ("internalDatabasePath" in data) {
    throw new TypeError("不支持内部数据库字段。");
  }
  rejectUnsafeRecordedText(text);
  const issues = readArray(data.issues, "issues").map((item, index) => {
    const issue = requireRecord(item, `issues[${index}]`);
    return {
      id: readString(issue.id, `issues[${index}].id`),
      severity: readSeverity(issue.severity, `issues[${index}].severity`),
      artifactUri: normalizeRecordedUri(
        issue.artifact,
        `issues[${index}].artifact`,
      ),
      message: readString(issue.message, `issues[${index}].message`),
    };
  });
  return {
    parserVersion: "hcheck-appanalyzer-v1",
    ...(typeof data.reportVersion === "string"
      ? { reportVersion: data.reportVersion }
      : {}),
    ...(typeof data.analyzerVersion === "string"
      ? { analyzerVersion: data.analyzerVersion }
      : {}),
    ...(typeof data.generatedAt === "string"
      ? { generatedAt: data.generatedAt }
      : {}),
    rawReportHash: sha256Text(text),
    issues,
  };
}

function parseRecord(text: string): Record<string, unknown> {
  try {
    return requireRecord(JSON.parse(text), "AppAnalyzer report");
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new TypeError("AppAnalyzer 报告不是有效 JSON。");
    throw error;
  }
}

function rejectUnsafeRecordedText(text: string): void {
  if (/(?:^|["\s])(?:\/Users\/|\/tmp\/|\/var\/|[A-Za-z]:[\\/])/u.test(text)) {
    throw new TypeError("录制样本必须先脱敏。");
  }
}

function normalizeRecordedUri(value: unknown, label: string): string {
  const uri = readString(value, label).replaceAll("\\", "/");
  if (uri.startsWith("/") || /^[A-Za-z]:\//u.test(uri) || uri.includes("..")) {
    throw new TypeError("录制样本必须先脱敏。");
  }
  return uri.replace(/^\.\/+/u, "").replace(/\/{2,}/gu, "/");
}

function readSeverity(value: unknown, label: string): Severity {
  if (
    value === "BLOCKER" ||
    value === "HIGH" ||
    value === "MEDIUM" ||
    value === "LOW" ||
    value === "INFO"
  ) {
    return value;
  }
  throw new TypeError(`${label} 无效。`);
}

function readArray(value: unknown, label: string): readonly unknown[] {
  if (Array.isArray(value)) return value;
  throw new TypeError(`${label} 必须是数组。`);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new TypeError(`${label} 必须是对象。`);
}

function readString(value: unknown, label: string): string {
  if (typeof value === "string" && value.length > 0) return value;
  throw new TypeError(`${label} 必须是非空字符串。`);
}

function sha256Text(text: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}
