import { createHash } from "node:crypto";
import type { ProcessRunnerPort, Severity } from "@hcheck/core";

export type CodelinterCapabilityStatus =
  "available" | "unavailable" | "failed" | "timed_out";

export interface CodelinterAdapterCapability {
  readonly available: boolean;
  readonly status: CodelinterCapabilityStatus;
  readonly version?: string;
  readonly reason?: string;
}

export interface ProbeCodelinterOptions {
  readonly runner: ProcessRunnerPort;
  readonly executable?: string;
  readonly cwd?: string;
}

export interface ImportedToolFinding {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly uri: string;
  readonly message: string;
}

export interface ImportedCodelinterReport {
  readonly parserVersion: "hcheck-codelinter-v1";
  readonly toolVersion?: string;
  readonly generatedAt?: string;
  readonly rawReportHash: `sha256:${string}`;
  readonly findings: readonly ImportedToolFinding[];
}

export const adapterStatus = "P1 录制样本与 Fake runner 合同已接入" as const;

export async function probeCodelinter({
  runner,
  executable = "codelinter",
  cwd,
}: ProbeCodelinterOptions): Promise<CodelinterAdapterCapability> {
  const result = await runner.run({
    executable,
    args: ["--version"],
    ...(cwd === undefined ? {} : { cwd }),
    timeoutMs: 10_000,
    maxStdoutBytes: 4 * 1024,
    maxStderrBytes: 4 * 1024,
  });
  if (result.status === "start_failed") {
    return {
      available: false,
      status: "unavailable",
      reason: "codelinter 不可用。",
    };
  }
  if (result.status === "timed_out" || result.timedOut) {
    return {
      available: false,
      status: "timed_out",
      reason: "codelinter 探测超时。",
    };
  }
  if (result.exitCode !== 0) {
    return {
      available: false,
      status: "failed",
      reason: "codelinter 版本探测失败。",
    };
  }
  const version = safeLine(result.stdout);
  return {
    available: true,
    status: "available",
    ...(version === undefined ? {} : { version }),
  };
}

export function parseCodelinterReport(text: string): ImportedCodelinterReport {
  rejectUnsafeRecordedText(text);
  const data = parseRecord(text);
  const findings = readArray(data.findings, "findings").map((item, index) => {
    const finding = requireRecord(item, `findings[${index}]`);
    return {
      ruleId: readString(finding.ruleId, `findings[${index}].ruleId`),
      severity: readSeverity(finding.severity, `findings[${index}].severity`),
      uri: normalizeRecordedUri(finding.file, `findings[${index}].file`),
      message: readString(finding.message, `findings[${index}].message`),
    };
  });
  return {
    parserVersion: "hcheck-codelinter-v1",
    ...(typeof data.toolVersion === "string"
      ? { toolVersion: data.toolVersion }
      : {}),
    ...(typeof data.generatedAt === "string"
      ? { generatedAt: data.generatedAt }
      : {}),
    rawReportHash: sha256Text(text),
    findings,
  };
}

function parseRecord(text: string): Record<string, unknown> {
  try {
    return requireRecord(JSON.parse(text), "codelinter report");
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new TypeError("codelinter 报告不是有效 JSON。");
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

function safeLine(value: string): string | undefined {
  const line = value.split(/\r?\n/u).find((item) => item.trim().length > 0);
  if (line === undefined) return undefined;
  return line.replace(
    /(?:\/Users\/|\/tmp\/|\/var\/|[A-Za-z]:[\\/])\S*/gu,
    "[REDACTED_PATH]",
  );
}

function sha256Text(text: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}
