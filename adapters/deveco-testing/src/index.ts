import { createHash } from "node:crypto";

export interface DevecoTestingAdapterCapability {
  readonly available: boolean;
  readonly version?: string;
  readonly reason?: string;
}

export type DevecoTestingCaseStatus =
  "passed" | "failed" | "skipped" | "blocked";

export interface ImportedDevecoTestingCase {
  readonly id: string;
  readonly status: DevecoTestingCaseStatus;
  readonly category: string;
  readonly device: string;
  readonly message: string;
}

export interface ImportedDevecoTestingSummary {
  readonly sourceKind: "official_ui_summary";
  readonly total: number;
  readonly passed: number;
  readonly failed: number;
  readonly warnings: number;
  readonly deviceCount: number;
}

export interface ImportedDevecoTestingOfficialUiSource {
  readonly sourceKind: "official_ui_transcription";
  readonly reportReferenceHash: `sha256:${string}`;
  readonly testedAt: string;
  readonly testDimension: string;
  readonly deviceFormFactor: string;
}

export interface ImportedDevecoTestingReport {
  readonly parserVersion: "hcheck-deveco-testing-v1";
  readonly reportVersion?: string;
  readonly testingVersion?: string;
  readonly generatedAt?: string;
  readonly rawReportHash: `sha256:${string}`;
  readonly redacted: true;
  readonly cases: readonly ImportedDevecoTestingCase[];
  readonly summary?: ImportedDevecoTestingSummary;
  readonly source?: ImportedDevecoTestingOfficialUiSource;
}

export const adapterStatus = "P2 受控报告导入合同已接入" as const;

export function parseDevecoTestingReport(
  text: string,
): ImportedDevecoTestingReport {
  const data = parseRecord(text);
  if ("internalDatabasePath" in data) {
    throw new TypeError("不支持内部数据库字段。");
  }
  requireAllowedFields(data);
  rejectUnsafeRecordedText(text);
  if (data.redacted !== true) {
    throw new TypeError("录制样本必须先脱敏。");
  }
  const cases = readArray(data.cases, "cases").map((item, index) => {
    const testingCase = requireRecord(item, `cases[${index}]`);
    return {
      id: readString(testingCase.id, `cases[${index}].id`),
      status: readCaseStatus(testingCase.status, `cases[${index}].status`),
      category: readString(testingCase.category, `cases[${index}].category`),
      device: readString(testingCase.device, `cases[${index}].device`),
      message: readString(testingCase.message, `cases[${index}].message`),
    };
  });
  const summary =
    data.summary === undefined ? undefined : readSummary(data.summary);
  const source =
    data.source === undefined ? undefined : readOfficialUiSource(data.source);
  if (summary !== undefined && cases.length > 0) {
    throw new TypeError("官方云测汇总不能包含逐用例结果。");
  }
  if (summary !== undefined && source === undefined) {
    throw new TypeError("官方云测汇总必须提供来源绑定。");
  }
  return {
    parserVersion: "hcheck-deveco-testing-v1",
    ...(typeof data.reportVersion === "string"
      ? { reportVersion: data.reportVersion }
      : {}),
    ...(typeof data.testingVersion === "string"
      ? { testingVersion: data.testingVersion }
      : {}),
    ...(typeof data.generatedAt === "string"
      ? { generatedAt: data.generatedAt }
      : {}),
    rawReportHash: sha256Text(text),
    redacted: true,
    cases,
    ...(summary === undefined ? {} : { summary }),
    ...(source === undefined ? {} : { source }),
  };
}

function requireAllowedFields(data: Record<string, unknown>): void {
  requireOnlyKeys(
    data,
    [
      "tool",
      "reportVersion",
      "testingVersion",
      "generatedAt",
      "redacted",
      "cases",
      "summary",
      "source",
    ],
    "DevEco Testing 报告",
  );
}

function requireOnlyKeys(
  data: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const allowedKeys = new Set(allowed);
  for (const key of Object.keys(data)) {
    if (!allowedKeys.has(key)) {
      throw new TypeError(`${label} 包含未支持字段。`);
    }
  }
}

function parseRecord(text: string): Record<string, unknown> {
  try {
    return requireRecord(JSON.parse(text), "DevEco Testing report");
  } catch (error) {
    if (error instanceof SyntaxError)
      throw new TypeError("DevEco Testing 报告不是有效 JSON。");
    throw error;
  }
}

function rejectUnsafeRecordedText(text: string): void {
  if (/(?:^|["\s])(?:\/Users\/|\/tmp\/|\/var\/|[A-Za-z]:[\\/])/u.test(text)) {
    throw new TypeError("录制样本必须先脱敏。");
  }
}

function readCaseStatus(
  value: unknown,
  label: string,
): DevecoTestingCaseStatus {
  if (
    value === "passed" ||
    value === "failed" ||
    value === "skipped" ||
    value === "blocked"
  ) {
    return value;
  }
  throw new TypeError(`${label} 无效。`);
}

function readSummary(value: unknown): ImportedDevecoTestingSummary {
  const summary = requireRecord(value, "summary");
  requireOnlyKeys(
    summary,
    ["sourceKind", "total", "passed", "failed", "warnings", "deviceCount"],
    "summary",
  );
  if (summary.sourceKind !== "official_ui_summary") {
    throw new TypeError("summary.sourceKind 无效。");
  }
  const total = readPositiveInteger(summary.total, "summary.total");
  const passed = readNonNegativeInteger(summary.passed, "summary.passed");
  const failed = readNonNegativeInteger(summary.failed, "summary.failed");
  const warnings = readNonNegativeInteger(summary.warnings, "summary.warnings");
  const deviceCount = readPositiveInteger(
    summary.deviceCount,
    "summary.deviceCount",
  );
  if (passed + failed > total || warnings > total) {
    throw new TypeError("summary 汇总计数不能超过 total。");
  }
  return {
    sourceKind: "official_ui_summary",
    total,
    passed,
    failed,
    warnings,
    deviceCount,
  };
}

function readOfficialUiSource(
  value: unknown,
): ImportedDevecoTestingOfficialUiSource {
  const source = requireRecord(value, "source");
  requireOnlyKeys(
    source,
    [
      "sourceKind",
      "reportReferenceHash",
      "testedAt",
      "testDimension",
      "deviceFormFactor",
    ],
    "source",
  );
  if (source.sourceKind !== "official_ui_transcription") {
    throw new TypeError("source.sourceKind 无效。");
  }
  const reportReferenceHash = readSha256(
    source.reportReferenceHash,
    "source.reportReferenceHash",
  );
  return {
    sourceKind: "official_ui_transcription",
    reportReferenceHash,
    testedAt: readString(source.testedAt, "source.testedAt"),
    testDimension: readString(source.testDimension, "source.testDimension"),
    deviceFormFactor: readString(
      source.deviceFormFactor,
      "source.deviceFormFactor",
    ),
  };
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

function readNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  throw new TypeError(`${label} 必须是非负整数。`);
}

function readPositiveInteger(value: unknown, label: string): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return value;
  }
  throw new TypeError(`${label} 必须是正整数。`);
}

function readSha256(value: unknown, label: string): `sha256:${string}` {
  if (typeof value === "string" && /^sha256:[0-9a-f]{64}$/u.test(value)) {
    return value as `sha256:${string}`;
  }
  throw new TypeError(`${label} 必须是 SHA-256。`);
}

function sha256Text(text: string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(text).digest("hex")}`;
}
