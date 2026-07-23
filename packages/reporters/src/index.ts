import {
  HCheckError,
  SEVERITIES,
  compareCodePoints,
  compareFindings,
  validateEvidence,
  validateFinding,
  type Evidence,
  type Finding,
  type HCheckErrorCode,
  type Severity,
} from "@hcheck/core";

export interface ClockPort {
  now(): Date;
}

export interface RunIdPort {
  next(): string;
}

export interface RulePackReport {
  readonly id: string;
  readonly version: string;
}

export interface ProjectModuleReport {
  readonly name: string;
  readonly type: "entry" | "feature" | "har" | "shared" | "skill";
  readonly isExternal?: boolean;
}

export interface ProjectReport {
  readonly bundleName: string;
  readonly modules: readonly ProjectModuleReport[];
  readonly hasExternalModules: boolean;
}

export interface ReportError {
  readonly kind: HCheckErrorCode;
  readonly message: string;
}

export interface ScanReport {
  readonly schemaVersion: "1.0.0";
  readonly run: {
    readonly id: string;
    readonly hcheckVersion: string;
    readonly mode: "quick";
    readonly startedAt: string;
    readonly finishedAt: string;
    readonly rulePacks: readonly RulePackReport[];
  };
  readonly completeness: "COMPLETE" | "PARTIAL" | "FAILED";
  readonly project: ProjectReport;
  readonly summary: {
    readonly total: number;
    readonly bySeverity: Readonly<Record<Severity, number>>;
    readonly gate: "PASS" | "FAIL" | "INCOMPLETE";
  };
  readonly findings: readonly Finding[];
  readonly evidence: readonly Evidence[];
  readonly errors: readonly ReportError[];
  readonly incompleteReasons: readonly string[];
  readonly redaction: {
    readonly applied: true;
  };
}

export interface BuildScanReportInput {
  readonly hcheckVersion: string;
  readonly mode: "quick";
  readonly project: ProjectReport;
  readonly rulePacks: readonly RulePackReport[];
  readonly findings: readonly Finding[];
  readonly evidence: readonly Evidence[];
  readonly errors: readonly unknown[];
  readonly incompleteReasons: readonly string[];
  readonly gate: "PASS" | "FAIL";
}

export interface ReportBuilderPorts {
  readonly clock: ClockPort;
  readonly runId: RunIdPort;
}

const ERROR_MESSAGES: Readonly<Record<HCheckErrorCode, string>> = Object.freeze(
  {
    CONFIGURATION_ERROR: "配置无效。",
    UNSUPPORTED_PROJECT: "不支持该项目。",
    TOOL_UNAVAILABLE: "所需工具不可用。",
    TOOL_EXECUTION_ERROR: "工具执行失败。",
    BUILD_FAILED: "项目构建失败。",
    ARTIFACT_PARSE_ERROR: "构建产物解析失败。",
    EXTERNAL_SERVICE_UNAVAILABLE: "外部服务不可用。",
    CREDENTIAL_ERROR: "凭证不可用。",
    DEVICE_UNAVAILABLE: "设备不可用。",
    RULE_DEFINITION_ERROR: "规则定义无效。",
    EVIDENCE_INCOMPLETE: "证据收集不完整。",
    INTERNAL_ERROR: "内部执行失败。",
  },
);
const SAFE_IDENTIFIER = /^(?=.*\S)[A-Za-z0-9._@+-]+$/u;
const STRICT_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;
const MODULE_TYPES = new Set(["entry", "feature", "har", "shared", "skill"]);

export function buildScanReport(
  input: BuildScanReportInput,
  ports: ReportBuilderPorts,
): ScanReport {
  const started = readClock(ports.clock, "开始");
  validateInputContract(input);
  const runId = ports.runId.next();
  requireSafeIdentifier(runId, "运行 ID");

  const evidence = [...input.evidence];
  for (const item of evidence) {
    validateEvidence(item);
    rejectUnsafeReportContent(item, "Evidence");
  }
  evidence.sort((left, right) => compareCodePoints(left.id, right.id));
  const evidenceIds = new Set(evidence.map(({ id }) => id));

  const findings = [...input.findings];
  for (const item of findings) {
    validateFinding(item);
    rejectUnsafeReportContent(item, "Finding");
    for (const evidenceId of item.evidenceIds) {
      if (!evidenceIds.has(evidenceId as Evidence["id"])) {
        throw new TypeError(`Finding 的 Evidence ID 无法解析：${evidenceId}`);
      }
    }
  }
  findings.sort(compareFindings);

  const errors = input.errors.map(toReportError).sort(compareErrors);
  const incompleteReasons = [...input.incompleteReasons];
  for (const reason of incompleteReasons) requireSafeText(reason, "不完整原因");
  const errorReasons = errors.map(({ message }) => message);
  const allReasons = [...new Set([...incompleteReasons, ...errorReasons])].sort(
    compareCodePoints,
  );
  const hasEvidenceError = errors.some(
    ({ kind }) => kind === "EVIDENCE_INCOMPLETE",
  );
  const hasOtherError = errors.some(
    ({ kind }) => kind !== "EVIDENCE_INCOMPLETE",
  );
  const completeness = hasOtherError
    ? "FAILED"
    : hasEvidenceError || allReasons.length > 0
      ? "PARTIAL"
      : "COMPLETE";
  const finished = readClock(ports.clock, "结束");
  if (finished.getTime() < started.getTime()) {
    throw new TypeError("报告结束时间不得早于开始时间。");
  }

  const bySeverity: Record<Severity, number> = {
    BLOCKER: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const item of findings) bySeverity[item.severity] += 1;

  const report: ScanReport = {
    schemaVersion: "1.0.0",
    run: {
      id: runId,
      hcheckVersion: input.hcheckVersion,
      mode: input.mode,
      startedAt: started.toISOString(),
      finishedAt: finished.toISOString(),
      rulePacks: [...input.rulePacks].sort(compareRulePacks),
    },
    completeness,
    project: {
      bundleName: input.project.bundleName,
      modules: [...input.project.modules]
        .map((module) => ({
          name: module.name,
          type: module.type,
          ...(module.isExternal === undefined
            ? {}
            : { isExternal: module.isExternal }),
        }))
        .sort(
          (left, right) =>
            compareCodePoints(left.name, right.name) ||
            compareCodePoints(left.type, right.type),
        ),
      hasExternalModules: input.project.hasExternalModules,
    },
    summary: {
      total: findings.length,
      bySeverity,
      gate: completeness === "COMPLETE" ? input.gate : "INCOMPLETE",
    },
    findings,
    evidence,
    errors,
    incompleteReasons: allReasons,
    redaction: { applied: true },
  };
  rejectUnsafeReportContent(report, "报告");
  return cloneAndDeepFreeze(report);
}

export function renderTerminal(report: ScanReport): string {
  validateScanReport(report);
  const lines = [
    "鸿鉴 HCheck 扫描报告",
    `运行 ID：${report.run.id}`,
    `模式：${report.run.mode}`,
    `项目：${report.project.bundleName}`,
    `规则包：${report.run.rulePacks.map(({ id, version }) => `${id}@${version}`).join("、")}`,
    `完整性：${report.completeness}`,
    `门禁：${report.summary.gate}`,
    `问题总数：${report.summary.total}`,
    ...SEVERITIES.map(
      (severity) => `${severity}：${report.summary.bySeverity[severity]}`,
    ),
  ];

  if (report.errors.length > 0) {
    lines.push(
      "错误：",
      ...report.errors.map(({ kind, message }) => `- [${kind}] ${message}`),
    );
  }
  if (report.incompleteReasons.length > 0) {
    lines.push(
      "不完整原因：",
      ...report.incompleteReasons.map((reason) => `- ${reason}`),
    );
  }
  if (report.findings.length === 0 && report.completeness === "COMPLETE") {
    lines.push("未发现满足当前扫描范围的问题。");
  } else {
    for (const finding of report.findings) {
      const location = finding.locations[0];
      const position = location
        ? `${location.uri}${location.line === undefined ? "" : `:${location.line}`}${location.column === undefined ? "" : `:${location.column}`}`
        : "项目级";
      lines.push(
        `[${finding.severity}] ${finding.ruleId} ${finding.title}`,
        `  位置：${position}`,
        `  ${finding.message}`,
        `  修复：${finding.remediation.summary}`,
      );
    }
  }
  return `${lines.join("\n")}\n`;
}

export function renderJson(report: ScanReport): string {
  validateScanReport(report);
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function renderSarif(report: ScanReport): string {
  validateScanReport(report);
  const rules = [...new Set(report.findings.map((finding) => finding.ruleId))]
    .sort(compareCodePoints)
    .map((id) => {
      const finding = report.findings.find((item) => item.ruleId === id);
      return {
        id,
        name: finding?.title ?? id,
        shortDescription: { text: finding?.title ?? id },
        help: {
          text: finding?.remediation.summary ?? "查看 HCheck 规则说明。",
        },
      };
    });
  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "鸿鉴 HCheck",
            semanticVersion: report.run.hcheckVersion,
            rules,
          },
        },
        results: report.findings.map((finding) => {
          const location = finding.locations[0];
          return {
            ruleId: finding.ruleId,
            level: sarifLevel(finding.severity),
            message: { text: finding.message },
            properties: {
              severity: finding.severity,
              confidence: finding.confidence,
              applicability: finding.applicability,
              status: finding.status,
            },
            locations:
              location === undefined
                ? []
                : [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: location.uri },
                        ...(location.line === undefined
                          ? {}
                          : {
                              region: {
                                startLine: location.line,
                                ...(location.column === undefined
                                  ? {}
                                  : { startColumn: location.column }),
                              },
                            }),
                      },
                    },
                  ],
            partialFingerprints: { hcheck: finding.fingerprint },
          };
        }),
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function renderJunit(report: ScanReport): string {
  validateScanReport(report);
  const failures = report.findings.filter(
    (finding) => finding.status !== "suppressed",
  );
  const cases = failures.map(
    (finding) =>
      `  <testcase classname="${escapeXml(finding.ruleId)}" name="${escapeXml(finding.title)}">\n` +
      `    <failure message="${escapeXml(finding.message)}" type="${escapeXml(finding.severity)}">${escapeXml(finding.remediation.summary)}</failure>\n` +
      "  </testcase>",
  );
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuite name="hcheck" tests="${failures.length}" failures="${failures.length}" errors="${report.errors.length}" skipped="0">`,
    ...cases,
    "</testsuite>",
    "",
  ].join("\n");
}

export function renderHtml(report: ScanReport): string {
  validateScanReport(report);
  const findingRows =
    report.findings.length === 0
      ? '<tr><td colspan="6">未发现满足当前扫描范围的问题。</td></tr>'
      : report.findings
          .map((finding) => {
            const location = finding.locations[0];
            const position =
              location === undefined
                ? "项目级"
                : `${location.uri}${location.line === undefined ? "" : `:${location.line}`}${location.column === undefined ? "" : `:${location.column}`}`;
            return [
              "<tr>",
              `<td>${escapeXml(finding.severity)}</td>`,
              `<td>${escapeXml(finding.ruleId)}</td>`,
              `<td>${escapeXml(finding.title)}</td>`,
              `<td>${escapeXml(position)}</td>`,
              `<td>${escapeXml(finding.message)}</td>`,
              `<td>${escapeXml(finding.remediation.summary)}</td>`,
              "</tr>",
            ].join("");
          })
          .join("\n");
  const errorItems = report.errors
    .map(
      ({ kind, message }) =>
        `<li><code>${escapeXml(kind)}</code> ${escapeXml(message)}</li>`,
    )
    .join("");
  const incompleteItems = report.incompleteReasons
    .map((reason) => `<li>${escapeXml(reason)}</li>`)
    .join("");

  return [
    "<!doctype html>",
    '<html lang="zh-CN">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>鸿鉴 HCheck 扫描报告</title>",
    "<style>",
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:32px;color:#111827;background:#fff;line-height:1.5}",
    "main{max-width:1120px;margin:0 auto}",
    "table{width:100%;border-collapse:collapse;margin-top:16px}",
    "th,td{border:1px solid #d1d5db;padding:8px;text-align:left;vertical-align:top}",
    "th{background:#f3f4f6}",
    "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}",
    "</style>",
    "</head>",
    "<body>",
    "<main>",
    "<h1>鸿鉴 HCheck 扫描报告</h1>",
    `<p>运行 ID：<code>${escapeXml(report.run.id)}</code></p>`,
    `<p>项目：${escapeXml(report.project.bundleName)}；完整性：${escapeXml(report.completeness)}；门禁：${escapeXml(report.summary.gate)}；问题总数：${report.summary.total}</p>`,
    "<h2>问题</h2>",
    "<table>",
    "<thead><tr><th>严重性</th><th>规则</th><th>标题</th><th>位置</th><th>说明</th><th>修复建议</th></tr></thead>",
    `<tbody>${findingRows}</tbody>`,
    "</table>",
    report.errors.length === 0 ? "" : `<h2>错误</h2><ul>${errorItems}</ul>`,
    report.incompleteReasons.length === 0
      ? ""
      : `<h2>不完整原因</h2><ul>${incompleteItems}</ul>`,
    "</main>",
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

function sarifLevel(severity: Severity): "error" | "warning" | "note" {
  if (severity === "BLOCKER" || severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

function escapeXml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

export function validateScanReport(
  value: unknown,
): asserts value is ScanReport {
  requireExactRecord(
    value,
    [
      "schemaVersion",
      "run",
      "completeness",
      "project",
      "summary",
      "findings",
      "evidence",
      "errors",
      "incompleteReasons",
      "redaction",
    ],
    "扫描报告",
  );
  if (value.schemaVersion !== "1.0.0") {
    throw new TypeError("扫描报告 schemaVersion 无效。");
  }
  validateReportRun(value.run);
  validateProject(value.project as ProjectReport);
  if (!Array.isArray(value.findings) || !Array.isArray(value.evidence)) {
    throw new TypeError("扫描报告 Finding/Evidence 必须是数组。");
  }
  const findings = value.findings as unknown[];
  const evidence = value.evidence as unknown[];
  const evidenceIds = new Set<string>();
  for (const item of evidence) {
    validateEvidence(item);
    rejectUnsafeReportContent(item, "Evidence");
    if (evidenceIds.has(item.id)) throw new TypeError("Evidence ID 不得重复。");
    evidenceIds.add(item.id);
  }
  for (const item of findings) {
    validateFinding(item);
    rejectUnsafeReportContent(item, "Finding");
    for (const evidenceId of item.evidenceIds) {
      if (!evidenceIds.has(evidenceId)) {
        throw new TypeError(`Finding 的 Evidence ID 无法解析：${evidenceId}`);
      }
    }
  }

  requireExactRecord(
    value.summary,
    ["total", "bySeverity", "gate"],
    "报告汇总",
  );
  const summary = value.summary;
  if (!Number.isInteger(summary.total) || (summary.total as number) < 0) {
    throw new TypeError("报告汇总总数无效。");
  }
  requireExactRecord(summary.bySeverity, SEVERITIES, "严重性汇总");
  const bySeverity = summary.bySeverity;
  const expectedBySeverity: Record<Severity, number> = {
    BLOCKER: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const item of findings as Finding[])
    expectedBySeverity[item.severity] += 1;
  for (const severity of SEVERITIES) {
    if (
      !Number.isInteger(bySeverity[severity]) ||
      bySeverity[severity] !== expectedBySeverity[severity]
    ) {
      throw new TypeError("报告严重性汇总与 Finding 不一致。");
    }
  }
  if (summary.total !== findings.length) {
    throw new TypeError("报告总数与 Finding 不一致。");
  }

  if (!Array.isArray(value.errors) || !Array.isArray(value.incompleteReasons)) {
    throw new TypeError("扫描报告错误与不完整原因必须是数组。");
  }
  const errors = value.errors as unknown[];
  for (const error of errors) {
    requireExactRecord(error, ["kind", "message"], "报告错误");
    if (
      typeof error.kind !== "string" ||
      !Object.hasOwn(ERROR_MESSAGES, error.kind) ||
      error.message !== ERROR_MESSAGES[error.kind as HCheckErrorCode]
    ) {
      throw new TypeError("报告错误合同无效。");
    }
  }
  for (const reason of value.incompleteReasons as unknown[]) {
    requireSafeText(reason, "不完整原因");
  }
  const errorKinds = errors.map(
    (error) => (error as { readonly kind: HCheckErrorCode }).kind,
  );
  const expectedCompleteness = errorKinds.some(
    (kind) => kind !== "EVIDENCE_INCOMPLETE",
  )
    ? "FAILED"
    : errorKinds.length > 0 || value.incompleteReasons.length > 0
      ? "PARTIAL"
      : "COMPLETE";
  if (value.completeness !== expectedCompleteness) {
    throw new TypeError("报告完整性与错误状态不一致。");
  }
  if (
    (expectedCompleteness === "COMPLETE" &&
      summary.gate !== "PASS" &&
      summary.gate !== "FAIL") ||
    (expectedCompleteness !== "COMPLETE" && summary.gate !== "INCOMPLETE")
  ) {
    throw new TypeError("报告完整性与门禁状态不一致。");
  }
  requireExactRecord(value.redaction, ["applied"], "报告脱敏状态");
  if (value.redaction.applied !== true) {
    throw new TypeError("报告必须标记为已脱敏。");
  }
  rejectUnsafeReportContent(value, "报告");
}

function validateReportRun(value: unknown): void {
  requireExactRecord(
    value,
    ["id", "hcheckVersion", "mode", "startedAt", "finishedAt", "rulePacks"],
    "报告运行信息",
  );
  requireSafeIdentifier(value.id, "运行 ID");
  if (
    typeof value.hcheckVersion !== "string" ||
    !STRICT_SEMVER.test(value.hcheckVersion)
  ) {
    throw new TypeError("HCheck 版本必须是合法 SemVer。");
  }
  if (value.mode !== "quick") throw new TypeError("报告模式仅支持 quick。");
  const startedAt = parseReportDate(value.startedAt, "开始");
  const finishedAt = parseReportDate(value.finishedAt, "结束");
  if (finishedAt.getTime() < startedAt.getTime()) {
    throw new TypeError("报告结束时间不得早于开始时间。");
  }
  if (!Array.isArray(value.rulePacks) || value.rulePacks.length === 0) {
    throw new TypeError("报告规则包无效。");
  }
  const ids = new Set<string>();
  for (const pack of value.rulePacks) {
    requireExactRecord(pack, ["id", "version"], "规则包");
    requireSafeIdentifier(pack.id, "规则包 ID");
    if (typeof pack.version !== "string" || !STRICT_SEMVER.test(pack.version)) {
      throw new TypeError("规则包版本无效。");
    }
    if (ids.has(pack.id)) throw new TypeError("规则包 ID 不得重复。");
    ids.add(pack.id);
  }
  if (!ids.has("hcheck-p0"))
    throw new TypeError("报告至少需要 hcheck-p0 规则包。");
}

function parseReportDate(value: unknown, label: string): Date {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d\.\d{3}Z$/u.test(value)
  ) {
    throw new TypeError(`报告${label}时间必须是严格 UTC 日期。`);
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) {
    throw new TypeError(`报告${label}时间必须是严格 UTC 日期。`);
  }
  return date;
}

function validateInputContract(input: BuildScanReportInput): void {
  requireExactRecord(
    input,
    [
      "hcheckVersion",
      "mode",
      "project",
      "rulePacks",
      "findings",
      "evidence",
      "errors",
      "incompleteReasons",
      "gate",
    ],
    "报告输入",
  );
  if (!STRICT_SEMVER.test(input.hcheckVersion)) {
    throw new TypeError("HCheck 版本必须是合法 SemVer。");
  }
  if (input.mode !== "quick") throw new TypeError("报告模式仅支持 quick。");
  if (input.gate !== "PASS" && input.gate !== "FAIL") {
    throw new TypeError("报告门禁无效。");
  }
  if (
    !Array.isArray(input.rulePacks) ||
    input.rulePacks.length === 0 ||
    !input.rulePacks.some(({ id }) => id === "hcheck-p0")
  ) {
    throw new TypeError("报告至少需要 hcheck-p0 规则包。");
  }
  for (const pack of input.rulePacks) {
    requireExactRecord(pack, ["id", "version"], "规则包");
    requireSafeIdentifier(pack.id, "规则包 ID");
    if (typeof pack.version !== "string" || !STRICT_SEMVER.test(pack.version)) {
      throw new TypeError("规则包版本无效。");
    }
  }
  if (
    new Set(input.rulePacks.map(({ id }) => id)).size !== input.rulePacks.length
  ) {
    throw new TypeError("规则包 ID 不得重复。");
  }
  validateProject(input.project);
  for (const [label, value] of [
    ["findings", input.findings],
    ["evidence", input.evidence],
    ["errors", input.errors],
    ["incompleteReasons", input.incompleteReasons],
  ] as const) {
    if (!Array.isArray(value))
      throw new TypeError(`报告 ${label} 必须是数组。`);
  }
}

function validateProject(project: ProjectReport): void {
  requireExactRecord(
    project,
    ["bundleName", "modules", "hasExternalModules"],
    "项目摘要",
  );
  if (
    !SAFE_IDENTIFIER.test(project.bundleName) ||
    !project.bundleName.includes(".")
  ) {
    throw new TypeError("项目摘要 bundleName 无效。");
  }
  if (!Array.isArray(project.modules))
    throw new TypeError("项目摘要 modules 无效。");
  if (typeof project.hasExternalModules !== "boolean") {
    throw new TypeError("项目摘要 hasExternalModules 无效。");
  }
  for (const module of project.modules) {
    requireExactRecord(module, ["name", "type"], "项目模块摘要", [
      "isExternal",
    ]);
    requireSafeIdentifier(module.name, "项目模块名");
    if (typeof module.type !== "string" || !MODULE_TYPES.has(module.type)) {
      throw new TypeError("项目模块类型无效。");
    }
    if (
      module.isExternal !== undefined &&
      typeof module.isExternal !== "boolean"
    ) {
      throw new TypeError("项目模块外部标记无效。");
    }
  }
  const actualExternal = project.modules.some(
    ({ isExternal }) => isExternal === true,
  );
  if (actualExternal !== project.hasExternalModules) {
    throw new TypeError("项目摘要外部模块标记不一致。");
  }
}

function requireExactRecord(
  value: unknown,
  required: readonly string[],
  label: string,
  optional: readonly string[] = [],
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} 必须是普通对象。`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} 必须是普通对象。`);
  }
  const allowed = new Set([...required, ...optional]);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new TypeError(`${label}字段合同无效。`);
  }
}

function toReportError(error: unknown): ReportError {
  const kind = error instanceof HCheckError ? error.code : "INTERNAL_ERROR";
  return { kind, message: ERROR_MESSAGES[kind] };
}

function compareErrors(left: ReportError, right: ReportError): number {
  return compareCodePoints(left.kind, right.kind);
}

function compareRulePacks(left: RulePackReport, right: RulePackReport): number {
  return (
    compareCodePoints(left.id, right.id) ||
    compareCodePoints(left.version, right.version)
  );
}

function readClock(clock: ClockPort, stage: string): Date {
  const value = clock.now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new TypeError(`报告${stage}时间必须是有效 UTC 日期。`);
  }
  return new Date(value.getTime());
}

function requireSafeIdentifier(
  value: unknown,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) {
    throw new TypeError(`${label}无效。`);
  }
}

function requireSafeText(
  value: unknown,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    throw new TypeError(`${label}包含不安全内容。`);
  }
  rejectUnsafeString(value, label);
}

function rejectUnsafeReportContent(value: unknown, label: string): void {
  const visit = (current: unknown): void => {
    if (typeof current === "string") {
      rejectUnsafeString(current, label);
      return;
    }
    if (Array.isArray(current)) {
      for (const child of current) visit(child);
      return;
    }
    if (current !== null && typeof current === "object") {
      for (const [key, child] of Object.entries(current)) {
        rejectUnsafeString(key, label);
        visit(child);
      }
    }
  };
  visit(value);
}

function rejectUnsafeString(value: string, label: string): void {
  if (
    hasUnsafeControlCharacter(value) ||
    hasUnsafeCredentialAssignment(value) ||
    /\b(?:HOME|USERPROFILE|WORKSPACE)\s*=/u.test(value) ||
    /(?:^|[^A-Za-z0-9/])\/(?!\/)(?:[^/\s，。；：、（）()]+\/)+[^/\s，。；：、（）()]+/u.test(
      value,
    ) ||
    /(?:^|[^A-Za-z0-9])[A-Za-z]:[\\/][^\\/\s，。；：、（）()]+/u.test(value) ||
    /(?:^|[^\\A-Za-z0-9])\\\\[^\\\s]+\\[^\\\s]+(?:\\[^\\\s]+)?/u.test(value) ||
    /\bfile:\/\//iu.test(value) ||
    /\bBearer\s+[A-Za-z0-9._~+/-]+/u.test(value) ||
    /\b(?:AKIA[0-9A-Z]{16}|gh[oprsu]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,})\b/u.test(
      value,
    )
  ) {
    throw new TypeError(`${label}包含不安全内容。`);
  }
}

function hasUnsafeControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) as number;
    if (
      (codePoint <= 0x1f && codePoint !== 0x09) ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      codePoint === 0x2028 ||
      codePoint === 0x2029
    ) {
      return true;
    }
  }
  return false;
}

function hasUnsafeCredentialAssignment(value: string): boolean {
  const assignments = value.matchAll(
    /\b(?:apiKey|credential|accessKey|access[ _-]?token|password|token|secret)\b\s*[:=：]\s*([^\s，。；、）)]+)/giu,
  );
  for (const assignment of assignments) {
    const assignedValue = assignment[1];
    if (assignedValue !== "[REDACTED]" && assignedValue !== "***") return true;
  }
  return false;
}

function cloneAndDeepFreeze<T>(value: T): T {
  const clone = structuredClone(value);
  const freeze = (current: unknown): void => {
    if (
      current === null ||
      typeof current !== "object" ||
      Object.isFrozen(current)
    )
      return;
    for (const child of Object.values(current)) freeze(child);
    Object.freeze(current);
  };
  freeze(clone);
  return clone;
}
