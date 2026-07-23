import {
  compareCodePoints,
  compareFindings,
  validateFinding,
  type AutofixLevel,
  type Finding,
} from "@hcheck/core";

export interface AgentTask {
  readonly schemaVersion: "1.0.0";
  readonly finding: Finding;
  readonly allowedPaths: readonly string[];
  readonly forbiddenPaths: readonly string[];
  readonly autofix: AutofixLevel;
  readonly verificationCommands: readonly string[];
  readonly requiresHumanReview: boolean;
}

export interface AgentTaskResult {
  readonly schemaVersion: "1.0.0";
  readonly findingId: string;
  readonly status: "fixed" | "not-fixed" | "blocked";
  readonly changedPaths: readonly string[];
  readonly verification: readonly {
    readonly command: string;
    readonly status: "passed" | "failed" | "not-run";
    readonly summary: string;
  }[];
}

export type AgentJsonCompleteness = "COMPLETE" | "PARTIAL" | "FAILED";
export type AgentJsonGate = "PASS" | "FAIL" | "INCOMPLETE";
export type AgentJsonRisk = "blocker" | "high" | "medium" | "low" | "info";

export interface AgentJsonRun {
  readonly id: string;
  readonly hcheckVersion: string;
  readonly completeness: AgentJsonCompleteness;
  readonly gate: AgentJsonGate;
}

export interface BuildAgentJsonReportInput {
  readonly run: AgentJsonRun;
  readonly findings: readonly Finding[];
  readonly allowedPaths: readonly string[];
  readonly forbiddenPaths: readonly string[];
  readonly verificationCommands: readonly string[];
}

export interface AgentJsonAction {
  readonly findingId: string;
  readonly ruleId: string;
  readonly title: string;
  readonly risk: AgentJsonRisk;
  readonly autofix: AutofixLevel;
  readonly locations: readonly string[];
  readonly suggestedFix: string;
  readonly verificationCommands: readonly string[];
}

export interface AgentJsonReport {
  readonly schemaVersion: "1.0.0";
  readonly run: AgentJsonRun;
  readonly summary: {
    readonly total: number;
    readonly actionable: number;
  };
  readonly actions: readonly AgentJsonAction[];
  readonly safety: {
    readonly allowedPaths: readonly string[];
    readonly forbiddenPaths: readonly string[];
    readonly boundaries: readonly string[];
  };
}

export type SafeFixMode = "dry-run";
export type SafeFixBlockedReason =
  | "AUTOFIX_FORBIDDEN"
  | "HUMAN_REVIEW_REQUIRED"
  | "RULE_NOT_ALLOWED"
  | "PATH_NOT_ALLOWED"
  | "PATH_FORBIDDEN"
  | "NO_TARGET_PATH";

export interface BuildSafeFixPlanInput {
  readonly report: AgentJsonReport;
  readonly mode: SafeFixMode;
  readonly allowedRules?: readonly string[];
}

export interface SafeFixExecutableAction {
  readonly findingId: string;
  readonly ruleId: string;
  readonly targetPath: string;
  readonly status: "executable";
  readonly verificationCommands: readonly string[];
}

export interface SafeFixBlockedAction {
  readonly findingId: string;
  readonly ruleId: string;
  readonly targetPath: string;
  readonly reason: SafeFixBlockedReason;
}

export interface SafeFixPlan {
  readonly schemaVersion: "1.0.0";
  readonly mode: SafeFixMode;
  readonly actions: readonly SafeFixExecutableAction[];
  readonly blockedActions: readonly SafeFixBlockedAction[];
  readonly verificationCommands: readonly string[];
  readonly rescanCommand: string;
  readonly audit: {
    readonly rescanRequired: true;
    readonly canMarkFixedWithoutRescan: false;
    readonly allowedPaths: readonly string[];
    readonly forbiddenPaths: readonly string[];
    readonly allowedRules: readonly string[];
  };
}

export interface PostFixVerification {
  readonly command: string;
  readonly status: "passed" | "failed" | "not-run";
  readonly summary: string;
}

export interface EvaluatePostFixRescanInput {
  readonly beforeFindingIds: readonly string[];
  readonly afterFindings: readonly Finding[];
  readonly completeness: AgentJsonCompleteness;
  readonly verification: readonly PostFixVerification[];
}

export interface PostFixRescanEvaluation {
  readonly schemaVersion: "1.0.0";
  readonly status: "fixed" | "not-fixed" | "blocked";
  readonly unresolvedFindingIds: readonly string[];
  readonly reason:
    | "VERIFIED_BY_RESCAN"
    | "RESCAN_INCOMPLETE"
    | "FINDINGS_STILL_PRESENT"
    | "VERIFICATION_FAILED"
    | "VERIFICATION_NOT_RUN";
}

export function buildAgentJsonReport(
  input: BuildAgentJsonReportInput,
): AgentJsonReport {
  validateRun(input.run);
  const allowedPaths = normalizeRelativePaths(input.allowedPaths);
  const forbiddenPaths = normalizeRelativePaths(input.forbiddenPaths);
  const verificationCommands = normalizeCommands(input.verificationCommands);
  const findings = [...input.findings].sort(compareFindings);
  for (const finding of findings) validateFinding(finding);
  const actions = findings
    .filter((finding) => finding.status !== "suppressed")
    .map((finding) => ({
      findingId: finding.id,
      ruleId: finding.ruleId,
      title: finding.title,
      risk: severityToRisk(finding.severity),
      autofix: finding.autofix,
      locations: finding.locations.map(formatLocation),
      suggestedFix: finding.remediation.summary,
      verificationCommands,
    }));

  return deepFreeze({
    schemaVersion: "1.0.0",
    run: { ...input.run },
    summary: { total: findings.length, actionable: actions.length },
    actions,
    safety: {
      allowedPaths,
      forbiddenPaths,
      boundaries: [
        "只允许修改 allowedPaths 中声明的仓库相对路径。",
        "禁止读取或写入凭证、私钥、Token、真实用户数据和生产数据。",
        "修复后必须执行 verificationCommands 并回填结果。",
      ],
    },
  });
}

export function renderAgentJsonReport(report: AgentJsonReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function buildSafeFixPlan(input: BuildSafeFixPlanInput): SafeFixPlan {
  if (input.report.schemaVersion !== "1.0.0") {
    throw new TypeError("Agent JSON 版本无效。");
  }
  if (input.mode !== "dry-run") {
    throw new TypeError("P2 安全修复仅支持 dry-run。");
  }
  validateRun(input.report.run);
  const allowedPaths = normalizeRelativePaths(input.report.safety.allowedPaths);
  const forbiddenPaths = normalizeRelativePaths(
    input.report.safety.forbiddenPaths,
  );
  const verificationCommands = normalizeCommands(
    collectVerificationCommands(input.report),
  );
  const allowedRules = normalizeRuleIds(
    input.allowedRules ?? input.report.actions.map((action) => action.ruleId),
  );
  const allowedRuleSet = new Set(allowedRules);
  const actions: SafeFixExecutableAction[] = [];
  const blockedActions: SafeFixBlockedAction[] = [];

  for (const action of [...input.report.actions].sort(compareActions)) {
    const target = firstTargetPath(action);
    const reason =
      target.blockedReason ??
      blockedReasonForAction(action, {
        targetPath: target.path,
        allowedPaths,
        forbiddenPaths,
        allowedRuleSet,
      });
    if (reason === undefined) {
      actions.push({
        findingId: action.findingId,
        ruleId: action.ruleId,
        targetPath: target.path,
        status: "executable",
        verificationCommands: action.verificationCommands,
      });
    } else {
      blockedActions.push({
        findingId: action.findingId,
        ruleId: action.ruleId,
        targetPath: target.path,
        reason,
      });
    }
  }

  return deepFreeze({
    schemaVersion: "1.0.0",
    mode: input.mode,
    actions,
    blockedActions,
    verificationCommands,
    rescanCommand: verificationCommands[0] ?? "pnpm check",
    audit: {
      rescanRequired: true,
      canMarkFixedWithoutRescan: false,
      allowedPaths,
      forbiddenPaths,
      allowedRules,
    },
  });
}

export function evaluatePostFixRescan(
  input: EvaluatePostFixRescanInput,
): PostFixRescanEvaluation {
  const beforeFindingIds = normalizeIds(input.beforeFindingIds);
  for (const finding of input.afterFindings) validateFinding(finding);

  if (input.completeness !== "COMPLETE") {
    return deepFreeze({
      schemaVersion: "1.0.0",
      status: "blocked",
      unresolvedFindingIds: beforeFindingIds,
      reason: "RESCAN_INCOMPLETE",
    });
  }

  if (input.verification.some((item) => item.status === "not-run")) {
    return deepFreeze({
      schemaVersion: "1.0.0",
      status: "blocked",
      unresolvedFindingIds: beforeFindingIds,
      reason: "VERIFICATION_NOT_RUN",
    });
  }

  if (input.verification.some((item) => item.status === "failed")) {
    return deepFreeze({
      schemaVersion: "1.0.0",
      status: "not-fixed",
      unresolvedFindingIds: beforeFindingIds,
      reason: "VERIFICATION_FAILED",
    });
  }

  const afterFindingIds: ReadonlySet<string> = new Set(
    input.afterFindings.map((finding) => finding.id),
  );
  const unresolved = beforeFindingIds.filter((id) => afterFindingIds.has(id));
  if (unresolved.length > 0) {
    return deepFreeze({
      schemaVersion: "1.0.0",
      status: "not-fixed",
      unresolvedFindingIds: unresolved,
      reason: "FINDINGS_STILL_PRESENT",
    });
  }

  return deepFreeze({
    schemaVersion: "1.0.0",
    status: "fixed",
    unresolvedFindingIds: [],
    reason: "VERIFIED_BY_RESCAN",
  });
}

function validateRun(run: AgentJsonRun): void {
  if (!/^(?=.*\S)[A-Za-z0-9._@+-]+$/u.test(run.id)) {
    throw new TypeError("Agent JSON 运行 ID 无效。");
  }
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(run.hcheckVersion)) {
    throw new TypeError("Agent JSON HCheck 版本无效。");
  }
}

function normalizeRelativePaths(paths: readonly string[]): readonly string[] {
  return [...paths].map(normalizeRelativePath).sort(compareCodePoints);
}

function normalizeRelativePath(path: string): string {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\/+/u, "");
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//u.test(normalized) ||
    normalized.split("/").includes("..")
  ) {
    throw new TypeError("Agent JSON 路径必须是仓库相对路径。");
  }
  return normalized.replace(/\/{2,}/gu, "/");
}

function normalizeCommands(commands: readonly string[]): readonly string[] {
  if (commands.length === 0) throw new TypeError("复验命令不能为空。");
  return [...commands].map((command) => {
    if (
      typeof command !== "string" ||
      command.length === 0 ||
      command.length > 200 ||
      /[\r\n]/u.test(command)
    ) {
      throw new TypeError("复验命令无效。");
    }
    return command;
  });
}

function normalizeRuleIds(ruleIds: readonly string[]): readonly string[] {
  const unique = new Set<string>();
  for (const ruleId of ruleIds) {
    if (!/^[A-Z0-9-]+$/u.test(ruleId)) {
      throw new TypeError("规则 ID 无效。");
    }
    unique.add(ruleId);
  }
  return [...unique].sort(compareCodePoints);
}

function normalizeIds(ids: readonly string[]): readonly string[] {
  const unique = new Set<string>();
  for (const id of ids) {
    if (typeof id !== "string" || id.trim().length === 0) {
      throw new TypeError("Finding ID 无效。");
    }
    unique.add(id);
  }
  return [...unique].sort(compareCodePoints);
}

function collectVerificationCommands(
  report: AgentJsonReport,
): readonly string[] {
  const commands = new Set<string>();
  for (const action of report.actions) {
    for (const command of action.verificationCommands) commands.add(command);
  }
  return commands.size === 0 ? ["pnpm check"] : [...commands];
}

function compareActions(a: AgentJsonAction, b: AgentJsonAction): number {
  return compareCodePoints(a.findingId, b.findingId);
}

function firstTargetPath(action: AgentJsonAction): {
  readonly path: string;
  readonly blockedReason?: SafeFixBlockedReason;
} {
  const firstLocation = action.locations[0];
  if (firstLocation === undefined) {
    return { path: "<unknown>", blockedReason: "NO_TARGET_PATH" };
  }
  const withoutLine = firstLocation.replace(/:\d+(?::\d+)?$/u, "");
  try {
    return { path: normalizeRelativePath(withoutLine) };
  } catch {
    return { path: "<invalid>", blockedReason: "PATH_NOT_ALLOWED" };
  }
}

function blockedReasonForAction(
  action: AgentJsonAction,
  context: {
    readonly targetPath: string;
    readonly allowedPaths: readonly string[];
    readonly forbiddenPaths: readonly string[];
    readonly allowedRuleSet: ReadonlySet<string>;
  },
): SafeFixBlockedReason | undefined {
  if (action.autofix === "forbidden") return "AUTOFIX_FORBIDDEN";
  if (action.autofix === "review_required") return "HUMAN_REVIEW_REQUIRED";
  if (!context.allowedRuleSet.has(action.ruleId)) return "RULE_NOT_ALLOWED";
  if (
    context.forbiddenPaths.some((candidate) =>
      isWithinPathBoundary(context.targetPath, candidate),
    )
  ) {
    return "PATH_FORBIDDEN";
  }
  if (
    !context.allowedPaths.some((candidate) =>
      isWithinPathBoundary(context.targetPath, candidate),
    )
  ) {
    return "PATH_NOT_ALLOWED";
  }
  return undefined;
}

function isWithinPathBoundary(path: string, boundary: string): boolean {
  return path === boundary || path.startsWith(`${boundary}/`);
}

function severityToRisk(severity: Finding["severity"]): AgentJsonRisk {
  return severity.toLowerCase() as AgentJsonRisk;
}

function formatLocation(location: Finding["locations"][number]): string {
  return `${location.uri}${location.line === undefined ? "" : `:${location.line}`}${location.column === undefined ? "" : `:${location.column}`}`;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => deepFreeze(item))) as T;
  }
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}
