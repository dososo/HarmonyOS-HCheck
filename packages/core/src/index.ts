export * from "./runtime-flow.js";

export const SEVERITIES = Object.freeze([
  "BLOCKER",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFO",
] as const);
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCES = Object.freeze([
  "CONFIRMED",
  "PROBABLE",
  "POSSIBLE",
  "MANUAL",
] as const);
export type Confidence = (typeof CONFIDENCES)[number];

export const APPLICABILITIES = Object.freeze([
  "APPLICABLE",
  "NOT_APPLICABLE",
  "UNKNOWN",
  "NEEDS_ATTESTATION",
] as const);
export type Applicability = (typeof APPLICABILITIES)[number];

function parseEnumValue<const Values extends readonly string[]>(
  label: string,
  allowedValues: Values,
  value: unknown,
): Values[number] {
  if (typeof value !== "string" || !allowedValues.includes(value)) {
    throw new TypeError(
      `${label}必须是以下值之一：${allowedValues.join("、")}`,
    );
  }

  return value as Values[number];
}

export function parseSeverity(value: unknown): Severity {
  return parseEnumValue("严重性（severity）", SEVERITIES, value);
}

export function parseConfidence(value: unknown): Confidence {
  return parseEnumValue("置信度（confidence）", CONFIDENCES, value);
}

export function parseApplicability(value: unknown): Applicability {
  return parseEnumValue("适用性（applicability）", APPLICABILITIES, value);
}

export type FindingStatus =
  "new" | "existing" | "suppressed" | "resolved" | "needs-attestation";
export type AutofixLevel = "allowed" | "review_required" | "forbidden";

export interface SourceLocation {
  readonly uri: string;
  readonly line?: number;
  readonly column?: number;
  readonly logicalPath?: string;
}

export type EvidenceType =
  | "source"
  | "config"
  | "dependency"
  | "artifact"
  | "tool"
  | "agc"
  | "runtime"
  | "manual"
  | "derived";

const EVIDENCE_TYPES: ReadonlySet<string> = new Set([
  "source",
  "config",
  "dependency",
  "artifact",
  "tool",
  "agc",
  "runtime",
  "manual",
  "derived",
]);
const FINDING_STATUSES: ReadonlySet<string> = new Set([
  "new",
  "existing",
  "suppressed",
  "resolved",
  "needs-attestation",
]);
const AUTOFIX_LEVELS: ReadonlySet<string> = new Set([
  "allowed",
  "review_required",
  "forbidden",
]);
const STRICT_SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;

// 深度、节点数与 canonical UTF-8 总量无法由当前 Schema 完整表达；生产入口必须执行 Core Validator。
export const SAFE_JSON_BUDGET = Object.freeze({
  maxDepth: 64,
  maxNodes: 10_000,
  maxArrayItems: 1_000,
  maxObjectKeys: 256,
  maxStringLength: 16 * 1024,
  maxCanonicalBytes: 1024 * 1024,
} as const);
const UTF8_ENCODER = new TextEncoder();

export interface Evidence {
  readonly id: `evidence:${string}`;
  readonly type: EvidenceType;
  readonly source: string;
  readonly summary: string;
  readonly contentHash: `sha256:${string}`;
  readonly redacted: boolean;
  readonly location?: SourceLocation;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly archiveRef?: string;
  readonly collectedAt?: string;
}

export interface EvidenceInput {
  readonly type: EvidenceType;
  readonly source: string;
  readonly summary: string;
  readonly content: string | Uint8Array;
  readonly redacted: boolean;
  readonly location?: SourceLocation;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly archiveRef?: string;
  readonly collectedAt?: string;
}

export interface Remediation {
  readonly summary: string;
  readonly verification: string;
  readonly details?: string;
}

export interface FindingPolicyReference {
  readonly source: string;
  readonly section: string;
  readonly url?: string;
  readonly verifiedAt?: string;
}

export interface FindingBaseline {
  readonly present?: boolean;
  readonly reference?: string;
}

export interface Finding {
  readonly schemaVersion: "1.0.0";
  readonly id: `finding:${string}`;
  readonly ruleId: string;
  readonly ruleVersion: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly applicability: Applicability;
  readonly fingerprint: `sha256:${string}`;
  readonly message: string;
  readonly locations: readonly SourceLocation[];
  readonly evidenceIds: readonly string[];
  readonly policyRefs?: readonly FindingPolicyReference[];
  readonly remediation: Remediation;
  readonly autofix: AutofixLevel;
  readonly status: FindingStatus;
  readonly baseline?: FindingBaseline;
  readonly properties?: Readonly<Record<string, unknown>>;
}

export interface FindingInput {
  readonly ruleId: string;
  readonly ruleVersion: string;
  readonly moduleId: string;
  readonly semanticKey: string;
  readonly primaryLocationUri: string;
  readonly title: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly applicability: Applicability;
  readonly message: string;
  readonly locations: readonly SourceLocation[];
  readonly evidenceIds: readonly string[];
  readonly policyRefs?: readonly FindingPolicyReference[];
  readonly remediation: Remediation;
  readonly autofix: AutofixLevel;
  readonly status: FindingStatus;
  readonly baseline?: FindingBaseline;
  readonly properties?: Readonly<Record<string, unknown>>;
}

export interface BaselineFindingEntry {
  readonly fingerprint: `sha256:${string}`;
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
}

export interface BaselineSnapshot {
  readonly schemaVersion: "1.0.0";
  readonly hcheckVersion: string;
  readonly createdAt: string;
  readonly reference: string;
  readonly findings: readonly BaselineFindingEntry[];
}

export interface CreateBaselineSnapshotOptions {
  readonly hcheckVersion: string;
  readonly createdAt: string;
  readonly reference: string;
}

export interface ResolvedBaselineFinding {
  readonly fingerprint: `sha256:${string}`;
  readonly ruleId: string;
  readonly title: string;
  readonly severity: Severity;
  readonly reference: string;
}

export interface BaselineDiffResult {
  readonly findings: readonly Finding[];
  readonly resolved: readonly ResolvedBaselineFinding[];
}

export interface SuppressionEntry {
  readonly fingerprint: `sha256:${string}`;
  readonly ruleId: string;
  readonly reason: string;
  readonly expiresAt: string;
}

export interface SuppressionFile {
  readonly schemaVersion: "1.0.0";
  readonly suppressions: readonly SuppressionEntry[];
}

export type HCheckErrorCode =
  | "CONFIGURATION_ERROR"
  | "UNSUPPORTED_PROJECT"
  | "TOOL_UNAVAILABLE"
  | "TOOL_EXECUTION_ERROR"
  | "BUILD_FAILED"
  | "ARTIFACT_PARSE_ERROR"
  | "EXTERNAL_SERVICE_UNAVAILABLE"
  | "CREDENTIAL_ERROR"
  | "DEVICE_UNAVAILABLE"
  | "RULE_DEFINITION_ERROR"
  | "EVIDENCE_INCOMPLETE"
  | "INTERNAL_ERROR";

export class HCheckError extends Error {
  public constructor(
    public readonly code: HCheckErrorCode,
    message: string,
    public readonly details: Readonly<Record<string, unknown>> = {},
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "HCheckError";
  }
}

export interface HashPort {
  sha256(content: string | Uint8Array): Promise<`sha256:${string}`>;
}

export type ProcessRunStatus = "completed" | "timed_out" | "start_failed";

export interface ProcessRunRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly timeoutMs?: number;
  readonly maxStdoutBytes?: number;
  readonly maxStderrBytes?: number;
}

export interface ProcessRunResult {
  readonly status: ProcessRunStatus;
  readonly exitCode?: number;
  readonly signal?: string;
  readonly timedOut: boolean;
  readonly stdout: string;
  readonly stderr: string;
  readonly stdoutTruncated: boolean;
  readonly stderrTruncated: boolean;
  readonly errorMessage?: string;
}

export interface ProcessRunnerPort {
  run(request: ProcessRunRequest): Promise<ProcessRunResult>;
}

export function normalizeRelativeUri(uri: string): string {
  let normalized = uri.replaceAll("\\", "/");
  while (normalized.startsWith("./")) normalized = normalized.slice(2);
  return normalized.replace(/\/{2,}/gu, "/");
}

export function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(
    left,
    (character) => character.codePointAt(0) as number,
  );
  const rightPoints = Array.from(
    right,
    (character) => character.codePointAt(0) as number,
  );
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference =
      (leftPoints[index] as number) - (rightPoints[index] as number);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

export function canonicalStringify(value: unknown): string {
  return canonicalizeWithBudget(value, "规范序列化");
}

export async function createEvidence(
  input: EvidenceInput,
  hash: HashPort,
): Promise<Evidence> {
  if (!EVIDENCE_TYPES.has(input.type)) {
    throw new TypeError("证据类型无效。");
  }
  const source = requireSafePath(input.source, "证据来源");
  if (input.summary.length === 0) throw new TypeError("证据摘要不能为空。");
  if (input.collectedAt !== undefined && !isStrictDateTime(input.collectedAt)) {
    throw new TypeError("证据采集时间必须是 date-time。");
  }
  const location =
    input.location === undefined
      ? undefined
      : normalizeLocation(input.location);
  const archiveRef =
    input.archiveRef === undefined
      ? undefined
      : requireSafePath(input.archiveRef, "证据归档引用");
  const contentHash = requireSha256(await hash.sha256(input.content));
  const identityHash = requireSha256(
    await hash.sha256(
      canonicalStringify({ type: input.type, source, contentHash }),
    ),
  );
  const evidence: Evidence = {
    id: `evidence:${identityHash.slice("sha256:".length)}`,
    type: input.type,
    source,
    summary: input.summary,
    contentHash,
    redacted: input.redacted,
    ...(location === undefined ? {} : { location }),
    ...(input.metadata === undefined ? {} : { metadata: input.metadata }),
    ...(archiveRef === undefined ? {} : { archiveRef }),
    ...(input.collectedAt === undefined
      ? {}
      : { collectedAt: input.collectedAt }),
  };
  validateEvidence(evidence);
  return cloneAndDeepFreeze(evidence);
}

export async function createFinding(
  input: FindingInput,
  hash: HashPort,
): Promise<Finding> {
  if (input.locations.length === 0) {
    throw new TypeError("Finding 至少需要一个位置。");
  }
  if (input.moduleId.length === 0 || input.semanticKey.length === 0) {
    throw new TypeError("Finding 身份字段不能为空。");
  }
  const moduleId = requireSafePath(input.moduleId, "模块标识");
  const ruleMajor = STRICT_SEMVER.exec(input.ruleVersion)?.[1];
  if (ruleMajor === undefined) {
    throw new TypeError("Finding 规则版本必须是合法 SemVer。");
  }
  if (input.evidenceIds.length === 0) {
    throw new TypeError("Finding 至少需要一个 Evidence ID。");
  }
  if (input.evidenceIds.some((id) => !/^evidence:[a-f0-9]{64}$/u.test(id))) {
    throw new TypeError("Finding Evidence ID 格式无效。");
  }
  if (new Set(input.evidenceIds).size !== input.evidenceIds.length) {
    throw new TypeError("Finding Evidence ID 不得重复。");
  }
  const locations = input.locations
    .map(normalizeLocation)
    .sort(compareLocations);
  const primaryUri = requireSafePath(
    input.primaryLocationUri,
    "Finding 主位置 URI",
  );
  if (!locations.some((location) => location.uri === primaryUri)) {
    throw new TypeError("Finding 主位置必须存在于 locations 中。");
  }
  const fingerprint = requireSha256(
    await hash.sha256(
      canonicalStringify({
        ruleId: input.ruleId,
        ruleMajor,
        moduleId,
        uri: primaryUri,
        semanticKey: input.semanticKey,
      }),
    ),
  );
  const finding: Finding = {
    schemaVersion: "1.0.0",
    id: `finding:${fingerprint.slice("sha256:".length)}`,
    ruleId: input.ruleId,
    ruleVersion: input.ruleVersion,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    applicability: input.applicability,
    fingerprint,
    message: input.message,
    locations,
    evidenceIds: [...input.evidenceIds].sort(compareCodePoints),
    ...(input.policyRefs === undefined ? {} : { policyRefs: input.policyRefs }),
    remediation: input.remediation,
    autofix: input.autofix,
    status: input.status,
    ...(input.baseline === undefined ? {} : { baseline: input.baseline }),
    ...(input.properties === undefined ? {} : { properties: input.properties }),
  };
  validateFinding(finding);
  return cloneAndDeepFreeze(finding);
}

export function validateEvidence(value: unknown): asserts value is Evidence {
  const evidence = requireExactRecord(
    value,
    ["id", "type", "source", "summary", "contentHash", "redacted"],
    ["location", "metadata", "archiveRef", "collectedAt"],
    "Evidence",
  );
  requirePattern(evidence.id, /^evidence:[a-f0-9]{64}$/u, "Evidence ID");
  if (typeof evidence.type !== "string" || !EVIDENCE_TYPES.has(evidence.type)) {
    throw new TypeError("Evidence 类型无效。");
  }
  requireCanonicalPath(evidence.source, "Evidence 来源");
  requireNonEmptyText(evidence.summary, "Evidence 摘要");
  requirePattern(
    evidence.contentHash,
    /^sha256:[a-f0-9]{64}$/u,
    "Evidence 内容哈希",
  );
  if (evidence.redacted !== true) {
    throw new TypeError("Evidence 必须已经脱敏。");
  }
  if (evidence.location !== undefined)
    validateSourceLocation(evidence.location);
  if (evidence.metadata !== undefined) {
    validateJsonRecord(evidence.metadata, "Evidence metadata");
  }
  if (evidence.archiveRef !== undefined) {
    requireCanonicalPath(evidence.archiveRef, "Evidence 归档引用");
  }
  if (evidence.collectedAt !== undefined) {
    requireDateTime(evidence.collectedAt, "Evidence 采集时间");
  }
}

export function validateFinding(value: unknown): asserts value is Finding {
  const finding = requireExactRecord(
    value,
    [
      "schemaVersion",
      "id",
      "ruleId",
      "ruleVersion",
      "title",
      "severity",
      "confidence",
      "applicability",
      "fingerprint",
      "message",
      "locations",
      "evidenceIds",
      "remediation",
      "autofix",
      "status",
    ],
    ["policyRefs", "baseline", "properties"],
    "Finding",
  );
  if (finding.schemaVersion !== "1.0.0") {
    throw new TypeError("Finding schemaVersion 无效。");
  }
  const fingerprint = requirePattern(
    finding.fingerprint,
    /^sha256:([a-f0-9]{64})$/u,
    "Finding 指纹",
  );
  requirePattern(finding.id, /^finding:[a-f0-9]{64}$/u, "Finding ID");
  if (finding.id !== `finding:${fingerprint[1]}`) {
    throw new TypeError("Finding ID 与指纹不一致。");
  }
  requirePattern(finding.ruleId, /^HOS-[A-Z]+-[0-9]{3}$/u, "Finding 规则 ID");
  requirePattern(finding.ruleVersion, STRICT_SEMVER, "Finding 规则版本");
  requireNonEmptyText(finding.title, "Finding 标题");
  if (
    typeof finding.severity !== "string" ||
    !SEVERITIES.includes(finding.severity as Severity)
  ) {
    throw new TypeError("Finding 严重性无效。");
  }
  if (
    typeof finding.confidence !== "string" ||
    !CONFIDENCES.includes(finding.confidence as Confidence)
  ) {
    throw new TypeError("Finding 置信度无效。");
  }
  if (
    typeof finding.applicability !== "string" ||
    !APPLICABILITIES.includes(finding.applicability as Applicability)
  ) {
    throw new TypeError("Finding 适用性无效。");
  }
  requireNonEmptyText(finding.message, "Finding 消息");
  if (!Array.isArray(finding.locations) || finding.locations.length === 0) {
    throw new TypeError("Finding 至少需要一个位置。");
  }
  for (const location of finding.locations) validateSourceLocation(location);
  if (!Array.isArray(finding.evidenceIds) || finding.evidenceIds.length === 0) {
    throw new TypeError("Finding 至少需要一个 Evidence ID。");
  }
  for (const evidenceId of finding.evidenceIds) {
    requirePattern(
      evidenceId,
      /^evidence:[a-f0-9]{64}$/u,
      "Finding Evidence ID",
    );
  }
  if (new Set(finding.evidenceIds).size !== finding.evidenceIds.length) {
    throw new TypeError("Finding Evidence ID 不得重复。");
  }
  validateRemediation(finding.remediation);
  if (
    typeof finding.autofix !== "string" ||
    !AUTOFIX_LEVELS.has(finding.autofix)
  ) {
    throw new TypeError("Finding autofix 无效。");
  }
  if (
    typeof finding.status !== "string" ||
    !FINDING_STATUSES.has(finding.status)
  ) {
    throw new TypeError("Finding status 无效。");
  }
  if (finding.policyRefs !== undefined)
    validatePolicyReferences(finding.policyRefs);
  if (finding.baseline !== undefined) validateBaseline(finding.baseline);
  if (finding.properties !== undefined) {
    validateJsonRecord(finding.properties, "Finding properties");
  }
}

export function createBaselineSnapshot(
  findings: readonly Finding[],
  options: CreateBaselineSnapshotOptions,
): BaselineSnapshot {
  requirePattern(options.hcheckVersion, STRICT_SEMVER, "基线 HCheck 版本");
  if (!isStrictDateTime(options.createdAt)) {
    throw new TypeError("基线创建时间必须是严格 date-time。");
  }
  requireNonEmptyText(options.reference, "基线引用");
  const entries = findings.map((finding) => {
    validateFinding(finding);
    return {
      fingerprint: requireSha256(finding.fingerprint),
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
    };
  });
  entries.sort((left, right) =>
    compareCodePoints(left.fingerprint, right.fingerprint),
  );
  const unique = new Set(entries.map(({ fingerprint }) => fingerprint));
  if (unique.size !== entries.length) {
    throw new TypeError("基线 Finding 指纹不得重复。");
  }
  return cloneAndDeepFreeze({
    schemaVersion: "1.0.0",
    hcheckVersion: options.hcheckVersion,
    createdAt: options.createdAt,
    reference: options.reference,
    findings: entries,
  });
}

export function diffFindingsWithBaseline(
  findings: readonly Finding[],
  baseline: BaselineSnapshot,
): BaselineDiffResult {
  validateBaselineSnapshot(baseline);
  const baselineByFingerprint = new Map(
    baseline.findings.map((entry) => [entry.fingerprint, entry]),
  );
  const currentFingerprints = new Set<string>();
  const diffed = findings.map((finding) => {
    validateFinding(finding);
    currentFingerprints.add(finding.fingerprint);
    const present = baselineByFingerprint.has(finding.fingerprint);
    return withFindingState(finding, present ? "existing" : "new", {
      present,
      reference: baseline.reference,
    });
  });
  const resolved = baseline.findings
    .filter((entry) => !currentFingerprints.has(entry.fingerprint))
    .map((entry) => ({
      fingerprint: entry.fingerprint,
      ruleId: entry.ruleId,
      title: entry.title,
      severity: entry.severity,
      reference: baseline.reference,
    }))
    .sort((left, right) =>
      compareCodePoints(left.fingerprint, right.fingerprint),
    );
  return cloneAndDeepFreeze({ findings: diffed, resolved });
}

export function applySuppressions(
  findings: readonly Finding[],
  suppressions: SuppressionFile,
  now: Date,
): readonly Finding[] {
  validateSuppressionFile(suppressions, now);
  const byKey = new Map(
    suppressions.suppressions.map((entry) => [suppressionKey(entry), entry]),
  );
  const matched = new Set<string>();
  const next = findings.map((finding) => {
    validateFinding(finding);
    const key = suppressionKey(finding);
    const suppression = byKey.get(key);
    if (suppression === undefined) return finding;
    matched.add(key);
    return withFindingState(finding, "suppressed", finding.baseline);
  });
  if (
    suppressions.suppressions.some(
      (entry) => !matched.has(suppressionKey(entry)),
    )
  ) {
    throw new HCheckError(
      "CONFIGURATION_ERROR",
      "抑制配置无效：未匹配到同规则同指纹的 Finding。",
    );
  }
  return cloneAndDeepFreeze(next);
}

function suppressionKey(
  value: Pick<Finding, "ruleId" | "fingerprint"> | SuppressionEntry,
): string {
  return `${value.ruleId}:${value.fingerprint}`;
}

export function compareFindings(left: Finding, right: Finding): number {
  const severityRank: Record<Severity, number> = {
    BLOCKER: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };
  return (
    severityRank[left.severity] - severityRank[right.severity] ||
    compareCodePoints(left.ruleId, right.ruleId) ||
    compareCodePoints(
      left.locations[0]?.uri ?? "",
      right.locations[0]?.uri ?? "",
    ) ||
    compareCodePoints(left.fingerprint, right.fingerprint)
  );
}

function requireExactRecord(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isPlainRecord(value)) {
    throw new TypeError(`${label} 必须是普通对象。`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  if (
    required.some((key) => !Object.hasOwn(value, key)) ||
    keys.some((key) => !allowed.has(key))
  ) {
    throw new TypeError(`${label} 字段合同无效。`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function requirePattern(
  value: unknown,
  pattern: RegExp,
  label: string,
): RegExpExecArray {
  if (typeof value !== "string") {
    throw new TypeError(`${label} 格式无效。`);
  }
  const match = pattern.exec(value);
  if (match === null) throw new TypeError(`${label} 格式无效。`);
  return match;
}

function requireNonEmptyText(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label}不能为空。`);
  }
  return value;
}

function requireCanonicalPath(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label}必须是安全的相对或逻辑路径。`);
  }
  const normalized = requireSafePath(value, label);
  if (normalized !== value) {
    throw new TypeError(`${label}必须使用规范相对路径。`);
  }
  return value;
}

function validateSourceLocation(value: unknown): void {
  const location = requireExactRecord(
    value,
    ["uri"],
    ["line", "column", "logicalPath"],
    "SourceLocation",
  );
  requireCanonicalPath(location.uri, "位置 URI");
  if (location.line !== undefined)
    requirePositiveInteger(location.line, "位置行号");
  if (location.column !== undefined) {
    requirePositiveInteger(location.column, "位置列号");
  }
  if (location.logicalPath !== undefined) {
    requireCanonicalPath(location.logicalPath, "位置逻辑路径");
  }
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError(`${label}必须是正整数。`);
  }
  return value as number;
}

function validateRemediation(value: unknown): void {
  const remediation = requireExactRecord(
    value,
    ["summary", "verification"],
    ["details"],
    "Remediation",
  );
  requireNonEmptyText(remediation.summary, "Remediation 摘要");
  requireNonEmptyText(remediation.verification, "Remediation 复验命令");
  if (remediation.details !== undefined) {
    requireNonEmptyText(remediation.details, "Remediation 详情");
  }
}

function validatePolicyReferences(value: unknown): void {
  if (!Array.isArray(value)) {
    throw new TypeError("Finding policyRefs 必须是数组。");
  }
  for (const item of value) {
    const reference = requireExactRecord(
      item,
      ["source", "section"],
      ["url", "verifiedAt"],
      "PolicyReference",
    );
    requireNonEmptyText(reference.source, "PolicyReference 来源");
    requireNonEmptyText(reference.section, "PolicyReference 章节");
    if (reference.url !== undefined) requireAbsoluteUri(reference.url);
    if (reference.verifiedAt !== undefined) {
      requireDate(reference.verifiedAt, "PolicyReference 核验日期");
    }
  }
}

function requireAbsoluteUri(value: unknown): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError("PolicyReference URL 无效。");
  }
  try {
    const url = new URL(value);
    if (url.protocol.length === 0) throw new TypeError();
  } catch {
    throw new TypeError("PolicyReference URL 无效。");
  }
}

function validateBaseline(value: unknown): void {
  const baseline = requireExactRecord(
    value,
    [],
    ["present", "reference"],
    "Finding baseline",
  );
  if (baseline.present !== undefined && typeof baseline.present !== "boolean") {
    throw new TypeError("Finding baseline.present 必须是布尔值。");
  }
  if (baseline.reference !== undefined) {
    requireNonEmptyText(baseline.reference, "Finding baseline.reference");
  }
}

function validateBaselineSnapshot(
  value: unknown,
): asserts value is BaselineSnapshot {
  const baseline = requireExactRecord(
    value,
    ["schemaVersion", "hcheckVersion", "createdAt", "reference", "findings"],
    [],
    "基线快照",
  );
  if (baseline.schemaVersion !== "1.0.0") {
    throw new TypeError("基线 schemaVersion 无效。");
  }
  requirePattern(baseline.hcheckVersion, STRICT_SEMVER, "基线 HCheck 版本");
  if (
    typeof baseline.createdAt !== "string" ||
    !isStrictDateTime(baseline.createdAt)
  ) {
    throw new TypeError("基线 createdAt 必须是严格 date-time。");
  }
  requireNonEmptyText(baseline.reference, "基线引用");
  if (!Array.isArray(baseline.findings)) {
    throw new TypeError("基线 findings 必须是数组。");
  }
  const fingerprints = new Set<string>();
  for (const entry of baseline.findings) {
    validateBaselineFindingEntry(entry);
    if (fingerprints.has(entry.fingerprint)) {
      throw new TypeError("基线 Finding 指纹不得重复。");
    }
    fingerprints.add(entry.fingerprint);
  }
}

function validateBaselineFindingEntry(
  value: unknown,
): asserts value is BaselineFindingEntry {
  const entry = requireExactRecord(
    value,
    ["fingerprint", "ruleId", "title", "severity"],
    [],
    "基线 Finding",
  );
  requireSha256(entry.fingerprint as string);
  requirePattern(entry.ruleId, /^HOS-[A-Z]+-[0-9]{3}$/u, "基线规则 ID");
  requireNonEmptyText(entry.title, "基线标题");
  if (
    typeof entry.severity !== "string" ||
    !SEVERITIES.includes(entry.severity as Severity)
  ) {
    throw new TypeError("基线严重性无效。");
  }
}

function validateSuppressionFile(
  value: unknown,
  now: Date,
): asserts value is SuppressionFile {
  if (!Number.isFinite(now.getTime())) {
    throw new HCheckError(
      "CONFIGURATION_ERROR",
      "当前时间无效，无法判断抑制是否过期。",
    );
  }
  const file = requireExactRecord(
    value,
    ["schemaVersion", "suppressions"],
    [],
    "抑制文件",
  );
  if (file.schemaVersion !== "1.0.0") {
    throw new HCheckError(
      "CONFIGURATION_ERROR",
      "抑制文件 schemaVersion 无效。",
    );
  }
  if (!Array.isArray(file.suppressions)) {
    throw new HCheckError("CONFIGURATION_ERROR", "抑制列表必须是数组。");
  }
  const keys = new Set<string>();
  for (const entry of file.suppressions) {
    validateSuppressionEntry(entry, now);
    const key = `${entry.ruleId}:${entry.fingerprint}`;
    if (keys.has(key)) {
      throw new HCheckError("CONFIGURATION_ERROR", "抑制项不得重复。");
    }
    keys.add(key);
  }
}

function validateSuppressionEntry(
  value: unknown,
  now: Date,
): asserts value is SuppressionEntry {
  const entry = requireExactRecord(
    value,
    ["fingerprint", "ruleId", "reason", "expiresAt"],
    [],
    "抑制项",
  );
  requireSha256(entry.fingerprint as string);
  requirePattern(entry.ruleId, /^HOS-[A-Z]+-[0-9]{3}$/u, "抑制规则 ID");
  try {
    requireNonEmptyText(entry.reason, "抑制理由");
    if (
      typeof entry.expiresAt !== "string" ||
      !isStrictDateTime(entry.expiresAt)
    ) {
      throw new TypeError("抑制过期时间无效。");
    }
    const expiresAt = new Date(entry.expiresAt);
    if (expiresAt.getTime() <= now.getTime()) {
      throw new TypeError("抑制项已过期。");
    }
  } catch {
    throw new HCheckError("CONFIGURATION_ERROR", "抑制配置无效。");
  }
}

function withFindingState(
  finding: Finding,
  status: FindingStatus,
  baseline: FindingBaseline | undefined,
): Finding {
  const next: Finding = {
    ...structuredClone(finding),
    status,
    ...(baseline === undefined ? {} : { baseline }),
  };
  validateFinding(next);
  return cloneAndDeepFreeze(next);
}

function validateJsonRecord(value: unknown, label: string): void {
  if (!isPlainRecord(value)) {
    throw new TypeError(`${label} 必须是安全 JSON 对象。`);
  }
  canonicalizeWithBudget(value, label);
}

interface JsonBudgetFrame {
  readonly value: unknown;
  readonly depth: number;
  readonly exiting: boolean;
}

function canonicalizeWithBudget(value: unknown, label: string): string {
  validateJsonBudget(value, label);
  const serialized = JSON.stringify(canonicalize(value, new WeakSet<object>()));
  if (serialized === undefined)
    throw new TypeError(`${label} 不是安全 JSON 值。`);
  return serialized;
}

function validateJsonBudget(value: unknown, label: string): void {
  const stack: JsonBudgetFrame[] = [{ value, depth: 0, exiting: false }];
  const ancestors = new WeakSet<object>();
  let nodes = 0;
  let canonicalBytes = 0;
  const addCanonicalBytes = (bytes: number): void => {
    canonicalBytes += bytes;
    if (canonicalBytes > SAFE_JSON_BUDGET.maxCanonicalBytes) {
      throw new TypeError(`${label} 超过 JSON UTF-8 总量预算。`);
    }
  };
  while (stack.length > 0) {
    const frame = stack.pop() as JsonBudgetFrame;
    if (frame.exiting) {
      ancestors.delete(frame.value as object);
      continue;
    }
    nodes += 1;
    if (nodes > SAFE_JSON_BUDGET.maxNodes) {
      throw new TypeError(`${label} 超过 JSON 节点预算。`);
    }
    if (frame.depth > SAFE_JSON_BUDGET.maxDepth) {
      throw new TypeError(`${label} 超过 JSON 深度预算。`);
    }
    const item = frame.value;
    if (typeof item === "string") {
      requireJsonStringBudget(item, label);
      addCanonicalBytes(jsonUtf8Bytes(item));
      continue;
    }
    if (item === null || typeof item === "boolean") {
      addCanonicalBytes(jsonUtf8Bytes(item));
      continue;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) {
        throw new TypeError(`${label} 包含不安全 JSON 值。`);
      }
      addCanonicalBytes(jsonUtf8Bytes(item));
      continue;
    }
    if (typeof item !== "object") {
      throw new TypeError(`${label} 包含不安全 JSON 值。`);
    }
    if (!Array.isArray(item) && !isPlainRecord(item)) {
      throw new TypeError(`${label} 包含不安全 JSON 对象。`);
    }
    if (ancestors.has(item)) {
      throw new TypeError(`${label} 包含循环引用。`);
    }
    ancestors.add(item);
    stack.push({ value: item, depth: frame.depth, exiting: true });
    if (Array.isArray(item)) {
      if (item.length > SAFE_JSON_BUDGET.maxArrayItems) {
        throw new TypeError(`${label} 超过 JSON 数组预算。`);
      }
      addCanonicalBytes(2 + Math.max(0, item.length - 1));
      for (let index = item.length - 1; index >= 0; index -= 1) {
        stack.push({
          value: item[index],
          depth: frame.depth + 1,
          exiting: false,
        });
      }
      continue;
    }
    const entries = Object.entries(item);
    if (entries.length > SAFE_JSON_BUDGET.maxObjectKeys) {
      throw new TypeError(`${label} 超过 JSON 对象字段预算。`);
    }
    addCanonicalBytes(2 + Math.max(0, entries.length - 1));
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const [key, child] = entries[index] as [string, unknown];
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new TypeError(`${label} 包含危险字段。`);
      }
      requireJsonStringBudget(key, label);
      addCanonicalBytes(jsonUtf8Bytes(key) + 1);
      stack.push({
        value: child,
        depth: frame.depth + 1,
        exiting: false,
      });
    }
  }
}

function requireJsonStringBudget(value: string, label: string): void {
  let codePoints = 0;
  for (const character of value) {
    if (character.length > 0) codePoints += 1;
    if (codePoints > SAFE_JSON_BUDGET.maxStringLength) {
      throw new TypeError(`${label} 超过 JSON 字符串预算。`);
    }
  }
}

function jsonUtf8Bytes(value: string | number | boolean | null): number {
  const serialized = JSON.stringify(value);
  if (serialized === undefined)
    throw new TypeError("JSON primitive 无法序列化。");
  return UTF8_ENCODER.encode(serialized).byteLength;
}

function requireDate(value: unknown, label: string): void {
  if (typeof value !== "string" || !isStrictDate(value)) {
    throw new TypeError(`${label}必须是有效日历日期。`);
  }
}

function requireDateTime(value: unknown, label: string): void {
  if (typeof value !== "string" || !isStrictDateTime(value)) {
    throw new TypeError(`${label}必须是有效 date-time。`);
  }
}

function isStrictDateTime(value: string): boolean {
  const match =
    /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/u.exec(value);
  return (
    match !== null &&
    isStrictDate(match[1] as string) &&
    Number(match[2]) <= 23 &&
    Number(match[3]) <= 59 &&
    Number(match[4]) <= 59
  );
}

function isStrictDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12 || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= (days[month - 1] as number);
}

function requireSha256(value: string): `sha256:${string}` {
  if (!/^sha256:[a-f0-9]{64}$/u.test(value)) {
    throw new TypeError("HashPort 必须返回合法 SHA-256。");
  }
  return value as `sha256:${string}`;
}

function requireSafePath(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label}必须是安全的相对或逻辑路径。`);
  }
  const normalized = normalizeRelativeUri(value);
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized) ||
    value.startsWith("\\\\") ||
    normalized.split("/").includes("..") ||
    normalized.includes("\0")
  ) {
    throw new TypeError(`${label}必须是安全的相对或逻辑路径。`);
  }
  return normalized;
}

function normalizeLocation(location: SourceLocation): SourceLocation {
  if (
    location.line !== undefined &&
    (!Number.isSafeInteger(location.line) || location.line < 1)
  ) {
    throw new TypeError("位置行号必须是正整数。");
  }
  if (
    location.column !== undefined &&
    (!Number.isSafeInteger(location.column) || location.column < 1)
  ) {
    throw new TypeError("位置列号必须是正整数。");
  }
  return {
    uri: requireSafePath(location.uri, "位置 URI"),
    ...(location.line === undefined ? {} : { line: location.line }),
    ...(location.column === undefined ? {} : { column: location.column }),
    ...(location.logicalPath === undefined
      ? {}
      : {
          logicalPath: requireSafePath(location.logicalPath, "位置逻辑路径"),
        }),
  };
}

function compareLocations(left: SourceLocation, right: SourceLocation): number {
  return (
    compareCodePoints(left.uri, right.uri) ||
    (left.line ?? 0) - (right.line ?? 0) ||
    (left.column ?? 0) - (right.column ?? 0) ||
    compareCodePoints(left.logicalPath ?? "", right.logicalPath ?? "")
  );
}

function canonicalize(value: unknown, ancestors: WeakSet<object>): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("规范序列化不接受非有限数字。");
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new TypeError("规范序列化只接受 JSON 值。");
  }
  if (ancestors.has(value)) {
    throw new TypeError("规范序列化不接受循环引用。");
  }
  ancestors.add(value);
  let canonical: unknown;
  if (Array.isArray(value)) {
    canonical = value.map((item) => canonicalize(item, ancestors));
  } else {
    const entries = Object.entries(value).sort(([left], [right]) =>
      compareCodePoints(left, right),
    );
    canonical = Object.fromEntries(
      entries.map(([key, item]) => [key, canonicalize(item, ancestors)]),
    );
  }
  ancestors.delete(value);
  return canonical;
}

function cloneAndDeepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => cloneAndDeepFreeze(item))) as T;
  }
  return Object.freeze(
    Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        cloneAndDeepFreeze(item),
      ]),
    ),
  ) as T;
}
