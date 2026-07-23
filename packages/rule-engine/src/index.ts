import {
  canonicalStringify,
  compareCodePoints,
  compareFindings,
  HCheckError,
  validateEvidence,
  validateFinding,
  type Applicability,
  type Confidence,
  type Evidence,
  type Finding,
  type HashPort,
  type Severity,
} from "@hcheck/core";
import type {
  ProjectSnapshot,
  ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import { createHash } from "node:crypto";
import addFormats from "ajv-formats";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import { satisfies, valid, validRange } from "semver";
import { parse as parseYaml } from "yaml";

export { metadataPlaceholderDetector } from "./detectors/metadata-placeholder.js";
export {
  buildArkTsSymbolIndex,
  buildCallGraph,
  findConsentGateCandidates,
  type ArkTsCallSite,
  type ArkTsDeclaration,
  type ArkTsImportBinding,
  type ArkTsSourceUnit,
  type ArkTsSymbolIndex,
  type BuildCallGraphOptions,
  type CallGraph,
  type CallGraphBudget,
  type CallGraphEdge,
  type CallGraphIncompleteReason,
  type ConsentGateCandidate,
  type SensitiveApiDescriptor,
} from "./arkts-symbol-index.js";
export {
  detectPackageBundleIdentity,
  detectPackageDebugMaterial,
  packageBundleIdentityDetector,
  packageDebugMaterialDetector,
} from "./detectors/package-artifact.js";
export {
  detectSdkDisclosureConsistency,
  privacySdkDisclosureDetector,
} from "./detectors/privacy-sdk.js";
export {
  apiPermissionDetector,
  detectApiPermissionConsistency,
} from "./detectors/api-permission.js";
export { testEndpointDetector } from "./detectors/test-endpoint.js";

const MAX_PACK_BYTES = 64 * 1024;
const MAX_RULE_BYTES = 256 * 1024;

export type RuleStatus = "experimental" | "active" | "deprecated";
export type RuleInput =
  | "project_snapshot"
  | "source_text"
  | "source_ast"
  | "dependency_graph"
  | "privacy_policy"
  | "package_manifest"
  | "tool_report"
  | "agc_snapshot"
  | "runtime_timeline"
  | "manual_attestation";
export type DetectorType =
  "structural" | "semantic" | "artifact" | "composite" | "runtime" | "manual";

export interface RuleCategory {
  readonly technical: string;
  readonly review: string;
}

export type AppliesWhen =
  | string
  | { readonly all: readonly string[] }
  | { readonly any: readonly string[] };

export interface RuleDetector {
  readonly type: DetectorType;
  readonly implementation: string;
  readonly options?: Readonly<Record<string, unknown>>;
}

export interface PolicyReference {
  readonly source: string;
  readonly section: string;
  readonly url: string;
  readonly verifiedAt: string;
  readonly notes?: string;
}

export interface RuleAutofix {
  readonly level: "allowed" | "review_required" | "forbidden";
  readonly implementation?: string;
  readonly allowedPaths?: readonly string[];
}

export interface RuleDefinition {
  readonly id: string;
  readonly version: string;
  readonly status: RuleStatus;
  readonly title: string;
  readonly summary: string;
  readonly category: RuleCategory;
  readonly appliesWhen: AppliesWhen;
  readonly inputs: readonly RuleInput[];
  readonly detector: RuleDetector;
  readonly severity: Severity;
  readonly defaultConfidence: Confidence;
  readonly policyRefs: readonly PolicyReference[];
  readonly remediation: {
    readonly summary: string;
    readonly verification: string;
    readonly details?: string;
  };
  readonly autofix: RuleAutofix;
  readonly knownFalsePositives?: readonly string[];
  readonly tags?: readonly string[];
  readonly introducedAt?: string;
  readonly deprecatedBy?: string;
}

export interface RulePack {
  readonly id: string;
  readonly version: string;
  readonly hcheckCompatibility: string;
  readonly rules: readonly RuleDefinition[];
  readonly signature?: {
    readonly status: "verified";
    readonly keyId: string;
    readonly algorithm: RulePackSignatureManifest["algorithm"];
  };
}

export interface RulePackSignatureManifest {
  readonly version: 1;
  readonly keyId: string;
  readonly algorithm: "local-test-ed25519";
  readonly signedAt: string;
  readonly files: readonly {
    readonly path: string;
    readonly sha256: string;
  }[];
  readonly signature: string;
}

export interface RulePackSignatureVerifier {
  verify(input: {
    readonly canonicalPayload: string;
    readonly signature: string;
    readonly keyId: string;
    readonly algorithm: RulePackSignatureManifest["algorithm"];
  }): Promise<boolean>;
}

export type RulePackSignaturePolicy =
  | { readonly mode: "disabled" }
  | {
      readonly mode: "required";
      readonly manifestPath?: string;
      readonly verifier: RulePackSignatureVerifier;
    };

export interface RuleSchemas {
  readonly rule: object;
  readonly pack: object;
}

export interface LoadRulePackOptions {
  readonly packPath: string;
  readonly hcheckVersion: string;
  readonly fs: ReadonlyFileSystemPort;
  readonly schemas: RuleSchemas;
  readonly signaturePolicy?: RulePackSignaturePolicy;
}

export interface ScanContext {
  readonly mode: "quick";
  readonly project: ProjectSnapshot;
}

export interface ApplicabilityContext {
  readonly mode?: "quick";
  readonly project: {
    readonly platform?: "harmonyos";
  };
}

export interface DetectionContext {
  readonly project: ProjectSnapshot;
  readonly rule: RuleDefinition;
  readonly fs: ReadonlyFileSystemPort;
  readonly hash: HashPort;
  readonly workspaceRoot: string;
  readonly globalExcludePaths: readonly string[];
}

export interface DetectionResult {
  readonly evidence: readonly Evidence[];
  readonly findings: readonly Finding[];
}

export interface Detector {
  readonly implementation: string;
  detect(context: DetectionContext): Promise<DetectionResult>;
}

export interface ApplicabilityResult {
  readonly value: Applicability;
  readonly reason: string;
}

export interface RuleEvaluation {
  readonly ruleId: string;
  readonly applicability: Applicability;
  readonly reason: string;
  readonly executed: boolean;
}

export interface RuleExecutionResult extends DetectionResult {
  readonly evaluations: readonly RuleEvaluation[];
}

export interface ExecuteRulesOptions {
  readonly rules: readonly RuleDefinition[];
  readonly context: {
    readonly mode?: "quick";
    readonly project: ProjectSnapshot;
    readonly fs: ReadonlyFileSystemPort;
    readonly hash: HashPort;
    readonly workspaceRoot: string;
    readonly globalExcludePaths: readonly string[];
  };
  readonly registry: DetectorRegistry;
}

interface SerializedRule {
  readonly id: string;
  readonly version: string;
  readonly status: RuleStatus;
  readonly title: string;
  readonly summary: string;
  readonly category: RuleCategory;
  readonly applies_when: AppliesWhen;
  readonly inputs: readonly RuleInput[];
  readonly detector: RuleDetector;
  readonly severity: Severity;
  readonly default_confidence: Confidence;
  readonly policy_refs: readonly {
    readonly source: string;
    readonly section: string;
    readonly url: string;
    readonly verified_at: string;
    readonly notes?: string;
  }[];
  readonly remediation: RuleDefinition["remediation"];
  readonly autofix: {
    readonly level: RuleAutofix["level"];
    readonly implementation?: string;
    readonly allowed_paths?: readonly string[];
  };
  readonly known_false_positives?: readonly string[];
  readonly tags?: readonly string[];
  readonly introduced_at?: string;
  readonly deprecated_by?: string;
}

interface SerializedPack {
  readonly id: string;
  readonly version: string;
  readonly hcheck_compatibility: string;
  readonly rules: readonly string[];
}

function createValidators(schemas: RuleSchemas): {
  readonly rule: ValidateFunction<SerializedRule>;
  readonly pack: ValidateFunction<SerializedPack>;
} {
  try {
    if (hasAsyncSchema(schemas.rule) || hasAsyncSchema(schemas.pack)) {
      throw ruleDefinitionError(
        "规则 Schema 不得启用异步校验。",
        "async_schema",
      );
    }
    if (
      Reflect.get(schemas.rule, "$id") !==
        "https://hcheck.dev/schemas/rule.schema.json" ||
      Reflect.get(schemas.pack, "$id") !==
        "https://hcheck.dev/schemas/rule-pack.schema.json"
    ) {
      throw ruleDefinitionError("规则 Schema 标识无效。", "schema");
    }
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    const formatsPlugin = addFormats as unknown as (
      instance: Ajv2020,
    ) => Ajv2020;
    formatsPlugin(ajv);
    ajv.addSchema(schemas.rule);
    const rule = ajv.getSchema<SerializedRule>(
      "https://hcheck.dev/schemas/rule.schema.json",
    );
    if (rule === undefined) {
      throw ruleDefinitionError("规则 Schema 无法编译。", "schema");
    }
    const pack = ajv.compile<SerializedPack>(schemas.pack);
    if (
      Reflect.get(rule, "$async") === true ||
      Reflect.get(pack, "$async") === true
    ) {
      throw ruleDefinitionError(
        "规则 Schema 不得启用异步校验。",
        "async_schema",
      );
    }
    return { rule, pack };
  } catch (error) {
    if (error instanceof HCheckError) throw error;
    throw ruleDefinitionError("规则 Schema 无法编译。", "schema");
  }
}

function hasAsyncSchema(value: unknown, seen = new WeakSet<object>()): boolean {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (!Array.isArray(value) && Reflect.get(value, "$async") === true)
    return true;
  return Object.values(value).some((item) => hasAsyncSchema(item, seen));
}

function ruleDefinitionError(message: string, kind: string): HCheckError {
  return new HCheckError("RULE_DEFINITION_ERROR", message, { kind });
}

function parseYamlSafely(source: string, kind: "rule" | "pack"): unknown {
  try {
    const value = parseYaml(source, { maxAliasCount: 0 });
    assertSafeYamlValue(value, new WeakSet<object>());
    return value;
  } catch {
    throw ruleDefinitionError(
      kind === "rule" ? "规则 YAML 无法解析。" : "规则包 YAML 无法解析。",
      `${kind}_yaml`,
    );
  }
}

function assertSafeYamlValue(value: unknown, ancestors: WeakSet<object>): void {
  if (value === null || typeof value !== "object") return;
  if (ancestors.has(value)) throw new Error("cyclic YAML value");
  ancestors.add(value);
  if (Array.isArray(value)) {
    for (const item of value) assertSafeYamlValue(item, ancestors);
  } else {
    for (const [key, item] of Object.entries(value)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new Error("dangerous YAML key");
      }
      assertSafeYamlValue(item, ancestors);
    }
  }
  ancestors.delete(value);
}

export function parseRuleDefinition(
  source: string,
  schemas: RuleSchemas,
): RuleDefinition {
  return parseRuleDefinitionWithValidator(
    source,
    createValidators(schemas).rule,
  );
}

function parseRuleDefinitionWithValidator(
  source: string,
  validator: ValidateFunction<SerializedRule>,
): RuleDefinition {
  const value = parseYamlSafely(source, "rule");
  if (!validator(value)) {
    throw ruleDefinitionError("规则定义不符合 Rule Schema。", "rule_schema");
  }
  if (valid(value.version) === null) {
    throw ruleDefinitionError("规则版本不是合法 SemVer。", "rule_version");
  }
  validateApplicability(value.applies_when);

  return cloneAndFreeze({
    id: value.id,
    version: value.version,
    status: value.status,
    title: value.title,
    summary: value.summary,
    category: value.category,
    appliesWhen: value.applies_when,
    inputs: value.inputs,
    detector: value.detector,
    severity: value.severity,
    defaultConfidence: value.default_confidence,
    policyRefs: value.policy_refs.map((reference) => ({
      source: reference.source,
      section: reference.section,
      url: reference.url,
      verifiedAt: reference.verified_at,
      ...(reference.notes === undefined ? {} : { notes: reference.notes }),
    })),
    remediation: value.remediation,
    autofix: {
      level: value.autofix.level,
      ...(value.autofix.implementation === undefined
        ? {}
        : { implementation: value.autofix.implementation }),
      ...(value.autofix.allowed_paths === undefined
        ? {}
        : { allowedPaths: value.autofix.allowed_paths }),
    },
    ...(value.known_false_positives === undefined
      ? {}
      : { knownFalsePositives: value.known_false_positives }),
    ...(value.tags === undefined ? {} : { tags: value.tags }),
    ...(value.introduced_at === undefined
      ? {}
      : { introducedAt: value.introduced_at }),
    ...(value.deprecated_by === undefined
      ? {}
      : { deprecatedBy: value.deprecated_by }),
  });
}

export async function loadRulePack(
  options: LoadRulePackOptions,
): Promise<RulePack> {
  const validators = createValidators(options.schemas);
  const packPath = await portCall("pack_path", () =>
    options.fs.resolve(options.packPath),
  );
  const packSource = await readDefinitionFile(packPath, "pack", options.fs);
  const packValue = parseYamlSafely(packSource, "pack");
  if (!validators.pack(packValue)) {
    throw ruleDefinitionError(
      "规则包定义不符合 Rule Pack Schema。",
      "pack_schema",
    );
  }
  if (valid(packValue.version) === null) {
    throw ruleDefinitionError("规则包版本不是合法 SemVer。", "pack_version");
  }
  if (
    !matchesCompatibility(options.hcheckVersion, packValue.hcheck_compatibility)
  ) {
    throw ruleDefinitionError(
      "规则包与当前 HCheck 版本不兼容。",
      "pack_incompatible",
    );
  }

  const rules: RuleDefinition[] = [];
  const seen = new Map<string, string>();
  const packDirectory = await portCall("pack_path", () =>
    options.fs.parent(packPath),
  );
  const rulesRoot = await portCall("pack_path", () =>
    options.fs.resolve(packDirectory, ".."),
  );
  const canonicalRulesRoot = await portCall("pack_path", () =>
    options.fs.realpath(rulesRoot),
  );
  const ruleSources: { path: string; source: string }[] = [];
  for (const relativeRulePath of packValue.rules) {
    const rulePath = await portCall("rule_path", () =>
      options.fs.resolve(rulesRoot, relativeRulePath),
    );
    const canonicalRulePath = await portCall("rule_file", () =>
      options.fs.realpath(rulePath),
    );
    if (!isWithin(canonicalRulesRoot, canonicalRulePath)) {
      throw ruleDefinitionError("规则包包含不安全的规则路径。", "rule_path");
    }
    ruleSources.push({
      path: relativeRulePath,
      source: await readDefinitionFile(canonicalRulePath, "rule", options.fs),
    });
  }

  const signature = await verifyRulePackSignature({
    policy: options.signaturePolicy ?? { mode: "disabled" },
    fs: options.fs,
    packPath,
    packDirectory,
    rulesRoot,
    canonicalRulesRoot,
    packSource,
    ruleSources,
  });

  for (const ruleSource of ruleSources) {
    const rule = parseRuleDefinitionWithValidator(
      ruleSource.source,
      validators.rule,
    );
    const previousVersion = seen.get(rule.id);
    if (previousVersion !== undefined) {
      if (previousVersion === rule.version) {
        throw ruleDefinitionError(
          "规则包包含重复规则 ID。",
          "duplicate_rule_id",
        );
      }
      throw ruleDefinitionError(
        "规则包包含同一规则 ID 的版本冲突。",
        "rule_version_conflict",
      );
    }
    seen.set(rule.id, rule.version);
    rules.push(rule);
  }

  return cloneAndFreeze({
    id: packValue.id,
    version: packValue.version,
    hcheckCompatibility: packValue.hcheck_compatibility,
    rules,
    ...(signature === undefined ? {} : { signature }),
  });
}

async function verifyRulePackSignature(options: {
  readonly policy: RulePackSignaturePolicy;
  readonly fs: ReadonlyFileSystemPort;
  readonly packPath: string;
  readonly packDirectory: string;
  readonly rulesRoot: string;
  readonly canonicalRulesRoot: string;
  readonly packSource: string;
  readonly ruleSources: readonly {
    readonly path: string;
    readonly source: string;
  }[];
}): Promise<RulePack["signature"] | undefined> {
  if (options.policy.mode === "disabled") return undefined;

  const manifestPath = await resolveSignatureManifestPath(
    options.fs,
    options.packPath,
    options.packDirectory,
    options.policy.manifestPath,
  );
  const manifestSource = await readSignatureManifestSource(
    manifestPath,
    options.fs,
  );
  const manifest = parseSignatureManifest(manifestSource);
  const files = new Map<string, string>();
  for (const file of manifest.files) {
    if (!isSafeManifestPath(file.path)) {
      throw ruleDefinitionError(
        "规则包签名清单包含不安全路径。",
        "signature_path",
      );
    }
    if (files.has(file.path)) {
      throw ruleDefinitionError(
        "规则包签名清单包含重复路径。",
        "signature_path",
      );
    }
    const resolved = await portCall("signature_path", () =>
      options.fs.resolve(options.rulesRoot, file.path),
    );
    const canonical = await portCall("signature_path", () =>
      options.fs.realpath(resolved),
    );
    if (!isWithin(options.canonicalRulesRoot, canonical)) {
      throw ruleDefinitionError(
        "规则包签名清单包含不安全路径。",
        "signature_path",
      );
    }
    files.set(file.path, file.sha256);
  }

  await assertSignedFileHash(
    files,
    await relativePathFromRoot(options.fs, options.rulesRoot, options.packPath),
    options.packSource,
  );
  for (const rule of options.ruleSources) {
    await assertSignedFileHash(files, rule.path, rule.source);
  }

  const canonicalPayload = canonicalStringify({
    version: manifest.version,
    keyId: manifest.keyId,
    algorithm: manifest.algorithm,
    signedAt: manifest.signedAt,
    files: [...manifest.files]
      .map((file) => ({ path: file.path, sha256: file.sha256 }))
      .sort((left, right) => compareCodePoints(left.path, right.path)),
  });
  const verified = await options.policy.verifier.verify({
    canonicalPayload,
    signature: manifest.signature,
    keyId: manifest.keyId,
    algorithm: manifest.algorithm,
  });
  if (!verified) {
    throw ruleDefinitionError("规则包签名校验失败。", "signature_verification");
  }

  return {
    status: "verified",
    keyId: manifest.keyId,
    algorithm: manifest.algorithm,
  };
}

async function resolveSignatureManifestPath(
  fs: ReadonlyFileSystemPort,
  packPath: string,
  packDirectory: string,
  explicitPath: string | undefined,
): Promise<string> {
  if (explicitPath !== undefined) {
    if (!isSafeManifestPath(explicitPath)) {
      throw ruleDefinitionError("规则包签名清单路径不安全。", "signature_path");
    }
    return portCall("signature_path", () =>
      fs.resolve(packDirectory, explicitPath),
    );
  }
  const filename = packPath.split(/[\\/]/u).at(-1) ?? "pack.yml";
  const manifestFilename = filename.replace(/\.ya?ml$/u, ".signature.json");
  if (manifestFilename === filename) {
    throw ruleDefinitionError("规则包签名清单路径不安全。", "signature_path");
  }
  return portCall("signature_path", () =>
    fs.resolve(packDirectory, manifestFilename),
  );
}

async function readSignatureManifestSource(
  file: string,
  fs: ReadonlyFileSystemPort,
): Promise<string> {
  let size: number;
  try {
    size = await fs.size(file);
  } catch {
    throw ruleDefinitionError("无法读取规则包签名清单。", "signature_file");
  }
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_PACK_BYTES) {
    throw ruleDefinitionError("规则包签名清单超过大小限制。", "signature_size");
  }
  try {
    return await fs.readText(file);
  } catch {
    throw ruleDefinitionError("无法读取规则包签名清单。", "signature_file");
  }
}

function parseSignatureManifest(source: string): RulePackSignatureManifest {
  let value: unknown;
  try {
    value = JSON.parse(source);
  } catch {
    throw ruleDefinitionError("规则包签名清单无法解析。", "signature_json");
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw ruleDefinitionError("规则包签名清单结构无效。", "signature_schema");
  }
  const object = value as Record<string, unknown>;
  const files = object.files;
  if (
    object.version !== 1 ||
    typeof object.key_id !== "string" ||
    object.key_id.length === 0 ||
    object.key_id.length > 128 ||
    object.algorithm !== "local-test-ed25519" ||
    typeof object.signed_at !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(object.signed_at) ||
    !Array.isArray(files) ||
    files.length === 0 ||
    files.length > 512 ||
    typeof object.signature !== "string" ||
    object.signature.length === 0 ||
    object.signature.length > 1024
  ) {
    throw ruleDefinitionError("规则包签名清单结构无效。", "signature_schema");
  }
  return {
    version: 1,
    keyId: object.key_id,
    algorithm: "local-test-ed25519",
    signedAt: object.signed_at,
    signature: object.signature,
    files: files.map((file) => {
      if (
        file === null ||
        typeof file !== "object" ||
        Array.isArray(file) ||
        typeof Reflect.get(file, "path") !== "string" ||
        typeof Reflect.get(file, "sha256") !== "string" ||
        !/^[a-f0-9]{64}$/u.test(Reflect.get(file, "sha256") as string)
      ) {
        throw ruleDefinitionError(
          "规则包签名清单结构无效。",
          "signature_schema",
        );
      }
      return {
        path: Reflect.get(file, "path") as string,
        sha256: Reflect.get(file, "sha256") as string,
      };
    }),
  };
}

async function relativePathFromRoot(
  fs: ReadonlyFileSystemPort,
  root: string,
  file: string,
): Promise<string> {
  const resolvedRoot = await portCall("signature_path", () => fs.resolve(root));
  const resolvedFile = await portCall("signature_path", () => fs.resolve(file));
  const relative = normalizeAbsolutePath(resolvedFile).slice(
    normalizeAbsolutePath(resolvedRoot).replace(/\/$/u, "").length + 1,
  );
  return relative;
}

async function assertSignedFileHash(
  files: ReadonlyMap<string, string>,
  filePath: string,
  source: string,
): Promise<void> {
  const expected = files.get(filePath);
  if (expected === undefined) {
    throw ruleDefinitionError(
      "规则包签名清单缺少必要文件。",
      "signature_manifest",
    );
  }
  const actual = createHash("sha256").update(source).digest("hex");
  if (actual !== expected) {
    throw ruleDefinitionError(
      "规则包签名清单与文件内容不一致。",
      "signature_hash",
    );
  }
}

function isSafeManifestPath(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 512 &&
    !value.startsWith("/") &&
    !isWindowsAbsolutePath(value.replaceAll("\\", "/")) &&
    !value.split(/[\\/]+/u).includes("..") &&
    !value.split(/[\\/]+/u).includes("")
  );
}

async function readDefinitionFile(
  file: string,
  kind: "rule" | "pack",
  fs: ReadonlyFileSystemPort,
): Promise<string> {
  const limit = kind === "pack" ? MAX_PACK_BYTES : MAX_RULE_BYTES;
  let size: number;
  try {
    size = await fs.size(file);
  } catch {
    throw ruleDefinitionError(
      kind === "rule" ? "无法读取规则文件。" : "无法读取规则包文件。",
      `${kind}_file`,
    );
  }
  if (!Number.isSafeInteger(size) || size < 0 || size > limit) {
    throw ruleDefinitionError(
      kind === "rule" ? "规则文件超过大小限制。" : "规则包文件超过大小限制。",
      `${kind}_size`,
    );
  }
  try {
    const source = await fs.readText(file);
    if (new TextEncoder().encode(source).byteLength > limit) {
      throw ruleDefinitionError(
        kind === "rule" ? "规则文件超过大小限制。" : "规则包文件超过大小限制。",
        `${kind}_size`,
      );
    }
    return source;
  } catch (error) {
    if (error instanceof HCheckError) throw error;
    throw ruleDefinitionError(
      kind === "rule" ? "无法读取规则文件。" : "无法读取规则包文件。",
      `${kind}_file`,
    );
  }
}

function isWithin(root: string, candidate: string): boolean {
  let normalizedRoot = normalizeAbsolutePath(root);
  let normalizedCandidate = normalizeAbsolutePath(candidate);
  if (isWindowsAbsolutePath(normalizedRoot)) {
    normalizedRoot = normalizedRoot.toLowerCase();
    normalizedCandidate = normalizedCandidate.toLowerCase();
  }
  const rootPrefix = normalizedRoot.endsWith("/")
    ? normalizedRoot
    : `${normalizedRoot}/`;
  return (
    normalizedCandidate === normalizedRoot ||
    normalizedCandidate.startsWith(rootPrefix)
  );
}

function isWindowsAbsolutePath(value: string): boolean {
  return /^[A-Za-z]:\//u.test(value) || value.startsWith("//");
}

function normalizeAbsolutePath(value: string): string {
  const normalized = value.replaceAll("\\", "/");
  if (normalized === "/") return normalized;
  if (/^[A-Za-z]:\/+$/u.test(normalized)) return `${normalized.slice(0, 2)}/`;
  return normalized.replace(/\/+$/u, "");
}

async function portCall<T>(
  kind: string,
  operation: () => T | Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch {
    throw ruleDefinitionError("无法解析规则包路径。", kind);
  }
}

function cloneAndFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) {
    return Object.freeze(value.map((item) => cloneAndFreeze(item))) as T;
  }
  const clone = Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, cloneAndFreeze(item)]),
  );
  return Object.freeze(clone) as T;
}

function matchesCompatibility(version: string, range: string): boolean {
  if (valid(version) === null) {
    throw ruleDefinitionError("HCheck 版本格式无效。", "hcheck_version");
  }
  const normalizedRange = validRange(range);
  if (normalizedRange === null) {
    throw ruleDefinitionError("规则包兼容范围无效。", "pack_compatibility");
  }
  return satisfies(version, normalizedRange);
}

type TruthValue = true | false | "unknown";
const REGISTERED_APPLICABILITY_PATHS = new Set([
  "project.platform",
  "scan.mode",
]);
const APPLICABILITY_VALUES: Readonly<
  Record<ParsedApplicabilityExpression["field"], ReadonlySet<string>>
> = {
  "project.platform": new Set(["harmonyos"]),
  "scan.mode": new Set(["quick", "release", "submit"]),
};
const EXPRESSION =
  /^\s*([A-Za-z][A-Za-z0-9_.]*)\s*(==|!=)\s*(?:"([^"\\]*)"|'([^'\\]*)'|([A-Za-z][A-Za-z0-9_-]*))\s*$/u;

interface ParsedApplicabilityExpression {
  readonly field: "project.platform" | "scan.mode";
  readonly operator: "==" | "!=";
  readonly expected: string;
}

export function validateApplicability(appliesWhen: AppliesWhen): void {
  if (typeof appliesWhen === "string") {
    parseApplicabilityExpression(appliesWhen);
    return;
  }
  const keys = Object.keys(appliesWhen);
  if (keys.length !== 1 || (keys[0] !== "all" && keys[0] !== "any")) {
    throw ruleDefinitionError(
      "适用性组合必须恰好包含一个 all 或 any。",
      "applicability_shape",
    );
  }
  const expressions =
    keys[0] === "all" && "all" in appliesWhen
      ? appliesWhen.all
      : keys[0] === "any" && "any" in appliesWhen
        ? appliesWhen.any
        : undefined;
  if (!Array.isArray(expressions) || expressions.length === 0) {
    throw ruleDefinitionError(
      "适用性组合必须包含表达式。",
      "applicability_shape",
    );
  }
  for (const expression of expressions)
    parseApplicabilityExpression(expression);
}

export function evaluateApplicability(
  appliesWhen: AppliesWhen,
  context: ApplicabilityContext,
): ApplicabilityResult {
  validateApplicability(appliesWhen);
  let truth: TruthValue;
  if (typeof appliesWhen === "string") {
    truth = evaluateExpression(appliesWhen, context);
  } else {
    const keys = Object.keys(appliesWhen);
    if (keys.length !== 1 || (keys[0] !== "all" && keys[0] !== "any")) {
      throw ruleDefinitionError(
        "适用性组合必须恰好包含一个 all 或 any。",
        "applicability_shape",
      );
    }
    const operator = keys[0];
    const expressions =
      operator === "all" && "all" in appliesWhen
        ? appliesWhen.all
        : operator === "any" && "any" in appliesWhen
          ? appliesWhen.any
          : undefined;
    if (!Array.isArray(expressions) || expressions.length === 0) {
      throw ruleDefinitionError(
        "适用性组合必须包含表达式。",
        "applicability_shape",
      );
    }
    const values = expressions.map((expression) =>
      evaluateExpression(expression, context),
    );
    truth = operator === "all" ? all(values) : any(values);
  }
  return truth === "unknown"
    ? { value: "UNKNOWN", reason: "登记字段在当前扫描上下文中缺值。" }
    : truth
      ? { value: "APPLICABLE", reason: "适用性条件成立。" }
      : { value: "NOT_APPLICABLE", reason: "适用性条件不成立。" };
}

function evaluateExpression(
  expression: string,
  context: ApplicabilityContext,
): TruthValue {
  const { field, operator, expected } =
    parseApplicabilityExpression(expression);
  const actual =
    field === "project.platform" ? context.project.platform : context.mode;
  if (actual === undefined) return "unknown";
  return operator === "==" ? actual === expected : actual !== expected;
}

function parseApplicabilityExpression(
  expression: string,
): ParsedApplicabilityExpression {
  const match = EXPRESSION.exec(expression);
  if (match === null || !REGISTERED_APPLICABILITY_PATHS.has(match[1] ?? "")) {
    throw ruleDefinitionError(
      "适用性表达式包含未登记路径或不支持的语法。",
      "applicability_syntax",
    );
  }
  const expected = match[3] ?? match[4] ?? match[5];
  if (expected === undefined) {
    throw ruleDefinitionError(
      "适用性表达式包含未登记路径或不支持的语法。",
      "applicability_syntax",
    );
  }
  const field = match[1] as ParsedApplicabilityExpression["field"];
  if (!APPLICABILITY_VALUES[field].has(expected)) {
    throw ruleDefinitionError(
      "适用性表达式包含未登记的字段值。",
      "applicability_value",
    );
  }
  return {
    field,
    operator: match[2] as ParsedApplicabilityExpression["operator"],
    expected,
  };
}

function all(values: readonly TruthValue[]): TruthValue {
  if (values.includes(false)) return false;
  return values.includes("unknown") ? "unknown" : true;
}

function any(values: readonly TruthValue[]): TruthValue {
  if (values.includes(true)) return true;
  return values.includes("unknown") ? "unknown" : false;
}

export class DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();

  public register(detector: Detector): void {
    if (this.detectors.has(detector.implementation)) {
      throw internalError("检测器重复注册。", "duplicate_detector");
    }
    this.detectors.set(detector.implementation, detector);
  }

  public get(implementation: string): Detector | undefined {
    return this.detectors.get(implementation);
  }
}

export async function executeRules(
  options: ExecuteRulesOptions,
): Promise<RuleExecutionResult> {
  const evaluations: RuleEvaluation[] = [];
  const evidenceById = new Map<
    string,
    { readonly evidence: Evidence; readonly canonical: string }
  >();
  const findings: Finding[] = [];

  for (const rule of options.rules) {
    const applicability = evaluateApplicability(rule.appliesWhen, {
      ...(options.context.mode === undefined
        ? {}
        : { mode: options.context.mode }),
      project: { platform: options.context.project.platform },
    });
    if (applicability.value !== "APPLICABLE") {
      evaluations.push({
        ruleId: rule.id,
        applicability: applicability.value,
        reason: applicability.reason,
        executed: false,
      });
      continue;
    }

    const detector = options.registry.get(rule.detector.implementation);
    if (detector === undefined) {
      throw internalError("适用规则缺少已注册检测器。", "missing_detector");
    }
    let detected: DetectionResult;
    try {
      detected = await detector.detect({
        project: options.context.project,
        rule,
        fs: options.context.fs,
        hash: options.context.hash,
        workspaceRoot: options.context.workspaceRoot,
        globalExcludePaths: options.context.globalExcludePaths,
      });
    } catch (error) {
      if (
        error instanceof HCheckError &&
        error.code === "EVIDENCE_INCOMPLETE"
      ) {
        throw new HCheckError("EVIDENCE_INCOMPLETE", "源码证据采集不完整。", {
          kind: "detector_evidence_incomplete",
        });
      }
      throw internalError("检测器执行失败。", "detector_failure");
    }
    let result: DetectionResult;
    try {
      result = normalizeDetectionResult(detected);
    } catch (error) {
      if (error instanceof HCheckError) throw error;
      throw internalError("检测结果结构无效。", "invalid_detection_result");
    }
    for (const item of result.evidence) {
      let canonical: string;
      try {
        canonical = canonicalStringify(item);
      } catch {
        throw internalError("检测结果结构无效。", "invalid_detection_result");
      }
      const existing = evidenceById.get(item.id);
      if (existing === undefined) {
        evidenceById.set(item.id, { evidence: item, canonical });
      } else if (existing.canonical !== canonical) {
        throw internalError(
          "跨规则 Evidence 内容冲突。",
          "conflicting_evidence",
        );
      }
    }
    findings.push(...result.findings);
    evaluations.push({
      ruleId: rule.id,
      applicability: applicability.value,
      reason: applicability.reason,
      executed: true,
    });
  }

  let normalized: DetectionResult;
  try {
    normalized = normalizeDetectionResult({
      evidence: [...evidenceById.values()].map(({ evidence }) => evidence),
      findings,
    });
  } catch (error) {
    if (error instanceof HCheckError) throw error;
    throw internalError("检测结果结构无效。", "invalid_detection_result");
  }
  return cloneAndFreeze({
    evidence: normalized.evidence,
    findings: normalized.findings,
    evaluations,
  });
}

export function normalizeDetectionResult(result: unknown): DetectionResult {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    Object.getPrototypeOf(result) !== Object.prototype ||
    !Object.hasOwn(result, "evidence") ||
    !Object.hasOwn(result, "findings") ||
    Object.keys(result).some(
      (key) => key !== "evidence" && key !== "findings",
    ) ||
    !Array.isArray(Reflect.get(result, "evidence")) ||
    !Array.isArray(Reflect.get(result, "findings"))
  ) {
    throw internalError("检测结果结构无效。", "invalid_detection_result");
  }
  const resultEvidence = Reflect.get(result, "evidence") as unknown[];
  const resultFindings = Reflect.get(result, "findings") as unknown[];
  const evidenceById = new Map<string, Evidence>();
  for (const item of resultEvidence) {
    try {
      validateEvidence(item);
    } catch {
      throw internalError("检测器返回了无效 Evidence。", "invalid_evidence");
    }
    if (evidenceById.has(item.id)) {
      throw internalError(
        "检测器返回了重复 Evidence ID。",
        "duplicate_evidence_id",
      );
    }
    evidenceById.set(item.id, item);
  }

  const findingByFingerprint = new Map<string, Finding>();
  for (const item of resultFindings) {
    try {
      validateFinding(item);
    } catch {
      throw internalError("检测器返回了无效 Finding。", "invalid_finding");
    }
    for (const evidenceId of item.evidenceIds) {
      if (!evidenceById.has(evidenceId)) {
        throw internalError(
          "Finding 引用了当前结果中不存在的证据。",
          "dangling_evidence",
        );
      }
    }
    const existing = findingByFingerprint.get(item.fingerprint);
    if (existing === undefined) {
      findingByFingerprint.set(item.fingerprint, item);
      continue;
    }
    if (findingSemantics(existing) !== findingSemantics(item)) {
      throw internalError(
        "相同指纹的 Finding 语义冲突。",
        "conflicting_finding",
      );
    }
    findingByFingerprint.set(item.fingerprint, mergeFinding(existing, item));
  }

  return cloneAndFreeze({
    evidence: [...evidenceById.values()].sort((left, right) =>
      compareCodePoints(left.id, right.id),
    ),
    findings: [...findingByFingerprint.values()].sort(compareFindings),
  });
}

function findingSemantics(finding: Finding): string {
  return canonicalStringify(
    Object.fromEntries(
      Object.entries(finding).filter(
        ([key]) => key !== "evidenceIds" && key !== "locations",
      ),
    ),
  );
}

function mergeFinding(left: Finding, right: Finding): Finding {
  const evidenceIds = [
    ...new Set([...left.evidenceIds, ...right.evidenceIds]),
  ].sort(compareCodePoints);
  const locations = new Map<string, Finding["locations"][number]>();
  for (const location of [...left.locations, ...right.locations]) {
    locations.set(canonicalStringify(location), location);
  }
  return {
    ...left,
    evidenceIds,
    locations: [...locations.entries()]
      .map(([, location]) => location)
      .sort(compareSourceLocations),
  };
}

function compareSourceLocations(
  left: Finding["locations"][number],
  right: Finding["locations"][number],
): number {
  return (
    compareCodePoints(left.uri, right.uri) ||
    (left.line ?? 0) - (right.line ?? 0) ||
    (left.column ?? 0) - (right.column ?? 0) ||
    compareCodePoints(left.logicalPath ?? "", right.logicalPath ?? "")
  );
}

function internalError(message: string, kind: string): HCheckError {
  return new HCheckError("INTERNAL_ERROR", message, { kind });
}
