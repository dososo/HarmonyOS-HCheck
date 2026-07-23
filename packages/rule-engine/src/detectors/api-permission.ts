import {
  compareCodePoints,
  createEvidence,
  createFinding,
  HCheckError,
  normalizeRelativeUri,
  type SourceLocation,
} from "@hcheck/core";
import {
  collectPermissionDeclarations,
  hasDeclaredPermission,
} from "@hcheck/project-model";
import { minimatch } from "minimatch";
import ts from "typescript";
import type { DetectionContext, DetectionResult, Detector } from "../index.js";

const IMPLEMENTATION = "permission.apiDeclarationConsistency";
const MAPPING_SOURCE = "official-minimal-2026-07-11";
const EXPECTED_MAPPING = Object.freeze({
  importModule: "@kit.LocationKit",
  importName: "geoLocationManager",
  member: "getCurrentLocation",
  permission: "ohos.permission.APPROXIMATELY_LOCATION",
  source:
    "https://developer.huawei.com/consumer/cn/doc/harmonyos-references-V5/js-apis-geolocationmanager-V5",
  verifiedAt: "2026-07-11",
});
const ALLOWED_EXTENSIONS = new Set([".ets", ".ts"]);
const ALLOWED_OPTION_KEYS = new Set([
  "mapping_source",
  "extensions",
  "exclude_paths",
  "mappings",
]);
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_AST_DEPTH = 64;
const MAX_AST_NODES = 10_000;
const MAX_EXCLUDE_PATHS = 64;
const MAX_EXCLUDE_PATH_LENGTH = 256;
const UTF8_ENCODER = new TextEncoder();

interface ApiPermissionScanOptions {
  readonly extensions: readonly string[];
  readonly ruleExcludePaths: readonly string[];
  readonly globalExcludePaths: readonly string[];
}

interface ApiPermissionLimits {
  readonly directories: number;
  readonly directoryEntries: number;
  readonly candidateFiles: number;
  readonly totalReadBytes: number;
  readonly matches: number;
}

const API_PERMISSION_LIMITS: ApiPermissionLimits = Object.freeze({
  directories: 2_048,
  directoryEntries: 100_000,
  candidateFiles: 20_000,
  totalReadBytes: 64 * 1024 * 1024,
  matches: 20_000,
});

interface ScanBudget {
  directories: number;
  directoryEntries: number;
  candidateFiles: number;
  totalReadBytes: number;
  matches: number;
}

interface DirectoryState {
  readonly visited: Set<string>;
  readonly visiting: Set<string>;
}

interface ApiPermissionMatch {
  readonly index: number;
  readonly uri: string;
  readonly moduleName: string;
  readonly location: SourceLocation;
  readonly api: string;
  readonly permission: string;
}

export const apiPermissionDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectApiPermissionConsistency(context);
  },
});

export async function detectApiPermissionConsistency(
  context: DetectionContext,
  limits: ApiPermissionLimits = API_PERMISSION_LIMITS,
): Promise<DetectionResult> {
  validateLimits(limits);
  const options = readOptions(context);
  const inventory = collectPermissionDeclarations(context.project);
  const matches = await scanApiPermissionCalls(context, options, limits);
  const evidence = [];
  const findings = [];
  const ordinalByUri = new Map<string, number>();
  const seen = new Set<string>();

  for (const match of matches) {
    if (hasDeclaredPermission(inventory, match.moduleName, match.permission)) {
      continue;
    }
    const positionKey = `${match.uri}\0${match.index}\0${match.permission}`;
    if (seen.has(positionKey)) continue;
    seen.add(positionKey);
    const ordinal = (ordinalByUri.get(match.uri) ?? 0) + 1;
    ordinalByUri.set(match.uri, ordinal);
    const item = await createEvidence(
      {
        type: "source",
        source: match.uri,
        summary: "发现需要权限声明的官方 API 调用。",
        content: `${match.uri}\0${match.api}\0${match.permission}\0${ordinal}`,
        redacted: true,
        location: match.location,
        metadata: {
          api: match.api,
          requiredPermission: match.permission,
          mappingSource: MAPPING_SOURCE,
        },
      },
      context.hash,
    );
    const finding = await createFinding(
      {
        ruleId: context.rule.id,
        ruleVersion: context.rule.version,
        moduleId: match.moduleName,
        semanticKey: `api-permission:${match.api}:${match.permission}:${ordinal}`,
        primaryLocationUri: match.uri,
        title: context.rule.title,
        severity: context.rule.severity,
        confidence: context.rule.defaultConfidence,
        applicability: "APPLICABLE",
        message: `源码调用 ${match.api}，但模块未声明 ${match.permission}。`,
        locations: [match.location],
        evidenceIds: [item.id],
        policyRefs: context.rule.policyRefs.map((reference) => ({
          source: reference.source,
          section: reference.section,
          url: reference.url,
          verifiedAt: reference.verifiedAt,
        })),
        remediation: context.rule.remediation,
        autofix: context.rule.autofix.level,
        status: "new",
        properties: {
          api: match.api,
          missingPermission: match.permission,
          mappingSource: MAPPING_SOURCE,
        },
      },
      context.hash,
    );
    evidence.push(item);
    findings.push(finding);
  }

  return deepFreeze({ evidence, findings });
}

async function scanApiPermissionCalls(
  context: DetectionContext,
  options: ApiPermissionScanOptions,
  limits: ApiPermissionLimits,
): Promise<readonly ApiPermissionMatch[]> {
  const root = await safePortCall(() =>
    context.fs.realpath(context.workspaceRoot),
  );
  const matches: ApiPermissionMatch[] = [];
  const directoryState: DirectoryState = {
    visited: new Set<string>(),
    visiting: new Set<string>(),
  };
  const budget: ScanBudget = {
    directories: 0,
    directoryEntries: 0,
    candidateFiles: 0,
    totalReadBytes: 0,
    matches: 0,
  };

  for (const module of context.project.modules) {
    if (module.isExternal) throw incomplete();
    for (const sourceRoot of [...module.sourceRoots].sort(compareCodePoints)) {
      const normalizedRoot = normalizeProjectPath(sourceRoot);
      if (matchesAny(normalizedRoot, options.globalExcludePaths)) continue;
      if (matchesAny(normalizedRoot, options.ruleExcludePaths)) continue;
      const absoluteRoot = await safePortCall(() =>
        context.fs.resolve(context.workspaceRoot, normalizedRoot),
      );
      const canonicalRoot = await safePortCall(() =>
        context.fs.realpath(absoluteRoot),
      );
      if (!isWithin(root, canonicalRoot)) throw incomplete();
      const kind = await safePortCall(() => context.fs.kind(absoluteRoot));
      if (kind !== "directory") throw incomplete();
      await walkDirectory(
        context,
        root,
        absoluteRoot,
        normalizedRoot,
        module.name,
        options,
        matches,
        directoryState,
        canonicalRoot,
        budget,
        limits,
      );
    }
  }

  return matches.sort((left, right) => {
    const uriOrder = compareCodePoints(left.uri, right.uri);
    return uriOrder === 0 ? left.index - right.index : uriOrder;
  });
}

async function walkDirectory(
  context: DetectionContext,
  canonicalWorkspaceRoot: string,
  absoluteDirectory: string,
  relativeDirectory: string,
  moduleName: string,
  options: ApiPermissionScanOptions,
  output: ApiPermissionMatch[],
  directoryState: DirectoryState,
  canonicalDirectory: string,
  budget: ScanBudget,
  limits: ApiPermissionLimits,
): Promise<void> {
  consumeBudget(budget, "directories", 1, limits);
  const directoryKey = canonicalPathKey(canonicalDirectory);
  if (
    directoryState.visited.has(directoryKey) ||
    directoryState.visiting.has(directoryKey)
  ) {
    throw incomplete();
  }
  directoryState.visiting.add(directoryKey);
  try {
    const entries = [
      ...(await safePortCall(() => context.fs.list(absoluteDirectory))),
    ]
      .map(validateEntryName)
      .sort(compareCodePoints);
    consumeBudget(budget, "directoryEntries", entries.length, limits);
    for (const entry of entries) {
      const uri = normalizeProjectPath(`${relativeDirectory}/${entry}`);
      if (matchesAny(uri, options.globalExcludePaths)) continue;
      if (matchesAny(uri, options.ruleExcludePaths)) continue;
      const absolute = await safePortCall(() =>
        context.fs.resolve(absoluteDirectory, entry),
      );
      const kind = await safePortCall(() => context.fs.kind(absolute));
      if (kind === "symlink") {
        const canonical = await safePortCall(() =>
          context.fs.realpath(absolute),
        );
        if (!isWithin(canonicalWorkspaceRoot, canonical)) throw incomplete();
        throw incomplete();
      }
      if (kind === "other") throw incomplete();
      if (kind === "directory") {
        const canonical = await safePortCall(() =>
          context.fs.realpath(absolute),
        );
        if (!isWithin(canonicalWorkspaceRoot, canonical)) throw incomplete();
        await walkDirectory(
          context,
          canonicalWorkspaceRoot,
          absolute,
          uri,
          moduleName,
          options,
          output,
          directoryState,
          canonical,
          budget,
          limits,
        );
        continue;
      }
      if (!options.extensions.some((extension) => uri.endsWith(extension))) {
        continue;
      }
      consumeBudget(budget, "candidateFiles", 1, limits);
      const canonical = await safePortCall(() => context.fs.realpath(absolute));
      if (!isWithin(canonicalWorkspaceRoot, canonical)) throw incomplete();
      const { source, bytes } = await readSource(
        context,
        absolute,
        limits.totalReadBytes - budget.totalReadBytes,
      );
      consumeBudget(budget, "totalReadBytes", bytes, limits);
      const fileMatches = findApiPermissionMatches(
        source,
        uri,
        moduleName,
        limits.matches - budget.matches,
      );
      consumeBudget(budget, "matches", fileMatches.length, limits);
      output.push(...fileMatches);
    }
  } finally {
    directoryState.visiting.delete(directoryKey);
  }
  directoryState.visited.add(directoryKey);
}

function findApiPermissionMatches(
  source: string,
  uri: string,
  moduleName: string,
  remainingMatches: number,
): readonly ApiPermissionMatch[] {
  const ast = ts.createSourceFile(
    uri,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const diagnostics = (
    ast as ts.SourceFile & {
      readonly parseDiagnostics?: readonly ts.Diagnostic[];
    }
  ).parseDiagnostics;
  if (diagnostics?.some((item) => item.code === 1002 || item.code === 1160)) {
    throw incomplete();
  }
  const importedNames = collectImportedNames(ast);
  if (importedNames.size === 0) return [];
  const matches: ApiPermissionMatch[] = [];
  const lineStarts = buildLineStarts(source);
  const stack: Array<{ node: ts.Node; depth: number }> = [
    { node: ast, depth: 1 },
  ];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    nodes += 1;
    if (nodes > MAX_AST_NODES || current.depth > MAX_AST_DEPTH) {
      throw incomplete();
    }
    if (
      ts.isCallExpression(current.node) &&
      ts.isPropertyAccessExpression(current.node.expression) &&
      current.node.expression.name.text === EXPECTED_MAPPING.member &&
      ts.isIdentifier(current.node.expression.expression) &&
      importedNames.has(current.node.expression.expression.text)
    ) {
      if (matches.length >= remainingMatches) throw budgetExceeded();
      const index = current.node.expression.getStart(ast);
      matches.push({
        index,
        uri,
        moduleName,
        location: locate(lineStarts, index, uri),
        api: `${EXPECTED_MAPPING.importName}.${EXPECTED_MAPPING.member}`,
        permission: EXPECTED_MAPPING.permission,
      });
    }
    const children: ts.Node[] = [];
    current.node.forEachChild((child) => {
      children.push(child);
    });
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const child = children[index];
      if (child !== undefined)
        stack.push({ node: child, depth: current.depth + 1 });
    }
  }
  return matches.sort((left, right) => left.index - right.index);
}

function collectImportedNames(ast: ts.SourceFile): ReadonlySet<string> {
  const names = new Set<string>();
  for (const statement of ast.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteral(statement.moduleSpecifier) ||
      statement.moduleSpecifier.text !== EXPECTED_MAPPING.importModule
    ) {
      continue;
    }
    const bindings = statement.importClause?.namedBindings;
    if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      if (element.propertyName?.text === EXPECTED_MAPPING.importName) {
        names.add(element.name.text);
        continue;
      }
      if (
        element.propertyName === undefined &&
        element.name.text === EXPECTED_MAPPING.importName
      ) {
        names.add(element.name.text);
      }
    }
  }
  return names;
}

function readOptions(context: DetectionContext): ApiPermissionScanOptions {
  const raw = context.rule.detector.options;
  const extensions = raw?.extensions;
  const excludePaths = raw?.exclude_paths;
  const mappings = raw?.mappings;
  const optionKeys = Object.keys(raw ?? {});
  if (
    optionKeys.length !== ALLOWED_OPTION_KEYS.size ||
    optionKeys.some((key) => !ALLOWED_OPTION_KEYS.has(key)) ||
    raw?.mapping_source !== MAPPING_SOURCE ||
    !Array.isArray(extensions) ||
    extensions.length !== ALLOWED_EXTENSIONS.size ||
    extensions.some(
      (value) => typeof value !== "string" || !ALLOWED_EXTENSIONS.has(value),
    ) ||
    new Set(extensions).size !== ALLOWED_EXTENSIONS.size ||
    !Array.isArray(excludePaths) ||
    !validExcludePaths(excludePaths) ||
    !validExcludePaths(context.globalExcludePaths) ||
    !validMappings(mappings)
  ) {
    throw invalidDetectorOptions();
  }
  return {
    extensions: extensions as readonly string[],
    ruleExcludePaths: excludePaths as readonly string[],
    globalExcludePaths: context.globalExcludePaths,
  };
}

function validMappings(value: unknown): boolean {
  if (!Array.isArray(value) || value.length !== 1) return false;
  const [mapping] = value;
  if (mapping === null || typeof mapping !== "object") return false;
  return (
    Reflect.get(mapping, "import_module") === EXPECTED_MAPPING.importModule &&
    Reflect.get(mapping, "import_name") === EXPECTED_MAPPING.importName &&
    Reflect.get(mapping, "member") === EXPECTED_MAPPING.member &&
    Reflect.get(mapping, "permission") === EXPECTED_MAPPING.permission &&
    Reflect.get(mapping, "source") === EXPECTED_MAPPING.source &&
    Reflect.get(mapping, "verified_at") === EXPECTED_MAPPING.verifiedAt &&
    Object.keys(mapping).length === 6
  );
}

function validateLimits(limits: ApiPermissionLimits): void {
  const keys = Object.keys(limits);
  const allowedKeys = Object.keys(API_PERMISSION_LIMITS) as Array<
    keyof ApiPermissionLimits
  >;
  if (
    keys.length !== allowedKeys.length ||
    keys.some((key) => !allowedKeys.includes(key as keyof ApiPermissionLimits))
  ) {
    throw invalidDetectorOptions();
  }
  for (const key of allowedKeys) {
    const value = limits[key];
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > API_PERMISSION_LIMITS[key]
    ) {
      throw invalidDetectorOptions();
    }
  }
}

function validExcludePaths(value: readonly unknown[]): boolean {
  return (
    value.length <= MAX_EXCLUDE_PATHS &&
    value.every(
      (item) =>
        typeof item === "string" &&
        item.length >= 1 &&
        item.length <= MAX_EXCLUDE_PATH_LENGTH &&
        !item.includes("\0"),
    )
  );
}

function consumeBudget(
  budget: ScanBudget,
  key: keyof ScanBudget,
  amount: number,
  limits: ApiPermissionLimits,
): void {
  const next = budget[key] + amount;
  if (!Number.isSafeInteger(next) || next > limits[key]) {
    throw budgetExceeded();
  }
  budget[key] = next;
}

async function readSource(
  context: DetectionContext,
  absolute: string,
  remainingReadBytes: number,
): Promise<{ readonly source: string; readonly bytes: number }> {
  const size = await safePortCall(() => context.fs.size(absolute));
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_FILE_BYTES) {
    throw incomplete();
  }
  if (size > remainingReadBytes) throw budgetExceeded();
  const source = await safePortCall(() => context.fs.readText(absolute));
  const sizeAfterRead = await safePortCall(() => context.fs.size(absolute));
  const bytes = UTF8_ENCODER.encode(source).byteLength;
  if (
    sizeAfterRead !== size ||
    bytes !== size ||
    bytes > MAX_FILE_BYTES ||
    source.includes("\uFFFD")
  ) {
    throw incomplete();
  }
  return { source, bytes };
}

function buildLineStarts(source: string): readonly number[] {
  const starts = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") starts.push(index + 1);
  }
  return starts;
}

function locate(
  lineStarts: readonly number[],
  index: number,
  uri: string,
): SourceLocation {
  let low = 0;
  let high = lineStarts.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if ((lineStarts[middle] ?? 0) <= index) low = middle + 1;
    else high = middle;
  }
  const lineIndex = Math.max(0, low - 1);
  return {
    uri,
    line: lineIndex + 1,
    column: index - (lineStarts[lineIndex] ?? 0) + 1,
  };
}

function matchesAny(uri: string, patterns: readonly string[]): boolean {
  return patterns.some(
    (pattern) =>
      minimatch(uri, pattern, { dot: true }) ||
      minimatch(`${uri}/`, pattern, { dot: true }),
  );
}

function validateEntryName(entry: string): string {
  if (
    entry.length === 0 ||
    entry === "." ||
    entry === ".." ||
    entry.includes("/") ||
    entry.includes("\\") ||
    entry.includes("\0")
  ) {
    throw incomplete();
  }
  return entry;
}

function normalizeProjectPath(value: string): string {
  const normalized = normalizeRelativeUri(value).replace(/\/+$/u, "");
  if (
    normalized.length === 0 ||
    normalized.startsWith("/") ||
    /(^|\/)\.\.?($|\/)/u.test(normalized) ||
    /^[A-Za-z]:\//u.test(normalized)
  ) {
    throw incomplete();
  }
  return normalized;
}

function isWithin(root: string, candidate: string): boolean {
  let normalizedRoot = normalizeAbsolutePath(root);
  let normalizedCandidate = normalizeAbsolutePath(candidate);
  if (/^[A-Za-z]:\//u.test(normalizedRoot) || normalizedRoot.startsWith("//")) {
    normalizedRoot = normalizedRoot.toLowerCase();
    normalizedCandidate = normalizedCandidate.toLowerCase();
  }
  return (
    normalizedCandidate === normalizedRoot ||
    normalizedRoot === "/" ||
    normalizedCandidate.startsWith(`${normalizedRoot}/`)
  );
}

function canonicalPathKey(value: string): string {
  const normalized = normalizeAbsolutePath(value);
  return /^[A-Za-z]:\//u.test(normalized) || normalized.startsWith("//")
    ? normalized.toLowerCase()
    : normalized;
}

function normalizeAbsolutePath(value: string): string {
  const normalized = value.replaceAll("\\", "/").replace(/\/+$/u, "");
  return normalized === "" ? "/" : normalized;
}

async function safePortCall<T>(operation: () => T | Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof HCheckError && error.code === "EVIDENCE_INCOMPLETE") {
      throw error;
    }
    throw incomplete();
  }
}

function incomplete(): HCheckError {
  return new HCheckError("EVIDENCE_INCOMPLETE", "源码证据采集不完整。", {
    kind: "source_collection",
  });
}

function budgetExceeded(): HCheckError {
  return new HCheckError("EVIDENCE_INCOMPLETE", "源码证据采集不完整。", {
    kind: "source_collection",
    reason: "resource_budget",
  });
}

function invalidDetectorOptions(): HCheckError {
  return new HCheckError("INTERNAL_ERROR", "内置检测器配置无效。", {
    kind: "invalid_detector_options",
  });
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  const stack: Array<{
    readonly value: object;
    readonly depth: number;
    readonly exit: boolean;
  }> = [{ value, depth: 1, exit: false }];
  const seen = new WeakSet<object>();
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    if (current.exit) {
      Object.freeze(current.value);
      continue;
    }
    if (seen.has(current.value)) continue;
    seen.add(current.value);
    nodes += 1;
    if (nodes > MAX_AST_NODES || current.depth > MAX_AST_DEPTH) {
      throw incomplete();
    }
    stack.push({ ...current, exit: true });
    const children = Object.values(current.value);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const child = children[index];
      if (child !== null && typeof child === "object") {
        stack.push({ value: child, depth: current.depth + 1, exit: false });
      }
    }
  }
  return value;
}
