import {
  compareCodePoints,
  createEvidence,
  createFinding,
  HCheckError,
  normalizeRelativeUri,
  type SourceLocation,
} from "@hcheck/core";
import { parseJSON, type AST as JsonAst } from "jsonc-eslint-parser";
import { minimatch } from "minimatch";
import ts from "typescript";
import type { DetectionContext, DetectionResult, Detector } from "../index.js";

const IMPLEMENTATION = "metadata.placeholderContent";
const MARKER = "HCHECK_PLACEHOLDER";
const MAX_FILE_BYTES = 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set([".ets", ".ts", ".json5"]);
const ALLOWED_OPTION_KEYS = new Set(["marker", "extensions", "exclude_paths"]);
const UTF8_ENCODER = new TextEncoder();
const MAX_AST_DEPTH = 64;
const MAX_AST_NODES = 10_000;
const MAX_EXCLUDE_PATHS = 64;
const MAX_EXCLUDE_PATH_LENGTH = 256;

export interface SourceStringMatch {
  readonly index: number;
  readonly kind: string;
}

export interface LocatedSourceStringMatch extends SourceStringMatch {
  readonly uri: string;
  readonly moduleId: string;
  readonly location: SourceLocation;
}

export interface SourceStringScanOptions {
  readonly extensions: readonly string[];
  readonly ruleExcludePaths: readonly string[];
  readonly globalExcludePaths: readonly string[];
}

export type SourceStringMatchCollector = (
  source: string,
  start: number,
  end: number,
  output: SourceStringMatch[],
  remainingMatches: number,
) => void;

export interface MetadataPlaceholderLimits {
  readonly directories: number;
  readonly directoryEntries: number;
  readonly candidateFiles: number;
  readonly totalReadBytes: number;
  readonly matches: number;
}

export const METADATA_PLACEHOLDER_LIMITS: MetadataPlaceholderLimits =
  Object.freeze({
    directories: 2_048,
    directoryEntries: 100_000,
    candidateFiles: 20_000,
    totalReadBytes: 64 * 1024 * 1024,
    matches: 20_000,
  });
export const SOURCE_STRING_SCAN_LIMITS = METADATA_PLACEHOLDER_LIMITS;
export type SourceStringScanLimits = MetadataPlaceholderLimits;

interface ScanBudget {
  directories: number;
  directoryEntries: number;
  candidateFiles: number;
  totalReadBytes: number;
  matches: number;
}

export const metadataPlaceholderDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectMetadataPlaceholder(context, METADATA_PLACEHOLDER_LIMITS);
  },
});

export async function detectMetadataPlaceholder(
  context: DetectionContext,
  limits: MetadataPlaceholderLimits = METADATA_PLACEHOLDER_LIMITS,
): Promise<DetectionResult> {
  const options = readOptions(context);
  const matches = await scanSourceStrings(
    context,
    options,
    limits,
    collectPlaceholderMatches,
  );
  const evidence = [];
  const findings = [];
  const ordinalByUri = new Map<string, number>();
  const seen = new Set<string>();
  for (const match of matches) {
    const positionKey = `${match.uri}\0${match.index}`;
    if (seen.has(positionKey)) continue;
    seen.add(positionKey);
    const ordinal = (ordinalByUri.get(match.uri) ?? 0) + 1;
    ordinalByUri.set(match.uri, ordinal);
    const location = match.location;
    const item = await createEvidence(
      {
        type: match.uri.endsWith(".json5") ? "config" : "source",
        source: match.uri,
        summary: `发现精确占位标记 ${MARKER}。`,
        content: `${match.uri}\0${match.kind}\0${ordinal}`,
        redacted: true,
        location,
      },
      context.hash,
    );
    const finding = await createFinding(
      {
        ruleId: context.rule.id,
        ruleVersion: context.rule.version,
        moduleId: match.moduleId,
        semanticKey: `placeholder:${MARKER}:${ordinal}`,
        primaryLocationUri: match.uri,
        title: context.rule.title,
        severity: context.rule.severity,
        confidence: context.rule.defaultConfidence,
        applicability: "APPLICABLE",
        message: "可发布内容中发现精确占位标记。",
        locations: [location],
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
      },
      context.hash,
    );
    evidence.push(item);
    findings.push(finding);
  }

  return deepFreeze({ evidence, findings });
}

export async function scanSourceStrings(
  context: DetectionContext,
  options: SourceStringScanOptions,
  limits: SourceStringScanLimits,
  collectMatches: SourceStringMatchCollector,
): Promise<readonly LocatedSourceStringMatch[]> {
  validateLimits(limits);
  const root = await safePortCall(() =>
    context.fs.realpath(context.workspaceRoot),
  );
  const matches: LocatedSourceStringMatch[] = [];
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
        module.relativePath,
        options,
        matches,
        directoryState,
        canonicalRoot,
        budget,
        limits,
        collectMatches,
      );
    }
  }

  return matches.sort((left, right) => {
    const uriOrder = compareCodePoints(left.uri, right.uri);
    return uriOrder === 0 ? left.index - right.index : uriOrder;
  });
}

function validateLimits(limits: MetadataPlaceholderLimits): void {
  const keys = Object.keys(limits);
  const allowedKeys = Object.keys(METADATA_PLACEHOLDER_LIMITS) as Array<
    keyof MetadataPlaceholderLimits
  >;
  if (
    keys.length !== allowedKeys.length ||
    keys.some(
      (key) => !allowedKeys.includes(key as keyof MetadataPlaceholderLimits),
    )
  ) {
    throw invalidDetectorOptions();
  }
  for (const key of allowedKeys) {
    const value = limits[key];
    if (
      !Number.isSafeInteger(value) ||
      value < 1 ||
      value > METADATA_PLACEHOLDER_LIMITS[key]
    ) {
      throw invalidDetectorOptions();
    }
  }
}

function consumeBudget(
  budget: ScanBudget,
  key: keyof ScanBudget,
  amount: number,
  limits: MetadataPlaceholderLimits,
): void {
  const next = budget[key] + amount;
  if (!Number.isSafeInteger(next) || next > limits[key]) {
    throw budgetExceeded();
  }
  budget[key] = next;
}

function readOptions(context: DetectionContext): SourceStringScanOptions {
  const raw = context.rule.detector.options;
  const extensions = raw?.extensions;
  const excludePaths = raw?.exclude_paths;
  const optionKeys = Object.keys(raw ?? {});
  if (
    optionKeys.length !== ALLOWED_OPTION_KEYS.size ||
    optionKeys.some((key) => !ALLOWED_OPTION_KEYS.has(key)) ||
    raw?.marker !== MARKER ||
    !Array.isArray(extensions) ||
    extensions.length !== ALLOWED_EXTENSIONS.size ||
    extensions.some(
      (value) => typeof value !== "string" || !ALLOWED_EXTENSIONS.has(value),
    ) ||
    new Set(extensions).size !== ALLOWED_EXTENSIONS.size ||
    !Array.isArray(excludePaths) ||
    !validExcludePaths(excludePaths) ||
    !validExcludePaths(context.globalExcludePaths)
  ) {
    throw invalidDetectorOptions();
  }
  return {
    extensions: extensions as readonly string[],
    ruleExcludePaths: excludePaths as readonly string[],
    globalExcludePaths: context.globalExcludePaths,
  };
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

interface DirectoryState {
  readonly visited: Set<string>;
  readonly visiting: Set<string>;
}

async function walkDirectory(
  context: DetectionContext,
  canonicalWorkspaceRoot: string,
  absoluteDirectory: string,
  relativeDirectory: string,
  moduleId: string,
  options: SourceStringScanOptions,
  output: LocatedSourceStringMatch[],
  directoryState: DirectoryState,
  canonicalDirectory: string,
  budget: ScanBudget,
  limits: MetadataPlaceholderLimits,
  collectMatches: SourceStringMatchCollector,
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
          moduleId,
          options,
          output,
          directoryState,
          canonical,
          budget,
          limits,
          collectMatches,
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
      const fileMatches = safelyFindMatches(
        source,
        uri,
        limits.matches - budget.matches,
        collectMatches,
      );
      consumeBudget(budget, "matches", fileMatches.length, limits);
      if (fileMatches.length === 0) continue;
      const lineStarts = buildLineStarts(source);
      for (const match of fileMatches) {
        output.push({
          ...match,
          uri,
          moduleId,
          location: locate(lineStarts, match.index, uri),
        });
      }
    }
  } finally {
    directoryState.visiting.delete(directoryKey);
  }
  directoryState.visited.add(directoryKey);
}

function safelyFindMatches(
  source: string,
  uri: string,
  remainingMatches: number,
  collectMatches: SourceStringMatchCollector,
): readonly SourceStringMatch[] {
  try {
    return uri.endsWith(".json5")
      ? findJson5Matches(source, remainingMatches, collectMatches)
      : findTypeScriptMatches(source, uri, remainingMatches, collectMatches);
  } catch (error) {
    if (error instanceof HCheckError && error.code === "EVIDENCE_INCOMPLETE") {
      throw error;
    }
    throw incomplete();
  }
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

function findJson5Matches(
  source: string,
  remainingMatches: number,
  collectMatches: SourceStringMatchCollector,
): readonly SourceStringMatch[] {
  let program: JsonAst.JSONProgram;
  try {
    program = parseJSON(source.replace(/^\uFEFF/u, ""), {
      jsonSyntax: "JSON5",
    });
  } catch {
    throw incomplete();
  }
  const expression = program.body[0]?.expression;
  if (expression === undefined) throw incomplete();
  const matches: SourceStringMatch[] = [];
  const stack: Array<{ node: JsonAst.JSONExpression; depth: number }> = [
    { node: expression, depth: 1 },
  ];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    nodes += 1;
    if (nodes > MAX_AST_NODES || current.depth > MAX_AST_DEPTH) {
      throw incomplete();
    }
    const { node, depth } = current;
    if (node.type === "JSONLiteral") {
      if (typeof node.value === "string") {
        collectMatches(
          source,
          node.range[0],
          node.range[1],
          matches,
          remainingMatches,
        );
      }
      continue;
    }
    if (node.type === "JSONArrayExpression") {
      for (let index = node.elements.length - 1; index >= 0; index -= 1) {
        const element = node.elements[index];
        if (element !== null && element !== undefined) {
          stack.push({ node: element, depth: depth + 1 });
        }
      }
      continue;
    }
    if (node.type === "JSONObjectExpression") {
      const lastPropertyByKey = new Map<string, JsonAst.JSONProperty>();
      for (const property of node.properties) {
        const key =
          property.key.type === "JSONIdentifier"
            ? property.key.name
            : String(property.key.value);
        lastPropertyByKey.set(key, property);
      }
      const properties = [...lastPropertyByKey.values()];
      for (let index = properties.length - 1; index >= 0; index -= 1) {
        const property = properties[index];
        if (property !== undefined) {
          stack.push({ node: property.value, depth: depth + 1 });
        }
      }
    }
  }
  return matches.sort((left, right) => left.index - right.index);
}

function findTypeScriptMatches(
  source: string,
  uri: string,
  remainingMatches: number,
  collectMatches: SourceStringMatchCollector,
): readonly SourceStringMatch[] {
  const scriptKind = uri.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.TS;
  const ast = ts.createSourceFile(
    uri,
    source,
    ts.ScriptTarget.Latest,
    true,
    scriptKind,
  );
  const diagnostics = (
    ast as ts.SourceFile & {
      readonly parseDiagnostics?: readonly ts.Diagnostic[];
    }
  ).parseDiagnostics;
  if (diagnostics?.some((item) => item.code === 1002 || item.code === 1160)) {
    throw incomplete();
  }
  const matches: SourceStringMatch[] = [];
  const stack: Array<{ node: ts.Node; depth: number }> = [
    { node: ast, depth: 1 },
  ];
  let nodes = 0;
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    nodes += 1;
    if (nodes > MAX_AST_NODES || current.depth > MAX_AST_DEPTH)
      throw incomplete();
    if (
      ts.isStringLiteral(current.node) ||
      ts.isNoSubstitutionTemplateLiteral(current.node) ||
      current.node.kind === ts.SyntaxKind.TemplateHead ||
      current.node.kind === ts.SyntaxKind.TemplateMiddle ||
      current.node.kind === ts.SyntaxKind.TemplateTail
    ) {
      collectMatches(
        source,
        current.node.getStart(ast),
        current.node.end,
        matches,
        remainingMatches,
      );
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

function collectPlaceholderMatches(
  source: string,
  start: number,
  end: number,
  output: SourceStringMatch[],
  remainingMatches: number,
): void {
  let index = source.indexOf(MARKER, start);
  while (index !== -1 && index < end) {
    if (output.length >= remainingMatches) throw budgetExceeded();
    output.push({ index, kind: MARKER });
    index = source.indexOf(MARKER, index + MARKER.length);
  }
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
