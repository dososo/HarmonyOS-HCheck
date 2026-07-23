import { createEvidence, createFinding, HCheckError } from "@hcheck/core";
import type { DetectionContext, DetectionResult, Detector } from "../index.js";
import {
  scanSourceStrings,
  SOURCE_STRING_SCAN_LIMITS,
  type SourceStringMatch,
  type SourceStringScanLimits,
  type SourceStringScanOptions,
} from "./metadata-placeholder.js";

const IMPLEMENTATION = "package.testEndpoint";
const ALLOWED_EXTENSIONS = new Set([".ets", ".ts", ".json5"]);
const ALLOWED_OPTION_KEYS = new Set([
  "schemes",
  "blocked_hosts",
  "extensions",
  "exclude_paths",
]);
const EXPECTED_SCHEMES = ["http", "https"] as const;
const EXPECTED_BLOCKED_HOSTS = [
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "[::1]",
] as const;
const MAX_EXCLUDE_PATHS = 64;
const MAX_EXCLUDE_PATH_LENGTH = 256;
const LOOPBACK_ENDPOINT =
  /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?::[0-9]{1,5})?(?=$|[/?#:'"`\s\\])/giu;

export const testEndpointDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectTestEndpoint(context);
  },
});

export async function detectTestEndpoint(
  context: DetectionContext,
  limits: SourceStringScanLimits = SOURCE_STRING_SCAN_LIMITS,
): Promise<DetectionResult> {
  const options = readOptions(context);
  const matches = await scanSourceStrings(
    context,
    options,
    limits,
    collectTestEndpointMatches,
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
    const item = await createEvidence(
      {
        type: match.uri.endsWith(".json5") ? "config" : "source",
        source: match.uri,
        summary: "发现本地环回测试地址。",
        content: `${match.uri}\0loopback-endpoint\0${ordinal}`,
        redacted: true,
        location: match.location,
      },
      context.hash,
    );
    const finding = await createFinding(
      {
        ruleId: context.rule.id,
        ruleVersion: context.rule.version,
        moduleId: match.moduleId,
        semanticKey: `test-endpoint:${ordinal}`,
        primaryLocationUri: match.uri,
        title: context.rule.title,
        severity: context.rule.severity,
        confidence: context.rule.defaultConfidence,
        applicability: "APPLICABLE",
        message: "可发布内容中发现本地环回测试地址。",
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
      },
      context.hash,
    );
    evidence.push(item);
    findings.push(finding);
  }

  return deepFreeze({ evidence, findings });
}

function readOptions(context: DetectionContext): SourceStringScanOptions {
  const raw = context.rule.detector.options;
  const schemes = raw?.schemes;
  const blockedHosts = raw?.blocked_hosts;
  const extensions = raw?.extensions;
  const excludePaths = raw?.exclude_paths;
  const optionKeys = Object.keys(raw ?? {});
  if (
    optionKeys.length !== ALLOWED_OPTION_KEYS.size ||
    optionKeys.some((key) => !ALLOWED_OPTION_KEYS.has(key)) ||
    !arrayEquals(schemes, EXPECTED_SCHEMES) ||
    !arrayEquals(blockedHosts, EXPECTED_BLOCKED_HOSTS) ||
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

function collectTestEndpointMatches(
  source: string,
  start: number,
  end: number,
  output: SourceStringMatch[],
  remainingMatches: number,
): void {
  LOOPBACK_ENDPOINT.lastIndex = start;
  while (true) {
    const match = LOOPBACK_ENDPOINT.exec(source);
    if (match === null) return;
    if (match.index >= end) return;
    if (match.index + match[0].length > end) continue;
    if (output.length >= remainingMatches) throw budgetExceeded();
    output.push({ index: match.index, kind: "loopback-endpoint" });
  }
}

function arrayEquals(
  value: unknown,
  expected: readonly string[],
): value is readonly string[] {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    expected.every((item, index) => value[index] === item)
  );
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

function invalidDetectorOptions(): HCheckError {
  return new HCheckError("INTERNAL_ERROR", "内置检测器配置无效。", {
    kind: "invalid_detector_options",
  });
}

function budgetExceeded(): HCheckError {
  return new HCheckError("EVIDENCE_INCOMPLETE", "源码证据采集不完整。", {
    kind: "source_collection",
    reason: "resource_budget",
  });
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  const stack: object[] = [value];
  const seen = new WeakSet<object>();
  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) {
      if (child !== null && typeof child === "object") stack.push(child);
    }
    Object.freeze(current);
  }
  return value;
}
