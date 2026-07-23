import {
  createEvidence,
  createFinding,
  HCheckError,
  type SourceLocation,
} from "@hcheck/core";
import {
  collectDependencyManifest,
  collectPrivacyPolicyEvidence,
  createDependencyGraph,
  type SdkCandidate,
  type SdkCandidateConfidence,
} from "@hcheck/project-model";
import type { DetectionContext, DetectionResult, Detector } from "../index.js";

const IMPLEMENTATION = "privacy.sdkDisclosureConsistency";
const DEFAULT_POLICY_FILES = Object.freeze(["docs/privacy-policy.md"]);
const OPTION_POLICY_FILES = "policy_files";
const OPTION_MINIMUM_CONFIDENCE = "minimum_fingerprint_confidence";
const ALLOWED_OPTION_KEYS = new Set([
  OPTION_POLICY_FILES,
  OPTION_MINIMUM_CONFIDENCE,
]);
const CONFIDENCE_RANK: Record<SdkCandidateConfidence, number> = {
  PROBABLE: 0,
  POSSIBLE: 1,
};

interface PrivacySdkOptions {
  readonly policyFiles: readonly string[];
  readonly minimumConfidence: SdkCandidateConfidence;
}

export const privacySdkDisclosureDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectSdkDisclosureConsistency(context);
  },
});

export async function detectSdkDisclosureConsistency(
  context: DetectionContext,
): Promise<DetectionResult> {
  const options = readOptions(context);
  const manifest = await readDependencyManifest(context);
  const graph = createDependencyGraph(manifest);
  const candidates = graph.sdkCandidates.filter((candidate) =>
    confidenceAtLeast(candidate.confidence, options.minimumConfidence),
  );
  if (candidates.length === 0) {
    return deepFreeze({ evidence: [], findings: [] });
  }

  const expectedDisclosures = uniqueSorted(
    candidates.flatMap((candidate) => candidate.disclosureNames),
  );
  const privacyEvidence = await collectPrivacyPolicyEvidence(
    context.workspaceRoot,
    context.fs,
    {
      policyFiles: options.policyFiles,
      expectedDisclosures,
    },
  );
  const disclosed = new Set(
    privacyEvidence.files.flatMap((file) => file.disclosedSdkNames),
  );
  const missing = candidates.filter(
    (candidate) =>
      !candidate.disclosureNames.some((name) => disclosed.has(name)),
  );
  if (missing.length === 0) {
    return deepFreeze({ evidence: [], findings: [] });
  }

  const evidence = await Promise.all(
    missing.map((candidate) => createCandidateEvidence(candidate, context)),
  );
  const findings = await Promise.all(
    missing.map((candidate, index) =>
      createCandidateFinding(
        candidate,
        evidence[index]?.id ?? "evidence:invalid",
        privacyEvidence.completeness,
        context,
      ),
    ),
  );
  return deepFreeze({ evidence, findings });
}

function readOptions(context: DetectionContext): PrivacySdkOptions {
  const raw = context.rule.detector.options ?? {};
  const keys = Object.keys(raw);
  if (keys.some((key) => !ALLOWED_OPTION_KEYS.has(key))) {
    throw invalidDetectorOptions();
  }
  const policyFiles =
    raw[OPTION_POLICY_FILES] === undefined
      ? DEFAULT_POLICY_FILES
      : readPolicyFiles(raw[OPTION_POLICY_FILES]);
  const minimumConfidence =
    raw[OPTION_MINIMUM_CONFIDENCE] === undefined
      ? "PROBABLE"
      : readMinimumConfidence(raw[OPTION_MINIMUM_CONFIDENCE]);
  return { policyFiles, minimumConfidence };
}

function readPolicyFiles(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 16) {
    throw invalidDetectorOptions();
  }
  if (
    value.some((item) => typeof item !== "string" || !isSafeRelativePath(item))
  ) {
    throw invalidDetectorOptions();
  }
  return value;
}

function readMinimumConfidence(value: unknown): SdkCandidateConfidence {
  if (value === "probable") return "PROBABLE";
  if (value === "possible") return "POSSIBLE";
  throw invalidDetectorOptions();
}

async function readDependencyManifest(context: DetectionContext) {
  try {
    return await collectDependencyManifest(context.workspaceRoot, context.fs);
  } catch {
    throw new HCheckError("EVIDENCE_INCOMPLETE", "依赖证据无法完整解析。", {
      kind: "dependency_manifest",
    });
  }
}

async function createCandidateEvidence(
  candidate: SdkCandidate,
  context: DetectionContext,
) {
  return createEvidence(
    {
      type: "dependency",
      source: candidate.source,
      summary: "依赖图发现未披露第三方 SDK 候选。",
      content: `undisclosed-sdk\0${candidate.fingerprint}\0${candidate.dependencyPath.join("\0")}`,
      redacted: true,
      location: candidateLocation(candidate),
    },
    context.hash,
  );
}

async function createCandidateFinding(
  candidate: SdkCandidate,
  evidenceId: `evidence:${string}`,
  privacyCompleteness: "COMPLETE" | "INCOMPLETE",
  context: DetectionContext,
) {
  const missingPolicyNote =
    privacyCompleteness === "INCOMPLETE"
      ? "隐私政策证据不完整，不能视为已披露。"
      : "隐私政策未披露该 SDK 候选。";
  return createFinding(
    {
      ruleId: context.rule.id,
      ruleVersion: context.rule.version,
      moduleId: "privacy",
      semanticKey: `undisclosed-sdk:${candidate.fingerprint}`,
      primaryLocationUri: candidate.source,
      title: context.rule.title,
      severity: context.rule.severity,
      confidence: context.rule.defaultConfidence,
      applicability: "APPLICABLE",
      message: `${missingPolicyNote} 候选：${candidate.name}。`,
      locations: [candidateLocation(candidate)],
      evidenceIds: [evidenceId],
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
}

function candidateLocation(candidate: SdkCandidate): SourceLocation {
  return {
    uri: candidate.source,
    logicalPath:
      candidate.source === "oh-package-lock.json5"
        ? `packages.${candidate.id}`
        : `dependencies.${candidate.name}`,
  };
}

function confidenceAtLeast(
  candidate: SdkCandidateConfidence,
  minimum: SdkCandidateConfidence,
): boolean {
  return CONFIDENCE_RANK[candidate] <= CONFIDENCE_RANK[minimum];
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
}

function isSafeRelativePath(value: string): boolean {
  return (
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.includes("\0") &&
    !/^[A-Za-z]:/u.test(value) &&
    !value.split("/").includes("..")
  );
}

function invalidDetectorOptions(): HCheckError {
  return new HCheckError("INTERNAL_ERROR", "内置检测器配置无效。", {
    kind: "invalid_detector_options",
  });
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}
