import {
  createEvidence,
  createFinding,
  HCheckError,
  type SourceLocation,
} from "@hcheck/core";
import type { DetectionContext, DetectionResult, Detector } from "../index.js";

const SNAPSHOT_OPTION = "snapshot_path";
const DEFAULT_SNAPSHOT_PATH = ".hcheck/package-snapshot.json";
const IMPLEMENTATION_BUNDLE = "package.bundleIdentityConsistency";
const IMPLEMENTATION_DEBUG = "package.debugMaterial";
const ALLOWED_OPTION_KEYS = new Set([SNAPSHOT_OPTION]);

interface RecordedPackageSnapshot {
  readonly sourcePath: string;
  readonly artifact: {
    readonly type: string;
    readonly sizeBytes: number;
  };
  readonly bundleName: string;
  readonly debug: {
    readonly enabledModules: readonly string[];
    readonly markerFiles: readonly string[];
  };
  readonly completeness: "COMPLETE" | "INCOMPLETE";
}

export const packageBundleIdentityDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION_BUNDLE,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectPackageBundleIdentity(context);
  },
});

export const packageDebugMaterialDetector: Detector = Object.freeze({
  implementation: IMPLEMENTATION_DEBUG,
  async detect(context: DetectionContext): Promise<DetectionResult> {
    return detectPackageDebugMaterial(context);
  },
});

export async function detectPackageBundleIdentity(
  context: DetectionContext,
): Promise<DetectionResult> {
  const snapshot = await readRecordedPackageSnapshot(context);
  if (
    snapshot === undefined ||
    snapshot.bundleName === context.project.bundleName
  ) {
    return deepFreeze({ evidence: [], findings: [] });
  }

  const location = packageSnapshotLocation(snapshot.sourcePath, "bundleName");
  const evidence = await createEvidence(
    {
      type: "artifact",
      source: snapshot.sourcePath,
      summary: "录制软件包 Bundle 与工程 Bundle 不一致。",
      content: `bundle-mismatch\0${context.project.bundleName}\0${snapshot.bundleName}`,
      redacted: true,
      location,
    },
    context.hash,
  );
  const finding = await createFinding(
    {
      ruleId: context.rule.id,
      ruleVersion: context.rule.version,
      moduleId: "package",
      semanticKey: `bundle-mismatch:${context.project.bundleName}:${snapshot.bundleName}`,
      primaryLocationUri: snapshot.sourcePath,
      title: context.rule.title,
      severity: context.rule.severity,
      confidence: context.rule.defaultConfidence,
      applicability: "APPLICABLE",
      message: "本地工程 Bundle 与录制软件包 Bundle 不一致。",
      locations: [location],
      evidenceIds: [evidence.id],
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
  return deepFreeze({ evidence: [evidence], findings: [finding] });
}

export async function detectPackageDebugMaterial(
  context: DetectionContext,
): Promise<DetectionResult> {
  const snapshot = await readRecordedPackageSnapshot(context);
  const signals = debugSignals(snapshot);
  if (snapshot === undefined || signals.length === 0) {
    return deepFreeze({ evidence: [], findings: [] });
  }

  const logicalPath =
    snapshot.debug.markerFiles.length > 0
      ? "debug.markerFiles"
      : "debug.enabledModules";
  const location = packageSnapshotLocation(snapshot.sourcePath, logicalPath);
  const evidence = await createEvidence(
    {
      type: "artifact",
      source: snapshot.sourcePath,
      summary: "录制软件包发现调试或测试资源标记。",
      content: `debug-material\0${signals.join("\0")}`,
      redacted: true,
      location,
    },
    context.hash,
  );
  const finding = await createFinding(
    {
      ruleId: context.rule.id,
      ruleVersion: context.rule.version,
      moduleId: "package",
      semanticKey: `debug-material:${signals.join("|")}`,
      primaryLocationUri: snapshot.sourcePath,
      title: context.rule.title,
      severity: context.rule.severity,
      confidence: context.rule.defaultConfidence,
      applicability: "APPLICABLE",
      message: "录制软件包快照中发现调试或测试资源标记。",
      locations: [location],
      evidenceIds: [evidence.id],
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
  return deepFreeze({ evidence: [evidence], findings: [finding] });
}

async function readRecordedPackageSnapshot(
  context: DetectionContext,
): Promise<RecordedPackageSnapshot | undefined> {
  const snapshotPath = readSnapshotPath(context);
  const absolutePath = context.fs.resolve(context.workspaceRoot, snapshotPath);
  if (!(await context.fs.exists(absolutePath))) return undefined;
  if ((await context.fs.kind(absolutePath)) !== "file") {
    throw incompletePackageEvidence("录制软件包快照不是普通文件。");
  }
  let raw: unknown;
  try {
    raw = JSON.parse(await context.fs.readText(absolutePath)) as unknown;
  } catch {
    throw incompletePackageEvidence("录制软件包快照不是有效 JSON。");
  }
  return validateRecordedPackageSnapshot(raw, snapshotPath);
}

function readSnapshotPath(context: DetectionContext): string {
  const raw = context.rule.detector.options ?? {};
  const keys = Object.keys(raw);
  if (keys.some((key) => !ALLOWED_OPTION_KEYS.has(key)) || keys.length > 1) {
    throw invalidDetectorOptions();
  }
  const value = raw[SNAPSHOT_OPTION] ?? DEFAULT_SNAPSHOT_PATH;
  if (typeof value !== "string" || !isSafeRelativePath(value)) {
    throw invalidDetectorOptions();
  }
  return value;
}

function validateRecordedPackageSnapshot(
  value: unknown,
  sourcePath: string,
): RecordedPackageSnapshot {
  const root = asRecord(value);
  const artifact = asRecord(root.artifact);
  const debug = asRecord(root.debug);
  const bundleName = readString(root.bundleName);
  const type = readString(artifact.type);
  const sizeBytes = artifact.sizeBytes;
  const completeness = root.completeness;
  const enabledModules = readStringArray(debug.enabledModules);
  const markerFiles = readStringArray(debug.markerFiles);
  if (
    root.schemaVersion !== "1.0.0" ||
    bundleName === undefined ||
    type === undefined ||
    !["app", "hap", "hsp", "har"].includes(type) ||
    !Number.isSafeInteger(sizeBytes) ||
    (sizeBytes as number) < 0 ||
    (completeness !== "COMPLETE" && completeness !== "INCOMPLETE") ||
    markerFiles.some((item) => !isSafeRelativePath(item)) ||
    enabledModules.length > 128 ||
    markerFiles.length > 256
  ) {
    throw incompletePackageEvidence("录制软件包快照结构不完整。");
  }
  if (completeness !== "COMPLETE") {
    throw incompletePackageEvidence("录制软件包快照标记为不完整。");
  }
  return {
    sourcePath,
    artifact: { type, sizeBytes: sizeBytes as number },
    bundleName,
    debug: {
      enabledModules,
      markerFiles,
    },
    completeness,
  };
}

function debugSignals(
  snapshot: RecordedPackageSnapshot | undefined,
): readonly string[] {
  if (snapshot === undefined) return [];
  return [
    ...snapshot.debug.enabledModules.map((name) => `module:${name}`),
    ...snapshot.debug.markerFiles.map((file) => `marker:${file}`),
  ].sort();
}

function packageSnapshotLocation(
  sourcePath: string,
  logicalPath: string,
): SourceLocation {
  return { uri: sourcePath, logicalPath };
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readStringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
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

function incompletePackageEvidence(message: string): HCheckError {
  return new HCheckError("EVIDENCE_INCOMPLETE", message, {
    kind: "package_snapshot",
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
