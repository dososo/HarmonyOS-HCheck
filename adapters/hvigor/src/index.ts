import path from "node:path";
import {
  compareCodePoints,
  type HashPort,
  type HCheckErrorCode,
} from "@hcheck/core";
import type { ProcessRunnerPort } from "@hcheck/core";

export type HvigorProbeStatus =
  "available" | "unavailable" | "failed" | "timed_out";

export interface HvigorCommandSummary {
  readonly executable: string;
  readonly args: readonly string[];
}

export interface HvigorAdapterCapability {
  readonly available: boolean;
  readonly status: HvigorProbeStatus;
  readonly command?: HvigorCommandSummary;
  readonly version?: string;
  readonly reason?: string;
  readonly exitCode?: number;
  readonly stdoutSummary?: string;
  readonly stderrSummary?: string;
}

export interface HvigorFileSystemPort {
  exists(file: string): Promise<boolean>;
  listFiles?(root: string): Promise<readonly string[]>;
  statFile?(file: string): Promise<{
    readonly size: number;
    readonly isFile: boolean;
    readonly isSymbolicLink: boolean;
  }>;
  readFile?(file: string): Promise<Uint8Array>;
}

export interface ProbeHvigorOptions {
  readonly projectRoot: string;
  readonly fs: HvigorFileSystemPort;
  readonly runner: ProcessRunnerPort;
  readonly platform?: NodeJS.Platform;
  readonly timeoutMs?: number;
}

const VERSION_ARGS = Object.freeze(["--version"] as const);
const SUMMARY_LIMIT = 200;
const UNSUPPORTED_SHELL_SYNTAX = /[;&|<>`$]/u;
const CREDENTIAL_ASSIGNMENT =
  /\b(?:api[_-]?key|api[_-]?token|access[_-]?token|password|passwd|secret|credential|private[_-]?key)\b\s*[:=：]\s*([^\s，。；、）)]+)/giu;

export async function probeHvigor(
  options: ProbeHvigorOptions,
): Promise<HvigorAdapterCapability> {
  const wrapper = await findProjectWrapper(
    options.projectRoot,
    options.fs,
    options.platform ?? process.platform,
  );
  if (wrapper === undefined) {
    return {
      available: false,
      status: "unavailable",
      reason: "项目根目录未发现 hvigorw wrapper。",
    };
  }

  const result = await options.runner.run({
    executable: wrapper.absolutePath,
    args: VERSION_ARGS,
    cwd: options.projectRoot,
    ...(options.timeoutMs === undefined
      ? {}
      : { timeoutMs: options.timeoutMs }),
  });
  const command = {
    executable: wrapper.relativePath,
    args: VERSION_ARGS,
  };

  if (result.status === "start_failed") {
    return {
      available: false,
      status: "unavailable",
      command,
      reason: "无法启动 hvigorw wrapper。",
      ...(result.errorMessage === undefined
        ? {}
        : {
            stderrSummary: safeSummary(
              result.errorMessage,
              options.projectRoot,
            ),
          }),
    };
  }

  if (result.status === "timed_out") {
    return {
      available: false,
      status: "timed_out",
      command,
      reason: "hvigorw --version 执行超时。",
    };
  }

  if (result.exitCode !== 0) {
    return {
      available: false,
      status: "failed",
      command,
      ...(typeof result.exitCode === "number"
        ? { exitCode: result.exitCode }
        : {}),
      reason: "hvigorw --version 返回非零退出码。",
      stdoutSummary: safeSummary(result.stdout, options.projectRoot),
      stderrSummary: safeSummary(result.stderr, options.projectRoot),
    };
  }

  const version = firstLine(result.stdout) ?? firstLine(result.stderr);
  return {
    available: true,
    status: "available",
    command,
    ...(version === undefined
      ? {}
      : { version: safeSummary(version, options.projectRoot) }),
    stdoutSummary: safeSummary(result.stdout, options.projectRoot),
    stderrSummary: safeSummary(result.stderr, options.projectRoot),
  };
}

export interface HvigorBuildConfig {
  readonly profile: string;
  readonly clean: boolean;
  readonly command: string;
  readonly artifact: {
    readonly include: readonly string[];
    readonly exclude: readonly string[];
  };
}

export type HvigorBuildStatus =
  "success" | "unavailable" | "build_failed" | "failed" | "timed_out";

export interface HvigorArtifactCandidate {
  readonly relativePath: string;
  readonly type: "app" | "hap" | "hsp" | "har" | "unknown";
}

export interface HvigorBuildRun {
  readonly status: HvigorBuildStatus;
  readonly command?: HvigorCommandSummary;
  readonly artifacts: readonly HvigorArtifactCandidate[];
  readonly errorCode?: HCheckErrorCode;
  readonly reason?: string;
  readonly exitCode?: number;
  readonly stdoutSummary?: string;
  readonly stderrSummary?: string;
}

export interface RunCleanReleaseBuildOptions extends ProbeHvigorOptions {
  readonly build: HvigorBuildConfig;
}

export async function runCleanReleaseBuild(
  options: RunCleanReleaseBuildOptions,
): Promise<HvigorBuildRun> {
  const wrapper = await findProjectWrapper(
    options.projectRoot,
    options.fs,
    options.platform ?? process.platform,
  );
  if (wrapper === undefined) {
    return {
      status: "unavailable",
      artifacts: [],
      errorCode: "TOOL_UNAVAILABLE",
      reason: "项目根目录未发现 hvigorw wrapper。",
    };
  }

  const parsed = parseBuildCommand(options.build);
  if (parsed === undefined) {
    return {
      status: "failed",
      artifacts: [],
      errorCode: "TOOL_EXECUTION_ERROR",
      reason: "构建命令包含不支持的 shell 语法。",
    };
  }

  const command = {
    executable: wrapper.relativePath,
    args: parsed.args,
  };
  const result = await options.runner.run({
    executable: wrapper.absolutePath,
    args: parsed.args,
    cwd: options.projectRoot,
    ...(options.timeoutMs === undefined
      ? {}
      : { timeoutMs: options.timeoutMs }),
  });

  if (result.status === "start_failed") {
    return {
      status: "unavailable",
      command,
      artifacts: [],
      errorCode: "TOOL_UNAVAILABLE",
      reason: "无法启动 hvigorw wrapper。",
      ...(result.errorMessage === undefined
        ? {}
        : {
            stderrSummary: safeSummary(
              result.errorMessage,
              options.projectRoot,
            ),
          }),
    };
  }

  if (result.status === "timed_out") {
    return {
      status: "timed_out",
      command,
      artifacts: [],
      errorCode: "TOOL_EXECUTION_ERROR",
      reason: "Release 构建执行超时。",
    };
  }

  if (result.exitCode !== 0) {
    return {
      status: "build_failed",
      command,
      artifacts: [],
      errorCode: "BUILD_FAILED",
      ...(typeof result.exitCode === "number"
        ? { exitCode: result.exitCode }
        : {}),
      reason: "Release 构建返回非零退出码。",
      stdoutSummary: safeSummary(result.stdout, options.projectRoot),
      stderrSummary: safeSummary(result.stderr, options.projectRoot),
    };
  }

  return {
    status: "success",
    command,
    artifacts: await discoverArtifactCandidates(options),
    stdoutSummary: safeSummary(result.stdout, options.projectRoot),
    stderrSummary: safeSummary(result.stderr, options.projectRoot),
  };
}

export type ArtifactManifestCompleteness = "COMPLETE" | "INCOMPLETE";

export type ArtifactManifestErrorKind =
  | "NO_ARTIFACTS"
  | "MISSING_ARTIFACT_TYPE"
  | "UNSAFE_ARTIFACT_PATH"
  | "INVALID_ARTIFACT"
  | "SYMLINK_ARTIFACT"
  | "ARTIFACT_READ_FAILED";

export interface ArtifactManifestEntry {
  readonly relativePath: string;
  readonly type: HvigorArtifactCandidate["type"];
  readonly sizeBytes: number;
  readonly sha256: `sha256:${string}`;
}

export interface ArtifactManifestError {
  readonly kind: ArtifactManifestErrorKind;
  readonly artifact?: string;
  readonly message: string;
}

export interface HvigorArtifactManifest {
  readonly completeness: ArtifactManifestCompleteness;
  readonly run: {
    readonly id: string;
    readonly hvigorVersion?: string;
  };
  readonly build: {
    readonly status: HvigorBuildStatus;
    readonly command?: HvigorCommandSummary;
  };
  readonly artifacts: readonly ArtifactManifestEntry[];
  readonly errors: readonly ArtifactManifestError[];
}

export interface CreateArtifactManifestOptions {
  readonly projectRoot: string;
  readonly fs: HvigorFileSystemPort;
  readonly hash: HashPort;
  readonly build: Pick<HvigorBuildRun, "status" | "command" | "artifacts">;
  readonly runId: string;
  readonly hvigorVersion?: string;
  readonly requiredTypes?: readonly ("app" | "hap" | "hsp" | "har")[];
}

export async function createArtifactManifest(
  options: CreateArtifactManifestOptions,
): Promise<HvigorArtifactManifest> {
  const errors: ArtifactManifestError[] = [];
  const entries: ArtifactManifestEntry[] = [];
  const candidates = [...options.build.artifacts].sort((left, right) =>
    compareCodePoints(left.relativePath, right.relativePath),
  );

  if (candidates.length === 0) {
    errors.push({
      kind: "NO_ARTIFACTS",
      message: "未发现构建产物候选。",
    });
  }

  for (const candidate of candidates) {
    const relativePath = candidate.relativePath.replaceAll("\\", "/");
    if (!isSafeRelativePath(relativePath)) {
      errors.push({
        kind: "UNSAFE_ARTIFACT_PATH",
        artifact: "[REDACTED_PATH]",
        message: "产物路径必须是工程内相对路径。",
      });
      continue;
    }

    const absolutePath = path.join(options.projectRoot, relativePath);
    try {
      if (
        options.fs.statFile === undefined ||
        options.fs.readFile === undefined
      )
        throw new Error("artifact file port unavailable");
      const stat = await options.fs.statFile(absolutePath);
      if (stat.isSymbolicLink) {
        errors.push({
          kind: "SYMLINK_ARTIFACT",
          artifact: relativePath,
          message: "产物候选不能是符号链接。",
        });
        continue;
      }
      if (!stat.isFile) {
        errors.push({
          kind: "INVALID_ARTIFACT",
          artifact: relativePath,
          message: "产物候选不是普通文件。",
        });
        continue;
      }
      const content = await options.fs.readFile(absolutePath);
      entries.push({
        relativePath,
        type: candidate.type,
        sizeBytes: stat.size,
        sha256: await options.hash.sha256(content),
      });
    } catch {
      errors.push({
        kind: "ARTIFACT_READ_FAILED",
        artifact: relativePath,
        message: "读取产物候选失败。",
      });
    }
  }

  const availableTypes = new Set(entries.map(({ type }) => type));
  const requiredTypes = [...new Set(options.requiredTypes ?? [])].sort(
    compareCodePoints,
  );
  for (const requiredType of requiredTypes) {
    if (availableTypes.has(requiredType)) continue;
    errors.push({
      kind: "MISSING_ARTIFACT_TYPE",
      message: `缺少必需的 ${requiredType.toUpperCase()} 产物。`,
    });
  }

  return deepFreeze({
    completeness: errors.length === 0 ? "COMPLETE" : "INCOMPLETE",
    run: {
      id: options.runId,
      ...(options.hvigorVersion === undefined
        ? {}
        : { hvigorVersion: options.hvigorVersion }),
    },
    build: {
      status: options.build.status,
      ...(options.build.command === undefined
        ? {}
        : { command: options.build.command }),
    },
    artifacts: entries.sort((left, right) =>
      compareCodePoints(left.relativePath, right.relativePath),
    ),
    errors,
  });
}

interface ProjectWrapper {
  readonly absolutePath: string;
  readonly relativePath: string;
}

async function findProjectWrapper(
  projectRoot: string,
  fs: HvigorFileSystemPort,
  platform: NodeJS.Platform,
): Promise<ProjectWrapper | undefined> {
  const names =
    platform === "win32"
      ? ["hvigorw.bat", "hvigorw.cmd", "hvigorw"]
      : ["hvigorw"];
  for (const name of names) {
    const absolutePath = path.join(projectRoot, name);
    if (await fs.exists(absolutePath)) {
      return { absolutePath, relativePath: name };
    }
  }
  return undefined;
}

function firstLine(text: string): string | undefined {
  return text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .find((line) => line.length > 0);
}

function safeSummary(text: string, projectRoot: string): string {
  return text
    .replaceAll(projectRoot, "[REDACTED_PATH]")
    .replace(CREDENTIAL_ASSIGNMENT, (match) =>
      match.replace(/([:=：]\s*)([^\s，。；、）)]+)/u, "$1[REDACTED_SECRET]"),
    )
    .trim()
    .slice(0, SUMMARY_LIMIT);
}

function parseBuildCommand(
  build: HvigorBuildConfig,
): { readonly args: readonly string[] } | undefined {
  if (UNSUPPORTED_SHELL_SYNTAX.test(build.command)) return undefined;
  const tokens = build.command.trim().split(/\s+/u).filter(Boolean);
  const executable = tokens[0];
  if (executable === undefined) return undefined;
  const executableName = executable.replaceAll("\\", "/").split("/").at(-1);
  if (!["hvigorw", "hvigorw.bat", "hvigorw.cmd"].includes(executableName ?? ""))
    return undefined;

  const args = stripBuildMode(tokens.slice(1));
  return {
    args: [
      ...(build.clean && !args.includes("clean") ? ["clean"] : []),
      ...args,
      "-p",
      `buildMode=${build.profile}`,
    ],
  };
}

function stripBuildMode(tokens: readonly string[]): string[] {
  const result: string[] = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] as string;
    const next = tokens[index + 1];
    if (token === "-p" && next?.startsWith("buildMode=")) {
      index += 1;
      continue;
    }
    if (token.startsWith("buildMode=")) continue;
    result.push(token);
  }
  return result;
}

async function discoverArtifactCandidates(
  options: RunCleanReleaseBuildOptions,
): Promise<readonly HvigorArtifactCandidate[]> {
  const files = await options.fs.listFiles?.(options.projectRoot);
  if (files === undefined) return [];
  return files
    .map(normalizeRelativeArtifactPath)
    .filter((file) => matchesAny(options.build.artifact.include, file))
    .filter((file) => !matchesAny(options.build.artifact.exclude, file))
    .sort(compareCodePoints)
    .map((relativePath) => ({
      relativePath,
      type: artifactType(relativePath),
    }));
}

function normalizeRelativeArtifactPath(file: string): string {
  return file.replaceAll("\\", "/").replace(/^\.?\//u, "");
}

function matchesAny(patterns: readonly string[], file: string): boolean {
  return patterns.some((pattern) => globToRegExp(pattern).test(file));
}

function globToRegExp(pattern: string): RegExp {
  let source = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index] as string;
    if (character === "*" && pattern[index + 1] === "*") {
      source += ".*";
      index += 1;
    } else if (character === "*") {
      source += "[^/]*";
    } else {
      source += escapeRegExp(character);
    }
  }
  return new RegExp(`^${source}$`, "u");
}

function escapeRegExp(character: string): string {
  return /[\\^$.*+?()[\]{}|]/u.test(character) ? `\\${character}` : character;
}

function artifactType(relativePath: string): HvigorArtifactCandidate["type"] {
  const extension = relativePath.split(".").at(-1);
  if (
    extension === "app" ||
    extension === "hap" ||
    extension === "hsp" ||
    extension === "har"
  ) {
    return extension;
  }
  return "unknown";
}

function isSafeRelativePath(relativePath: string): boolean {
  if (
    relativePath.length === 0 ||
    path.posix.isAbsolute(relativePath) ||
    path.win32.isAbsolute(relativePath)
  ) {
    return false;
  }
  return !relativePath.split("/").includes("..");
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}
