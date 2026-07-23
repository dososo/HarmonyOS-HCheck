import { HCheckError, type ProcessRunnerPort } from "@hcheck/core";
import { loadConfig } from "@hcheck/config";
import {
  collectDependencyManifest,
  collectProjectIdentity,
  createBuildTargetModel,
  createProjectSnapshot,
  findProjectRoot,
  type BuildTargetModel,
  type DependencyManifest,
  type ProjectIdentitySnapshot,
  type ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import { exitCodeForError } from "./exit-code.js";

export type DoctorFormat = "terminal" | "json";

export interface DoctorArguments {
  readonly path: string;
  readonly format: DoctorFormat;
}

export interface DoctorPorts {
  readonly fs: ReadonlyFileSystemPort;
  readonly runner: ProcessRunnerPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly environment?: Readonly<Record<string, string | undefined>>;
}

export type DoctorStatus = "pass" | "warning" | "fail";
export type DoctorToolStatus = "available" | "unavailable" | "unknown";

export interface DoctorToolCheck {
  readonly id:
    | "node"
    | "path"
    | "pnpm"
    | "ohpm"
    | "hvigorw"
    | "hdc"
    | "harmonyos-sdk"
    | "agc";
  readonly status: DoctorToolStatus;
  readonly version?: string;
  readonly reason?: string;
}

export interface DoctorReport {
  readonly schemaVersion: "1.0.0";
  readonly status: DoctorStatus;
  readonly project: ProjectIdentitySnapshot;
  readonly build: BuildTargetModel;
  readonly dependencies: DependencyManifest;
  readonly tools: readonly DoctorToolCheck[];
}

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

export function parseDoctorArguments(args: readonly string[]): DoctorArguments {
  if (args[0] !== "doctor") configuration("doctor 命令格式无效。");
  let target = ".";
  let format: DoctorFormat = "terminal";
  let index = 1;
  if (args[index] !== undefined && !args[index]?.startsWith("-")) {
    target = args[index] as string;
    index += 1;
  }
  while (index < args.length) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--format") configuration("存在未知 doctor 参数。");
    if (value === undefined || value.startsWith("--"))
      configuration("doctor 参数缺少值。");
    if (value !== "terminal" && value !== "json")
      configuration("doctor 输出格式仅支持 terminal 或 json。");
    format = value;
    index += 2;
  }
  return { path: target, format };
}

export async function runDoctor(
  args: readonly string[],
  ports: DoctorPorts,
): Promise<number> {
  let parsed: DoctorArguments;
  try {
    parsed = parseDoctorArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  try {
    const projectRoot = await findProjectRoot(parsed.path, ports.fs);
    const config = await loadConfig({
      projectRoot,
      environment: ports.environment ?? {},
      textReader: { readText: (file) => ports.fs.readText(file) },
    });
    const snapshot = await createProjectSnapshot(projectRoot, ports.fs);
    const project = collectProjectIdentity(snapshot);
    const build = createBuildTargetModel(snapshot, {
      build: config.build,
      minimumApi: config.project.minimum_api,
      runtimeDevice: config.runtime.device,
    });
    const dependencies = await collectDependencyManifest(projectRoot, ports.fs);
    const tools = await collectToolChecks(projectRoot, ports);
    const status = reportStatus(build, dependencies, tools);
    const report: DoctorReport = {
      schemaVersion: "1.0.0",
      status,
      project,
      build,
      dependencies,
      tools,
    };
    ports.stdout(
      parsed.format === "json"
        ? `${JSON.stringify(report, null, 2)}\n`
        : renderTerminal(report),
    );
    return status === "fail" ? 1 : 0;
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "doctor 执行失败。"}\n`,
    );
    return exitCodeForError(error);
  }
}

async function collectToolChecks(
  projectRoot: string,
  ports: DoctorPorts,
): Promise<readonly DoctorToolCheck[]> {
  return [
    {
      id: "node",
      status: "available",
      version: process.versions.node,
    },
    pathCheck(ports.environment),
    await probeCommand("pnpm", "pnpm", ["--version"], projectRoot, ports),
    await probeCommand("ohpm", "ohpm", ["--version"], projectRoot, ports),
    await probeHvigorw(projectRoot, ports),
    await probeCommand("hdc", "hdc", ["--version"], projectRoot, ports),
    await sdkCheck(ports),
    {
      id: "agc",
      status: "unknown",
      reason: "AGC 只读授权和远端能力留给 P1-7；doctor 不访问真实账号。",
    },
  ];
}

function pathCheck(
  environment: Readonly<Record<string, string | undefined>> | undefined,
): DoctorToolCheck {
  return environment?.PATH === undefined || environment.PATH.length === 0
    ? { id: "path", status: "unavailable", reason: "PATH 未配置。" }
    : { id: "path", status: "available" };
}

async function sdkCheck(ports: DoctorPorts): Promise<DoctorToolCheck> {
  const candidates = [
    ports.environment?.HARMONYOS_SDK_HOME,
    ports.environment?.DEVECO_SDK_HOME,
  ].filter((value): value is string => value !== undefined && value.length > 0);
  let foundVersionDirectory = false;
  let foundIncompleteRoot = false;
  for (const candidate of candidates) {
    if (
      (await ports.fs.exists(candidate)) &&
      (await ports.fs.kind(candidate)) === "directory"
    ) {
      const layout = await inspectSdkDirectory(candidate, ports.fs);
      if (layout === "version-directory") {
        foundVersionDirectory = true;
        continue;
      }
      if (layout === "incomplete") {
        foundIncompleteRoot = true;
        continue;
      }
      return {
        id: "harmonyos-sdk",
        status: "available",
        version:
          "本地 SDK 根目录包含可识别版本包和 ArkTS 构建组件，具体版本需由后续官方工具适配器确认。",
      };
    }
  }
  return {
    id: "harmonyos-sdk",
    status: "unavailable",
    reason: foundIncompleteRoot
      ? "SDK 根目录中的版本包或 ArkTS 构建组件不完整。"
      : foundVersionDirectory
        ? "SDK 环境变量必须指向包含版本目录和构建组件的 SDK 根目录，不能直接指向具体版本目录。"
        : "未发现 HARMONYOS_SDK_HOME 或 DEVECO_SDK_HOME 指向的本地 SDK 目录。",
  };
}

const REQUIRED_SDK_COMPONENT_MANIFESTS = Object.freeze([
  "openharmony/ets/oh-uni-package.json",
  "openharmony/toolchains/oh-uni-package.json",
  "hms/ets/uni-package.json",
  "hms/toolchains/uni-package.json",
] as const);

type SdkDirectoryLayout = "available" | "version-directory" | "incomplete";

async function inspectSdkDirectory(
  sdkRoot: string,
  fs: ReadonlyFileSystemPort,
): Promise<SdkDirectoryLayout> {
  if (await fs.exists(fs.resolve(sdkRoot, "sdk-pkg.json"))) {
    return "version-directory";
  }
  for (const entry of await fs.list(sdkRoot)) {
    const versionRoot = fs.resolve(sdkRoot, entry);
    if ((await fs.kind(versionRoot)) !== "directory") continue;
    if (!(await fs.exists(fs.resolve(versionRoot, "sdk-pkg.json")))) continue;
    const required = [
      ...REQUIRED_SDK_COMPONENT_MANIFESTS.map((manifest) =>
        fs.resolve(versionRoot, manifest),
      ),
    ];
    if (
      await Promise.all(required.map((file) => fs.exists(file))).then(
        (exists) => exists.every(Boolean),
      )
    ) {
      return "available";
    }
  }
  return "incomplete";
}

async function probeHvigorw(
  projectRoot: string,
  ports: DoctorPorts,
): Promise<DoctorToolCheck> {
  const candidates =
    process.platform === "win32" ? ["hvigorw.bat", "hvigorw"] : ["hvigorw"];
  for (const candidate of candidates) {
    const absolute = ports.fs.resolve(projectRoot, candidate);
    if (
      (await ports.fs.exists(absolute)) &&
      (await ports.fs.kind(absolute)) === "file"
    ) {
      return probeCommand(
        "hvigorw",
        absolute,
        ["--version"],
        projectRoot,
        ports,
      );
    }
  }
  return {
    id: "hvigorw",
    status: "unavailable",
    reason: "项目根目录未发现 hvigorw wrapper。",
  };
}

async function probeCommand(
  id: DoctorToolCheck["id"],
  executable: string,
  args: readonly string[],
  projectRoot: string,
  ports: DoctorPorts,
): Promise<DoctorToolCheck> {
  const result = await ports.runner.run({
    executable,
    args,
    cwd: projectRoot,
    timeoutMs: 5_000,
    maxStdoutBytes: 4_096,
    maxStderrBytes: 4_096,
  });
  if (result.status === "start_failed") {
    return {
      id,
      status: "unavailable",
      reason: safeSummary(
        result.errorMessage ?? "无法启动工具。",
        projectRoot,
        ports.environment,
      ),
    };
  }
  if (result.status === "timed_out") {
    return { id, status: "unknown", reason: "工具版本探测超时。" };
  }
  if (result.exitCode !== 0) {
    return {
      id,
      status: "unknown",
      reason: safeSummary(
        firstLine(result.stderr) ??
          firstLine(result.stdout) ??
          "工具返回非零退出码。",
        projectRoot,
        ports.environment,
      ),
    };
  }
  return {
    id,
    status: "available",
    version: safeSummary(
      firstLine(result.stdout) ?? firstLine(result.stderr) ?? "unknown",
      projectRoot,
      ports.environment,
    ),
  };
}

function reportStatus(
  build: BuildTargetModel,
  dependencies: DependencyManifest,
  tools: readonly DoctorToolCheck[],
): DoctorStatus {
  if (build.completeness !== "COMPLETE") return "warning";
  if (dependencies.completeness !== "COMPLETE") return "warning";
  if (tools.some((tool) => tool.status !== "available")) return "warning";
  return "pass";
}

function renderTerminal(report: DoctorReport): string {
  return [
    `鸿鉴 HCheck doctor：${report.status}`,
    `工程：${report.project.bundleName}`,
    `构建目标：${report.build.profile} / API ${report.build.api.minimum} / ${report.build.devices.join(", ")}`,
    `依赖：直接 ${report.dependencies.directDependencies.length}，lockfile ${report.dependencies.lockfilePackages.length}`,
    "工具：",
    ...report.tools.map(
      (tool) =>
        `- ${tool.id}: ${tool.status}${tool.version === undefined ? "" : ` (${tool.version})`}`,
    ),
    "",
  ].join("\n");
}

function firstLine(value: string): string | undefined {
  return value
    .split(/\r?\n/u)
    .find((line) => line.trim().length > 0)
    ?.trim();
}

const CREDENTIAL_ASSIGNMENT =
  /\b(?:api[_-]?key|api[_-]?token|access[_-]?token|token|password|passwd|secret|credential|private[_-]?key)\b\s*[:=：]\s*([^\s，。；、）)]+)/giu;

function safeSummary(
  value: string,
  projectRoot: string,
  environment: Readonly<Record<string, string | undefined>> | undefined,
): string {
  let result = value.replaceAll(projectRoot, "[REDACTED_PATH]");
  for (const [key, secret] of Object.entries(environment ?? {})) {
    if (
      secret !== undefined &&
      secret.length > 0 &&
      /(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY)/iu.test(
        key,
      )
    ) {
      result = result.replaceAll(secret, "[REDACTED]");
    }
  }
  return result.replace(CREDENTIAL_ASSIGNMENT, (match) =>
    match.replace(/([:=：]\s*)([^\s，。；、）)]+)/u, "$1[REDACTED]"),
  );
}
