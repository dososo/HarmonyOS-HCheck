import { HCheckError } from "@hcheck/core";
import {
  readHarmonyPackage,
  type HarmonyPackageSnapshot,
  type PackageFileSystemPort,
} from "@hcheck/project-model";
import { exitCodeForError } from "./exit-code.js";

export type PackageInspectFormat = "terminal" | "json";

export interface PackageInspectArguments {
  readonly artifact: string;
  readonly format: PackageInspectFormat;
}

export interface PackageInspectPorts {
  readonly fs: PackageFileSystemPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

export function parsePackageInspectArguments(
  args: readonly string[],
): PackageInspectArguments {
  if (args[0] !== "package" || args[1] !== "inspect") {
    configuration("package 当前仅支持 package inspect。");
  }
  if (args[2] === undefined || args[2].startsWith("-")) {
    configuration("package inspect 需要 APP/HAP/HSP/HAR 产物路径。");
  }
  let format: PackageInspectFormat = "terminal";
  for (let index = 3; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--format") {
      configuration("存在未知 package inspect 参数。");
    }
    if (value === undefined || value.startsWith("--")) {
      configuration("package inspect 参数缺少值。");
    }
    if (value !== "terminal" && value !== "json") {
      configuration("package inspect 输出格式仅支持 terminal 或 json。");
    }
    format = value;
  }
  return { artifact: args[2], format };
}

export async function runPackageInspect(
  args: readonly string[],
  ports: PackageInspectPorts,
): Promise<number> {
  let parsed: PackageInspectArguments;
  try {
    parsed = parsePackageInspectArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "package inspect 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  try {
    const snapshot = await readHarmonyPackage(parsed.artifact, {
      fs: ports.fs,
    });
    ports.stdout(
      parsed.format === "json"
        ? `${JSON.stringify(snapshot, null, 2)}\n`
        : renderTerminal(snapshot),
    );
    if (snapshot.completeness === "INCOMPLETE") {
      return exitCodeForError(
        new HCheckError("EVIDENCE_INCOMPLETE", "软件包证据不完整。"),
      );
    }
    return 0;
  } catch (error) {
    ports.stderr(renderPackageError(error));
    return error instanceof HCheckError ? exitCodeForError(error) : 8;
  }
}

function renderTerminal(snapshot: HarmonyPackageSnapshot): string {
  const bundle = snapshot.bundleName ?? "UNKNOWN";
  const version = [
    ...(snapshot.version?.code !== undefined
      ? [String(snapshot.version.code)]
      : []),
    ...(snapshot.version?.name !== undefined ? [snapshot.version.name] : []),
  ].join(" / ");
  const modules =
    snapshot.modules.length === 0
      ? "未发现"
      : snapshot.modules.map(({ name }) => name).join("、");
  const permissions =
    snapshot.permissions.length === 0 ? "无" : snapshot.permissions.join("、");
  const debugModules =
    snapshot.debug.enabledModules.length === 0
      ? "无"
      : snapshot.debug.enabledModules.join("、");
  const markerFiles =
    snapshot.debug.markerFiles.length === 0
      ? "无"
      : snapshot.debug.markerFiles.join("、");
  const issues =
    snapshot.issues.length === 0 ? "无" : snapshot.issues.join("；");
  return [
    "鸿鉴 HCheck 软件包检查",
    `类型：${snapshot.artifact.type}`,
    `完整性：${snapshot.completeness}`,
    `Bundle：${bundle}`,
    `版本：${version === "" ? "UNKNOWN" : version}`,
    `模块：${modules}`,
    `权限：${permissions}`,
    `Debug 模块：${debugModules}`,
    `Debug/测试资源标记：${markerFiles}`,
    `问题：${issues}`,
    "",
  ].join("\n");
}

function renderPackageError(error: unknown): string {
  if (error instanceof HCheckError) {
    return `[${error.code}] ${error.message}\n`;
  }
  return "[ARTIFACT_PARSE_ERROR] package inspect 无法安全读取或解析产物。\n";
}
