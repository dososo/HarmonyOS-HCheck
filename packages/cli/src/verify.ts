import {
  buildRuntimeReplay,
  HCheckError,
  type ProcessRunnerPort,
  type RuntimeReplay,
} from "@hcheck/core";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";
import {
  runDeviceConfirmation,
  runDevicePreflight,
  type DeviceVerificationPorts,
} from "./device-verification.js";
import { exitCodeForError } from "./exit-code.js";
import {
  parseVerifyRunArguments,
  runVerifyRun,
  type VerifyRunArguments,
} from "./verify-run.js";

export type VerifyReplayFormat = "terminal" | "json";

export interface VerifyReplayArguments {
  readonly manifestPath: string;
  readonly format: VerifyReplayFormat;
}

export interface VerifyPorts {
  readonly fs: Pick<ReadonlyFileSystemPort, "readText">;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  /**
   * P4-4A 仅由测试注入受控端口。默认 CLI 不构造真实进程运行器，
   * 因而无法在未单独授权的环境中触发设备或验签工具。
   */
  readonly deviceVerification?: DeviceVerificationPorts;
}

const dryRunRunner: ProcessRunnerPort = {
  async run(): Promise<never> {
    throw new Error("dry-run 不允许进程调用。");
  },
};

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

export function parseVerifyArguments(
  args: readonly string[],
): VerifyReplayArguments {
  if (args[0] !== "verify" || args[1] !== "replay") {
    configuration("verify 当前仅支持 verify replay。");
  }
  if (args[2] === undefined || args[2].startsWith("-")) {
    configuration("verify replay 需要运行时 manifest.json 路径。");
  }
  let format: VerifyReplayFormat = "terminal";
  for (let index = 3; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--format") {
      configuration("存在未知 verify replay 参数。");
    }
    if (value === undefined || value.startsWith("--")) {
      configuration("verify replay 参数缺少值。");
    }
    if (value !== "terminal" && value !== "json") {
      configuration("verify replay 输出格式仅支持 terminal 或 json。");
    }
    format = value;
  }
  return { manifestPath: args[2], format };
}

export async function runVerify(
  args: readonly string[],
  ports: VerifyPorts,
): Promise<number> {
  if (args[0] === "verify" && args[1] === "run") {
    return runDeviceVerify(args, ports);
  }

  let parsed: VerifyReplayArguments;
  try {
    parsed = parseVerifyArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "verify 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  try {
    const manifest = JSON.parse(await ports.fs.readText(parsed.manifestPath));
    const replay = buildRuntimeReplay(manifest);
    ports.stdout(
      parsed.format === "json"
        ? `${JSON.stringify(replay, null, 2)}\n`
        : renderRuntimeReplay(replay),
    );
    return 0;
  } catch (error) {
    const message =
      error instanceof TypeError
        ? error.message
        : "verify replay 无法读取或渲染运行回放。";
    ports.stderr(`${message}\n`);
    return 3;
  }
}

async function runDeviceVerify(
  args: readonly string[],
  ports: VerifyPorts,
): Promise<number> {
  let parsed: VerifyRunArguments;
  try {
    parsed = parseVerifyRunArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "verify run 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  if (parsed.mode === "dry_run") {
    return runVerifyRun(args, {
      fs: ports.fs,
      runner: dryRunRunner,
      stdout: ports.stdout,
      stderr: ports.stderr,
    });
  }
  if (ports.deviceVerification === undefined) {
    ports.stderr("verify run 未注入受控设备验证端口。\n");
    return 4;
  }
  if (parsed.mode === "preflight_only") {
    try {
      const result = await runDevicePreflight(parsed, ports.deviceVerification);
      ports.stdout(renderDevicePreflightResult(result.written, parsed.format));
      return 0;
    } catch {
      ports.stderr("设备预检未完成。\n");
      return 4;
    }
  }
  try {
    const result = await runDeviceConfirmation(
      parsed,
      ports.deviceVerification,
    );
    ports.stdout(renderDeviceConfirmationResult(result, parsed.format));
    return result.exitCode;
  } catch {
    ports.stderr("设备确认运行未完成。\n");
    return 4;
  }
}

function renderDevicePreflightResult(
  result: {
    readonly relativePath: string;
    readonly sha256: `sha256:${string}`;
    readonly expiresAt: string;
  },
  format: "terminal" | "json",
): string {
  if (format === "json") {
    return `${JSON.stringify({
      mode: "preflight_only",
      preflight: {
        path: result.relativePath,
        sha256: result.sha256,
        expiresAt: result.expiresAt,
      },
    })}\n`;
  }
  return [
    "鸿鉴 HCheck 设备预检",
    `预检文件：${result.relativePath}`,
    `SHA-256：${result.sha256}`,
    `过期时间：${result.expiresAt}`,
    "",
  ].join("\n");
}

function renderDeviceConfirmationResult(
  result: {
    readonly status: "PASS" | "FAILED" | "INCOMPLETE";
    readonly exitCode: 0 | 1 | 4;
  },
  format: "terminal" | "json",
): string {
  if (format === "json") {
    return `${JSON.stringify({
      mode: "confirm_device_actions",
      status: result.status,
      exitCode: result.exitCode,
    })}\n`;
  }
  return [
    "鸿鉴 HCheck 设备确认运行",
    `状态：${result.status}`,
    `退出码：${result.exitCode}`,
    "",
  ].join("\n");
}

function renderRuntimeReplay(replay: RuntimeReplay): string {
  const failed =
    replay.failure === undefined
      ? "无"
      : `${replay.failure.kind}：${replay.failure.summary}`;
  return [
    "鸿鉴 HCheck 运行回放",
    `运行 ID：${replay.runId}`,
    `流程：${replay.flow.id}@${replay.flow.version}`,
    `状态：${replay.status}`,
    `只读：${replay.readOnly ? "是" : "否"}`,
    `步骤：${replay.summary.passedSteps}/${replay.summary.totalSteps} 通过，失败 ${replay.summary.failedSteps}`,
    `断言：${replay.summary.passedAssertions}/${replay.summary.totalAssertions} 通过，失败 ${replay.summary.failedAssertions}，不完整 ${replay.summary.incompleteAssertions}`,
    `证据文件：${replay.summary.evidenceFiles}`,
    `失败摘要：${failed}`,
    ...replay.timeline.map(
      (step) =>
        `- 步骤 ${step.stepId} ${step.status} ${step.result}：${step.summary}`,
    ),
    ...replay.assertions.map(
      (assertion) =>
        `- 断言 ${assertion.id} ${assertion.status}：${assertion.summary}`,
    ),
    "",
  ].join("\n");
}
