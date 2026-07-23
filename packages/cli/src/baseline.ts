import {
  HCheckError,
  createBaselineSnapshot,
  type BaselineSnapshot,
  type Finding,
} from "@hcheck/core";
import { exitCodeForError } from "./exit-code.js";
import { runScan, type ScanPorts } from "./scan.js";
import { HCHECK_VERSION } from "./version.js";

export interface BaselineArguments {
  readonly path: string;
  readonly format: "json";
  readonly reference: string;
  readonly config?: string;
  readonly rules: readonly string[];
}

export type BaselinePorts = ScanPorts;

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

export function parseBaselineArguments(
  args: readonly string[],
): BaselineArguments {
  if (args[0] !== "baseline" || args[1] !== "create") {
    configuration("baseline 当前仅支持 baseline create。");
  }
  if (args[2] === undefined || args[2].startsWith("-")) {
    configuration("baseline create 需要工程目录。");
  }
  const format = "json";
  let reference = "baseline/local";
  let config: string | undefined;
  let rules: readonly string[] = [];
  for (let index = 3; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (
      !["--format", "--reference", "--config", "--rules"].includes(flag ?? "")
    ) {
      configuration("存在未知 baseline 参数。");
    }
    if (value === undefined || value.startsWith("--")) {
      configuration("baseline 参数缺少值。");
    }
    if (flag === "--format") {
      if (value !== "json") configuration("baseline create 仅支持 json 输出。");
    } else if (flag === "--reference") {
      if (value.trim().length === 0) configuration("--reference 不能为空。");
      reference = value;
    } else if (flag === "--config") {
      config = value;
    } else if (flag === "--rules") {
      rules = value.split(",").filter(Boolean);
      if (rules.length === 0) configuration("--rules 至少需要一个规则 ID。");
    }
  }
  return {
    path: args[2],
    format,
    reference,
    ...(config === undefined ? {} : { config }),
    rules,
  };
}

export async function runBaseline(
  args: readonly string[],
  ports: BaselinePorts,
): Promise<number> {
  let parsed: BaselineArguments;
  try {
    parsed = parseBaselineArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "baseline 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  let scanStdout = "",
    scanStderr = "";
  const scanArgs = [
    "scan",
    parsed.path,
    "--format",
    "json",
    "--fail-on",
    "none",
    ...(parsed.config === undefined ? [] : ["--config", parsed.config]),
    ...(parsed.rules.length === 0 ? [] : ["--rules", parsed.rules.join(",")]),
  ];
  const scanCode = await runScan(scanArgs, {
    ...ports,
    stdout: (text) => {
      scanStdout += text;
    },
    stderr: (text) => {
      scanStderr += text;
    },
  });
  if (scanCode !== 0) {
    ports.stderr(
      scanStderr.length === 0
        ? "baseline create 需要完整扫描结果，当前扫描未完成。\n"
        : scanStderr,
    );
    return scanCode;
  }

  try {
    const report = JSON.parse(scanStdout) as {
      readonly run?: { readonly hcheckVersion?: string };
      readonly findings?: readonly Finding[];
    };
    const baseline: BaselineSnapshot = createBaselineSnapshot(
      report.findings ?? [],
      {
        hcheckVersion: report.run?.hcheckVersion ?? HCHECK_VERSION,
        createdAt: ports.clock.now().toISOString(),
        reference: parsed.reference,
      },
    );
    ports.stdout(`${JSON.stringify(baseline, null, 2)}\n`);
    return 0;
  } catch (error) {
    ports.stderr("[INTERNAL_ERROR] baseline create 无法生成有效基线。\n");
    return exitCodeForError(error);
  }
}
