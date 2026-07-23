import {
  buildSafeFixPlan,
  type AgentJsonReport,
  type SafeFixPlan,
} from "@hcheck/agent-protocol";
import { HCheckError } from "@hcheck/core";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";
import { exitCodeForError } from "./exit-code.js";

interface FixArguments {
  readonly agentJsonPath: string;
  readonly dryRun: true;
  readonly allowedRules: readonly string[];
}

export interface FixPorts {
  readonly fs: ReadonlyFileSystemPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

export function parseFixArguments(args: readonly string[]): FixArguments {
  if (args[0] !== "fix") configuration("fix 命令需要以 fix 开头。");
  let agentJsonPath: string | undefined;
  let dryRun = false;
  const allowedRules: string[] = [];

  for (let index = 1; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (flag === "--from-agent-json" || flag === "--allow-rule") {
      const value = args[index + 1];
      if (value === undefined || value.startsWith("--")) {
        configuration(`${flag} 参数缺少值。`);
      }
      if (flag === "--from-agent-json") {
        agentJsonPath = value;
      } else {
        allowedRules.push(value);
      }
      index += 1;
      continue;
    }
    configuration("存在未知 fix 参数。");
  }

  if (agentJsonPath === undefined) {
    configuration("fix 需要 --from-agent-json <文件>。");
  }
  if (!dryRun) {
    configuration("P2 仅支持 --dry-run；不会直接改写源码。");
  }
  return { agentJsonPath, dryRun: true, allowedRules };
}

export async function runFix(
  args: readonly string[],
  ports: FixPorts,
): Promise<number> {
  let parsed: FixArguments;
  try {
    parsed = parseFixArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "fix 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  try {
    const report = JSON.parse(
      await ports.fs.readText(parsed.agentJsonPath),
    ) as AgentJsonReport;
    const plan = buildSafeFixPlan({
      report,
      mode: "dry-run",
      ...(parsed.allowedRules.length === 0
        ? {}
        : { allowedRules: parsed.allowedRules }),
    });
    ports.stdout(renderSafeFixPlan(plan));
    return 0;
  } catch (error) {
    ports.stderr(
      `${error instanceof Error ? error.message : "fix 无法生成安全修复计划。"}\n`,
    );
    return error instanceof HCheckError ? exitCodeForError(error) : 3;
  }
}

function renderSafeFixPlan(plan: SafeFixPlan): string {
  return `${JSON.stringify(plan, null, 2)}\n`;
}
