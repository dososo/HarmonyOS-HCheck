import { fileURLToPath } from "node:url";
import path from "node:path";
import { HCheckError } from "@hcheck/core";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";
import { loadRulePack, type RuleDefinition } from "@hcheck/rule-engine";
import { exitCodeForError } from "./exit-code.js";
import { HCHECK_VERSION } from "./version.js";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);

export interface ExplainPorts {
  readonly fs: ReadonlyFileSystemPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly repositoryRoot?: string;
}

interface ExplainArguments {
  readonly ruleId: string;
  readonly format: "terminal" | "json";
}

export async function runExplain(
  args: readonly string[],
  ports: ExplainPorts,
): Promise<number> {
  let parsed: ExplainArguments;
  try {
    parsed = parseExplainArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  try {
    const repo = ports.repositoryRoot ?? REPOSITORY_ROOT;
    const pack = await loadRulePack({
      packPath: path.join(repo, "rules/packs/p0.yml"),
      hcheckVersion: HCHECK_VERSION,
      fs: ports.fs,
      schemas: await schemas(repo, ports.fs),
    });
    const rule = pack.rules.find((item) => item.id === parsed.ruleId);
    if (rule === undefined) {
      throw new HCheckError("CONFIGURATION_ERROR", "未知规则 ID。");
    }
    const explanation = explainRule(rule);
    ports.stdout(
      parsed.format === "json"
        ? `${JSON.stringify(explanation, null, 2)}\n`
        : renderTerminalExplanation(explanation),
    );
    return 0;
  } catch (error) {
    ports.stderr("规则说明失败。\n");
    return exitCodeForError(error);
  }
}

function parseExplainArguments(args: readonly string[]): ExplainArguments {
  if (
    args[0] !== "explain" ||
    args[1] === undefined ||
    args[1].startsWith("-")
  ) {
    throw new HCheckError("CONFIGURATION_ERROR", "explain 命令需要规则 ID。");
  }
  let format: "terminal" | "json" = "terminal";
  for (let index = 2; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (flag !== "--format") {
      throw new HCheckError("CONFIGURATION_ERROR", "存在未知 explain 参数。");
    }
    if (value !== "terminal" && value !== "json") {
      throw new HCheckError(
        "CONFIGURATION_ERROR",
        "explain 输出格式仅支持 terminal 或 json。",
      );
    }
    format = value;
  }
  return { ruleId: args[1], format };
}

async function schemas(
  root: string,
  fs: ReadonlyFileSystemPort,
): Promise<{ rule: object; pack: object }> {
  const rule = JSON.parse(
    await fs.readText(fs.resolve(root, "schemas", "rule.schema.json")),
  ) as object;
  const pack = JSON.parse(
    await fs.readText(fs.resolve(root, "schemas", "rule-pack.schema.json")),
  ) as object;
  return { rule, pack };
}

function explainRule(rule: RuleDefinition) {
  return {
    ruleId: rule.id,
    version: rule.version,
    status: rule.status,
    title: rule.title,
    summary: rule.summary,
    severity: rule.severity,
    confidence: rule.defaultConfidence,
    category: rule.category,
    appliesWhen: rule.appliesWhen,
    inputs: rule.inputs,
    detector: rule.detector.implementation,
    policyRefs: rule.policyRefs,
    remediation: rule.remediation,
    autofix: rule.autofix.level,
  };
}

function renderTerminalExplanation(
  rule: ReturnType<typeof explainRule>,
): string {
  return [
    `规则：${rule.ruleId} ${rule.title}`,
    `状态：${rule.status}`,
    `严重性：${rule.severity}`,
    `置信度：${rule.confidence}`,
    `证据输入：${rule.inputs.join("、")}`,
    `检测器：${rule.detector}`,
    `复验：${rule.remediation.verification}`,
    "",
  ].join("\n");
}
