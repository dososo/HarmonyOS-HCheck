import { fileURLToPath } from "node:url";
import path from "node:path";
import {
  buildAgentJsonReport,
  renderAgentJsonReport,
} from "@hcheck/agent-protocol";
import {
  applySuppressions,
  diffFindingsWithBaseline,
  HCheckError,
  type Confidence,
  type BaselineSnapshot,
  type Finding,
  type HashPort,
  type SuppressionFile,
} from "@hcheck/core";
import {
  loadConfig,
  type FailOn,
  type MinimumConfidence,
} from "@hcheck/config";
import {
  createProjectSnapshot,
  findProjectRoot,
  type ReadonlyFileSystemPort,
} from "@hcheck/project-model";
import {
  buildScanReport,
  renderHtml,
  renderJunit,
  renderJson,
  renderSarif,
  renderTerminal,
  type ClockPort,
  type RunIdPort,
} from "@hcheck/reporters";
import {
  apiPermissionDetector,
  DetectorRegistry,
  executeRules,
  loadRulePack,
  metadataPlaceholderDetector,
  packageBundleIdentityDetector,
  packageDebugMaterialDetector,
  privacySdkDisclosureDetector,
  testEndpointDetector,
} from "@hcheck/rule-engine";
import { exitCodeForError } from "./exit-code.js";
import { HCHECK_VERSION } from "./version.js";

const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const FAIL_ON = new Set<FailOn>(["blocker", "high", "medium", "low", "none"]);
const CONFIDENCE = new Set<MinimumConfidence>([
  "confirmed",
  "probable",
  "possible",
  "manual",
]);
export interface ScanArguments {
  readonly path: string;
  readonly mode: "quick";
  readonly format:
    "terminal" | "json" | "sarif" | "junit" | "html" | "agent-json";
  readonly config?: string;
  readonly failOn?: FailOn;
  readonly minimumConfidence?: MinimumConfidence;
  readonly baseline?: string;
  readonly suppressions?: string;
  readonly rules: readonly string[];
}
export interface ScanPorts {
  readonly fs: ReadonlyFileSystemPort;
  readonly hash: HashPort;
  readonly clock: ClockPort;
  readonly runId: RunIdPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly repositoryRoot?: string;
}

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}
export function parseScanArguments(args: readonly string[]): ScanArguments {
  if (args[0] !== "scan" || args[1] === undefined || args[1].startsWith("-"))
    configuration("scan 命令需要工程目录。");
  const mode = "quick" as const;
  let format: ScanArguments["format"] = "terminal";
  let config: string | undefined,
    failOn: FailOn | undefined,
    minimumConfidence: MinimumConfidence | undefined,
    baseline: string | undefined,
    suppressions: string | undefined;
  let rules: readonly string[] = [];
  for (let index = 2; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (
      ![
        "--mode",
        "--format",
        "--config",
        "--fail-on",
        "--confidence",
        "--baseline",
        "--suppressions",
        "--rules",
      ].includes(flag ?? "")
    )
      configuration("存在未知扫描参数。");
    if (value === undefined || value.startsWith("--"))
      configuration("扫描参数缺少值。");
    if (flag === "--mode") {
      if (value !== "quick")
        configuration("v0.1 仅支持 quick 扫描模式，release/submit 尚未实现。");
    } else if (flag === "--format") {
      if (
        value !== "terminal" &&
        value !== "json" &&
        value !== "sarif" &&
        value !== "junit" &&
        value !== "html" &&
        value !== "agent-json"
      )
        configuration(
          "输出格式仅支持 terminal、json、sarif、junit、html 或 agent-json。",
        );
      format = value;
    } else if (flag === "--config") config = value;
    else if (flag === "--fail-on") {
      if (!FAIL_ON.has(value as FailOn)) configuration("--fail-on 值无效。");
      failOn = value as FailOn;
    } else if (flag === "--confidence") {
      if (!CONFIDENCE.has(value as MinimumConfidence))
        configuration("--confidence 值无效。");
      minimumConfidence = value as MinimumConfidence;
    } else if (flag === "--baseline") {
      if (value.length === 0) configuration("--baseline 需要文件路径。");
      baseline = value;
    } else if (flag === "--suppressions") {
      if (value.length === 0) configuration("--suppressions 需要文件路径。");
      suppressions = value;
    } else if (flag === "--rules") {
      rules = value.split(",").filter(Boolean);
      if (rules.length === 0) configuration("--rules 至少需要一个规则 ID。");
    }
  }
  return {
    path: args[1],
    mode,
    format,
    ...(config === undefined ? {} : { config }),
    ...(failOn === undefined ? {} : { failOn }),
    ...(minimumConfidence === undefined ? {} : { minimumConfidence }),
    ...(baseline === undefined ? {} : { baseline }),
    ...(suppressions === undefined ? {} : { suppressions }),
    rules,
  };
}

const SEVERITY_RANK = {
  BLOCKER: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
} as const;
const FAIL_RANK: Record<Exclude<FailOn, "none">, number> = {
  blocker: 0,
  high: 1,
  medium: 2,
  low: 3,
};
const ALLOWED_CONFIDENCE: Record<MinimumConfidence, ReadonlySet<Confidence>> = {
  confirmed: new Set(["CONFIRMED"]),
  probable: new Set(["CONFIRMED", "PROBABLE"]),
  possible: new Set(["CONFIRMED", "PROBABLE", "POSSIBLE"]),
  manual: new Set(["CONFIRMED", "PROBABLE", "POSSIBLE", "MANUAL"]),
};
export function evaluateGate(
  findings: readonly Finding[],
  failOn: FailOn,
  confidence: MinimumConfidence,
): boolean {
  if (failOn === "none") return false;
  return findings.some(
    (finding) =>
      finding.status !== "suppressed" &&
      finding.applicability === "APPLICABLE" &&
      SEVERITY_RANK[finding.severity] <= FAIL_RANK[failOn] &&
      ALLOWED_CONFIDENCE[confidence].has(finding.confidence),
  );
}

interface GateDecision {
  readonly failed: boolean;
  readonly exitCode: 0 | 1 | 2;
}

function evaluateGateDecision(
  findings: readonly Finding[],
  failOn: FailOn,
  confidence: MinimumConfidence,
  failOnlyNew: boolean,
): GateDecision {
  if (failOn === "none") return { failed: false, exitCode: 0 };
  const blocking = findings.filter(
    (finding) =>
      finding.status !== "suppressed" &&
      finding.applicability === "APPLICABLE" &&
      SEVERITY_RANK[finding.severity] <= FAIL_RANK[failOn] &&
      ALLOWED_CONFIDENCE[confidence].has(finding.confidence),
  );
  if (blocking.length === 0) return { failed: false, exitCode: 0 };
  if (!failOnlyNew) return { failed: true, exitCode: 1 };
  return blocking.some((finding) => finding.status === "new")
    ? { failed: true, exitCode: 2 }
    : { failed: false, exitCode: 0 };
}

async function schemas(
  root: string,
  fs: ReadonlyFileSystemPort,
): Promise<{ rule: object; pack: object }> {
  const [rule, pack] = await Promise.all(
    ["rule.schema.json", "rule-pack.schema.json"].map(
      async (name) =>
        JSON.parse(
          await fs.readText(fs.resolve(root, "schemas", name)),
        ) as object,
    ),
  );
  return { rule: rule as object, pack: pack as object };
}
const SAFE_ERRORS: Readonly<Record<string, string>> = {
  CONFIGURATION_ERROR: "配置无效。",
  UNSUPPORTED_PROJECT: "不支持该项目。",
  RULE_DEFINITION_ERROR: "规则定义无效。",
  EVIDENCE_INCOMPLETE: "证据收集不完整。",
  INTERNAL_ERROR: "内部执行失败。",
};

export async function runScan(
  args: readonly string[],
  ports: ScanPorts,
): Promise<number> {
  let parsed: ScanArguments;
  try {
    parsed = parseScanArguments(args);
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
      ...(parsed.config === undefined ? {} : { explicitConfig: parsed.config }),
      environment: ports.environment ?? process.env,
      textReader: {
        readText: (file) => ports.fs.readText(file),
      },
      cli: {
        ...(parsed.failOn === undefined ? {} : { fail_on: parsed.failOn }),
        ...(parsed.minimumConfidence === undefined
          ? {}
          : { minimum_confidence: parsed.minimumConfidence }),
      },
    });
    const selected = new Set(parsed.rules);
    const conflict = config.scan.exclude.rules.find((id) => selected.has(id));
    if (conflict !== undefined)
      configuration("--rules 与配置中的排除规则冲突。");
    const project = await createProjectSnapshot(projectRoot, ports.fs);
    const repo = ports.repositoryRoot ?? REPOSITORY_ROOT;
    const pack = await loadRulePack({
      packPath: path.join(repo, "rules/packs/p0.yml"),
      hcheckVersion: HCHECK_VERSION,
      fs: ports.fs,
      schemas: await schemas(repo, ports.fs),
    });
    const knownIds = new Set(pack.rules.map(({ id }) => id));
    if ([...selected].some((id) => !knownIds.has(id)))
      configuration("--rules 包含未知规则 ID。");
    const rules = pack.rules.filter(
      ({ id }) =>
        (selected.size === 0 || selected.has(id)) &&
        !config.scan.exclude.rules.includes(id),
    );
    const registry = new DetectorRegistry();
    registry.register(metadataPlaceholderDetector);
    registry.register(packageBundleIdentityDetector);
    registry.register(packageDebugMaterialDetector);
    registry.register(privacySdkDisclosureDetector);
    registry.register(testEndpointDetector);
    registry.register(apiPermissionDetector);
    const errors: unknown[] = [];
    const incompleteReasons: string[] = [];
    let findings: readonly Finding[] = [],
      evidence = [] as Awaited<ReturnType<typeof executeRules>>["evidence"];
    try {
      const result = await executeRules({
        rules,
        context: {
          mode: "quick",
          project,
          fs: ports.fs,
          hash: ports.hash,
          workspaceRoot: projectRoot,
          globalExcludePaths: config.scan.exclude.paths,
        },
        registry,
      });
      findings = result.findings;
      evidence = result.evidence;
      if (project.modules.some(({ isExternal }) => isExternal))
        throw new HCheckError(
          "EVIDENCE_INCOMPLETE",
          "外部模块无法形成完整源码证据。",
        );
    } catch (error) {
      if (
        !(error instanceof HCheckError) ||
        error.code !== "EVIDENCE_INCOMPLETE"
      )
        throw error;
      errors.push(error);
      incompleteReasons.push("扫描范围包含无法完整验证的源码证据。");
    }
    const loadedBaseline = await readOptionalJson<BaselineSnapshot>(
      projectRoot,
      parsed.baseline ?? config.baseline.path,
      parsed.baseline !== undefined,
      "基线",
      ports.fs,
    );
    if (loadedBaseline !== undefined) {
      findings = diffFindingsWithBaseline(findings, loadedBaseline).findings;
    }
    const loadedSuppressions = await readOptionalJson<SuppressionFile>(
      projectRoot,
      parsed.suppressions ?? config.baseline.suppressions,
      parsed.suppressions !== undefined,
      "抑制",
      ports.fs,
    );
    if (loadedSuppressions !== undefined) {
      findings = applySuppressions(
        findings,
        loadedSuppressions,
        ports.clock.now(),
      );
    }
    const gate = evaluateGateDecision(
      findings,
      config.scan.fail_on,
      config.scan.minimum_confidence,
      loadedBaseline !== undefined && config.baseline.fail_only_new,
    );
    const report = buildScanReport(
      {
        hcheckVersion: HCHECK_VERSION,
        mode: "quick",
        project: {
          bundleName: project.bundleName,
          modules: project.modules.map(({ name, type, isExternal }) => ({
            name,
            type,
            isExternal,
          })),
          hasExternalModules: project.modules.some(
            ({ isExternal }) => isExternal,
          ),
        },
        rulePacks: [{ id: pack.id, version: pack.version }],
        findings,
        evidence,
        errors,
        incompleteReasons,
        gate: gate.failed ? "FAIL" : "PASS",
      },
      { clock: ports.clock, runId: ports.runId },
    );
    ports.stdout(renderScanOutput(report, parsed.format));
    return report.completeness === "COMPLETE" ? gate.exitCode : 4;
  } catch (error) {
    const code = error instanceof HCheckError ? error.code : "INTERNAL_ERROR";
    ports.stderr(`[${code}] ${SAFE_ERRORS[code] ?? "执行失败。"}\n`);
    return exitCodeForError(error);
  }
}

function renderScanOutput(
  report: Parameters<typeof renderJson>[0],
  format: ScanArguments["format"],
): string {
  if (format === "json") return renderJson(report);
  if (format === "sarif") return renderSarif(report);
  if (format === "junit") return renderJunit(report);
  if (format === "html") return renderHtml(report);
  if (format === "agent-json") {
    return renderAgentJsonReport(
      buildAgentJsonReport({
        run: {
          id: report.run.id,
          hcheckVersion: report.run.hcheckVersion,
          completeness: report.completeness,
          gate: report.summary.gate,
        },
        findings: report.findings,
        allowedPaths: ["AppScope", "entry", "features", "library", "shared"],
        forbiddenPaths: [".git", "build", "node_modules", "oh_modules"],
        verificationCommands: ["pnpm check"],
      }),
    );
  }
  return renderTerminal(report);
}

async function readOptionalJson<T>(
  projectRoot: string,
  file: string,
  required: boolean,
  label: string,
  fs: ReadonlyFileSystemPort,
): Promise<T | undefined> {
  const absolutePath = path.isAbsolute(file)
    ? file
    : fs.resolve(projectRoot, file);
  const exists = await fs.exists(absolutePath);
  if (!exists) {
    if (required)
      throw new HCheckError("CONFIGURATION_ERROR", `${label}文件不存在。`);
    return undefined;
  }
  if ((await fs.kind(absolutePath)) !== "file") {
    throw new HCheckError("CONFIGURATION_ERROR", `${label}路径不是文件。`);
  }
  try {
    return JSON.parse(await fs.readText(absolutePath)) as T;
  } catch (error) {
    if (error instanceof HCheckError) throw error;
    throw new HCheckError("CONFIGURATION_ERROR", `${label}文件不是有效 JSON。`);
  }
}
