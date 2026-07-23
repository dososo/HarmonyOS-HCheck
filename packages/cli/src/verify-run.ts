import {
  HCheckError,
  parseRuntimeFlowDefinition,
  type ProcessRunnerPort,
  type RuntimeDeviceKind,
  type RuntimeFlowDefinition,
} from "@hcheck/core";
import type { ReadonlyFileSystemPort } from "@hcheck/project-model";
import { parse } from "yaml";
import { exitCodeForError } from "./exit-code.js";

export type VerifyRunMode =
  "dry_run" | "preflight_only" | "confirm_device_actions";
export type VerifyRunFormat = "terminal" | "json";

export interface VerifyRunArguments {
  readonly mode: VerifyRunMode;
  readonly flowPath: string;
  readonly artifactPath: string;
  readonly bundleName: string;
  readonly abilityName: string;
  readonly moduleName: string;
  readonly versionName: string;
  readonly versionCode: number;
  readonly deviceKind: Exclude<RuntimeDeviceKind, "unknown">;
  readonly hilogTag: string;
  readonly hilogMarker: string;
  readonly hdcPath: string;
  readonly javaPath: string;
  readonly hapSignToolPath: string;
  readonly preflightPath?: string;
  readonly preflightSha256?: `sha256:${string}`;
  readonly format: VerifyRunFormat;
}

export interface VerifyRunPorts {
  readonly fs: Pick<ReadonlyFileSystemPort, "readText">;
  readonly runner: ProcessRunnerPort;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

interface DryRunPlan {
  readonly schemaVersion: "1.0.0";
  readonly mode: "dry_run";
  readonly flow: { readonly id: string; readonly version: number };
  readonly artifact: {
    readonly kind: "hap";
    readonly bundleName: string;
    readonly versionName: string;
    readonly versionCode: number;
    readonly pathDisclosed: false;
  };
  readonly device: {
    readonly kind: Exclude<RuntimeDeviceKind, "unknown">;
  };
  readonly plan: {
    readonly actions: readonly [
      "install",
      "launch",
      "checkpoint",
      "stop",
      "uninstall",
    ];
    readonly evidence: {
      readonly screenshot: "never";
      readonly video: "never";
      readonly hilog: true;
      readonly network_timeline: "none";
      readonly permission_timeline: false;
    };
    readonly cleanup: readonly [
      "stop_if_started",
      "uninstall_if_installed_by_this_run",
    ];
  };
  readonly verification: {
    readonly signature: "not_verified";
    readonly device: "not_verified";
    readonly bundlePresence: "not_verified";
  };
  readonly externalCalls: 0;
  readonly writes: 0;
}

const VALUE_FLAGS = Object.freeze([
  "--flow",
  "--artifact",
  "--bundle",
  "--ability",
  "--module",
  "--version-name",
  "--version-code",
  "--device-kind",
  "--hilog-tag",
  "--hilog-marker",
  "--hdc",
  "--java",
  "--hap-sign-tool",
  "--preflight",
  "--preflight-sha256",
  "--format",
] as const);

const MODE_FLAGS = Object.freeze([
  "--dry-run",
  "--preflight-only",
  "--confirm-device-actions",
] as const);

const ACTIONS = Object.freeze([
  "install",
  "launch",
  "checkpoint",
  "stop",
  "uninstall",
] as const);

function configuration(message: string): never {
  throw new HCheckError("CONFIGURATION_ERROR", message);
}

function requireArgument(
  values: ReadonlyMap<string, string>,
  flag: (typeof VALUE_FLAGS)[number],
): string {
  const value = values.get(flag);
  if (value === undefined) configuration("verify run 缺少必需参数。");
  return value;
}

function hasControlCharacter(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) as number;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

export function parseVerifyRunArguments(
  args: readonly string[],
): VerifyRunArguments {
  if (args[0] !== "verify" || args[1] !== "run") {
    configuration("verify run 命令前缀不正确。");
  }

  const values = new Map<string, string>();
  const modes = new Set<(typeof MODE_FLAGS)[number]>();
  for (let index = 2; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === undefined || hasControlCharacter(flag)) {
      configuration("verify run 参数不合法。");
    }
    if ((MODE_FLAGS as readonly string[]).includes(flag)) {
      if (modes.has(flag as (typeof MODE_FLAGS)[number])) {
        configuration("verify run 模式参数不得重复。");
      }
      modes.add(flag as (typeof MODE_FLAGS)[number]);
      continue;
    }
    if (!(VALUE_FLAGS as readonly string[]).includes(flag)) {
      configuration("verify run 存在未知参数。");
    }
    if (values.has(flag)) configuration("verify run 参数不得重复。");
    const value = args[index + 1];
    if (
      value === undefined ||
      value.length === 0 ||
      value.trim() !== value ||
      value.startsWith("-") ||
      hasControlCharacter(value)
    ) {
      configuration("verify run 参数缺少安全值。");
    }
    values.set(flag, value);
    index += 1;
  }

  if (modes.size !== 1) {
    configuration("verify run 必须且只能选择一种执行模式。");
  }

  const flowPath = requireArgument(values, "--flow");
  const artifactPath = requireArgument(values, "--artifact");
  const bundleName = requireArgument(values, "--bundle");
  const abilityName = requireArgument(values, "--ability");
  const moduleName = requireArgument(values, "--module");
  const versionName = requireArgument(values, "--version-name");
  const versionCodeText = requireArgument(values, "--version-code");
  const deviceKind = requireArgument(values, "--device-kind");
  const hilogTag = requireArgument(values, "--hilog-tag");
  const hilogMarker = requireArgument(values, "--hilog-marker");
  const hdcPath = requireArgument(values, "--hdc");
  const javaPath = requireArgument(values, "--java");
  const hapSignToolPath = requireArgument(values, "--hap-sign-tool");

  if (!artifactPath.endsWith(".hap")) {
    configuration("verify run 产物必须是 .hap 文件。");
  }
  if (!/^(0|[1-9][0-9]*)$/u.test(versionCodeText)) {
    configuration("verify run 版本号必须是 uint32。");
  }
  const versionCode = Number(versionCodeText);
  if (!Number.isSafeInteger(versionCode) || versionCode > 0xffff_ffff) {
    configuration("verify run 版本号必须是 uint32。");
  }
  if (
    deviceKind !== "physical" &&
    deviceKind !== "emulator" &&
    deviceKind !== "harmonyos_pc"
  ) {
    configuration("verify run 设备类别不受支持。");
  }

  const format = values.get("--format") ?? "terminal";
  if (format !== "terminal" && format !== "json") {
    configuration("verify run 输出格式仅支持 terminal 或 json。");
  }

  const selectedMode = [...modes][0];
  const mode =
    selectedMode === "--dry-run"
      ? "dry_run"
      : selectedMode === "--preflight-only"
        ? "preflight_only"
        : "confirm_device_actions";
  const preflightPath = values.get("--preflight");
  const preflightSha256 = values.get("--preflight-sha256");
  if (mode === "confirm_device_actions") {
    if (
      preflightPath === undefined ||
      preflightSha256 === undefined ||
      !/^sha256:[0-9a-f]{64}$/u.test(preflightSha256)
    ) {
      configuration("confirm 模式需要有效的 preflight 路径和 SHA-256。");
    }
  } else if (preflightPath !== undefined || preflightSha256 !== undefined) {
    configuration("只有 confirm 模式可以提供 preflight 参数。");
  }

  return {
    mode,
    flowPath,
    artifactPath,
    bundleName,
    abilityName,
    moduleName,
    versionName,
    versionCode,
    deviceKind,
    hilogTag,
    hilogMarker,
    hdcPath,
    javaPath,
    hapSignToolPath,
    ...(preflightPath === undefined ? {} : { preflightPath }),
    ...(preflightSha256 === undefined
      ? {}
      : { preflightSha256: preflightSha256 as `sha256:${string}` }),
    format,
  };
}

export function parseDeviceSmokeFlow(text: string): RuntimeFlowDefinition {
  let flow: RuntimeFlowDefinition;
  try {
    flow = parseRuntimeFlowDefinition(
      parse(text, { maxAliasCount: 0, uniqueKeys: true }),
    );
  } catch {
    configuration("Flow 配置不符合设备冒烟合同。");
  }

  if (
    flow.steps.length !== ACTIONS.length ||
    flow.steps.some((step, index) => step.action !== ACTIONS[index])
  ) {
    configuration("Flow 必须严格使用固定五步动作。");
  }
  const [install, , checkpoint] = flow.steps;
  if (install?.package !== "${artifact}") {
    configuration("Flow install 必须引用 ${artifact}。");
  }
  if (
    flow.steps.some(
      (step, index) =>
        (index !== 0 && step.package !== undefined) ||
        step.duration_ms !== undefined ||
        step.timeout_ms !== undefined ||
        step.selector !== undefined ||
        step.value !== undefined ||
        step.retry !== undefined,
    )
  ) {
    configuration("Flow 包含设备冒烟合同之外的步骤配置。");
  }
  if (
    flow.variables === undefined ||
    Object.keys(flow.variables).length !== 1 ||
    flow.variables.artifact !== "${artifact}"
  ) {
    configuration("Flow 只能声明固定 artifact 变量。");
  }
  if (
    flow.requires.clean_install !== true ||
    flow.requires.network_observation !== "none" ||
    flow.requires.test_account !== false ||
    (flow.requires.device_capabilities?.length ?? 0) !== 0
  ) {
    configuration("Flow requires 超出设备冒烟合同。");
  }
  const assertion = flow.assertions[0];
  if (
    flow.assertions.length !== 1 ||
    assertion?.type !== "hilog_contains_marker" ||
    assertion.after_step !== checkpoint?.id ||
    assertion.options !== undefined ||
    (assertion.severity !== undefined && assertion.severity !== "BLOCKER")
  ) {
    configuration("Flow 只能在 checkpoint 后执行唯一 Hilog 标记断言。");
  }
  if (
    flow.evidence.screenshot !== "never" ||
    flow.evidence.video !== "never" ||
    flow.evidence.hilog !== true ||
    flow.evidence.network_timeline !== "none" ||
    flow.evidence.permission_timeline !== false
  ) {
    configuration("Flow 证据策略超出设备冒烟合同。");
  }
  return flow;
}

export async function runVerifyRun(
  args: readonly string[],
  ports: VerifyRunPorts,
): Promise<number> {
  let parsedArguments: VerifyRunArguments;
  try {
    parsedArguments = parseVerifyRunArguments(args);
  } catch (error) {
    ports.stderr(
      `${error instanceof HCheckError ? error.message : "verify run 参数解析失败。"}\n`,
    );
    return exitCodeForError(error);
  }

  if (parsedArguments.mode !== "dry_run") {
    ports.stderr("verify run 的 preflight/confirm 模式在当前切片尚未实现。\n");
    return 3;
  }

  try {
    const flow = parseDeviceSmokeFlow(
      await ports.fs.readText(parsedArguments.flowPath),
    );
    const plan = buildDryRunPlan(parsedArguments, flow);
    ports.stdout(
      parsedArguments.format === "json"
        ? `${JSON.stringify(plan, null, 2)}\n`
        : renderDryRunPlan(plan),
    );
    return 0;
  } catch {
    ports.stderr("Flow 配置不符合设备冒烟合同。\n");
    return 3;
  }
}

function buildDryRunPlan(
  args: VerifyRunArguments,
  flow: RuntimeFlowDefinition,
): DryRunPlan {
  return {
    schemaVersion: "1.0.0",
    mode: "dry_run",
    flow: { id: flow.id, version: flow.version },
    artifact: {
      kind: "hap",
      bundleName: args.bundleName,
      versionName: args.versionName,
      versionCode: args.versionCode,
      pathDisclosed: false,
    },
    device: { kind: args.deviceKind },
    plan: {
      actions: ACTIONS,
      evidence: {
        screenshot: "never",
        video: "never",
        hilog: true,
        network_timeline: "none",
        permission_timeline: false,
      },
      cleanup: ["stop_if_started", "uninstall_if_installed_by_this_run"],
    },
    verification: {
      signature: "not_verified",
      device: "not_verified",
      bundlePresence: "not_verified",
    },
    externalCalls: 0,
    writes: 0,
  };
}

function renderDryRunPlan(plan: DryRunPlan): string {
  return [
    "鸿鉴 HCheck 设备验收 dry-run",
    `流程：${plan.flow.id}@${plan.flow.version}`,
    `动作：${plan.plan.actions.join(" → ")}`,
    "证据：仅采集专用标签 Hilog；不截图、不录屏、不采集网络或权限时间线。",
    "清理：仅在本次已启动时停止，并仅卸载本次安装的目标 Bundle。",
    "签名：未验证",
    "设备：未验证",
    "Bundle 安装状态：未验证",
    "外部调用：0；文件写入：0",
    "",
  ].join("\n");
}
