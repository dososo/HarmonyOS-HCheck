import { createHash } from "node:crypto";
import type {
  ProcessRunResult,
  ProcessRunnerPort,
  RuntimeArtifactRef,
  RuntimeAssertionResult,
  RuntimeDeviceAssertionRequest,
  RuntimeDeviceInfo,
  RuntimeDeviceKind,
  RuntimeDevicePort,
  RuntimeDeviceStepRequest,
  RuntimeStepResult,
} from "@hcheck/core";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_UNINSTALL_ATTEMPTS = 2;
const HILOG_POLL_ATTEMPTS = 3;
const HILOG_POLL_INTERVAL_MS = 500;
const MAX_UINT32 = 4_294_967_295;
const SAFE_TOKEN = /^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,127}$/u;
const SAFE_CHALLENGE = /^[A-Za-z0-9_-]{16,128}$/u;
const BUNDLE_NAME = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/u;
const BUNDLE_LIST_HEADER =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}: [A-Za-z0-9][A-Za-z0-9_.-]{0,127}:$/u;
const LISTED_BUNDLE_NAME = /^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+$/u;

export type HdcBundlePresence = "installed" | "not_installed" | "unknown";

export interface HdcInstalledBundleInfo {
  readonly name: string;
  readonly versionCode: number;
  readonly versionName: string;
  readonly moduleNames: readonly string[];
}

export type HdcInstalledBundleInfoResult =
  | {
      readonly available: true;
      readonly status: "available";
      readonly info: HdcInstalledBundleInfo;
    }
  | {
      readonly available: false;
      readonly status: "unknown";
      readonly reason: string;
    };

export interface HdcRuntimeDeviceMetadata {
  readonly kind: RuntimeDeviceKind;
  readonly model: string;
  readonly osVersion: string;
  readonly capabilities: readonly string[];
}

export interface HdcRuntimeArtifactRef extends RuntimeArtifactRef {
  readonly versionName: string;
  readonly versionCode: number;
}

export interface HdcRuntimeDeviceOptions {
  readonly runner: ProcessRunnerPort;
  /**
   * 调用方注入的一次性挑战。生产调用方必须使用密码学安全随机源生成；
   * adapter 只负责严格校验格式和精确回显，不提供可预测默认值。
   */
  readonly challenge: string;
  readonly artifact: HdcRuntimeArtifactRef;
  readonly abilityName: string;
  readonly moduleName: string;
  readonly hilogTag: string;
  readonly hilogMarker: string;
  readonly device: HdcRuntimeDeviceMetadata;
  readonly executable?: string;
  readonly cwd?: string;
  readonly timeoutMs?: number;
}

export interface HdcRuntimeDeviceState {
  readonly bundlePresence: HdcBundlePresence;
  readonly installAttempted: boolean;
  readonly installationUncertain: boolean;
  readonly installed: boolean;
  readonly launchAttempted: boolean;
  readonly started: boolean;
  readonly stopped: boolean;
  readonly uninstallUncertain: boolean;
  readonly uninstalled: boolean;
}

export interface HdcRuntimeDeviceBinding {
  readonly artifactSha256: `sha256:${string}`;
  readonly bundleName: string;
  readonly moduleName: string;
  readonly abilityName: string;
  readonly hilogTag: string;
  readonly hilogMarker: string;
  readonly deviceId: string;
}

export interface HdcCleanupResult {
  readonly status: "ok" | "cleanup_failed";
  readonly summary: string;
}

export type HdcRuntimeDeviceSessionResult =
  | {
      readonly status: "ready";
      readonly session: HdcRuntimeDeviceSession;
      readonly device: RuntimeDeviceInfo;
    }
  | {
      readonly status: "rejected";
      readonly reason:
        | "device_enumeration_failed"
        | "device_not_unique_or_ready"
        | "device_challenge_failed";
    };

interface ValidatedOptions {
  readonly runner: ProcessRunnerPort;
  readonly challenge: string;
  readonly artifact: HdcRuntimeArtifactRef;
  readonly abilityName: string;
  readonly moduleName: string;
  readonly hilogTag: string;
  readonly hilogMarker: string;
  readonly device: HdcRuntimeDeviceMetadata;
  readonly executable: string;
  readonly cwd?: string;
  readonly timeoutMs: number;
}

type UninstallAttemptOutcome =
  "succeeded" | "confirmed_absent" | "confirmed_present" | "unknown";

export async function createHdcRuntimeDeviceSession(
  options: HdcRuntimeDeviceOptions,
): Promise<HdcRuntimeDeviceSessionResult> {
  const validated = validateOptions(options);
  const enumeration = await run(
    validated,
    ["list", "targets"],
    MAX_OUTPUT_BYTES,
  );
  if (enumeration === undefined || !isSuccessful(enumeration)) {
    return { status: "rejected", reason: "device_enumeration_failed" };
  }
  const connectKey = parseUniqueReadyConnectKey(enumeration.stdout);
  if (connectKey === undefined) {
    return { status: "rejected", reason: "device_not_unique_or_ready" };
  }

  const challenge = await run(
    validated,
    ["-t", connectKey, "shell", "echo", validated.challenge],
    8 * 1024,
  );
  if (
    challenge === undefined ||
    !isSuccessful(challenge) ||
    !isExactEcho(challenge.stdout, validated.challenge)
  ) {
    return { status: "rejected", reason: "device_challenge_failed" };
  }

  const session = new HdcRuntimeDeviceSessionImpl(validated, connectKey);
  return {
    status: "ready",
    session,
    device: (await session.listDevices())[0] as RuntimeDeviceInfo,
  };
}

export interface HdcRuntimeDeviceSession extends RuntimeDevicePort {
  binding(): HdcRuntimeDeviceBinding;
  state(): HdcRuntimeDeviceState;
  queryBundlePresence(): Promise<HdcBundlePresence>;
  queryInstalledBundleInfo(): Promise<HdcInstalledBundleInfoResult>;
  cleanup(): Promise<HdcCleanupResult>;
}

class HdcRuntimeDeviceSessionImpl implements HdcRuntimeDeviceSession {
  readonly #runner: ProcessRunnerPort;
  readonly #connectKey: string;
  readonly #device: RuntimeDeviceInfo;
  readonly #artifact: HdcRuntimeArtifactRef;
  readonly #abilityName: string;
  readonly #moduleName: string;
  readonly #hilogTag: string;
  readonly #hilogMarker: string;
  readonly #executable: string;
  readonly #cwd: string | undefined;
  readonly #timeoutMs: number;
  readonly #hilogByStep = new Map<string, string>();
  #operationTail: Promise<void> = Promise.resolve();
  #cleanupInFlight: Promise<HdcCleanupResult> | undefined;
  #bundlePresence: HdcBundlePresence = "unknown";
  #installAttempted = false;
  #installationUncertain = false;
  #installed = false;
  #ownsInstallation = false;
  #installReady = false;
  #launchAttempted = false;
  #started = false;
  #stopAttempted = false;
  #stopped = false;
  #uninstallAttempts = 0;
  #uninstallUncertain = false;
  #uninstalled = false;

  public constructor(options: ValidatedOptions, connectKey: string) {
    this.#runner = options.runner;
    this.#connectKey = connectKey;
    const id = hashConnectKey(connectKey);
    this.#device = Object.freeze({
      id,
      redactedId: id,
      kind: options.device.kind,
      model: redactConnectKey(options.device.model, connectKey),
      osVersion: redactConnectKey(options.device.osVersion, connectKey),
      capabilities: Object.freeze(
        options.device.capabilities.map((capability) =>
          redactConnectKey(capability, connectKey),
        ),
      ),
    });
    this.#artifact = Object.freeze({ ...options.artifact });
    this.#abilityName = options.abilityName;
    this.#moduleName = options.moduleName;
    this.#hilogTag = options.hilogTag;
    this.#hilogMarker = options.hilogMarker;
    this.#executable = options.executable;
    this.#cwd = options.cwd;
    this.#timeoutMs = options.timeoutMs;
  }

  public async listDevices(): Promise<readonly RuntimeDeviceInfo[]> {
    return [this.#device];
  }

  public binding(): HdcRuntimeDeviceBinding {
    return {
      artifactSha256: this.#artifact.sha256,
      bundleName: redactConnectKey(this.#artifact.bundleName, this.#connectKey),
      moduleName: redactConnectKey(this.#moduleName, this.#connectKey),
      abilityName: redactConnectKey(this.#abilityName, this.#connectKey),
      hilogTag: redactConnectKey(this.#hilogTag, this.#connectKey),
      hilogMarker: redactConnectKey(this.#hilogMarker, this.#connectKey),
      deviceId: this.#device.id,
    };
  }

  public state(): HdcRuntimeDeviceState {
    return {
      bundlePresence: this.#bundlePresence,
      installAttempted: this.#installAttempted,
      installationUncertain: this.#installationUncertain,
      installed: this.#installed,
      launchAttempted: this.#launchAttempted,
      started: this.#started,
      stopped: this.#stopped,
      uninstallUncertain: this.#uninstallUncertain,
      uninstalled: this.#uninstalled,
    };
  }

  public async queryBundlePresence(): Promise<HdcBundlePresence> {
    return this.#enqueue(() => this.#queryBundlePresenceUnlocked());
  }

  public async queryInstalledBundleInfo(): Promise<HdcInstalledBundleInfoResult> {
    return this.#enqueue(() => this.#queryInstalledBundleInfoUnlocked());
  }

  public async performStep(
    request: RuntimeDeviceStepRequest,
  ): Promise<RuntimeStepResult> {
    return this.#enqueue(() => this.#performStepUnlocked(request));
  }

  public async evaluateAssertion(
    request: RuntimeDeviceAssertionRequest,
  ): Promise<RuntimeAssertionResult> {
    return this.#enqueue(() => this.#evaluateAssertionUnlocked(request));
  }

  public cleanup(): Promise<HdcCleanupResult> {
    if (this.#cleanupInFlight !== undefined) return this.#cleanupInFlight;
    const result = this.#enqueue(() => this.#cleanupUnlocked());
    this.#cleanupInFlight = result;
    const clear = (): void => {
      if (this.#cleanupInFlight === result) this.#cleanupInFlight = undefined;
    };
    void result.then(clear, clear);
    return result;
  }

  async #queryBundlePresenceUnlocked(): Promise<HdcBundlePresence> {
    const result = await this.#runDevice(["shell", "bm", "dump", "-a"]);
    const presence =
      result === undefined || !isSuccessful(result)
        ? "unknown"
        : parseBundlePresence(result.stdout, this.#artifact.bundleName);
    if (presence === "not_installed" && this.#ownsInstallation) {
      this.#markUninstalled();
    } else {
      this.#bundlePresence = presence;
      this.#installed = presence === "installed";
    }
    return presence;
  }

  async #queryInstalledBundleInfoUnlocked(): Promise<HdcInstalledBundleInfoResult> {
    const result = await this.#runDevice([
      "shell",
      "bm",
      "dump",
      "-n",
      this.#artifact.bundleName,
    ]);
    if (result === undefined || !isSuccessful(result)) {
      return unknownInstalledBundleInfo();
    }
    const info = parseInstalledBundleInfo(
      result.stdout,
      this.#artifact.bundleName,
    );
    if (
      info === undefined ||
      [info.name, info.versionName, ...info.moduleNames].some((value) =>
        value.includes(this.#connectKey),
      )
    ) {
      return unknownInstalledBundleInfo();
    }
    return { available: true, status: "available", info };
  }

  async #performStepUnlocked(
    request: RuntimeDeviceStepRequest,
  ): Promise<RuntimeStepResult> {
    if (!this.#matchesBinding(request)) {
      return failure("environment_failed", "运行目标与预检绑定不一致。");
    }

    switch (request.step.action) {
      case "install":
        return this.#install();
      case "launch":
        return this.#launch();
      case "checkpoint":
        return this.#checkpoint(request.step.id);
      case "stop":
        return this.#stop();
      case "uninstall":
        return this.#uninstall();
      default:
        return failure("unsupported_device", "当前设备端口不支持该动作。");
    }
  }

  async #evaluateAssertionUnlocked(
    request: RuntimeDeviceAssertionRequest,
  ): Promise<RuntimeAssertionResult> {
    if (!this.#matchesBinding(request)) {
      return assertionIncomplete("断言目标与预检绑定不一致。");
    }
    if (request.assertion.type !== "hilog_contains_marker") {
      return assertionIncomplete("当前设备端口不支持该断言。");
    }
    const stepId = request.assertion.after_step;
    if (stepId === undefined) {
      return assertionIncomplete("Hilog 断言缺少 checkpoint 绑定。");
    }
    const hilog = this.#hilogByStep.get(stepId);
    if (hilog === undefined || !hilog.includes(this.#hilogMarker)) {
      return assertionIncomplete("Hilog 中缺少预期标记。");
    }
    return { status: "passed", summary: "Hilog 标记断言通过。" };
  }

  async #cleanupUnlocked(): Promise<HdcCleanupResult> {
    if (this.#installationUncertain) {
      return {
        status: "cleanup_failed",
        summary: "安装结果无法判定，未自动卸载以避免影响非本会话应用。",
      };
    }
    if (this.#uninstallUncertain) {
      return {
        status: "cleanup_failed",
        summary: "卸载结果无法判定，已禁止后续自动卸载写操作。",
      };
    }
    if (!this.#ownsInstallation || this.#uninstalled) {
      return { status: "ok", summary: "本会话没有待清理安装。" };
    }
    if (this.#uninstallAttempts >= MAX_UNINSTALL_ATTEMPTS) {
      return {
        status: "cleanup_failed",
        summary: "本会话卸载重试次数已用尽。",
      };
    }

    let failed = false;
    if (this.#launchAttempted && !this.#stopped) {
      this.#stopAttempted = true;
      const stopped = await this.#runDevice([
        "shell",
        "aa",
        "force-stop",
        this.#artifact.bundleName,
      ]);
      if (stopped !== undefined && isSuccessful(stopped)) {
        this.#stopped = true;
      } else {
        failed = true;
      }
    }

    if (this.#uninstallAttempts > 0) {
      const adjacentPresence = await this.#queryBundlePresenceUnlocked();
      if (adjacentPresence === "not_installed") {
        return failed
          ? {
              status: "cleanup_failed",
              summary: "停止命令失败，但已确认卸载。",
            }
          : { status: "ok", summary: "已确认本会话目标不存在。" };
      }
      if (adjacentPresence === "unknown") {
        this.#uninstallUncertain = true;
        return {
          status: "cleanup_failed",
          summary: "重试卸载前无法确认 Bundle 状态。",
        };
      }
    }

    const outcome = await this.#attemptUninstall();
    if (outcome === "succeeded" || outcome === "confirmed_absent") {
      return failed
        ? { status: "cleanup_failed", summary: "停止命令失败，但已确认卸载。" }
        : { status: "ok", summary: "本会话目标已清理。" };
    }
    return { status: "cleanup_failed", summary: "本会话目标清理不完整。" };
  }

  async #install(): Promise<RuntimeStepResult> {
    if (
      this.#bundlePresence !== "not_installed" ||
      this.#installAttempted ||
      this.#installed ||
      this.#uninstalled
    ) {
      return failure("install_failed", "目标 Bundle 不满足全新安装条件。");
    }

    const adjacentPresence = await this.#queryBundlePresenceUnlocked();
    if (adjacentPresence !== "not_installed") {
      return failure("install_failed", "安装前 Bundle 状态已变化或无法确认。");
    }

    this.#installAttempted = true;
    const result = await this.#runDevice(["install", this.#artifact.uri]);
    if (result === undefined || !isSuccessful(result)) {
      const verifiedPresence = await this.#queryBundlePresenceUnlocked();
      if (verifiedPresence === "installed") {
        this.#installed = true;
        this.#ownsInstallation = true;
      } else if (verifiedPresence === "unknown") {
        this.#installationUncertain = true;
      }
      return failure("install_failed", "HAP 安装失败。");
    }
    this.#bundlePresence = "installed";
    this.#installed = true;
    this.#ownsInstallation = true;
    this.#installReady = false;
    const verified = await this.#queryInstalledBundleInfoUnlocked();
    if (
      !verified.available ||
      verified.info.name !== this.#artifact.bundleName ||
      verified.info.versionCode !== this.#artifact.versionCode ||
      verified.info.versionName !== this.#artifact.versionName ||
      !verified.info.moduleNames.includes(this.#moduleName)
    ) {
      return failure("install_failed", "安装后的 Bundle 信息复验失败。");
    }
    this.#installReady = true;
    return ok("HAP 安装完成。");
  }

  async #launch(): Promise<RuntimeStepResult> {
    if (
      !this.#installed ||
      !this.#ownsInstallation ||
      !this.#installReady ||
      this.#launchAttempted ||
      this.#started ||
      this.#uninstalled
    ) {
      return failure("environment_failed", "目标应用当前不可启动。");
    }
    this.#launchAttempted = true;
    const result = await this.#runDevice([
      "shell",
      "aa",
      "start",
      "-a",
      this.#abilityName,
      "-b",
      this.#artifact.bundleName,
    ]);
    if (result === undefined || !isSuccessful(result)) {
      return failure("environment_failed", "目标应用启动失败。");
    }
    this.#started = true;
    return ok("目标应用启动完成。");
  }

  async #checkpoint(stepId: string): Promise<RuntimeStepResult> {
    if (!this.#started || this.#stopped || this.#uninstalled) {
      return failure("evidence_incomplete", "当前状态无法采集 Hilog。");
    }
    let hilog = "";
    for (let attempt = 1; attempt <= HILOG_POLL_ATTEMPTS; attempt += 1) {
      const result = await this.#runDevice([
        "shell",
        "hilog",
        "-x",
        "-T",
        this.#hilogTag,
      ]);
      if (result === undefined || !isSuccessful(result)) {
        return failure("evidence_incomplete", "Hilog 采集不完整。");
      }
      const redacted = redactConnectKey(result.stdout, this.#connectKey);
      hilog = redacted;
      if (redacted.includes(this.#hilogMarker)) break;
      if (attempt < HILOG_POLL_ATTEMPTS) {
        await sleep(HILOG_POLL_INTERVAL_MS);
      }
    }
    this.#hilogByStep.set(stepId, hilog);
    const evidence = [
      {
        kind: "hilog" as const,
        path: `hilog/${safeStepId(stepId)}.log`,
        mediaType: "text/plain",
        content: hilog,
      },
    ];
    return hilog.includes(this.#hilogMarker)
      ? { status: "ok", summary: "Hilog checkpoint 完成。", evidence }
      : {
          status: "evidence_incomplete",
          summary: "Hilog 中缺少预期标记。",
          evidence,
        };
  }

  async #stop(): Promise<RuntimeStepResult> {
    if (
      !this.#installed ||
      !this.#ownsInstallation ||
      !this.#started ||
      this.#stopAttempted ||
      this.#stopped ||
      this.#uninstalled
    ) {
      return failure("environment_failed", "目标应用当前不可停止。");
    }
    this.#stopAttempted = true;
    const result = await this.#runDevice([
      "shell",
      "aa",
      "force-stop",
      this.#artifact.bundleName,
    ]);
    if (result === undefined || !isSuccessful(result)) {
      return failure("environment_failed", "目标应用停止失败。");
    }
    this.#stopped = true;
    return ok("目标应用停止完成。");
  }

  async #uninstall(): Promise<RuntimeStepResult> {
    if (
      !this.#installed ||
      !this.#ownsInstallation ||
      !this.#stopped ||
      this.#uninstalled ||
      this.#uninstallUncertain ||
      this.#uninstallAttempts > 0
    ) {
      return failure("environment_failed", "目标应用当前不可卸载。");
    }
    const outcome = await this.#attemptUninstall();
    if (outcome !== "succeeded") {
      return failure("environment_failed", "目标应用卸载失败。");
    }
    return ok("目标应用卸载完成。");
  }

  async #attemptUninstall(): Promise<UninstallAttemptOutcome> {
    this.#uninstallAttempts += 1;
    const result = await this.#runDevice([
      "uninstall",
      this.#artifact.bundleName,
    ]);
    if (result !== undefined && isSuccessful(result)) {
      this.#markUninstalled();
      return "succeeded";
    }

    const presence = await this.#queryBundlePresenceUnlocked();
    if (presence === "not_installed") {
      this.#markUninstalled();
      return "confirmed_absent";
    }
    if (presence === "installed") return "confirmed_present";
    this.#uninstallUncertain = true;
    return "unknown";
  }

  #markUninstalled(): void {
    this.#bundlePresence = "not_installed";
    this.#installed = false;
    this.#ownsInstallation = false;
    this.#installReady = false;
    this.#uninstalled = true;
  }

  #matchesBinding(
    request: RuntimeDeviceStepRequest | RuntimeDeviceAssertionRequest,
  ): boolean {
    const artifact = request.artifact;
    const stepPackage = "step" in request ? request.step.package : undefined;
    return (
      request.deviceId === this.#device.id &&
      artifact.uri === this.#artifact.uri &&
      artifact.sha256 === this.#artifact.sha256 &&
      artifact.bundleName === this.#artifact.bundleName &&
      artifact.versionName === this.#artifact.versionName &&
      artifact.versionCode === this.#artifact.versionCode &&
      (stepPackage === undefined ||
        stepPackage === this.#artifact.uri ||
        stepPackage === this.#artifact.bundleName ||
        (stepPackage === "${artifact}" &&
          request.flow.variables?.artifact === "${artifact}"))
    );
  }

  #enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#operationTail.then(operation);
    this.#operationTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  async #runDevice(
    args: readonly string[],
  ): Promise<ProcessRunResult | undefined> {
    try {
      return await this.#runner.run({
        executable: this.#executable,
        args: ["-t", this.#connectKey, ...args],
        ...(this.#cwd === undefined ? {} : { cwd: this.#cwd }),
        timeoutMs: this.#timeoutMs,
        maxStdoutBytes: MAX_OUTPUT_BYTES,
        maxStderrBytes: MAX_OUTPUT_BYTES,
      });
    } catch {
      return undefined;
    }
  }
}

function validateOptions(options: HdcRuntimeDeviceOptions): ValidatedOptions {
  if (
    !SAFE_CHALLENGE.test(options.challenge) ||
    !isSafeToken(options.abilityName) ||
    !isSafeToken(options.moduleName) ||
    !isSafeToken(options.hilogTag) ||
    !isSafeMarker(options.hilogMarker) ||
    !BUNDLE_NAME.test(options.artifact.bundleName) ||
    !isSafeArtifactUri(options.artifact.uri) ||
    !/^sha256:[a-f0-9]{64}$/u.test(options.artifact.sha256) ||
    typeof options.artifact.versionName !== "string" ||
    !isSafeMetadata(options.artifact.versionName) ||
    typeof options.artifact.versionCode !== "number" ||
    !Number.isSafeInteger(options.artifact.versionCode) ||
    options.artifact.versionCode < 0 ||
    options.artifact.versionCode > MAX_UINT32 ||
    !isSafeMetadata(options.device.model) ||
    !isSafeMetadata(options.device.osVersion) ||
    !["physical", "emulator", "harmonyos_pc", "unknown"].includes(
      options.device.kind,
    ) ||
    !options.device.capabilities.every(isSafeToken)
  ) {
    throw new TypeError("HDC Runtime 配置无效。");
  }
  const executable = options.executable ?? "hdc";
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (
    !isSafeExecutable(executable) ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 120_000 ||
    (options.cwd !== undefined && !isSafePath(options.cwd))
  ) {
    throw new TypeError("HDC Runtime 配置无效。");
  }
  return {
    runner: options.runner,
    challenge: options.challenge,
    artifact: { ...options.artifact },
    abilityName: options.abilityName,
    moduleName: options.moduleName,
    hilogTag: options.hilogTag,
    hilogMarker: options.hilogMarker,
    device: {
      ...options.device,
      capabilities: [...options.device.capabilities],
    },
    executable,
    ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    timeoutMs,
  };
}

async function run(
  options: ValidatedOptions,
  args: readonly string[],
  maxOutputBytes: number,
): Promise<ProcessRunResult | undefined> {
  try {
    return await options.runner.run({
      executable: options.executable,
      args,
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
      timeoutMs: options.timeoutMs,
      maxStdoutBytes: maxOutputBytes,
      maxStderrBytes: maxOutputBytes,
    });
  } catch {
    return undefined;
  }
}

function isSuccessful(result: ProcessRunResult): boolean {
  return (
    result.status === "completed" &&
    !result.timedOut &&
    result.exitCode === 0 &&
    result.signal === undefined &&
    result.errorMessage === undefined &&
    !result.stdoutTruncated &&
    !result.stderrTruncated &&
    result.stderr.length === 0 &&
    !containsCommandFailure(result.stdout)
  );
}

function containsCommandFailure(value: string): boolean {
  return /\[E\d{6}\]/u.test(value) || /\[fail\]/iu.test(value);
}

function parseUniqueReadyConnectKey(stdout: string): string | undefined {
  const lines = strictLines(stdout);
  if (lines === undefined || lines.length !== 1) return undefined;
  const match =
    /^(\S+?)(?:[\t ]+(ready|connected|offline|unauthorized|unknown))?$/iu.exec(
      lines[0] as string,
    );
  if (match === null || !isSafeConnectKey(match[1] as string)) return undefined;
  const connectKey = match[1];
  const state = match[2]?.toLowerCase() ?? "connected";
  return state === "ready" || state === "connected" ? connectKey : undefined;
}

function isExactEcho(stdout: string, challenge: string): boolean {
  return (
    stdout === challenge ||
    stdout === `${challenge}\n` ||
    stdout === `${challenge}\r\n`
  );
}

function parseBundlePresence(
  stdout: string,
  targetBundle: string,
): HdcBundlePresence {
  const lines = strictLines(stdout);
  if (lines === undefined || lines.length === 0) return "unknown";
  const bundleLines = BUNDLE_LIST_HEADER.test(lines[0] as string)
    ? lines.slice(1)
    : lines;
  if (bundleLines.length === 0) return "unknown";
  const bundles = new Set<string>();
  for (const line of bundleLines) {
    const match = /^\t(.+)$/u.exec(line);
    if (
      match === null ||
      !LISTED_BUNDLE_NAME.test(match[1] as string) ||
      bundles.has(match[1] as string)
    )
      return "unknown";
    bundles.add(match[1] as string);
  }
  return bundles.has(targetBundle) ? "installed" : "not_installed";
}

function parseInstalledBundleInfo(
  stdout: string,
  targetBundle: string,
): HdcInstalledBundleInfo | undefined {
  const prefix = `${targetBundle}:\n`;
  if (
    !stdout.startsWith(prefix) ||
    !stdout.endsWith("\n") ||
    stdout.includes("\r")
  ) {
    return undefined;
  }
  const jsonText = stdout.slice(prefix.length, -1);
  if (jsonText.length === 0 || jsonText.trim() !== jsonText) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  const record = parsed as Record<string, unknown>;
  if (
    record.name !== targetBundle ||
    typeof record.versionCode !== "number" ||
    !Number.isSafeInteger(record.versionCode) ||
    record.versionCode < 0 ||
    record.versionCode > MAX_UINT32 ||
    typeof record.versionName !== "string" ||
    !isSafeMetadata(record.versionName) ||
    !Array.isArray(record.moduleNames) ||
    record.moduleNames.length === 0 ||
    !record.moduleNames.every(
      (moduleName): moduleName is string =>
        typeof moduleName === "string" && isSafeToken(moduleName),
    )
  ) {
    return undefined;
  }
  const moduleNames = record.moduleNames as string[];
  if (new Set(moduleNames).size !== moduleNames.length) return undefined;
  return Object.freeze({
    name: targetBundle,
    versionCode: record.versionCode,
    versionName: record.versionName,
    moduleNames: Object.freeze([...moduleNames]),
  });
}

function unknownInstalledBundleInfo(): HdcInstalledBundleInfoResult {
  return {
    available: false,
    status: "unknown",
    reason: "无法确认目标 Bundle 信息。",
  };
}

function strictLines(value: string): readonly string[] | undefined {
  const normalized = value.replaceAll("\r\n", "\n");
  if (normalized.includes("\r")) return undefined;
  const withoutFinalNewline = normalized.endsWith("\n")
    ? normalized.slice(0, -1)
    : normalized;
  if (withoutFinalNewline.length === 0) return [];
  const lines = withoutFinalNewline.split("\n");
  return lines.some((line) => line.length === 0) ? undefined : lines;
}

function hashConnectKey(connectKey: string): string {
  return `device:sha256:${createHash("sha256").update(connectKey).digest("hex")}`;
}

function redactConnectKey(value: string, connectKey: string): string {
  return value.replaceAll(connectKey, "[REDACTED_DEVICE]");
}

function safeStepId(stepId: string): string {
  return /^[A-Za-z0-9_.-]{1,128}$/u.test(stepId)
    ? stepId
    : createHash("sha256").update(stepId).digest("hex");
}

function ok(summary: string): RuntimeStepResult {
  return { status: "ok", summary };
}

function failure(
  status: RuntimeStepResult["status"],
  summary: string,
): RuntimeStepResult {
  return { status, summary };
}

function assertionIncomplete(summary: string): RuntimeAssertionResult {
  return { status: "evidence_incomplete", summary };
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function isSafeToken(value: string): boolean {
  return SAFE_TOKEN.test(value) && !value.startsWith("-");
}

function isSafeConnectKey(value: string): boolean {
  return (
    value !== "[Empty]" &&
    value.length <= 512 &&
    !value.startsWith("-") &&
    /^[A-Za-z0-9_[\]][A-Za-z0-9_.:[\]-]*$/u.test(value)
  );
}

function isSafeMarker(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 128 &&
    value.trim() === value &&
    !value.startsWith("-") &&
    !hasAsciiControl(value)
  );
}

function isSafeMetadata(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 256 &&
    value.trim() === value &&
    isWellFormedUnicode(value) &&
    !hasAsciiControl(value)
  );
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isSafeArtifactUri(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 4096 &&
    value.trim() === value &&
    !value.startsWith("-") &&
    !hasAsciiControl(value)
  );
}

function isSafeExecutable(value: string): boolean {
  return isSafePath(value) && !value.startsWith("-");
}

function isSafePath(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 4096 &&
    value.trim() === value &&
    !hasAsciiControl(value)
  );
}

function hasAsciiControl(value: string): boolean {
  return Array.from(value).some((character) => {
    const codePoint = character.codePointAt(0) as number;
    return codePoint <= 31 || codePoint === 127;
  });
}
