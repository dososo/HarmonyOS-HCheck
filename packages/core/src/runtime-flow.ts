export const RUNTIME_FLOW_ACTIONS = Object.freeze([
  "install",
  "uninstall",
  "clear_data",
  "launch",
  "stop",
  "wait_for",
  "wait",
  "tap",
  "input",
  "press_key",
  "set_permission",
  "checkpoint",
  "invoke_test_hook",
] as const);

export type RuntimeFlowAction = (typeof RUNTIME_FLOW_ACTIONS)[number];

export const RUNTIME_NETWORK_OBSERVATION_MODES = Object.freeze([
  "none",
  "metadata_only",
  "explicit_deep_capture",
] as const);

export type RuntimeNetworkObservationMode =
  (typeof RUNTIME_NETWORK_OBSERVATION_MODES)[number];

export const RUNTIME_SCREENSHOT_POLICIES = Object.freeze([
  "each_checkpoint",
  "on_failure",
  "never",
] as const);

export type RuntimeScreenshotPolicy =
  (typeof RUNTIME_SCREENSHOT_POLICIES)[number];

export const RUNTIME_VIDEO_POLICIES = Object.freeze([
  "always",
  "on_failure",
  "never",
] as const);

export type RuntimeVideoPolicy = (typeof RUNTIME_VIDEO_POLICIES)[number];

export type RuntimeAssertionSeverity =
  "BLOCKER" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface RuntimeFlowRequires {
  readonly clean_install?: boolean;
  readonly network_observation?: RuntimeNetworkObservationMode;
  readonly test_account?: boolean;
  readonly device_capabilities?: readonly string[];
}

export interface RuntimeFlowStepRetry {
  readonly max_attempts?: number;
  readonly backoff_ms?: number;
}

export interface RuntimeFlowStep {
  readonly id: string;
  readonly action: RuntimeFlowAction;
  readonly package?: string;
  readonly duration_ms?: number;
  readonly timeout_ms?: number;
  readonly selector?: Readonly<Record<string, unknown>>;
  readonly value?: string;
  readonly retry?: RuntimeFlowStepRetry;
}

export interface RuntimeFlowAssertion {
  readonly id?: string;
  readonly type: string;
  readonly after_step?: string;
  readonly options?: Readonly<Record<string, unknown>>;
  readonly severity?: RuntimeAssertionSeverity;
}

export interface RuntimeFlowEvidencePolicy {
  readonly screenshot?: RuntimeScreenshotPolicy;
  readonly video?: RuntimeVideoPolicy;
  readonly hilog?: boolean;
  readonly network_timeline?: RuntimeNetworkObservationMode;
  readonly permission_timeline?: boolean;
}

export interface RuntimeFlowDefinition {
  readonly id: string;
  readonly version: number;
  readonly name: string;
  readonly description?: string;
  readonly requires: RuntimeFlowRequires;
  readonly variables?: Readonly<Record<string, string>>;
  readonly steps: readonly RuntimeFlowStep[];
  readonly assertions: readonly RuntimeFlowAssertion[];
  readonly evidence: RuntimeFlowEvidencePolicy;
}

export type AccountDeletionStubCheckId =
  | "delete-request-accepted"
  | "old-token-rejected"
  | "relogin-rejected"
  | "local-data-cleared";

export type AccountDeletionStubCheckStatus =
  "passed" | "failed" | "evidence_incomplete";

export interface AccountDeletionStubService {
  readonly kind: "local-recorded-stub";
  readonly endpoint: string;
  readonly production: false;
}

export interface AccountDeletionStubAccount {
  readonly subject: string;
  readonly redacted: true;
}

export interface AccountDeletionStubCheck {
  readonly id: AccountDeletionStubCheckId;
  readonly status: AccountDeletionStubCheckStatus;
  readonly summary: string;
}

export interface AccountDeletionStubEvidence {
  readonly collectedAt: string;
  readonly commands: readonly string[];
}

export interface AccountDeletionStubContract {
  readonly schemaVersion: "1.0.0";
  readonly fixtureId: string;
  readonly flowId: "account-delete";
  readonly evidenceKind: "account-deletion-stub-contract";
  readonly status: "local_contract";
  readonly runtimeConfirmed: false;
  readonly redacted: true;
  readonly service: AccountDeletionStubService;
  readonly account: AccountDeletionStubAccount;
  readonly checks: readonly AccountDeletionStubCheck[];
  readonly evidence: AccountDeletionStubEvidence;
  readonly boundaries: readonly string[];
}

export interface RuntimeHashPort {
  sha256(content: string | Uint8Array): Promise<`sha256:${string}`>;
}

export interface RuntimeTimingPort {
  sleep(milliseconds: number): Promise<void>;
  now(): string;
}

export interface RuntimeEvidenceWriteRequest {
  readonly archiveRoot: string;
  readonly relativePath: string;
  readonly bytes: Uint8Array;
}

export interface RuntimeEvidenceWriterPort {
  write(request: RuntimeEvidenceWriteRequest): Promise<void>;
}

export interface RuntimeArtifactRef {
  readonly uri: string;
  readonly sha256: `sha256:${string}`;
  readonly bundleName: string;
  readonly versionName?: string;
  readonly versionCode?: number;
}

export const RUNTIME_DEVICE_KINDS = Object.freeze([
  "physical",
  "emulator",
  "harmonyos_pc",
  "unknown",
] as const);

export type RuntimeDeviceKind = (typeof RUNTIME_DEVICE_KINDS)[number];

export interface RuntimeDeviceInfo {
  readonly id: string;
  readonly redactedId: string;
  readonly kind: RuntimeDeviceKind;
  readonly model: string;
  readonly osVersion: string;
  readonly capabilities: readonly string[];
}

export const RUNTIME_EVIDENCE_CAPTURE_KINDS = Object.freeze([
  "hilog",
  "screenshot",
  "video",
  "network_timeline",
  "permission_timeline",
] as const);

export type RuntimeEvidenceCaptureKind =
  (typeof RUNTIME_EVIDENCE_CAPTURE_KINDS)[number];

export type RuntimeStepResultStatus =
  | "ok"
  | "locator_failed"
  | "device_unavailable"
  | "install_failed"
  | "app_crashed"
  | "app_frozen"
  | "environment_failed"
  | "evidence_incomplete"
  | "unsupported_device";

export interface RuntimeEvidenceCapture {
  readonly kind: RuntimeEvidenceCaptureKind;
  readonly path: string;
  readonly mediaType: string;
  readonly content: string | Uint8Array;
}

export interface RuntimeStepResult {
  readonly status: RuntimeStepResultStatus;
  readonly summary: string;
  readonly evidence?: readonly RuntimeEvidenceCapture[];
}

export type RuntimeAssertionResultStatus =
  "passed" | "failed" | "evidence_incomplete";

export interface RuntimeAssertionResult {
  readonly status: RuntimeAssertionResultStatus;
  readonly summary: string;
}

export interface RuntimeDeviceStepRequest {
  readonly flow: RuntimeFlowDefinition;
  readonly step: RuntimeFlowStep;
  readonly artifact: RuntimeArtifactRef;
  readonly deviceId: string;
  readonly attempt: number;
}

export interface RuntimeDeviceAssertionRequest {
  readonly flow: RuntimeFlowDefinition;
  readonly assertion: RuntimeFlowAssertion;
  readonly artifact: RuntimeArtifactRef;
  readonly deviceId: string;
}

export interface RuntimeDevicePort {
  listDevices(): Promise<readonly RuntimeDeviceInfo[]>;
  performStep(request: RuntimeDeviceStepRequest): Promise<RuntimeStepResult>;
  evaluateAssertion(
    request: RuntimeDeviceAssertionRequest,
  ): Promise<RuntimeAssertionResult>;
}

export interface RecordedDeviceHistoryEntry {
  readonly stepId: string;
  readonly action: RuntimeFlowAction;
  readonly attempt: number;
}

export interface RecordedDevicePortInput {
  readonly devices: readonly RuntimeDeviceInfo[];
  readonly steps?: Readonly<Record<string, readonly RuntimeStepResult[]>>;
  readonly assertions?: Readonly<Record<string, RuntimeAssertionResult>>;
}

export type RuntimeFlowRunStatus = "PASS" | "FAILED" | "INCOMPLETE";

export type RuntimeFailureKind =
  | "FLOW_ASSERTION_FAILED"
  | "LOCATOR_FAILED"
  | "DEVICE_UNAVAILABLE"
  | "INSTALL_FAILED"
  | "APP_CRASHED"
  | "APP_FROZEN"
  | "EVIDENCE_INCOMPLETE"
  | "ENVIRONMENT_FAILED"
  | "UNSUPPORTED_DEVICE";

export interface RuntimeFailure {
  readonly kind: RuntimeFailureKind;
  readonly stepId?: string;
  readonly assertionId?: string;
  readonly summary: string;
}

export interface RuntimeStepTimelineEntry {
  readonly stepId: string;
  readonly action: RuntimeFlowAction;
  readonly attempts: number;
  readonly status: "PASSED" | "FAILED";
  readonly result: RuntimeStepResultStatus;
  readonly summary: string;
}

export interface RuntimeAssertionTimelineEntry {
  readonly id: string;
  readonly type: string;
  readonly status: "PASSED" | "FAILED" | "INCOMPLETE";
  readonly summary: string;
}

export interface RuntimeRedactionReport {
  readonly applied: true;
  readonly totalReplacements: number;
  readonly categories: Readonly<Record<string, number>>;
}

export interface RuntimeRedactionResult {
  readonly text: string;
  readonly report: RuntimeRedactionReport;
}

export interface RuntimeEvidenceFile {
  readonly path: string;
  readonly mediaType: string;
  readonly sizeBytes: number;
  readonly sha256: `sha256:${string}`;
  readonly redacted: true;
  readonly sourceStepId: string;
}

export interface RuntimeEvidenceManifest {
  readonly schemaVersion: "1.0.0";
  readonly runId: string;
  readonly flow: {
    readonly id: string;
    readonly version: number;
  };
  readonly hcheckVersion: string;
  readonly rulePackVersion: string;
  readonly artifact: RuntimeArtifactRef;
  readonly device: {
    readonly id: string;
    readonly kind: RuntimeDeviceKind;
    readonly model: string;
    readonly osVersion: string;
    readonly capabilities: readonly string[];
  };
  readonly archiveRoot: string;
  readonly timeline: readonly RuntimeStepTimelineEntry[];
  readonly assertions: readonly RuntimeAssertionTimelineEntry[];
  readonly files: readonly RuntimeEvidenceFile[];
  readonly redaction: RuntimeRedactionReport;
  readonly startedAt: string;
  readonly completedAt: string;
}

export interface RuntimeFlowRunOptions {
  readonly runId: string;
  readonly hcheckVersion: string;
  readonly rulePackVersion: string;
  readonly artifact: RuntimeArtifactRef;
  readonly deviceId: string;
  readonly startedAt: string;
  readonly hash: RuntimeHashPort;
  readonly timing: RuntimeTimingPort;
  readonly evidenceWriter: RuntimeEvidenceWriterPort;
}

export interface RuntimeFlowRunResult {
  readonly status: RuntimeFlowRunStatus;
  readonly failure?: RuntimeFailure;
  readonly timeline: readonly RuntimeStepTimelineEntry[];
  readonly assertions: readonly RuntimeAssertionTimelineEntry[];
  readonly evidenceManifest: RuntimeEvidenceManifest;
}

export interface RuntimeReplayEvidenceFile {
  readonly path: string;
  readonly mediaType: string;
  readonly sizeBytes: number;
  readonly sha256: `sha256:${string}`;
  readonly redacted: true;
  readonly sourceStepId: string;
}

export interface RuntimeReplay {
  readonly schemaVersion: "1.0.0";
  readonly runId: string;
  readonly flow: {
    readonly id: string;
    readonly version: number;
  };
  readonly status: RuntimeFlowRunStatus;
  readonly failure?: RuntimeFailure;
  readonly readOnly: true;
  readonly device: RuntimeEvidenceManifest["device"];
  readonly summary: {
    readonly totalSteps: number;
    readonly passedSteps: number;
    readonly failedSteps: number;
    readonly totalAssertions: number;
    readonly passedAssertions: number;
    readonly failedAssertions: number;
    readonly incompleteAssertions: number;
    readonly evidenceFiles: number;
  };
  readonly timeline: readonly RuntimeStepTimelineEntry[];
  readonly assertions: readonly RuntimeAssertionTimelineEntry[];
  readonly evidenceFiles: readonly RuntimeReplayEvidenceFile[];
  readonly redaction: RuntimeRedactionReport;
  readonly source: {
    readonly kind: "runtime-flow-result" | "evidence-manifest";
    readonly archiveRoot: string;
  };
  readonly startedAt: string;
  readonly completedAt: string;
}

export class RecordedDevicePort implements RuntimeDevicePort {
  public readonly history: RecordedDeviceHistoryEntry[] = [];

  public constructor(private readonly input: RecordedDevicePortInput) {}

  public async listDevices(): Promise<readonly RuntimeDeviceInfo[]> {
    return this.input.devices;
  }

  public async performStep({
    step,
    attempt,
  }: RuntimeDeviceStepRequest): Promise<RuntimeStepResult> {
    this.history.push({ stepId: step.id, action: step.action, attempt });
    const scripted =
      this.input.steps?.[step.id] ?? this.input.steps?.[step.action];
    return (
      scripted?.[attempt - 1] ?? { status: "ok", summary: "录制步骤通过。" }
    );
  }

  public async evaluateAssertion({
    assertion,
  }: RuntimeDeviceAssertionRequest): Promise<RuntimeAssertionResult> {
    const key = assertion.id ?? assertion.type;
    return (
      this.input.assertions?.[key] ?? {
        status: "passed",
        summary: "录制断言通过。",
      }
    );
  }
}

export function createRecordedDevicePort(
  input: RecordedDevicePortInput,
): RecordedDevicePort {
  return new RecordedDevicePort(input);
}

export function createPrivacyRefuseRuntimeFlow(): RuntimeFlowDefinition {
  return parseRuntimeFlowDefinition({
    id: "privacy-refuse",
    version: 1,
    name: "首次启动拒绝隐私政策",
    description: "验证用户明确同意前及拒绝后不存在非必要敏感行为。",
    requires: {
      clean_install: true,
      network_observation: "metadata_only",
      test_account: false,
      device_capabilities: ["screenshot", "hilog"],
    },
    variables: { artifact: "${artifact}" },
    steps: [
      {
        id: "install",
        action: "install",
        package: "${artifact}",
        timeout_ms: 60_000,
      },
      { id: "launch", action: "launch", timeout_ms: 15_000 },
      {
        id: "wait-dialog",
        action: "wait_for",
        selector: { text_contains: "隐私" },
        timeout_ms: 10_000,
        retry: { max_attempts: 2, backoff_ms: 500 },
      },
      { id: "checkpoint-before-choice", action: "checkpoint" },
      {
        id: "reject",
        action: "tap",
        selector: { text_any: ["不同意", "拒绝"] },
        timeout_ms: 5_000,
      },
      { id: "wait-after-reject", action: "wait", duration_ms: 5_000 },
    ],
    assertions: [
      {
        id: "no-permission-before-consent",
        type: "no_sensitive_permission_dialog_before_consent",
        after_step: "checkpoint-before-choice",
        severity: "BLOCKER",
      },
      {
        id: "no-network-before-consent",
        type: "no_sensitive_network_before_consent",
        after_step: "checkpoint-before-choice",
        severity: "BLOCKER",
      },
      {
        id: "not-crashed",
        type: "app_not_crashed",
        after_step: "wait-after-reject",
        severity: "BLOCKER",
      },
    ],
    evidence: {
      screenshot: "each_checkpoint",
      video: "on_failure",
      hilog: true,
      network_timeline: "metadata_only",
      permission_timeline: true,
    },
  });
}

export function createPermissionDenyRuntimeFlow(): RuntimeFlowDefinition {
  return parseRuntimeFlowDefinition({
    id: "permission-deny",
    version: 1,
    name: "权限拒绝后核心功能可用",
    description: "验证用户拒绝非必要权限后应用不崩溃且能保留基础功能。",
    requires: {
      clean_install: true,
      network_observation: "none",
      test_account: false,
      device_capabilities: ["screenshot", "permission"],
    },
    variables: { artifact: "${artifact}" },
    steps: [
      {
        id: "install",
        action: "install",
        package: "${artifact}",
        timeout_ms: 60_000,
      },
      { id: "launch", action: "launch", timeout_ms: 15_000 },
      {
        id: "trigger-permission",
        action: "tap",
        selector: { test_id: "request-permission" },
        timeout_ms: 5_000,
      },
      {
        id: "deny-permission",
        action: "set_permission",
        value: "deny",
        timeout_ms: 5_000,
      },
      { id: "checkpoint-after-deny", action: "checkpoint" },
    ],
    assertions: [
      {
        id: "permission-state-denied",
        type: "permission_denied_state_visible",
        after_step: "checkpoint-after-deny",
        severity: "HIGH",
      },
      {
        id: "not-crashed",
        type: "app_not_crashed",
        after_step: "checkpoint-after-deny",
        severity: "BLOCKER",
      },
    ],
    evidence: {
      screenshot: "each_checkpoint",
      video: "on_failure",
      hilog: true,
      network_timeline: "none",
      permission_timeline: true,
    },
  });
}

export function createAccountDeleteRuntimeFlow(): RuntimeFlowDefinition {
  return parseRuntimeFlowDefinition({
    id: "account-delete",
    version: 1,
    name: "账号注销本地测试桩协议",
    description:
      "验证隔离测试账号注销后旧会话失效、重新登录被拒绝且本地数据已清理；该流程只定义本地测试桩合同，不访问真实账号或生产服务。",
    requires: {
      clean_install: true,
      network_observation: "metadata_only",
      test_account: true,
      device_capabilities: ["screenshot", "hilog", "test_account_stub"],
    },
    variables: { artifact: "${artifact}" },
    steps: [
      {
        id: "install",
        action: "install",
        package: "${artifact}",
        timeout_ms: 60_000,
      },
      {
        id: "prepare-account-stub",
        action: "invoke_test_hook",
        value: "account-delete.prepare-local-stub",
        timeout_ms: 5_000,
      },
      { id: "launch", action: "launch", timeout_ms: 15_000 },
      {
        id: "login-test-account",
        action: "invoke_test_hook",
        value: "account-delete.login-redacted-test-account",
        timeout_ms: 5_000,
      },
      {
        id: "request-account-delete",
        action: "invoke_test_hook",
        value: "account-delete.request-delete",
        timeout_ms: 5_000,
      },
      {
        id: "clear-local-data",
        action: "clear_data",
        timeout_ms: 10_000,
      },
      {
        id: "verify-old-token-rejected",
        action: "invoke_test_hook",
        value: "account-delete.verify-old-session-rejected",
        timeout_ms: 5_000,
      },
      {
        id: "verify-relogin-rejected",
        action: "invoke_test_hook",
        value: "account-delete.verify-relogin-rejected",
        timeout_ms: 5_000,
      },
      { id: "checkpoint-after-delete", action: "checkpoint" },
    ],
    assertions: [
      {
        id: "delete-request-accepted",
        type: "delete_request_accepted_by_local_stub",
        after_step: "request-account-delete",
        severity: "BLOCKER",
      },
      {
        id: "old-token-rejected",
        type: "old_token_invalidated",
        after_step: "verify-old-token-rejected",
        severity: "BLOCKER",
      },
      {
        id: "relogin-rejected",
        type: "relogin_after_delete_rejected",
        after_step: "verify-relogin-rejected",
        severity: "BLOCKER",
      },
      {
        id: "local-data-cleared",
        type: "local_account_data_cleared",
        after_step: "checkpoint-after-delete",
        severity: "HIGH",
      },
      {
        id: "not-crashed",
        type: "app_not_crashed",
        after_step: "checkpoint-after-delete",
        severity: "BLOCKER",
      },
    ],
    evidence: {
      screenshot: "on_failure",
      video: "on_failure",
      hilog: true,
      network_timeline: "metadata_only",
      permission_timeline: false,
    },
  });
}

export function validateAccountDeletionStubContract(
  value: unknown,
): AccountDeletionStubContract {
  const contract = requireRecord(value, "账号注销测试桩合同");
  requireExactKeys(
    contract,
    [
      "schemaVersion",
      "fixtureId",
      "flowId",
      "evidenceKind",
      "status",
      "runtimeConfirmed",
      "redacted",
      "service",
      "account",
      "checks",
      "evidence",
      "boundaries",
    ],
    [],
    "账号注销测试桩合同",
  );
  if (contract.schemaVersion !== "1.0.0") {
    throw new TypeError("账号注销测试桩合同 schemaVersion 必须是 1.0.0。");
  }
  if (contract.flowId !== "account-delete") {
    throw new TypeError("账号注销测试桩合同 flowId 必须是 account-delete。");
  }
  if (contract.evidenceKind !== "account-deletion-stub-contract") {
    throw new TypeError(
      "账号注销测试桩合同 evidenceKind 必须是 account-deletion-stub-contract。",
    );
  }
  if (contract.status !== "local_contract") {
    throw new TypeError("账号注销测试桩合同 status 必须是 local_contract。");
  }
  if (contract.runtimeConfirmed !== false) {
    throw new TypeError(
      "账号注销测试桩合同 runtimeConfirmed 必须为 false，不能伪造真实账号注销。",
    );
  }
  if (contract.redacted !== true) {
    throw new TypeError("账号注销测试桩合同必须标记 redacted=true。");
  }

  const output: AccountDeletionStubContract = {
    schemaVersion: "1.0.0",
    fixtureId: requirePattern(contract.fixtureId, /^F[0-9]{3}$/u, "Fixture ID"),
    flowId: "account-delete",
    evidenceKind: "account-deletion-stub-contract",
    status: "local_contract",
    runtimeConfirmed: false,
    redacted: true,
    service: parseAccountDeletionStubService(contract.service),
    account: parseAccountDeletionStubAccount(contract.account),
    checks: parseAccountDeletionStubChecks(contract.checks),
    evidence: parseAccountDeletionStubEvidence(contract.evidence),
    boundaries: requireSafeTextArray(contract.boundaries, "账号注销测试桩边界"),
  };

  assertSafeRuntimeContractText(output, "账号注销测试桩合同");
  return deepFreeze(output);
}

export function validateRuntimeFlowDefinition(
  value: unknown,
): asserts value is RuntimeFlowDefinition {
  parseRuntimeFlowDefinition(value);
}

export function parseRuntimeFlowDefinition(
  value: unknown,
): RuntimeFlowDefinition {
  const flow = requireRecord(value, "Runtime Flow");
  requireExactKeys(
    flow,
    ["id", "version", "name", "requires", "steps", "assertions", "evidence"],
    ["description", "variables"],
    "Runtime Flow",
  );

  const requires = parseRequires(flow.requires);
  const steps = parseSteps(flow.steps);
  const stepIds = new Set<string>();
  for (const step of steps) {
    if (stepIds.has(step.id)) {
      throw new TypeError("Runtime Flow 步骤 ID 不得重复。");
    }
    stepIds.add(step.id);
  }

  const assertions = parseAssertions(flow.assertions, stepIds);
  const definition: RuntimeFlowDefinition = {
    id: requirePattern(flow.id, /^[a-z][a-z0-9-]+$/u, "Runtime Flow ID"),
    version: requirePositiveInteger(flow.version, "Runtime Flow 版本"),
    name: requireNonEmptyString(flow.name, "Runtime Flow 名称"),
    ...(flow.description === undefined
      ? {}
      : {
          description: requireNonEmptyString(
            flow.description,
            "Runtime Flow 描述",
          ),
        }),
    requires,
    ...(flow.variables === undefined
      ? {}
      : { variables: parseVariables(flow.variables) }),
    steps,
    assertions,
    evidence: parseEvidencePolicy(flow.evidence),
  };

  return deepFreeze(definition);
}

export async function runRuntimeFlow(
  inputFlow: RuntimeFlowDefinition,
  device: RuntimeDevicePort,
  options: RuntimeFlowRunOptions,
): Promise<RuntimeFlowRunResult> {
  const flow = parseRuntimeFlowDefinition(inputFlow);
  const runId = requireSafeSegment(options.runId, "运行 ID");
  const archiveRoot = `.hcheck/evidence/${runId}`;
  const startedAt = requireDateTime(options.startedAt, "运行开始时间");
  const hcheckVersion = requireSafeText(options.hcheckVersion, "HCheck 版本");
  const rulePackVersion = requireSafeText(
    options.rulePackVersion,
    "规则包版本",
  );
  const artifact = normalizeArtifact(options.artifact);
  assertSafeRuntimeContractText(
    { hcheckVersion, rulePackVersion, artifact },
    "运行元数据",
  );
  const selectedCandidate = await selectDevice(device, options.deviceId);
  const selectedDevice =
    selectedCandidate === undefined
      ? undefined
      : normalizeSelectedRuntimeDevice(selectedCandidate);
  const manifestDevice: RuntimeEvidenceManifest["device"] =
    selectedDevice === undefined
      ? {
          id: "device:unavailable",
          kind: "unknown",
          model: "unknown",
          osVersion: "unknown",
          capabilities: [],
        }
      : {
          id: selectedDevice.redactedId,
          kind: selectedDevice.kind,
          model: selectedDevice.model,
          osVersion: selectedDevice.osVersion,
          capabilities: selectedDevice.capabilities,
        };
  const timeline: RuntimeStepTimelineEntry[] = [];
  const assertions: RuntimeAssertionTimelineEntry[] = [];
  const files: RuntimeEvidenceFile[] = [];
  const preparedEvidence: PreparedRuntimeEvidence[] = [];
  const captureKinds = new Set<RuntimeEvidenceCaptureKind>();
  let redaction = emptyRedactionReport();
  let evidenceFailure: RuntimeFailure | undefined;
  let failure: RuntimeFailure | undefined =
    selectedDevice === undefined
      ? {
          kind: "DEVICE_UNAVAILABLE",
          summary: "未找到可用录制设备。",
        }
      : checkDeviceCapabilities(flow, selectedDevice);

  const evaluateAssertion = async (
    assertion: RuntimeFlowAssertion,
  ): Promise<RuntimeFailure | undefined> => {
    if (selectedDevice === undefined) return undefined;
    const result = await device.evaluateAssertion({
      flow,
      assertion,
      artifact,
      deviceId: selectedDevice.id,
    });
    const redactedResult = redactRuntimeText(result.summary, {
      extraSecrets: [selectedDevice.id],
    });
    redaction = mergeRedactionReports(redaction, redactedResult.report);
    assertions.push(
      assertionTimelineEntry(assertion, result, redactedResult.text),
    );
    return result.status === "passed"
      ? undefined
      : assertionFailure(assertion, result, redactedResult.text);
  };

  if (failure === undefined && selectedDevice !== undefined) {
    stepLoop: for (const step of flow.steps) {
      const execution = await executeStep({
        flow,
        step,
        device,
        selectedDevice,
        artifact,
        hash: options.hash,
        timing: options.timing,
        archiveRoot,
      });
      timeline.push(execution.timeline);
      preparedEvidence.push(...execution.preparedEvidence);
      redaction = mergeRedactionReports(redaction, execution.redaction);
      evidenceFailure ??= execution.evidenceFailure;
      if (execution.failure !== undefined) {
        failure = execution.failure;
        break;
      }
      for (const assertion of flow.assertions) {
        if (assertion.after_step !== step.id) continue;
        failure = await evaluateAssertion(assertion);
        if (failure !== undefined) break stepLoop;
      }
    }
  }

  if (failure === undefined && selectedDevice !== undefined) {
    for (const assertion of flow.assertions) {
      if (assertion.after_step !== undefined) continue;
      failure = await evaluateAssertion(assertion);
      if (failure !== undefined) break;
    }
  }

  let completedAt = startedAt;
  let timingFailure: RuntimeFailure | undefined;
  try {
    const observedCompletedAt = requireDateTime(
      options.timing.now(),
      "运行完成时间",
    );
    if (Date.parse(observedCompletedAt) < Date.parse(startedAt)) {
      timingFailure = {
        kind: "ENVIRONMENT_FAILED",
        summary: "运行完成时间早于开始时间。",
      };
    } else {
      completedAt = observedCompletedAt;
    }
  } catch {
    timingFailure = {
      kind: "ENVIRONMENT_FAILED",
      summary: "运行完成时间无效。",
    };
  }
  if (timingFailure !== undefined) failure ??= timingFailure;

  const pendingHilogFailure: RuntimeFailure | undefined =
    flow.evidence.hilog === true &&
    !preparedEvidence.some((evidence) => evidence.kind === "hilog")
      ? {
          kind: "EVIDENCE_INCOMPLETE",
          summary: "运行时证据缺少 HiLog capture。",
        }
      : undefined;

  normalizeRuntimeEvidenceManifest({
    schemaVersion: "1.0.0",
    runId,
    flow: { id: flow.id, version: flow.version },
    hcheckVersion,
    rulePackVersion,
    artifact,
    device: manifestDevice,
    archiveRoot,
    timeline,
    assertions,
    files: preparedEvidence.map((evidence) => evidence.file),
    redaction,
    startedAt,
    completedAt,
  });

  let writerFailure: RuntimeFailure | undefined;
  if (
    timingFailure === undefined &&
    evidenceFailure === undefined &&
    pendingHilogFailure === undefined
  ) {
    try {
      for (const evidence of preparedEvidence) {
        await options.evidenceWriter.write(evidence.writeRequest);
        files.push(evidence.file);
        captureKinds.add(evidence.kind);
      }
    } catch {
      writerFailure = {
        kind: "EVIDENCE_INCOMPLETE",
        summary: "运行时证据写入失败。",
      };
    }
  }

  if (failure === undefined) {
    failure =
      (flow.evidence.hilog === true && !captureKinds.has("hilog")
        ? {
            kind: "EVIDENCE_INCOMPLETE",
            summary: "运行时证据缺少 HiLog capture。",
          }
        : undefined) ??
      evidenceFailure ??
      writerFailure;
  }
  const evidenceManifest: RuntimeEvidenceManifest = deepFreeze({
    schemaVersion: "1.0.0",
    runId,
    flow: { id: flow.id, version: flow.version },
    hcheckVersion,
    rulePackVersion,
    artifact,
    device: manifestDevice,
    archiveRoot,
    timeline,
    assertions,
    files,
    redaction,
    startedAt,
    completedAt,
  });

  return deepFreeze({
    status: statusFromFailure(failure),
    ...(failure === undefined ? {} : { failure }),
    timeline,
    assertions,
    evidenceManifest,
  });
}

export function buildRuntimeReplay(
  input: RuntimeFlowRunResult | RuntimeEvidenceManifest,
): RuntimeReplay {
  const result = isRuntimeFlowRunResult(input) ? input : undefined;
  const manifest = normalizeRuntimeEvidenceManifest(
    result?.evidenceManifest ?? input,
  );
  const status = result?.status ?? replayStatusFromManifest(manifest);
  const failure = result?.failure;
  const timeline = manifest.timeline.map(normalizeRuntimeStepTimelineEntry);
  const assertions = manifest.assertions.map(
    normalizeRuntimeAssertionTimelineEntry,
  );
  const evidenceFiles = manifest.files.map(normalizeRuntimeReplayEvidenceFile);
  const replay: RuntimeReplay = {
    schemaVersion: "1.0.0",
    runId: manifest.runId,
    flow: manifest.flow,
    status,
    ...(failure === undefined
      ? {}
      : { failure: normalizeRuntimeFailure(failure) }),
    readOnly: true,
    device: manifest.device,
    summary: {
      totalSteps: timeline.length,
      passedSteps: timeline.filter((step) => step.status === "PASSED").length,
      failedSteps: timeline.filter((step) => step.status === "FAILED").length,
      totalAssertions: assertions.length,
      passedAssertions: assertions.filter(
        (assertion) => assertion.status === "PASSED",
      ).length,
      failedAssertions: assertions.filter(
        (assertion) => assertion.status === "FAILED",
      ).length,
      incompleteAssertions: assertions.filter(
        (assertion) => assertion.status === "INCOMPLETE",
      ).length,
      evidenceFiles: evidenceFiles.length,
    },
    timeline,
    assertions,
    evidenceFiles,
    redaction: normalizeRedactionReport(manifest.redaction),
    source: {
      kind: result === undefined ? "evidence-manifest" : "runtime-flow-result",
      archiveRoot: requireSafePath(manifest.archiveRoot, "运行回放归档目录"),
    },
    startedAt: requireDateTime(manifest.startedAt, "运行开始时间"),
    completedAt: requireDateTime(manifest.completedAt, "运行完成时间"),
  };
  assertSafeRuntimeContractText(replay, "运行回放");
  return deepFreeze(replay);
}

export function redactRuntimeText(
  text: string,
  options: { readonly extraSecrets?: readonly string[] } = {},
): RuntimeRedactionResult {
  let output = text;
  const categories: Record<string, number> = {};

  for (const secret of options.extraSecrets ?? []) {
    if (secret.length === 0) continue;
    output = replaceAndCount(
      output,
      new RegExp(escapeRegExp(secret), "gu"),
      "<REDACTED_SECRET>",
      "extra_secret",
      categories,
    );
  }
  output = replaceAndCount(
    output,
    /\b(token|password|secret|authorization|cookie)\s*[:=]\s*(?:Bearer\s+)?[^\s,;]+/giu,
    (_match, key: unknown) => `${String(key)}=<REDACTED_SECRET>`,
    "secret",
    categories,
  );
  output = replaceAndCount(
    output,
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu,
    "<REDACTED_EMAIL>",
    "email",
    categories,
  );
  output = replaceAndCount(
    output,
    /[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+/gu,
    "<REDACTED_PATH>",
    "absolute_path",
    categories,
  );
  output = replaceAndCount(
    output,
    /(?:\/Users|\/home|\/tmp|\/var|\/private\/tmp|\/Volumes)\/[^\s,;]+/gu,
    "<REDACTED_PATH>",
    "absolute_path",
    categories,
  );

  return {
    text: output,
    report: redactionReport(categories),
  };
}

interface PreparedRuntimeEvidence {
  readonly kind: RuntimeEvidenceCaptureKind;
  readonly writeRequest: RuntimeEvidenceWriteRequest;
  readonly file: RuntimeEvidenceFile;
}

async function executeStep({
  flow,
  step,
  device,
  selectedDevice,
  artifact,
  hash,
  timing,
  archiveRoot,
}: {
  readonly flow: RuntimeFlowDefinition;
  readonly step: RuntimeFlowStep;
  readonly device: RuntimeDevicePort;
  readonly selectedDevice: RuntimeDeviceInfo;
  readonly artifact: RuntimeArtifactRef;
  readonly hash: RuntimeHashPort;
  readonly timing: RuntimeTimingPort;
  readonly archiveRoot: string;
}): Promise<{
  readonly timeline: RuntimeStepTimelineEntry;
  readonly preparedEvidence: readonly PreparedRuntimeEvidence[];
  readonly redaction: RuntimeRedactionReport;
  readonly failure?: RuntimeFailure;
  readonly evidenceFailure?: RuntimeFailure;
}> {
  const maxAttempts = step.retry?.max_attempts ?? 1;
  let attempts = 0;
  let finalResult: RuntimeStepResult = {
    status: "environment_failed",
    summary: "步骤未执行。",
  };

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    attempts = attempt;
    finalResult = await device.performStep({
      flow,
      step,
      artifact,
      deviceId: selectedDevice.id,
      attempt,
    });
    if (finalResult.status !== "locator_failed" || attempt === maxAttempts) {
      break;
    }
    const backoffMs = step.retry?.backoff_ms ?? 0;
    if (backoffMs > 0) await timing.sleep(backoffMs);
  }

  const redactedSummary = redactRuntimeText(finalResult.summary, {
    extraSecrets: [selectedDevice.id],
  });
  const collected = await collectRuntimeEvidenceFiles({
    stepId: step.id,
    captures: finalResult.evidence ?? [],
    hash,
    archiveRoot,
    extraSecrets: [selectedDevice.id],
  });
  const failure =
    finalResult.status === "ok"
      ? undefined
      : stepFailure(step, finalResult, redactedSummary.text);

  return {
    timeline: {
      stepId: step.id,
      action: step.action,
      attempts,
      status: finalResult.status === "ok" ? "PASSED" : "FAILED",
      result: finalResult.status,
      summary: redactedSummary.text,
    },
    preparedEvidence: collected.preparedEvidence,
    redaction: mergeRedactionReports(
      redactedSummary.report,
      collected.redaction,
    ),
    ...(failure === undefined ? {} : { failure }),
    ...(collected.evidenceFailure === undefined
      ? {}
      : { evidenceFailure: collected.evidenceFailure }),
  };
}

async function collectRuntimeEvidenceFiles({
  stepId,
  captures,
  hash,
  archiveRoot,
  extraSecrets,
}: {
  readonly stepId: string;
  readonly captures: readonly RuntimeEvidenceCapture[];
  readonly hash: RuntimeHashPort;
  readonly archiveRoot: string;
  readonly extraSecrets: readonly string[];
}): Promise<{
  readonly preparedEvidence: readonly PreparedRuntimeEvidence[];
  readonly redaction: RuntimeRedactionReport;
  readonly evidenceFailure?: RuntimeFailure;
}> {
  const preparedEvidence: PreparedRuntimeEvidence[] = [];
  let redaction = emptyRedactionReport();
  let evidenceFailure: RuntimeFailure | undefined;
  for (const capture of captures) {
    try {
      const kind = requireEnum(
        capture.kind,
        RUNTIME_EVIDENCE_CAPTURE_KINDS,
        "运行时证据 kind",
      );
      const path = requireSafePath(capture.path, "运行时证据路径");
      const mediaType = requireSafeText(capture.mediaType, "运行时证据类型");
      const content =
        typeof capture.content === "string"
          ? redactRuntimeText(capture.content, { extraSecrets })
          : {
              text: capture.content,
              report: emptyRedactionReport(),
            };
      redaction = mergeRedactionReports(redaction, content.report);
      const bytes =
        typeof content.text === "string"
          ? new TextEncoder().encode(content.text)
          : content.text;
      const sha256 = requireSha256(await hash.sha256(bytes));
      preparedEvidence.push({
        kind,
        writeRequest: { archiveRoot, relativePath: path, bytes },
        file: {
          path,
          mediaType,
          sizeBytes: bytes.byteLength,
          sha256,
          redacted: true,
          sourceStepId: stepId,
        },
      });
    } catch {
      evidenceFailure ??= {
        kind: "EVIDENCE_INCOMPLETE",
        stepId,
        summary: "运行时证据校验或哈希失败。",
      };
    }
  }
  return {
    preparedEvidence,
    redaction,
    ...(evidenceFailure === undefined ? {} : { evidenceFailure }),
  };
}

function assertionTimelineEntry(
  assertion: RuntimeFlowAssertion,
  result: RuntimeAssertionResult,
  summary: string,
): RuntimeAssertionTimelineEntry {
  return {
    id: assertion.id ?? assertion.type,
    type: assertion.type,
    status:
      result.status === "passed"
        ? "PASSED"
        : result.status === "failed"
          ? "FAILED"
          : "INCOMPLETE",
    summary,
  };
}

function assertionFailure(
  assertion: RuntimeFlowAssertion,
  result: RuntimeAssertionResult,
  summary: string,
): RuntimeFailure {
  return {
    kind:
      result.status === "failed"
        ? "FLOW_ASSERTION_FAILED"
        : "EVIDENCE_INCOMPLETE",
    assertionId: assertion.id ?? assertion.type,
    summary,
  };
}

function stepFailure(
  step: RuntimeFlowStep,
  result: RuntimeStepResult,
  summary: string,
): RuntimeFailure {
  return {
    kind: stepFailureKind(result.status),
    stepId: step.id,
    summary,
  };
}

function stepFailureKind(status: RuntimeStepResultStatus): RuntimeFailureKind {
  switch (status) {
    case "locator_failed":
      return "LOCATOR_FAILED";
    case "device_unavailable":
      return "DEVICE_UNAVAILABLE";
    case "install_failed":
      return "INSTALL_FAILED";
    case "app_crashed":
      return "APP_CRASHED";
    case "app_frozen":
      return "APP_FROZEN";
    case "evidence_incomplete":
      return "EVIDENCE_INCOMPLETE";
    case "environment_failed":
      return "ENVIRONMENT_FAILED";
    case "unsupported_device":
      return "UNSUPPORTED_DEVICE";
    case "ok":
      throw new TypeError("通过步骤不应转换为失败。");
  }
}

function statusFromFailure(
  failure: RuntimeFailure | undefined,
): RuntimeFlowRunStatus {
  if (failure === undefined) return "PASS";
  return failure.kind === "FLOW_ASSERTION_FAILED" ||
    failure.kind === "APP_CRASHED" ||
    failure.kind === "APP_FROZEN"
    ? "FAILED"
    : "INCOMPLETE";
}

function checkDeviceCapabilities(
  flow: RuntimeFlowDefinition,
  device: RuntimeDeviceInfo,
): RuntimeFailure | undefined {
  const available = new Set(device.capabilities);
  const missing = (flow.requires.device_capabilities ?? []).filter(
    (capability) => !available.has(capability),
  );
  return missing.length === 0
    ? undefined
    : {
        kind: "UNSUPPORTED_DEVICE",
        summary: `设备缺少能力：${missing.join("、")}`,
      };
}

async function selectDevice(
  device: RuntimeDevicePort,
  deviceId: string,
): Promise<RuntimeDeviceInfo | undefined> {
  const devices = await device.listDevices();
  return devices.find(
    (candidate) =>
      candidate.id === deviceId || candidate.redactedId === deviceId,
  );
}

function normalizeSelectedRuntimeDevice(
  device: RuntimeDeviceInfo,
): RuntimeDeviceInfo {
  return {
    id: requireNonEmptyString(device.id, "运行设备 ID"),
    redactedId: requirePattern(
      device.redactedId,
      /^device:[A-Za-z0-9_.:-]+$/u,
      "运行设备脱敏 ID",
    ),
    kind: requireEnum(device.kind, RUNTIME_DEVICE_KINDS, "运行设备 kind"),
    model: requireSafeText(device.model, "运行设备型号"),
    osVersion: requireSafeText(device.osVersion, "运行设备系统版本"),
    capabilities: requireStringArray(device.capabilities, "运行设备能力")
      .map((capability) => requireSafeText(capability, "运行设备能力"))
      .sort(compareCodePoints),
  };
}

function normalizeRuntimeDeviceKind(value: unknown): RuntimeDeviceKind {
  return value === undefined
    ? "unknown"
    : requireEnum(value, RUNTIME_DEVICE_KINDS, "运行设备 kind");
}

function parseRequires(value: unknown): RuntimeFlowRequires {
  const record = requireRecord(value, "Runtime Flow requires");
  requireExactKeys(
    record,
    [],
    [
      "clean_install",
      "network_observation",
      "test_account",
      "device_capabilities",
    ],
    "Runtime Flow requires",
  );
  return {
    ...(record.clean_install === undefined
      ? {}
      : {
          clean_install: requireBoolean(record.clean_install, "clean_install"),
        }),
    ...(record.network_observation === undefined
      ? {}
      : {
          network_observation: requireEnum(
            record.network_observation,
            RUNTIME_NETWORK_OBSERVATION_MODES,
            "network_observation",
          ),
        }),
    ...(record.test_account === undefined
      ? {}
      : { test_account: requireBoolean(record.test_account, "test_account") }),
    ...(record.device_capabilities === undefined
      ? {}
      : {
          device_capabilities: requireStringArray(
            record.device_capabilities,
            "device_capabilities",
          ),
        }),
  };
}

function parseVariables(value: unknown): Readonly<Record<string, string>> {
  const record = requireRecord(value, "Runtime Flow variables");
  const output: Record<string, string> = {};
  for (const [key, variable] of Object.entries(record)) {
    output[requireNonEmptyString(key, "变量名")] = requireNonEmptyString(
      variable,
      "变量值",
    );
  }
  return output;
}

function parseSteps(value: unknown): readonly RuntimeFlowStep[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError("Runtime Flow steps 必须是非空数组。");
  }
  return value.map((item, index) => {
    const step = requireRecord(item, `Runtime Flow steps[${index}]`);
    requireExactKeys(
      step,
      ["id", "action"],
      ["package", "duration_ms", "timeout_ms", "selector", "value", "retry"],
      `Runtime Flow steps[${index}]`,
    );
    return {
      id: requireNonEmptyString(step.id, "步骤 ID"),
      action: requireEnum(step.action, RUNTIME_FLOW_ACTIONS, "步骤 action"),
      ...(step.package === undefined
        ? {}
        : { package: requireNonEmptyString(step.package, "步骤 package") }),
      ...(step.duration_ms === undefined
        ? {}
        : {
            duration_ms: requireNonNegativeInteger(
              step.duration_ms,
              "步骤 duration_ms",
            ),
          }),
      ...(step.timeout_ms === undefined
        ? {}
        : {
            timeout_ms: requirePositiveInteger(
              step.timeout_ms,
              "步骤 timeout_ms",
            ),
          }),
      ...(step.selector === undefined
        ? {}
        : { selector: requireRecord(step.selector, "步骤 selector") }),
      ...(step.value === undefined
        ? {}
        : { value: requireNonEmptyString(step.value, "步骤 value") }),
      ...(step.retry === undefined ? {} : { retry: parseRetry(step.retry) }),
    };
  });
}

function parseRetry(value: unknown): RuntimeFlowStepRetry {
  const record = requireRecord(value, "步骤 retry");
  requireExactKeys(record, [], ["max_attempts", "backoff_ms"], "步骤 retry");
  return {
    ...(record.max_attempts === undefined
      ? {}
      : {
          max_attempts: requireIntegerRange(
            record.max_attempts,
            1,
            5,
            "retry.max_attempts",
          ),
        }),
    ...(record.backoff_ms === undefined
      ? {}
      : {
          backoff_ms: requireNonNegativeInteger(
            record.backoff_ms,
            "retry.backoff_ms",
          ),
        }),
  };
}

function parseAssertions(
  value: unknown,
  stepIds: ReadonlySet<string>,
): readonly RuntimeFlowAssertion[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError("Runtime Flow assertions 必须是非空数组。");
  }
  return value.map((item, index) => {
    const assertion = requireRecord(item, `Runtime Flow assertions[${index}]`);
    requireExactKeys(
      assertion,
      ["type"],
      ["id", "after_step", "options", "severity"],
      `Runtime Flow assertions[${index}]`,
    );
    if (
      assertion.after_step !== undefined &&
      !stepIds.has(requireNonEmptyString(assertion.after_step, "after_step"))
    ) {
      throw new TypeError("Runtime Flow after_step 必须引用已定义步骤。");
    }
    return {
      ...(assertion.id === undefined
        ? {}
        : { id: requireNonEmptyString(assertion.id, "断言 ID") }),
      type: requireNonEmptyString(assertion.type, "断言 type"),
      ...(assertion.after_step === undefined
        ? {}
        : {
            after_step: requireNonEmptyString(
              assertion.after_step,
              "after_step",
            ),
          }),
      ...(assertion.options === undefined
        ? {}
        : {
            options: requireRecord(assertion.options, "断言 options"),
          }),
      ...(assertion.severity === undefined
        ? {}
        : {
            severity: requireEnum(
              assertion.severity,
              ["BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO"] as const,
              "断言 severity",
            ),
          }),
    };
  });
}

function parseEvidencePolicy(value: unknown): RuntimeFlowEvidencePolicy {
  const record = requireRecord(value, "Runtime Flow evidence");
  requireExactKeys(
    record,
    [],
    ["screenshot", "video", "hilog", "network_timeline", "permission_timeline"],
    "Runtime Flow evidence",
  );
  return {
    ...(record.screenshot === undefined
      ? {}
      : {
          screenshot: requireEnum(
            record.screenshot,
            RUNTIME_SCREENSHOT_POLICIES,
            "evidence.screenshot",
          ),
        }),
    ...(record.video === undefined
      ? {}
      : {
          video: requireEnum(
            record.video,
            RUNTIME_VIDEO_POLICIES,
            "evidence.video",
          ),
        }),
    ...(record.hilog === undefined
      ? {}
      : { hilog: requireBoolean(record.hilog, "evidence.hilog") }),
    ...(record.network_timeline === undefined
      ? {}
      : {
          network_timeline: requireEnum(
            record.network_timeline,
            RUNTIME_NETWORK_OBSERVATION_MODES,
            "evidence.network_timeline",
          ),
        }),
    ...(record.permission_timeline === undefined
      ? {}
      : {
          permission_timeline: requireBoolean(
            record.permission_timeline,
            "evidence.permission_timeline",
          ),
        }),
  };
}

function normalizeArtifact(artifact: RuntimeArtifactRef): RuntimeArtifactRef {
  return {
    uri: requireSafePath(artifact.uri, "产物路径"),
    sha256: requireSha256(artifact.sha256),
    bundleName: requireNonEmptyString(artifact.bundleName, "Bundle 名称"),
    ...(artifact.versionName === undefined
      ? {}
      : {
          versionName: requireNonEmptyString(artifact.versionName, "版本名称"),
        }),
    ...(artifact.versionCode === undefined
      ? {}
      : {
          versionCode: requireNonNegativeInteger(
            artifact.versionCode,
            "版本号",
          ),
        }),
  };
}

function normalizeRuntimeEvidenceManifest(
  value: unknown,
): RuntimeEvidenceManifest {
  const manifest = requireRecord(value, "运行时证据清单");
  requireExactKeys(
    manifest,
    [
      "schemaVersion",
      "runId",
      "flow",
      "hcheckVersion",
      "rulePackVersion",
      "artifact",
      "device",
      "archiveRoot",
      "timeline",
      "assertions",
      "files",
      "redaction",
      "startedAt",
      "completedAt",
    ],
    [],
    "运行时证据清单",
  );
  if (manifest.schemaVersion !== "1.0.0") {
    throw new TypeError("运行时证据清单 schemaVersion 必须是 1.0.0。");
  }
  const flow = requireRecord(manifest.flow, "运行时证据清单 flow");
  requireExactKeys(flow, ["id", "version"], [], "运行时证据清单 flow");
  const device = normalizeRuntimeReplayDevice(manifest.device);
  const normalized: RuntimeEvidenceManifest = {
    schemaVersion: "1.0.0",
    runId: requireSafeSegment(manifest.runId, "运行 ID"),
    flow: {
      id: requirePattern(flow.id, /^[a-z][a-z0-9-]+$/u, "Runtime Flow ID"),
      version: requirePositiveInteger(flow.version, "Runtime Flow 版本"),
    },
    hcheckVersion: requireNonEmptyString(manifest.hcheckVersion, "HCheck 版本"),
    rulePackVersion: requireNonEmptyString(
      manifest.rulePackVersion,
      "规则包版本",
    ),
    artifact: normalizeArtifact(manifest.artifact as RuntimeArtifactRef),
    device,
    archiveRoot: requireSafePath(manifest.archiveRoot, "运行回放归档目录"),
    timeline: requireArray(manifest.timeline, "运行回放步骤时间线").map(
      normalizeRuntimeStepTimelineEntry,
    ),
    assertions: requireArray(manifest.assertions, "运行回放断言时间线").map(
      normalizeRuntimeAssertionTimelineEntry,
    ),
    files: requireArray(manifest.files, "运行回放证据文件").map(
      normalizeRuntimeReplayEvidenceFile,
    ),
    redaction: normalizeRedactionReport(manifest.redaction),
    startedAt: requireDateTime(manifest.startedAt, "运行开始时间"),
    completedAt: requireDateTime(manifest.completedAt, "运行完成时间"),
  };
  assertSafeRuntimeContractText(normalized, "运行时证据清单");
  return normalized;
}

function normalizeRuntimeReplayDevice(
  value: unknown,
): RuntimeEvidenceManifest["device"] {
  const device = requireRecord(value, "运行回放设备");
  requireExactKeys(
    device,
    ["id", "model", "osVersion", "capabilities"],
    ["kind"],
    "运行回放设备",
  );
  const id = requirePattern(
    device.id,
    /^device:[A-Za-z0-9_.:-]+$/u,
    "运行回放设备 ID",
  );
  return {
    id,
    kind: normalizeRuntimeDeviceKind(device.kind),
    model: requireSafeText(device.model, "运行回放设备型号"),
    osVersion: requireSafeText(device.osVersion, "运行回放系统版本"),
    capabilities: requireStringArray(device.capabilities, "运行回放设备能力")
      .map((capability) => requireSafeText(capability, "运行回放设备能力"))
      .sort(compareCodePoints),
  };
}

function normalizeRuntimeStepTimelineEntry(
  value: RuntimeStepTimelineEntry | unknown,
): RuntimeStepTimelineEntry {
  const entry = requireRecord(value, "运行回放步骤");
  requireExactKeys(
    entry,
    ["stepId", "action", "attempts", "status", "result", "summary"],
    [],
    "运行回放步骤",
  );
  return {
    stepId: requireNonEmptyString(entry.stepId, "运行回放步骤 ID"),
    action: requireEnum(
      entry.action,
      RUNTIME_FLOW_ACTIONS,
      "运行回放步骤 action",
    ),
    attempts: requirePositiveInteger(entry.attempts, "运行回放步骤 attempts"),
    status: requireEnum(
      entry.status,
      ["PASSED", "FAILED"] as const,
      "运行回放步骤 status",
    ),
    result: requireEnum(
      entry.result,
      [
        "ok",
        "locator_failed",
        "device_unavailable",
        "install_failed",
        "app_crashed",
        "app_frozen",
        "environment_failed",
        "evidence_incomplete",
        "unsupported_device",
      ] as const,
      "运行回放步骤 result",
    ),
    summary: requireSafeText(entry.summary, "运行回放步骤 summary"),
  };
}

function normalizeRuntimeAssertionTimelineEntry(
  value: RuntimeAssertionTimelineEntry | unknown,
): RuntimeAssertionTimelineEntry {
  const entry = requireRecord(value, "运行回放断言");
  requireExactKeys(
    entry,
    ["id", "type", "status", "summary"],
    [],
    "运行回放断言",
  );
  return {
    id: requireNonEmptyString(entry.id, "运行回放断言 ID"),
    type: requireNonEmptyString(entry.type, "运行回放断言 type"),
    status: requireEnum(
      entry.status,
      ["PASSED", "FAILED", "INCOMPLETE"] as const,
      "运行回放断言 status",
    ),
    summary: requireSafeText(entry.summary, "运行回放断言 summary"),
  };
}

function normalizeRuntimeReplayEvidenceFile(
  value: RuntimeReplayEvidenceFile | RuntimeEvidenceFile | unknown,
): RuntimeReplayEvidenceFile {
  const file = requireRecord(value, "运行回放证据文件");
  requireExactKeys(
    file,
    ["path", "mediaType", "sizeBytes", "sha256", "redacted", "sourceStepId"],
    [],
    "运行回放证据文件",
  );
  if (file.redacted !== true) {
    throw new TypeError("运行回放证据文件必须已脱敏。");
  }
  return {
    path: requireSafePath(file.path, "运行回放证据路径"),
    mediaType: requireSafeText(file.mediaType, "运行回放证据类型"),
    sizeBytes: requireNonNegativeInteger(file.sizeBytes, "运行回放证据大小"),
    sha256: requireSha256(file.sha256),
    redacted: true,
    sourceStepId: requireNonEmptyString(file.sourceStepId, "运行回放证据步骤"),
  };
}

function normalizeRuntimeFailure(value: RuntimeFailure): RuntimeFailure {
  const failure = requireRecord(value, "运行回放失败摘要");
  requireExactKeys(
    failure,
    ["kind", "summary"],
    ["stepId", "assertionId"],
    "运行回放失败摘要",
  );
  return {
    kind: requireEnum(
      failure.kind,
      [
        "FLOW_ASSERTION_FAILED",
        "LOCATOR_FAILED",
        "DEVICE_UNAVAILABLE",
        "INSTALL_FAILED",
        "APP_CRASHED",
        "APP_FROZEN",
        "EVIDENCE_INCOMPLETE",
        "ENVIRONMENT_FAILED",
        "UNSUPPORTED_DEVICE",
      ] as const,
      "运行回放失败 kind",
    ),
    ...(failure.stepId === undefined
      ? {}
      : { stepId: requireNonEmptyString(failure.stepId, "失败步骤 ID") }),
    ...(failure.assertionId === undefined
      ? {}
      : {
          assertionId: requireNonEmptyString(
            failure.assertionId,
            "失败断言 ID",
          ),
        }),
    summary: requireSafeText(failure.summary, "运行回放失败摘要"),
  };
}

function normalizeRedactionReport(value: unknown): RuntimeRedactionReport {
  const report = requireRecord(value, "运行回放脱敏报告");
  requireExactKeys(
    report,
    ["applied", "totalReplacements", "categories"],
    [],
    "运行回放脱敏报告",
  );
  if (report.applied !== true) {
    throw new TypeError("运行回放脱敏报告 applied 必须是 true。");
  }
  const categories = requireRecord(report.categories, "运行回放脱敏分类");
  const normalizedCategories: Record<string, number> = {};
  for (const [key, count] of Object.entries(categories)) {
    normalizedCategories[requireNonEmptyString(key, "脱敏分类")] =
      requireNonNegativeInteger(count, "脱敏次数");
  }
  return {
    applied: true,
    totalReplacements: requireNonNegativeInteger(
      report.totalReplacements,
      "脱敏总次数",
    ),
    categories: normalizedCategories,
  };
}

function replayStatusFromManifest(
  manifest: RuntimeEvidenceManifest,
): RuntimeFlowRunStatus {
  if (manifest.assertions.some((assertion) => assertion.status === "FAILED")) {
    return "FAILED";
  }
  if (
    manifest.timeline.some((step) => step.status === "FAILED") ||
    manifest.assertions.some((assertion) => assertion.status === "INCOMPLETE")
  ) {
    return "INCOMPLETE";
  }
  return "PASS";
}

function isRuntimeFlowRunResult(
  value: RuntimeFlowRunResult | RuntimeEvidenceManifest,
): value is RuntimeFlowRunResult {
  return isRecordValue(value) && "evidenceManifest" in value;
}

function parseAccountDeletionStubService(
  value: unknown,
): AccountDeletionStubService {
  const service = requireRecord(value, "账号注销测试桩服务");
  requireExactKeys(
    service,
    ["kind", "endpoint", "production"],
    [],
    "账号注销测试桩服务",
  );
  if (service.kind !== "local-recorded-stub") {
    throw new TypeError("账号注销测试桩服务 kind 必须是 local-recorded-stub。");
  }
  if (service.production !== false) {
    throw new TypeError("账号注销测试桩服务不得指向生产环境。");
  }
  const endpoint = requireLocalStubEndpoint(service.endpoint);
  return { kind: "local-recorded-stub", endpoint, production: false };
}

function parseAccountDeletionStubAccount(
  value: unknown,
): AccountDeletionStubAccount {
  const account = requireRecord(value, "账号注销测试桩账号");
  requireExactKeys(account, ["subject", "redacted"], [], "账号注销测试桩账号");
  if (account.redacted !== true) {
    throw new TypeError("账号注销测试桩账号必须标记 redacted=true。");
  }
  const subject = requireSafeText(
    account.subject,
    "账号注销测试桩账号 subject",
  );
  if (!/^[a-z0-9][a-z0-9_.:-]*$/u.test(subject)) {
    throw new TypeError("账号注销测试桩账号 subject 必须是脱敏稳定 ID。");
  }
  return { subject, redacted: true };
}

function parseAccountDeletionStubChecks(
  value: unknown,
): readonly AccountDeletionStubCheck[] {
  if (!Array.isArray(value)) {
    throw new TypeError("账号注销测试桩 checks 必须是数组。");
  }
  const allowedIds: readonly AccountDeletionStubCheckId[] = [
    "delete-request-accepted",
    "old-token-rejected",
    "relogin-rejected",
    "local-data-cleared",
  ];
  const requiredIds = new Set<AccountDeletionStubCheckId>(allowedIds);
  const seen = new Set<string>();
  const checks = value.map((item, index): AccountDeletionStubCheck => {
    const check = requireRecord(item, `账号注销测试桩 checks[${index}]`);
    requireExactKeys(
      check,
      ["id", "status", "summary"],
      [],
      `账号注销测试桩 checks[${index}]`,
    );
    const id = requireEnum(check.id, allowedIds, "账号注销测试桩 check id");
    if (seen.has(id)) {
      throw new TypeError("账号注销测试桩 check id 不得重复。");
    }
    seen.add(id);
    requiredIds.delete(id);
    return {
      id,
      status: requireEnum(
        check.status,
        ["passed", "failed", "evidence_incomplete"] as const,
        "账号注销测试桩 check status",
      ),
      summary: requireSafeText(check.summary, "账号注销测试桩 check summary"),
    };
  });
  if (requiredIds.size > 0) {
    throw new TypeError(
      `账号注销测试桩 checks 缺少 ${[...requiredIds].join("、")}。`,
    );
  }
  return checks;
}

function parseAccountDeletionStubEvidence(
  value: unknown,
): AccountDeletionStubEvidence {
  const evidence = requireRecord(value, "账号注销测试桩 evidence");
  requireExactKeys(
    evidence,
    ["collectedAt", "commands"],
    [],
    "账号注销测试桩 evidence",
  );
  const commands = requireStringArray(
    evidence.commands,
    "账号注销测试桩 commands",
  );
  return {
    collectedAt: requireDateTime(
      evidence.collectedAt,
      "账号注销测试桩采集时间",
    ),
    commands: commands.map((command) =>
      requireSafeText(command, "账号注销测试桩命令"),
    ),
  };
}

function requireLocalStubEndpoint(value: unknown): string {
  const endpoint = requireNonEmptyString(value, "账号注销测试桩 endpoint");
  const allowed =
    endpoint.startsWith("stub://") ||
    /^http:\/\/(?:127\.0\.0\.1|localhost)(?::[0-9]{2,5})?(?:\/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]*)?$/u.test(
      endpoint,
    );
  if (!allowed) {
    throw new TypeError("账号注销测试桩 endpoint 必须是本地测试桩地址。");
  }
  return endpoint;
}

function requireSafeText(value: unknown, label: string): string {
  const text = requireNonEmptyString(value, label);
  const redacted = redactRuntimeText(text);
  if (redacted.report.totalReplacements > 0) {
    throw new TypeError(`${label} 必须是脱敏文本。`);
  }
  return text;
}

function requireSafeTextArray(
  value: unknown,
  label: string,
): readonly string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new TypeError(`${label} 必须是非空数组。`);
  }
  return value.map((item) => requireSafeText(item, label));
}

function assertSafeRuntimeContractText(value: unknown, label: string): void {
  const text = JSON.stringify(value);
  if (text === undefined) throw new TypeError(`${label} 必须可序列化。`);
  if (redactRuntimeText(text).report.totalReplacements > 0) {
    throw new TypeError(`${label} 必须只包含脱敏文本。`);
  }
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} 必须是对象。`);
  }
  return value as Record<string, unknown>;
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${label} 必须是数组。`);
  }
  return value;
}

function requireExactKeys(
  record: Readonly<Record<string, unknown>>,
  required: readonly string[],
  optional: readonly string[],
  label: string,
): void {
  const allowed = new Set([...required, ...optional]);
  for (const key of required) {
    if (!(key in record)) throw new TypeError(`${label} 缺少 ${key}。`);
  }
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new TypeError(`${label} 包含未知字段。`);
  }
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label} 必须是非空字符串。`);
  }
  return value;
}

function requirePattern(
  value: unknown,
  pattern: RegExp,
  label: string,
): string {
  const text = requireNonEmptyString(value, label);
  if (!pattern.test(text)) throw new TypeError(`${label} 格式无效。`);
  return text;
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean")
    throw new TypeError(`${label} 必须是布尔值。`);
  return value;
}

function requirePositiveInteger(value: unknown, label: string): number {
  return requireIntegerRange(value, 1, Number.MAX_SAFE_INTEGER, label);
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  return requireIntegerRange(value, 0, Number.MAX_SAFE_INTEGER, label);
}

function requireIntegerRange(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new TypeError(`${label} 必须是 ${minimum} 到 ${maximum} 的整数。`);
  }
  return value;
}

function requireEnum<const Values extends readonly string[]>(
  value: unknown,
  values: Values,
  label: string,
): Values[number] {
  if (typeof value !== "string" || !values.includes(value)) {
    throw new TypeError(`${label} 必须是允许值之一。`);
  }
  return value as Values[number];
}

function requireStringArray(value: unknown, label: string): readonly string[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} 必须是数组。`);
  return value.map((item) => requireNonEmptyString(item, label));
}

function requireSafePath(value: unknown, label: string): string {
  const text = requireNonEmptyString(value, label).replaceAll("\\", "/");
  if (
    text.startsWith("/") ||
    text.startsWith("./") ||
    /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(text) ||
    text.includes("//") ||
    text === ".." ||
    text.startsWith("../") ||
    text.includes("/../")
  ) {
    throw new TypeError(`${label} 必须是安全仓库相对路径。`);
  }
  return text;
}

function requireSafeSegment(value: unknown, label: string): string {
  return requirePattern(value, /^[A-Za-z0-9][A-Za-z0-9_.-]*$/u, label);
}

function requireSha256(value: unknown): `sha256:${string}` {
  const text = requirePattern(value, /^sha256:[a-f0-9]{64}$/u, "SHA-256");
  return text as `sha256:${string}`;
}

function requireDateTime(value: unknown, label: string): string {
  return requirePattern(
    value,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:[0-5]\d(?:\.\d+)?Z$/u,
    label,
  );
}

function emptyRedactionReport(): RuntimeRedactionReport {
  return { applied: true, totalReplacements: 0, categories: {} };
}

function redactionReport(
  categories: Readonly<Record<string, number>>,
): RuntimeRedactionReport {
  const normalized = Object.fromEntries(
    Object.entries(categories)
      .filter(([, count]) => count > 0)
      .sort(([left], [right]) => compareCodePoints(left, right)),
  );
  return {
    applied: true,
    totalReplacements: Object.values(normalized).reduce(
      (total, count) => total + count,
      0,
    ),
    categories: normalized,
  };
}

function mergeRedactionReports(
  left: RuntimeRedactionReport,
  right: RuntimeRedactionReport,
): RuntimeRedactionReport {
  const categories: Record<string, number> = {};
  for (const [key, count] of Object.entries(left.categories)) {
    categories[key] = (categories[key] ?? 0) + count;
  }
  for (const [key, count] of Object.entries(right.categories)) {
    categories[key] = (categories[key] ?? 0) + count;
  }
  return redactionReport(categories);
}

function replaceAndCount(
  input: string,
  pattern: RegExp,
  replacement:
    string | ((substring: string, ...args: readonly unknown[]) => string),
  category: string,
  categories: Record<string, number>,
): string {
  let count = 0;
  const output = input.replace(pattern, (...args) => {
    count += 1;
    return typeof replacement === "string"
      ? replacement
      : replacement(args[0] as string, ...args.slice(1));
  });
  if (count > 0) categories[category] = (categories[category] ?? 0) + count;
  return output;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(
    left,
    (character) => character.codePointAt(0) as number,
  );
  const rightPoints = Array.from(
    right,
    (character) => character.codePointAt(0) as number,
  );
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference =
      (leftPoints[index] as number) - (rightPoints[index] as number);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const property of Object.values(value)) {
      deepFreeze(property);
    }
    Object.freeze(value);
  }
  return value;
}
