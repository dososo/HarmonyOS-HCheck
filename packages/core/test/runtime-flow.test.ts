import { createHash } from "node:crypto";
import assert from "node:assert/strict";
import test from "node:test";
import {
  buildRuntimeReplay,
  createAccountDeleteRuntimeFlow,
  createPermissionDenyRuntimeFlow,
  createPrivacyRefuseRuntimeFlow,
  createRecordedDevicePort,
  parseRuntimeFlowDefinition,
  redactRuntimeText,
  runRuntimeFlow,
  validateAccountDeletionStubContract,
  type RuntimeDeviceInfo,
  type RuntimeDevicePort,
  type RuntimeEvidenceWriteRequest,
  type RuntimeEvidenceWriterPort,
  type RuntimeFlowDefinition,
  type RuntimeFlowRunOptions,
  type RuntimeHashPort,
  type RuntimeTimingPort,
} from "../src/index.js";

const SHA_A = `sha256:${"a".repeat(64)}` as const;
const hash: RuntimeHashPort = {
  async sha256(content) {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  },
};
const defaultTiming: RuntimeTimingPort = {
  async sleep() {},
  now() {
    return "2026-07-11T00:00:01Z";
  },
};
const noOpEvidenceWriter: RuntimeEvidenceWriterPort = {
  async write() {},
};

function createRunOptions(
  overrides: Partial<RuntimeFlowRunOptions> = {},
): RuntimeFlowRunOptions {
  return {
    runId: "run-test",
    hcheckVersion: "0.6.0",
    rulePackVersion: "hcheck-p0@0.6.0",
    deviceId: "raw-device",
    artifact: {
      uri: "artifacts/app.hap",
      sha256: SHA_A,
      bundleName: "com.example.app",
    },
    startedAt: "2026-07-11T00:00:00Z",
    hash,
    timing: defaultTiming,
    evidenceWriter: noOpEvidenceWriter,
    ...overrides,
  };
}

function createTestFlow({
  id,
  steps = [{ id: "finish", action: "checkpoint" }],
  assertions = [{ id: "after-all", type: "all_ok" }],
  evidence = { screenshot: "never", video: "never", hilog: false },
}: {
  readonly id: string;
  readonly steps?: RuntimeFlowDefinition["steps"];
  readonly assertions?: RuntimeFlowDefinition["assertions"];
  readonly evidence?: RuntimeFlowDefinition["evidence"];
}): RuntimeFlowDefinition {
  return parseRuntimeFlowDefinition({
    id,
    version: 1,
    name: id,
    requires: {},
    steps,
    assertions,
    evidence,
  });
}

function createTestDevice(
  overrides: Partial<RuntimeDeviceInfo> = {},
): RuntimeDeviceInfo {
  return {
    id: "raw-device",
    redactedId: "device:test",
    kind: "unknown",
    model: "Runtime Test",
    osVersion: "HarmonyOS NEXT test",
    capabilities: [],
    ...overrides,
  };
}

function createEventRecordingDevice(
  events: string[],
  failedAssertionId?: string,
): RuntimeDevicePort {
  return {
    async listDevices() {
      return [createTestDevice()];
    },
    async performStep({ step }) {
      events.push(`step:${step.id}`);
      return { status: "ok", summary: `${step.id} 通过。` };
    },
    async evaluateAssertion({ assertion }) {
      events.push(`assertion:${assertion.id}`);
      return assertion.id === failedAssertionId
        ? { status: "failed", summary: "断言失败。" }
        : { status: "passed", summary: "断言通过。" };
    },
  };
}

test("Runtime Flow 解析校验示例流程并拒绝重复步骤和悬空断言", () => {
  const flow = parseRuntimeFlowDefinition(createPrivacyRefuseRuntimeFlow());

  assert.equal(flow.id, "privacy-refuse");
  assert.equal(flow.requires.network_observation, "metadata_only");
  assert.ok(flow.steps.some((step) => step.id === "checkpoint-before-choice"));
  assert.throws(
    () =>
      parseRuntimeFlowDefinition({
        ...flow,
        steps: [
          { id: "launch", action: "launch" },
          { id: "launch", action: "checkpoint" },
        ],
      }),
    /步骤 ID 不得重复/u,
  );
  assert.throws(
    () =>
      parseRuntimeFlowDefinition({
        ...flow,
        assertions: [
          {
            id: "dangling",
            type: "app_not_crashed",
            after_step: "missing-step",
            severity: "BLOCKER",
          },
        ],
      }),
    /after_step 必须引用已定义步骤/u,
  );
});

test("录制 DevicePort 执行 Runtime Flow 时保留重试、状态时间线和脱敏证据清单", async () => {
  const flow = createPrivacyRefuseRuntimeFlow();
  const device = createRecordedDevicePort({
    devices: [
      {
        id: "RAW-SERIAL-123456",
        redactedId: "device:1",
        kind: "physical",
        model: "Mate Test",
        osVersion: "HarmonyOS NEXT test",
        capabilities: ["screenshot", "hilog"],
      },
    ],
    steps: {
      "wait-dialog": [
        { status: "locator_failed", summary: "首次未定位到隐私弹窗。" },
        { status: "ok", summary: "第二次定位到隐私弹窗。" },
      ],
      "wait-after-reject": [
        {
          status: "ok",
          summary: "拒绝后应用保持运行。",
          evidence: [
            {
              kind: "hilog",
              path: "hilog/privacy-refuse.log",
              mediaType: "text/plain",
              content:
                "HiLog 录制样本：token=abc123 password=hunter2 path=/Users/dev/project RAW-SERIAL-123456",
            },
          ],
        },
      ],
    },
    assertions: {
      "no-permission-before-consent": {
        status: "passed",
        summary: "同意前未出现敏感权限弹窗。",
      },
      "no-network-before-consent": {
        status: "passed",
        summary: "同意前未发现敏感网络元数据。",
      },
      "not-crashed": { status: "passed", summary: "应用未崩溃。" },
    },
  });

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      runId: "run-001",
      deviceId: "RAW-SERIAL-123456",
      artifact: {
        uri: "artifacts/app.hap",
        sha256: SHA_A,
        bundleName: "com.example.app",
        versionName: "1.0.0",
        versionCode: 1,
      },
    }),
  );

  assert.equal(result.status, "PASS");
  assert.equal(result.evidenceManifest.device.id, "device:1");
  assert.equal(result.evidenceManifest.files.length, 1);
  assert.equal(result.evidenceManifest.files[0]?.redacted, true);
  assert.equal(
    result.timeline.find((step) => step.stepId === "wait-dialog")?.attempts,
    2,
  );
  assert.deepEqual(
    device.history
      .filter((entry) => entry.stepId === "wait-dialog")
      .map((entry) => entry.attempt),
    [1, 2],
  );
  const serialized = JSON.stringify(result);
  assert.ok(!serialized.includes("RAW-SERIAL-123456"));
  assert.ok(!serialized.includes("abc123"));
  assert.ok(!serialized.includes("hunter2"));
  assert.ok(!serialized.includes("/Users/dev/project"));
});

test("Runtime Flow 状态机区分业务断言失败和环境失败", async () => {
  const flow = createPrivacyRefuseRuntimeFlow();
  const assertionFailed = createRecordedDevicePort({
    devices: [
      {
        id: "raw-device",
        redactedId: "device:1",
        kind: "emulator",
        model: "Test",
        osVersion: "HarmonyOS NEXT test",
        capabilities: ["screenshot", "hilog"],
      },
    ],
    assertions: {
      "no-permission-before-consent": {
        status: "failed",
        summary: "同意前出现敏感权限弹窗。",
      },
    },
  });

  const failed = await runRuntimeFlow(
    flow,
    assertionFailed,
    createRunOptions({
      runId: "run-assertion",
    }),
  );

  assert.equal(failed.status, "FAILED");
  assert.equal(failed.failure?.kind, "FLOW_ASSERTION_FAILED");

  const environmentFailed = createRecordedDevicePort({
    devices: [
      {
        id: "raw-device",
        redactedId: "device:1",
        kind: "emulator",
        model: "Test",
        osVersion: "HarmonyOS NEXT test",
        capabilities: ["screenshot", "hilog"],
      },
    ],
    steps: {
      launch: [{ status: "environment_failed", summary: "HDC 连接断开。" }],
    },
  });

  const incomplete = await runRuntimeFlow(
    flow,
    environmentFailed,
    createRunOptions({
      runId: "run-env",
    }),
  );

  assert.equal(incomplete.status, "INCOMPLETE");
  assert.equal(incomplete.failure?.kind, "ENVIRONMENT_FAILED");
});

test("权限拒绝本地流程合同可校验且统一脱敏不保留秘密原文", () => {
  const flow = parseRuntimeFlowDefinition(createPermissionDenyRuntimeFlow());
  assert.equal(flow.id, "permission-deny");
  assert.ok(flow.steps.some((step) => step.action === "set_permission"));
  assert.ok(
    flow.assertions.some((assertion) => assertion.type === "app_not_crashed"),
  );

  const redacted = redactRuntimeText(
    "Authorization=Bearer abc password=secret reviewer@example.com C:\\Users\\dev\\project",
    { extraSecrets: ["Bearer abc"] },
  );
  assert.equal(redacted.report.applied, true);
  assert.ok(redacted.report.totalReplacements >= 4);
  assert.ok(!redacted.text.includes("Bearer abc"));
  assert.ok(!redacted.text.includes("secret"));
  assert.ok(!redacted.text.includes("reviewer@example.com"));
  assert.ok(!redacted.text.includes("C:\\Users\\dev\\project"));
});

test("账号注销测试桩流程只定义本地合同且不冒充真实账号注销", () => {
  const flow = parseRuntimeFlowDefinition(createAccountDeleteRuntimeFlow());

  assert.equal(flow.id, "account-delete");
  assert.equal(flow.requires.test_account, true);
  assert.equal(flow.requires.network_observation, "metadata_only");
  assert.ok(flow.requires.device_capabilities?.includes("test_account_stub"));
  assert.deepEqual(
    flow.steps
      .filter((step) => step.action === "invoke_test_hook")
      .map((step) => step.id),
    [
      "prepare-account-stub",
      "login-test-account",
      "request-account-delete",
      "verify-old-token-rejected",
      "verify-relogin-rejected",
    ],
  );
  assert.ok(
    flow.assertions.some(
      (assertion) => assertion.type === "old_token_invalidated",
    ),
  );
  assert.ok(
    flow.assertions.some(
      (assertion) => assertion.type === "relogin_after_delete_rejected",
    ),
  );
  assert.equal(flow.evidence.network_timeline, "metadata_only");
});

test("账号注销测试桩合同只接受脱敏本地录制服务摘要", () => {
  const contract = validateAccountDeletionStubContract({
    schemaVersion: "1.0.0",
    fixtureId: "F007",
    flowId: "account-delete",
    evidenceKind: "account-deletion-stub-contract",
    status: "local_contract",
    runtimeConfirmed: false,
    redacted: true,
    service: {
      kind: "local-recorded-stub",
      endpoint: "http://127.0.0.1:18080/account-delete-stub",
      production: false,
    },
    account: {
      subject: "fixture-account-001",
      redacted: true,
    },
    checks: [
      {
        id: "delete-request-accepted",
        status: "passed",
        summary: "本地测试桩接受注销请求。",
      },
      {
        id: "old-token-rejected",
        status: "passed",
        summary: "旧会话摘要被本地测试桩拒绝。",
      },
      {
        id: "relogin-rejected",
        status: "passed",
        summary: "注销后重新登录被本地测试桩拒绝。",
      },
      {
        id: "local-data-cleared",
        status: "passed",
        summary: "本地缓存摘要已清理。",
      },
    ],
    evidence: {
      collectedAt: "2026-07-11T00:00:00Z",
      commands: [
        "pnpm schema:check",
        "pnpm --filter @hcheck/core test -- test/runtime-flow.test.ts",
      ],
    },
    boundaries: ["仅使用本地录制测试桩，不访问真实账号、生产服务或 AGC。"],
  });

  assert.equal(contract.status, "local_contract");
  assert.equal(contract.runtimeConfirmed, false);
  assert.equal(Object.isFrozen(contract.checks), true);
  const serialized = JSON.stringify(contract);
  assert.ok(!serialized.includes("password"));
  assert.ok(!serialized.includes("token="));
  assert.ok(!serialized.includes("@example.com"));
});

test("账号注销测试桩合同拒绝生产端点、账号明文、秘密和绝对路径", () => {
  const base = {
    schemaVersion: "1.0.0",
    fixtureId: "F007",
    flowId: "account-delete",
    evidenceKind: "account-deletion-stub-contract",
    status: "local_contract",
    runtimeConfirmed: false,
    redacted: true,
    service: {
      kind: "local-recorded-stub",
      endpoint: "http://127.0.0.1:18080/account-delete-stub",
      production: false,
    },
    account: { subject: "fixture-account-001", redacted: true },
    checks: [
      { id: "delete-request-accepted", status: "passed", summary: "ok" },
      { id: "old-token-rejected", status: "passed", summary: "ok" },
      { id: "relogin-rejected", status: "passed", summary: "ok" },
      { id: "local-data-cleared", status: "passed", summary: "ok" },
    ],
    evidence: {
      collectedAt: "2026-07-11T00:00:00Z",
      commands: [
        "pnpm schema:check",
        "pnpm --filter @hcheck/core test -- test/runtime-flow.test.ts",
      ],
    },
    boundaries: ["不访问生产服务。"],
  };

  for (const unsafe of [
    {
      ...base,
      service: { ...base.service, endpoint: "https://api.example.com" },
    },
    { ...base, service: { ...base.service, production: true } },
    { ...base, account: { subject: "reviewer@example.com", redacted: true } },
    { ...base, runtimeConfirmed: true },
    {
      ...base,
      checks: [
        ...base.checks.slice(0, 1),
        {
          id: "old-token-rejected",
          status: "passed",
          summary: "token=abc123",
        },
        ...base.checks.slice(2),
      ],
    },
    {
      ...base,
      evidence: {
        ...base.evidence,
        commands: ["/Users/dev/run-account-delete.sh"],
      },
    },
  ]) {
    assert.throws(
      () => validateAccountDeletionStubContract(unsafe),
      /本地|脱敏|生产|真实|路径|runtimeConfirmed/u,
    );
  }
});

test("运行回放从 Runtime Flow 结果生成只读时间线和证据摘要", async () => {
  const flow = createAccountDeleteRuntimeFlow();
  const device = createRecordedDevicePort({
    devices: [
      {
        id: "RAW-ACCOUNT-DEVICE",
        redactedId: "device:account-stub",
        kind: "physical",
        model: "Replay Test",
        osVersion: "HarmonyOS NEXT test",
        capabilities: ["screenshot", "hilog", "test_account_stub"],
      },
    ],
    steps: {
      "request-account-delete": [
        {
          status: "ok",
          summary: "本地测试桩接受注销请求。",
          evidence: [
            {
              kind: "hilog",
              path: "hilog/account-delete.log",
              mediaType: "text/plain",
              content: "HiLog 录制样本：本地测试桩记录旧会话摘要被拒绝。",
            },
          ],
        },
      ],
    },
    assertions: {
      "delete-request-accepted": {
        status: "passed",
        summary: "注销请求已被本地测试桩接受。",
      },
      "old-token-rejected": {
        status: "passed",
        summary: "旧会话摘要已被拒绝。",
      },
      "relogin-rejected": {
        status: "passed",
        summary: "重新登录已被拒绝。",
      },
      "local-data-cleared": {
        status: "passed",
        summary: "本地数据已清理。",
      },
      "not-crashed": { status: "passed", summary: "应用未崩溃。" },
    },
  });
  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      runId: "run-replay",
      deviceId: "RAW-ACCOUNT-DEVICE",
      artifact: {
        uri: "artifacts/account-delete.hap",
        sha256: SHA_A,
        bundleName: "com.example.account",
      },
    }),
  );

  const replay = buildRuntimeReplay(result);

  assert.equal(replay.schemaVersion, "1.0.0");
  assert.equal(replay.readOnly, true);
  assert.equal(replay.runId, "run-replay");
  assert.equal(replay.status, "PASS");
  assert.equal(replay.summary.totalSteps, flow.steps.length);
  assert.equal(replay.summary.evidenceFiles, 1);
  assert.equal(replay.timeline[0]?.stepId, "install");
  assert.equal(replay.evidenceFiles[0]?.path, "hilog/account-delete.log");
  assert.equal(Object.isFrozen(replay.timeline), true);
  assert.ok(!JSON.stringify(replay).includes("RAW-ACCOUNT-DEVICE"));
});

test("运行回放拒绝不安全或未脱敏的运行证据", async () => {
  const flow = createPermissionDenyRuntimeFlow();
  const device = createRecordedDevicePort({
    devices: [
      {
        id: "raw-device",
        redactedId: "device:1",
        kind: "harmonyos_pc",
        model: "Replay",
        osVersion: "HarmonyOS NEXT test",
        capabilities: ["screenshot", "permission"],
      },
    ],
  });
  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      runId: "run-unsafe-replay",
      artifact: { uri: "artifacts/app.hap", sha256: SHA_A, bundleName: "demo" },
    }),
  );

  assert.throws(
    () =>
      buildRuntimeReplay({
        ...result,
        evidenceManifest: {
          ...result.evidenceManifest,
          device: { ...result.evidenceManifest.device, id: "RAW-SERIAL" },
        },
      }),
    /脱敏|设备/u,
  );
  assert.throws(
    () =>
      buildRuntimeReplay({
        ...result,
        evidenceManifest: {
          ...result.evidenceManifest,
          files: [
            {
              path: "/Users/dev/runtime.log",
              mediaType: "text/plain",
              sizeBytes: 10,
              sha256: SHA_A,
              redacted: true,
              sourceStepId: "launch",
            },
          ],
        },
      }),
    /路径/u,
  );
});

test("目标设备不存在时返回脱敏 DEVICE_UNAVAILABLE 结果和 unknown 设备清单", async () => {
  const result = await runRuntimeFlow(
    createTestFlow({ id: "missing-device" }),
    createRecordedDevicePort({ devices: [] }),
    createRunOptions({
      runId: "run-device-unavailable",
      deviceId: "RAW-MISSING-DEVICE",
    }),
  );

  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.failure?.kind, "DEVICE_UNAVAILABLE");
  assert.deepEqual(result.evidenceManifest.device, {
    id: "device:unavailable",
    kind: "unknown",
    model: "unknown",
    osVersion: "unknown",
    capabilities: [],
  });
  assert.equal(
    result.evidenceManifest.archiveRoot,
    ".hcheck/evidence/run-device-unavailable",
  );
  assert.equal(buildRuntimeReplay(result).device.kind, "unknown");
  assert.ok(!JSON.stringify(result).includes("RAW-MISSING-DEVICE"));
});

test("after_step 断言紧随对应成功步骤执行且失败后立即停止", async () => {
  const events: string[] = [];
  const flow = createTestFlow({
    id: "assertion-order",
    steps: [
      { id: "first", action: "checkpoint" },
      { id: "second", action: "checkpoint" },
      { id: "third", action: "checkpoint" },
    ],
    assertions: [
      { id: "after-first", type: "first_ok", after_step: "first" },
      { id: "after-second", type: "second_ok", after_step: "second" },
      { id: "after-third", type: "third_ok", after_step: "third" },
      { id: "after-all", type: "all_ok" },
    ],
  });
  const device = createEventRecordingDevice(events, "after-second");

  const result = await runRuntimeFlow(flow, device, createRunOptions());

  assert.equal(result.status, "FAILED");
  assert.equal(result.failure?.assertionId, "after-second");
  assert.deepEqual(events, [
    "step:first",
    "assertion:after-first",
    "step:second",
    "assertion:after-second",
  ]);
});

test("无 after_step 的断言只在所有步骤及已到达断言完成后执行", async () => {
  const events: string[] = [];
  const flow = createTestFlow({
    id: "final-assertion-order",
    steps: [
      { id: "first", action: "checkpoint" },
      { id: "second", action: "checkpoint" },
    ],
    assertions: [
      { id: "after-first", type: "first_ok", after_step: "first" },
      { id: "after-all", type: "all_ok" },
    ],
  });
  const device = createEventRecordingDevice(events);

  const result = await runRuntimeFlow(flow, device, createRunOptions());

  assert.equal(result.status, "PASS");
  assert.deepEqual(events, [
    "step:first",
    "assertion:after-first",
    "step:second",
    "assertion:after-all",
  ]);
});

test("步骤失败后不执行其 after_step 断言、后续步骤和末尾断言", async () => {
  const events: string[] = [];
  const flow = createTestFlow({
    id: "failed-step-stops-flow",
    steps: [
      { id: "first", action: "checkpoint" },
      { id: "second", action: "checkpoint" },
    ],
    assertions: [
      { id: "after-first", type: "first_ok", after_step: "first" },
      { id: "after-all", type: "all_ok" },
    ],
  });
  const device: RuntimeDevicePort = {
    async listDevices() {
      return [createTestDevice()];
    },
    async performStep({ step }) {
      events.push(`step:${step.id}`);
      return {
        status: "environment_failed",
        summary: "步骤执行失败。",
      };
    },
    async evaluateAssertion({ assertion }) {
      events.push(`assertion:${assertion.id}`);
      return { status: "passed", summary: "不应执行。" };
    },
  };

  const result = await runRuntimeFlow(flow, device, createRunOptions());

  assert.equal(result.failure?.kind, "ENVIRONMENT_FAILED");
  assert.deepEqual(events, ["step:first"]);
});

test("运行元数据和所选设备元数据无效时不执行设备步骤或写证据", async () => {
  const flow = createTestFlow({
    id: "invalid-runtime-metadata",
    steps: [{ id: "capture", action: "checkpoint" }],
  });
  const cases: readonly {
    readonly name: string;
    readonly device: RuntimeDeviceInfo;
    readonly options: Partial<RuntimeFlowRunOptions>;
  }[] = [
    {
      name: "空 HCheck 版本",
      device: createTestDevice(),
      options: { hcheckVersion: "" },
    },
    {
      name: "非法产物路径",
      device: createTestDevice(),
      options: {
        artifact: {
          uri: "/tmp/app.hap",
          sha256: SHA_A,
          bundleName: "com.example.app",
        },
      },
    },
    {
      name: "非法设备 kind",
      device: createTestDevice({
        kind: "invalid" as RuntimeDeviceInfo["kind"],
      }),
      options: {},
    },
    {
      name: "未脱敏设备 ID",
      device: createTestDevice({ redactedId: "RAW-DEVICE-ID" }),
      options: {},
    },
    {
      name: "含秘密的设备型号",
      device: createTestDevice({ model: "token=model-secret" }),
      options: {},
    },
    {
      name: "含秘密的系统版本",
      device: createTestDevice({ osVersion: "password=os-secret" }),
      options: {},
    },
    {
      name: "含秘密的设备能力",
      device: createTestDevice({ capabilities: ["token=capability-secret"] }),
      options: {},
    },
  ];

  for (const testCase of cases) {
    let stepCalls = 0;
    let writes = 0;
    const device: RuntimeDevicePort = {
      async listDevices() {
        return [testCase.device];
      },
      async performStep() {
        stepCalls += 1;
        return {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "hilog",
              path: "captures/hilog.txt",
              mediaType: "text/plain",
              content: "安全内容",
            },
          ],
        };
      },
      async evaluateAssertion() {
        return { status: "passed", summary: "断言通过。" };
      },
    };

    await assert.rejects(
      () =>
        runRuntimeFlow(
          flow,
          device,
          createRunOptions({
            ...testCase.options,
            evidenceWriter: {
              async write() {
                writes += 1;
              },
            },
          }),
        ),
      undefined,
      testCase.name,
    );
    assert.equal(stepCalls, 0, `${testCase.name} 不得执行设备步骤`);
    assert.equal(writes, 0, `${testCase.name} 不得写证据`);
  }
});

test("设备步骤和断言使用预先规范化的 artifact", async () => {
  const receivedUris: string[] = [];
  const device: RuntimeDevicePort = {
    async listDevices() {
      return [createTestDevice()];
    },
    async performStep({ artifact }) {
      receivedUris.push(artifact.uri);
      return { status: "ok", summary: "步骤通过。" };
    },
    async evaluateAssertion({ artifact }) {
      receivedUris.push(artifact.uri);
      return { status: "passed", summary: "断言通过。" };
    },
  };

  const result = await runRuntimeFlow(
    createTestFlow({ id: "normalized-artifact" }),
    device,
    createRunOptions({
      artifact: {
        uri: "artifacts\\app.hap",
        sha256: SHA_A,
        bundleName: "com.example.app",
      },
    }),
  );

  assert.equal(result.status, "PASS");
  assert.deepEqual(receivedUris, ["artifacts/app.hap", "artifacts/app.hap"]);
});

test("只有 locator_failed 按 backoff 重试且完成时间来自 timing.now", async () => {
  const flow = createTestFlow({
    id: "retry-timing",
    steps: [
      {
        id: "locate",
        action: "wait_for",
        retry: { max_attempts: 3, backoff_ms: 250 },
      },
    ],
  });
  const locatorDevice = createRecordedDevicePort({
    devices: [createTestDevice({ kind: "emulator" })],
    steps: {
      locate: [
        { status: "locator_failed", summary: "第一次定位失败。" },
        { status: "locator_failed", summary: "第二次定位失败。" },
        { status: "locator_failed", summary: "第三次定位失败。" },
      ],
    },
  });
  const sleeps: number[] = [];
  const completedAt = "2026-07-11T00:00:02Z";
  const timing: RuntimeTimingPort = {
    async sleep(milliseconds) {
      sleeps.push(milliseconds);
    },
    now() {
      return completedAt;
    },
  };

  const locatorResult = await runRuntimeFlow(
    flow,
    locatorDevice,
    createRunOptions({ timing }),
  );

  assert.deepEqual(
    locatorDevice.history.map((entry) => entry.attempt),
    [1, 2, 3],
  );
  assert.deepEqual(sleeps, [250, 250]);
  assert.equal(locatorResult.evidenceManifest.completedAt, completedAt);
  assert.notEqual(
    locatorResult.evidenceManifest.completedAt,
    locatorResult.evidenceManifest.startedAt,
  );
  assert.ok(
    Date.parse(locatorResult.evidenceManifest.completedAt) >=
      Date.parse(locatorResult.evidenceManifest.startedAt),
  );

  const nonLocatorDevice = createRecordedDevicePort({
    devices: [createTestDevice({ kind: "physical" })],
    steps: {
      locate: [
        { status: "install_failed", summary: "安装失败。" },
        { status: "ok", summary: "不应执行的第二次尝试。" },
      ],
    },
  });
  sleeps.length = 0;

  const nonLocatorResult = await runRuntimeFlow(
    flow,
    nonLocatorDevice,
    createRunOptions({ timing }),
  );

  assert.equal(nonLocatorResult.failure?.kind, "INSTALL_FAILED");
  assert.deepEqual(
    nonLocatorDevice.history.map((entry) => entry.attempt),
    [1],
  );
  assert.deepEqual(sleeps, []);
});

test("timing.now 早于 startedAt 时归一完成时间并返回环境不完整", async () => {
  const startedAt = "2026-07-11T00:00:00Z";
  let writes = 0;
  const result = await runRuntimeFlow(
    createTestFlow({
      id: "reversed-timing",
      steps: [{ id: "capture", action: "checkpoint" }],
    }),
    createRecordedDevicePort({
      devices: [createTestDevice()],
      steps: {
        capture: [
          {
            status: "ok",
            summary: "采集完成。",
            evidence: [
              {
                kind: "hilog",
                path: "captures/hilog.txt",
                mediaType: "text/plain",
                content: "安全内容",
              },
            ],
          },
        ],
      },
    }),
    createRunOptions({
      startedAt,
      evidenceWriter: {
        async write() {
          writes += 1;
        },
      },
      timing: {
        async sleep() {},
        now() {
          return "2026-07-10T23:59:59Z";
        },
      },
    }),
  );

  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.failure?.kind, "ENVIRONMENT_FAILED");
  assert.equal(result.evidenceManifest.completedAt, startedAt);
  assert.equal(writes, 0);
  assert.deepEqual(result.evidenceManifest.files, []);
  assert.ok(
    Date.parse(result.evidenceManifest.completedAt) >=
      Date.parse(result.evidenceManifest.startedAt),
  );
});

test("timing.now 非法或抛错时零写入并返回不泄密的环境不完整", async () => {
  const flow = createTestFlow({
    id: "invalid-completed-at",
    steps: [{ id: "capture", action: "checkpoint" }],
  });
  const startedAt = "2026-07-11T00:00:00Z";
  const timingPorts: readonly RuntimeTimingPort[] = [
    {
      async sleep() {},
      now() {
        return "token=timing-secret";
      },
    },
    {
      async sleep() {},
      now() {
        throw new Error("password=clock-secret");
      },
    },
  ];

  for (const timing of timingPorts) {
    let writes = 0;
    const device = createRecordedDevicePort({
      devices: [createTestDevice()],
      steps: {
        capture: [
          {
            status: "ok",
            summary: "采集完成。",
            evidence: [
              {
                kind: "hilog",
                path: "captures/hilog.txt",
                mediaType: "text/plain",
                content: "安全内容",
              },
            ],
          },
        ],
      },
    });

    const result = await runRuntimeFlow(
      flow,
      device,
      createRunOptions({
        startedAt,
        timing,
        evidenceWriter: {
          async write() {
            writes += 1;
          },
        },
      }),
    );

    assert.equal(result.status, "INCOMPLETE");
    assert.equal(result.failure?.kind, "ENVIRONMENT_FAILED");
    assert.equal(result.evidenceManifest.completedAt, startedAt);
    assert.equal(writes, 0);
    assert.deepEqual(result.evidenceManifest.files, []);
    const serialized = JSON.stringify(result);
    assert.ok(!serialized.includes("timing-secret"));
    assert.ok(!serialized.includes("clock-secret"));
  }
});

test("timing.now 失败不覆盖已经发生的业务或步骤失败", async () => {
  const timing: RuntimeTimingPort = {
    async sleep() {},
    now() {
      return "invalid-completed-at";
    },
  };
  const assertionFlow = createTestFlow({
    id: "assertion-before-timing-failure",
    assertions: [{ id: "business-check", type: "business_ok" }],
  });
  const assertionResult = await runRuntimeFlow(
    assertionFlow,
    createRecordedDevicePort({
      devices: [createTestDevice()],
      assertions: {
        "business-check": {
          status: "failed",
          summary: "业务断言失败。",
        },
      },
    }),
    createRunOptions({ timing }),
  );

  assert.equal(assertionResult.status, "FAILED");
  assert.equal(assertionResult.failure?.kind, "FLOW_ASSERTION_FAILED");

  const stepFlow = createTestFlow({ id: "step-before-timing-failure" });
  const stepResult = await runRuntimeFlow(
    stepFlow,
    createRecordedDevicePort({
      devices: [createTestDevice()],
      steps: {
        finish: [{ status: "app_crashed", summary: "应用崩溃。" }],
      },
    }),
    createRunOptions({ timing }),
  );

  assert.equal(stepResult.status, "FAILED");
  assert.equal(stepResult.failure?.kind, "APP_CRASHED");
});

test("hilog 证据按显式 kind 判定并以脱敏字节写入新归档目录", async () => {
  const flow = createTestFlow({
    id: "hilog-evidence",
    steps: [{ id: "capture", action: "checkpoint" }],
    evidence: { screenshot: "never", video: "never", hilog: true },
  });
  const device = createRecordedDevicePort({
    devices: [
      createTestDevice({
        id: "RAW-EVIDENCE-DEVICE",
        redactedId: "device:evidence",
        kind: "physical",
      }),
    ],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "hilog",
              path: "captures/runtime.bin",
              mediaType: "application/octet-stream",
              content: "token=abc123 RAW-EVIDENCE-DEVICE",
            },
          ],
        },
      ],
    },
  });
  const requests: RuntimeEvidenceWriteRequest[] = [];
  const evidenceWriter: RuntimeEvidenceWriterPort = {
    async write(request) {
      requests.push(request);
    },
  };

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      runId: "run-hilog-evidence",
      deviceId: "RAW-EVIDENCE-DEVICE",
      evidenceWriter,
    }),
  );

  assert.equal(result.status, "PASS");
  assert.equal(requests.length, 1);
  const request = requests[0] as RuntimeEvidenceWriteRequest;
  assert.equal(request.archiveRoot, ".hcheck/evidence/run-hilog-evidence");
  assert.equal(request.relativePath, "captures/runtime.bin");
  const written = new TextDecoder().decode(request.bytes);
  assert.ok(!written.includes("abc123"));
  assert.ok(!written.includes("RAW-EVIDENCE-DEVICE"));
  assert.equal(
    result.evidenceManifest.files[0]?.sizeBytes,
    request.bytes.length,
  );
  assert.equal(
    result.evidenceManifest.files[0]?.sha256,
    await hash.sha256(request.bytes),
  );
});

test("零 Hilog 收敛为证据不完整且业务断言失败优先", async () => {
  const flow = createTestFlow({
    id: "missing-hilog",
    steps: [{ id: "capture", action: "checkpoint" }],
    assertions: [{ id: "business-check", type: "business_ok" }],
    evidence: { screenshot: "never", video: "never", hilog: true },
  });
  const createDevice = (assertionStatus: "passed" | "failed") =>
    createRecordedDevicePort({
      devices: [createTestDevice()],
      assertions: {
        "business-check": {
          status: assertionStatus,
          summary:
            assertionStatus === "failed" ? "业务断言失败。" : "业务断言通过。",
        },
      },
    });

  const incomplete = await runRuntimeFlow(
    flow,
    createDevice("passed"),
    createRunOptions(),
  );
  assert.equal(incomplete.status, "INCOMPLETE");
  assert.equal(incomplete.failure?.kind, "EVIDENCE_INCOMPLETE");

  const failed = await runRuntimeFlow(
    flow,
    createDevice("failed"),
    createRunOptions(),
  );
  assert.equal(failed.status, "FAILED");
  assert.equal(failed.failure?.kind, "FLOW_ASSERTION_FAILED");
});

test("证据 writer 失败收敛为 EVIDENCE_INCOMPLETE 且不泄露裸异常", async () => {
  const flow = createTestFlow({
    id: "writer-failure",
    steps: [{ id: "capture", action: "checkpoint" }],
    evidence: { screenshot: "never", video: "never", hilog: true },
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice({ kind: "emulator" })],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "hilog",
              path: "captures/hilog.txt",
              mediaType: "text/plain",
              content: "安全内容",
            },
          ],
        },
      ],
    },
  });

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      evidenceWriter: {
        async write() {
          throw new Error("token=writer-secret");
        },
      },
    }),
  );

  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.failure?.kind, "EVIDENCE_INCOMPLETE");
  assert.match(result.failure.summary, /HiLog/u);
  assert.equal(result.evidenceManifest.files.length, 0);
  assert.ok(!JSON.stringify(result).includes("writer-secret"));
});

test("多份证据写入中途失败时只登记已成功写入的文件", async () => {
  const flow = createTestFlow({
    id: "partial-writer-failure",
    steps: [{ id: "capture", action: "checkpoint" }],
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice()],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "network_timeline",
              path: "captures/network.json",
              mediaType: "application/json",
              content: '{"network":"ok"}',
            },
            {
              kind: "permission_timeline",
              path: "captures/permission.json",
              mediaType: "application/json",
              content: '{"permission":"ok"}',
            },
          ],
        },
      ],
    },
  });
  const requests: RuntimeEvidenceWriteRequest[] = [];

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      evidenceWriter: {
        async write(request) {
          requests.push(request);
          if (requests.length === 2) {
            throw new Error("token=second-write-secret");
          }
        },
      },
    }),
  );

  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.failure?.kind, "EVIDENCE_INCOMPLETE");
  assert.deepEqual(
    requests.map((request) => request.relativePath),
    ["captures/network.json", "captures/permission.json"],
  );
  assert.deepEqual(
    result.evidenceManifest.files.map((file) => file.path),
    ["captures/network.json"],
  );
  const firstRequest = requests[0] as RuntimeEvidenceWriteRequest;
  const firstFile = result.evidenceManifest.files[0];
  assert.equal(firstFile?.sizeBytes, firstRequest.bytes.byteLength);
  assert.equal(firstFile?.sha256, await hash.sha256(firstRequest.bytes));
  assert.ok(!JSON.stringify(result).includes("second-write-secret"));
});

test("证据 hash 抛错或返回非法值时不写文件并收敛为证据不完整", async () => {
  const flow = createTestFlow({
    id: "hash-failure",
    steps: [{ id: "capture", action: "checkpoint" }],
    evidence: { screenshot: "never", video: "never", hilog: true },
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice()],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "hilog",
              path: "captures/hilog.txt",
              mediaType: "text/plain",
              content: "安全内容",
            },
          ],
        },
      ],
    },
  });

  for (const hashPort of [
    {
      async sha256(): Promise<`sha256:${string}`> {
        throw new Error("token=hash-secret");
      },
    },
    {
      async sha256(): Promise<`sha256:${string}`> {
        return "sha256:not-a-valid-hash";
      },
    },
  ] satisfies readonly RuntimeHashPort[]) {
    let writes = 0;
    const result = await runRuntimeFlow(
      flow,
      device,
      createRunOptions({
        hash: hashPort,
        evidenceWriter: {
          async write() {
            writes += 1;
          },
        },
      }),
    );

    assert.equal(result.status, "INCOMPLETE");
    assert.equal(result.failure?.kind, "EVIDENCE_INCOMPLETE");
    assert.equal(writes, 0);
    assert.deepEqual(result.evidenceManifest.files, []);
    assert.ok(!JSON.stringify(result).includes("hash-secret"));
  }
});

test("非法 mediaType 在 hash 和 writer 前收敛为证据不完整", async () => {
  const flow = createTestFlow({
    id: "invalid-media-type",
    steps: [{ id: "capture", action: "checkpoint" }],
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice()],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "采集完成。",
          evidence: [
            {
              kind: "hilog",
              path: "captures/hilog.txt",
              mediaType: "",
              content: "安全内容",
            },
          ],
        },
      ],
    },
  });
  let hashes = 0;
  let writes = 0;

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      hash: {
        async sha256(content) {
          hashes += 1;
          return hash.sha256(content);
        },
      },
      evidenceWriter: {
        async write() {
          writes += 1;
        },
      },
    }),
  );

  assert.equal(result.status, "INCOMPLETE");
  assert.equal(result.failure?.kind, "EVIDENCE_INCOMPLETE");
  assert.equal(hashes, 0);
  assert.equal(writes, 0);
  assert.deepEqual(result.evidenceManifest.files, []);
});

test("网络与权限时间线是合法运行时证据 kind", async () => {
  const flow = createTestFlow({
    id: "timeline-evidence-kinds",
    steps: [{ id: "capture", action: "checkpoint" }],
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice()],
    steps: {
      capture: [
        {
          status: "ok",
          summary: "时间线采集完成。",
          evidence: [
            {
              kind: "network_timeline",
              path: "captures/network.json",
              mediaType: "application/json",
              content: "{}",
            },
            {
              kind: "permission_timeline",
              path: "captures/permission.json",
              mediaType: "application/json",
              content: "{}",
            },
          ],
        },
      ],
    },
  });
  const requests: RuntimeEvidenceWriteRequest[] = [];

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      evidenceWriter: {
        async write(request) {
          requests.push(request);
        },
      },
    }),
  );

  assert.equal(result.status, "PASS");
  assert.equal(requests.length, 2);
  assert.deepEqual(
    result.evidenceManifest.files.map((file) => file.path),
    ["captures/network.json", "captures/permission.json"],
  );
});

test("locator_failed 的 backoff 为零时重试但不调用 sleep", async () => {
  const flow = createTestFlow({
    id: "zero-backoff",
    steps: [
      {
        id: "locate",
        action: "wait_for",
        retry: { max_attempts: 2, backoff_ms: 0 },
      },
    ],
  });
  const device = createRecordedDevicePort({
    devices: [createTestDevice()],
    steps: {
      locate: [
        { status: "locator_failed", summary: "首次定位失败。" },
        { status: "ok", summary: "第二次定位成功。" },
      ],
    },
  });
  const sleeps: number[] = [];

  const result = await runRuntimeFlow(
    flow,
    device,
    createRunOptions({
      timing: {
        async sleep(milliseconds) {
          sleeps.push(milliseconds);
        },
        now: defaultTiming.now,
      },
    }),
  );

  assert.equal(result.status, "PASS");
  assert.deepEqual(
    device.history.map((entry) => entry.attempt),
    [1, 2],
  );
  assert.deepEqual(sleeps, []);
});

test("新运行和旧清单回放分别保留真实设备 kind 与 unknown", async () => {
  const flow = createTestFlow({ id: "device-kind" });
  const device = createRecordedDevicePort({
    devices: [createTestDevice({ kind: "physical" })],
  });
  const result = await runRuntimeFlow(flow, device, createRunOptions());

  assert.equal(result.evidenceManifest.device.kind, "physical");
  assert.equal(buildRuntimeReplay(result).device.kind, "physical");

  const { kind: _kind, ...legacyDevice } = result.evidenceManifest.device;
  assert.equal(_kind, "physical");
  const legacyReplay = buildRuntimeReplay({
    ...result.evidenceManifest,
    device: legacyDevice,
  } as unknown as typeof result.evidenceManifest);
  assert.equal(legacyReplay.device.kind, "unknown");
  assert.notEqual(legacyReplay.device.kind, "physical");
});
