import assert from "node:assert/strict";
import test from "node:test";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
  RuntimeArtifactRef,
  RuntimeDeviceAssertionRequest,
  RuntimeDeviceStepRequest,
  RuntimeFlowAssertion,
  RuntimeFlowDefinition,
  RuntimeFlowStep,
} from "@hcheck/core";
import {
  createHdcRuntimeDeviceSession,
  type HdcRuntimeDeviceOptions,
} from "../src/runtime-device.js";

const RAW_KEY = "192.0.2.10:8710";
const DEVICE_ID =
  "device:sha256:630de088630127fa26b4f3a6600969cc95b9cb9be03f7563925b87390f031d88";
const ARTIFACT = {
  uri: "artifacts/device-smoke.hap",
  sha256: `sha256:${"a".repeat(64)}`,
  bundleName: "com.example.hcheck.smoke",
  versionName: "1.2.3",
  versionCode: 7,
} satisfies RuntimeArtifactRef;
const FLOW = {
  id: "device-smoke",
  version: 1,
  name: "设备冒烟",
  requires: {},
  variables: { artifact: "${artifact}" },
  steps: [],
  assertions: [],
  evidence: {},
} as RuntimeFlowDefinition;

const completed = (
  fields: Partial<ProcessRunResult> = {},
): ProcessRunResult => ({
  status: "completed",
  exitCode: 0,
  timedOut: false,
  stdout: "",
  stderr: "",
  stdoutTruncated: false,
  stderrTruncated: false,
  ...fields,
});

type FakeRunOutcome = ProcessRunResult | Error;

class FakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];

  public constructor(private readonly results: readonly FakeRunOutcome[]) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    const result = this.results[this.requests.length - 1];
    assert.ok(result, `缺少第 ${this.requests.length} 条 FakeRunner 结果`);
    if (result instanceof Error) throw result;
    return result;
  }
}

function options(
  runner: ProcessRunnerPort,
  overrides: Partial<HdcRuntimeDeviceOptions> = {},
): HdcRuntimeDeviceOptions {
  return {
    runner,
    challenge: "hcheck-challenge-0123456789abcdef",
    artifact: ARTIFACT,
    abilityName: "EntryAbility",
    moduleName: "entry",
    hilogTag: "HCHECK_SMOKE",
    hilogMarker: "HCHECK_SMOKE_READY",
    device: {
      kind: "emulator",
      model: "Explicit Test Emulator",
      osVersion: "HarmonyOS NEXT test",
      capabilities: ["hilog"],
    },
    ...overrides,
  };
}

function stepRequest(
  action: RuntimeFlowStep["action"],
  overrides: Partial<RuntimeDeviceStepRequest> = {},
): RuntimeDeviceStepRequest {
  return {
    flow: FLOW,
    step: { id: action, action },
    artifact: ARTIFACT,
    deviceId: DEVICE_ID,
    attempt: 1,
    ...overrides,
  };
}

function assertionRequest(
  assertion: RuntimeFlowAssertion,
  overrides: Partial<RuntimeDeviceAssertionRequest> = {},
): RuntimeDeviceAssertionRequest {
  return {
    flow: FLOW,
    assertion,
    artifact: ARTIFACT,
    deviceId: DEVICE_ID,
    ...overrides,
  };
}

async function readySession(extra: readonly FakeRunOutcome[] = []) {
  const runner = new FakeRunner([
    completed({ stdout: `${RAW_KEY}\n` }),
    completed({ stdout: "hcheck-challenge-0123456789abcdef\n" }),
    ...extra,
  ]);
  const opened = await createHdcRuntimeDeviceSession(options(runner));
  assert.equal(opened.status, "ready");
  if (opened.status !== "ready") throw new Error("测试会话未建立");
  return { runner, session: opened.session, opened };
}

function installedBundleInfo(
  overrides: Record<string, unknown> = {},
): ProcessRunResult {
  return completed({
    stdout: `${ARTIFACT.bundleName}:\n${JSON.stringify({
      name: ARTIFACT.bundleName,
      versionCode: ARTIFACT.versionCode,
      versionName: ARTIFACT.versionName,
      moduleNames: ["entry", "shared"],
      ...overrides,
    })}\n`,
  });
}

test("只有 plain 唯一设备和调用方注入的密码学随机挑战精确回显才能建立会话", async () => {
  const { runner, session, opened } = await readySession();

  assert.deepEqual(
    runner.requests.map(({ args }) => args),
    [
      ["list", "targets"],
      ["-t", RAW_KEY, "shell", "echo", "hcheck-challenge-0123456789abcdef"],
    ],
  );
  assert.ok(
    runner.requests.every(({ args }) => !args.includes("-v")),
    "自动门禁不得调用 detail 枚举",
  );
  const devices = await session.listDevices();
  assert.equal(devices.length, 1);
  assert.equal(devices[0]?.id, devices[0]?.redactedId);
  assert.equal(devices[0]?.id, stepRequest("install").deviceId);
  assert.deepEqual(devices[0], {
    id: stepRequest("install").deviceId,
    redactedId: stepRequest("install").deviceId,
    kind: "emulator",
    model: "Explicit Test Emulator",
    osVersion: "HarmonyOS NEXT test",
    capabilities: ["hilog"],
  });
  assert.deepEqual(session.binding(), {
    artifactSha256: ARTIFACT.sha256,
    bundleName: ARTIFACT.bundleName,
    moduleName: "entry",
    abilityName: "EntryAbility",
    hilogTag: "HCHECK_SMOKE",
    hilogMarker: "HCHECK_SMOKE_READY",
    deviceId: DEVICE_ID,
  });
  assert.ok(!JSON.stringify(opened).includes(RAW_KEY));
});

test("无设备、多设备、非就绪状态和挑战非精确回显均拒绝会话", async () => {
  const cases: readonly (readonly ProcessRunResult[])[] = [
    [completed({ stdout: "[Empty]\n" })],
    [completed({ stdout: `${RAW_KEY}\nother-device\n` })],
    [completed({ stdout: `${RAW_KEY}\toffline\n` })],
    [completed({ stdout: `${RAW_KEY}\tunauthorized\n` })],
    [completed({ stdout: `${RAW_KEY}\tunknown\n` })],
    [completed({ stdout: "-invalid-key\n" })],
    [completed({ stdout: "invalid/key\n" })],
    [
      completed({ stdout: `${RAW_KEY}\n` }),
      completed({ stdout: "hcheck-challenge-0123456789abcdef extra\n" }),
    ],
  ];

  for (const results of cases) {
    const runner = new FakeRunner(results);
    const opened = await createHdcRuntimeDeviceSession(options(runner));
    assert.equal(opened.status, "rejected");
    assert.ok(!JSON.stringify(opened).includes(RAW_KEY));
    assert.ok(runner.requests.length <= 2);
  }
});

test("即使显式元数据或标记碰巧含 connect-key，公开绑定和设备信息仍脱敏", async () => {
  const runner = new FakeRunner([
    completed({ stdout: `${RAW_KEY}\n` }),
    completed({ stdout: "hcheck-challenge-0123456789abcdef\n" }),
  ]);
  const opened = await createHdcRuntimeDeviceSession(
    options(runner, {
      hilogMarker: RAW_KEY,
      device: {
        kind: "unknown",
        model: `Model ${RAW_KEY}`,
        osVersion: `Version ${RAW_KEY}`,
        capabilities: ["hilog"],
      },
    }),
  );

  assert.equal(opened.status, "ready");
  assert.ok(!JSON.stringify(opened).includes(RAW_KEY));
  if (opened.status === "ready") {
    assert.ok(!JSON.stringify(opened.session.binding()).includes(RAW_KEY));
    assert.ok(
      !JSON.stringify(await opened.session.listDevices()).includes(RAW_KEY),
    );
  }
});

test("枚举或挑战超时、截断、非零、标准错误、错误码和 Fail 均保守拒绝", async () => {
  const failures = [
    completed({ status: "timed_out", timedOut: true }),
    completed({ stdout: RAW_KEY, stdoutTruncated: true }),
    completed({ stdout: RAW_KEY, stderrTruncated: true }),
    completed({ exitCode: 1, stdout: RAW_KEY }),
    completed({ stdout: RAW_KEY, stderr: "warning" }),
    completed({ stdout: `[E123456] ${RAW_KEY}` }),
    completed({ stdout: `[Fail] ${RAW_KEY}` }),
  ];

  for (const failure of failures) {
    const enumerateRunner = new FakeRunner([failure]);
    const enumerate = await createHdcRuntimeDeviceSession(
      options(enumerateRunner),
    );
    assert.equal(enumerate.status, "rejected");

    const challengeRunner = new FakeRunner([
      completed({ stdout: RAW_KEY }),
      failure,
    ]);
    const challenge = await createHdcRuntimeDeviceSession(
      options(challengeRunner),
    );
    assert.equal(challenge.status, "rejected");
    assert.equal(challengeRunner.requests.length, 2);
    assert.ok(!JSON.stringify(challenge).includes(RAW_KEY));
  }
});

test("枚举、挑战和安装状态读取拒绝带 signal 或 errorMessage 的成功形状结果", async () => {
  const failures = [
    { fields: { signal: "SIGTERM" }, sensitive: "SIGTERM" },
    {
      fields: { errorMessage: "token=SECRET /Users/private/hdc" },
      sensitive: "token=SECRET /Users/private/hdc",
    },
  ] as const;

  for (const { fields, sensitive } of failures) {
    const enumeration = await createHdcRuntimeDeviceSession(
      options(
        new FakeRunner([
          completed({ stdout: `${RAW_KEY}\n`, ...fields }),
          completed({ stdout: "hcheck-challenge-0123456789abcdef\n" }),
        ]),
      ),
    );
    assert.deepEqual(enumeration, {
      status: "rejected",
      reason: "device_enumeration_failed",
    });

    const challenge = await createHdcRuntimeDeviceSession(
      options(
        new FakeRunner([
          completed({ stdout: `${RAW_KEY}\n` }),
          completed({
            stdout: "hcheck-challenge-0123456789abcdef\n",
            ...fields,
          }),
        ]),
      ),
    );
    assert.deepEqual(challenge, {
      status: "rejected",
      reason: "device_challenge_failed",
    });

    const { runner, session } = await readySession([
      completed({ stdout: "\tcom.example.other\n", ...fields }),
    ]);
    assert.equal(await session.queryBundlePresence(), "unknown");
    assert.equal(runner.requests.length, 3);
    for (const value of [enumeration, challenge, session.state()]) {
      assert.ok(!JSON.stringify(value).includes(sensitive));
      assert.ok(!JSON.stringify(value).includes(RAW_KEY));
    }
  }
});

test("BM dump -a 只在严格 tab Bundle 名单完整成功时分类", async () => {
  const installed = await readySession([
    completed({
      stdout: "\tcom.example.other\n\tcom.example.hcheck.smoke\n",
    }),
  ]);
  assert.equal(await installed.session.queryBundlePresence(), "installed");
  assert.deepEqual(installed.runner.requests[2]?.args, [
    "-t",
    RAW_KEY,
    "shell",
    "bm",
    "dump",
    "-a",
  ]);

  const absent = await readySession([
    completed({ stdout: "\tcom.example.other\n\tcom.example.second\n" }),
  ]);
  assert.equal(await absent.session.queryBundlePresence(), "not_installed");

  const ambiguousOutputs = [
    "",
    "com.example.other\n",
    "\tcom.example.other\nheader\n",
    "\tcom.example.other\n\tcom.example.other\n",
  ];
  for (const stdout of ambiguousOutputs) {
    const ambiguous = await readySession([completed({ stdout })]);
    assert.equal(await ambiguous.session.queryBundlePresence(), "unknown");
  }
  for (const result of [
    completed({ stdout: "\tcom.example.other\n", stderr: "warning" }),
    completed({ stdout: "\tcom.example.other\n", stdoutTruncated: true }),
    completed({ stdout: "\tcom.example.other\n", exitCode: 1 }),
    completed({ stdout: "[Fail]\n" }),
  ]) {
    const failed = await readySession([result]);
    assert.equal(await failed.session.queryBundlePresence(), "unknown");
  }
});

test("BM dump -a 接受当前 HDC 的双字段摘要头和带连字符 Bundle 名单", async () => {
  const { session } = await readySession([
    completed({
      stdout: "42: 6.1:\n\tcom.example.other\n\tcom.example.vendor-7\n",
    }),
  ]);

  assert.equal(await session.queryBundlePresence(), "not_installed");
});

test("bm dump -n 严格解析目标 Bundle 信息并忽略未返回的官方扩展字段", async () => {
  const payload = {
    name: ARTIFACT.bundleName,
    versionCode: 7,
    versionName: "1.2.3",
    moduleNames: ["entry", "shared"],
    officialExtra: { device: RAW_KEY, vendor: "OpenHarmony" },
  };
  const { runner, session } = await readySession([
    completed({
      stdout: `${ARTIFACT.bundleName}:\n${JSON.stringify(payload)}\n`,
    }),
  ]);

  const result = await session.queryInstalledBundleInfo();
  assert.deepEqual(runner.requests[2]?.args, [
    "-t",
    RAW_KEY,
    "shell",
    "bm",
    "dump",
    "-n",
    ARTIFACT.bundleName,
  ]);
  assert.deepEqual(result, {
    available: true,
    status: "available",
    info: {
      name: ARTIFACT.bundleName,
      versionCode: 7,
      versionName: "1.2.3",
      moduleNames: ["entry", "shared"],
    },
  });
  assert.ok(!JSON.stringify(result).includes(RAW_KEY));
});

test("bm dump -n 的命令失败、截断和 HDC 错误均返回 unknown", async () => {
  const valid = `${ARTIFACT.bundleName}:\n${JSON.stringify({
    name: ARTIFACT.bundleName,
    versionCode: 0,
    versionName: "1.0.0",
    moduleNames: ["entry"],
  })}\n`;
  const failures = [
    completed({ status: "timed_out", timedOut: true, stdout: valid }),
    completed({ stdout: valid, stdoutTruncated: true }),
    completed({ stdout: valid, stderrTruncated: true }),
    completed({ stdout: valid, exitCode: 1 }),
    completed({ stdout: valid, stderr: "warning" }),
    completed({ stdout: `[E123456] ${valid}` }),
    completed({ stdout: `[Fail] ${valid}` }),
    new Error(`bm failed ${RAW_KEY}`),
  ];

  for (const failure of failures) {
    const { session } = await readySession([failure]);
    const result = await session.queryInstalledBundleInfo();
    assert.deepEqual(result, {
      available: false,
      status: "unknown",
      reason: "无法确认目标 Bundle 信息。",
    });
    assert.ok(!JSON.stringify(result).includes(RAW_KEY));
  }
});

test("bm dump -n 拒绝前后缀、缺最终换行、尾垃圾和无效 JSON 合同", async () => {
  const base = {
    name: ARTIFACT.bundleName,
    versionCode: 0,
    versionName: "1.0.0",
    moduleNames: ["entry"],
  };
  const json = JSON.stringify(base);
  const invalidOutputs = [
    `${ARTIFACT.bundleName}:\n${json}`,
    `prefix\n${ARTIFACT.bundleName}:\n${json}\n`,
    `${ARTIFACT.bundleName}:\n${json}\nextra`,
    `${ARTIFACT.bundleName}:\n${json}\n\n`,
    `com.example.other:\n${json}\n`,
    `${ARTIFACT.bundleName}:\nnot-json\n`,
    `${ARTIFACT.bundleName}:\n ${json}\n`,
    `${ARTIFACT.bundleName}:\n${json} \n`,
  ];

  for (const stdout of invalidOutputs) {
    const { session } = await readySession([completed({ stdout })]);
    assert.equal((await session.queryInstalledBundleInfo()).status, "unknown");
  }
});

test("bm dump -n 拒绝 Bundle 不符、缺字段、非法版本和重复或不安全模块", async () => {
  const valid = {
    name: ARTIFACT.bundleName,
    versionCode: 0,
    versionName: "1.0.0",
    moduleNames: ["entry"],
  };
  const invalidPayloads = [
    [],
    { ...valid, name: "com.example.other" },
    { ...valid, versionCode: -1 },
    { ...valid, versionCode: 1.5 },
    { ...valid, versionCode: 4_294_967_296 },
    { ...valid, versionCode: Number.MAX_SAFE_INTEGER + 1 },
    { ...valid, versionName: "" },
    { ...valid, versionName: " 1.0.0" },
    { ...valid, versionName: "1.0.0\u0000" },
    { ...valid, versionName: "1.0.0\ud800" },
    { ...valid, versionName: "1.0.0\udc00" },
    { ...valid, moduleNames: [] },
    { ...valid, moduleNames: ["entry", "entry"] },
    { ...valid, moduleNames: ["-entry"] },
    {
      name: valid.name,
      versionCode: valid.versionCode,
      versionName: valid.versionName,
    },
  ];

  for (const payload of invalidPayloads) {
    const { session } = await readySession([
      completed({
        stdout: `${ARTIFACT.bundleName}:\n${JSON.stringify(payload)}\n`,
      }),
    ]);
    assert.equal(
      (await session.queryInstalledBundleInfo()).status,
      "unknown",
      JSON.stringify(payload),
    );
  }
});

test("install 成功后必须用严格 Bundle 元数据复验才允许 launch", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
  ]);
  await session.queryBundlePresence();

  assert.equal(
    (await session.performStep(stepRequest("install"))).status,
    "ok",
  );
  assert.equal((await session.performStep(stepRequest("launch"))).status, "ok");
  assert.deepEqual(
    runner.requests.slice(2).map(({ args }) => args),
    [
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
      ["-t", RAW_KEY, "install", ARTIFACT.uri],
      ["-t", RAW_KEY, "shell", "bm", "dump", "-n", ARTIFACT.bundleName],
      [
        "-t",
        RAW_KEY,
        "shell",
        "aa",
        "start",
        "-a",
        "EntryAbility",
        "-b",
        ARTIFACT.bundleName,
      ],
    ],
  );
});

test("安装前查询不得解锁，安装后版本或目标模块不匹配仍保留 cleanup 归属", async () => {
  const mismatches = [
    installedBundleInfo({ versionCode: 8 }),
    installedBundleInfo({ versionName: "1.2.4" }),
    installedBundleInfo({ moduleNames: ["shared"] }),
    completed({ stdout: "not-valid\n" }),
  ];

  for (const mismatch of mismatches) {
    const { runner, session } = await readySession([
      installedBundleInfo(),
      completed({ stdout: "\tcom.example.other\n" }),
      completed({ stdout: "\tcom.example.other\n" }),
      completed(),
      mismatch,
      completed(),
    ]);
    assert.equal(
      (await session.queryInstalledBundleInfo()).status,
      "available",
    );
    await session.queryBundlePresence();

    const install = await session.performStep(stepRequest("install"));
    assert.equal(install.status, "install_failed");
    const beforeLaunch = runner.requests.length;
    assert.equal(
      (await session.performStep(stepRequest("launch"))).status,
      "environment_failed",
    );
    assert.equal(runner.requests.length, beforeLaunch);
    assert.equal(session.state().installed, true);
    assert.equal((await session.cleanup()).status, "ok");
    assert.deepEqual(runner.requests.at(-1)?.args, [
      "-t",
      RAW_KEY,
      "uninstall",
      ARTIFACT.bundleName,
    ]);
  }
});

test("五步命令固定绑定目标设备且 checkpoint 只产出 Hilog 证据", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed({ stdout: `before ${RAW_KEY} HCHECK_SMOKE_READY after\n` }),
    completed(),
    completed(),
  ]);
  assert.equal(await session.queryBundlePresence(), "not_installed");

  for (const action of [
    "install",
    "launch",
    "checkpoint",
    "stop",
    "uninstall",
  ] as const) {
    const result = await session.performStep(
      stepRequest(
        action,
        action === "install"
          ? { step: { id: "install", action, package: "${artifact}" } }
          : {},
      ),
    );
    assert.equal(result.status, "ok", `${action} 应通过`);
    assert.ok(!JSON.stringify(result).includes(RAW_KEY));
    if (action === "checkpoint") {
      assert.equal(result.evidence?.[0]?.kind, "hilog");
      assert.equal(result.evidence?.[0]?.mediaType, "text/plain");
      assert.ok(result.evidence?.[0]?.content.includes("HCHECK_SMOKE_READY"));
      assert.ok(!result.evidence?.[0]?.content.includes(RAW_KEY));
    }
  }

  assert.deepEqual(
    runner.requests.slice(2).map(({ args }) => args),
    [
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
      ["-t", RAW_KEY, "install", ARTIFACT.uri],
      ["-t", RAW_KEY, "shell", "bm", "dump", "-n", ARTIFACT.bundleName],
      [
        "-t",
        RAW_KEY,
        "shell",
        "aa",
        "start",
        "-a",
        "EntryAbility",
        "-b",
        ARTIFACT.bundleName,
      ],
      ["-t", RAW_KEY, "shell", "hilog", "-x", "-T", "HCHECK_SMOKE"],
      ["-t", RAW_KEY, "shell", "aa", "force-stop", ARTIFACT.bundleName],
      ["-t", RAW_KEY, "uninstall", ARTIFACT.bundleName],
    ],
  );
  assert.ok(runner.requests.slice(3).every(({ args }) => args[0] === "-t"));
  assert.deepEqual(session.state(), {
    bundlePresence: "not_installed",
    installAttempted: true,
    installationUncertain: false,
    installed: false,
    launchAttempted: true,
    started: true,
    stopped: true,
    uninstallUncertain: false,
    uninstalled: true,
  });
});

test("checkpoint 在首次空 Hilog 后轮询同一标签直到读到固定标记", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed({ stdout: "" }),
    completed({ stdout: "HCHECK_SMOKE_READY\n" }),
  ]);
  await session.queryBundlePresence();
  assert.equal(
    (await session.performStep(stepRequest("install"))).status,
    "ok",
  );
  assert.equal((await session.performStep(stepRequest("launch"))).status, "ok");

  const checkpoint = await session.performStep(stepRequest("checkpoint"));

  assert.equal(checkpoint.status, "ok");
  assert.ok(checkpoint.evidence?.[0]?.content.includes("HCHECK_SMOKE_READY"));
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("hilog")).length,
    2,
  );
});

test("checkpoint 不拼接跨轮 Hilog 片段伪造固定标记", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed({ stdout: "HCHECK_SMOKE_" }),
    completed({ stdout: "READY\n" }),
    completed({ stdout: "marker-still-missing\n" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));
  await session.performStep(stepRequest("launch"));

  const checkpoint = await session.performStep(stepRequest("checkpoint"));

  assert.equal(checkpoint.status, "evidence_incomplete");
  assert.equal(checkpoint.evidence?.[0]?.content, "marker-still-missing\n");
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("hilog")).length,
    3,
  );
});

test("checkpoint 三次完整但无标记的 Hilog 后保持证据不完整", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed({ stdout: "first-missing\n" }),
    completed({ stdout: "second-missing\n" }),
    completed({ stdout: "third-missing\n" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));
  await session.performStep(stepRequest("launch"));

  const checkpoint = await session.performStep(stepRequest("checkpoint"));

  assert.equal(checkpoint.status, "evidence_incomplete");
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("hilog")).length,
    3,
  );
});

test("唯一 Hilog 断言按 checkpoint 精确子串判定，其他断言不冒充通过", async () => {
  const { session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed({ stdout: "HCHECK_SMOKE_READY\n" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));
  await session.performStep(stepRequest("launch"));
  await session.performStep(stepRequest("checkpoint"));

  const passed = await session.evaluateAssertion(
    assertionRequest({
      id: "marker",
      type: "hilog_contains_marker",
      after_step: "checkpoint",
    }),
  );
  assert.equal(passed.status, "passed");

  const unsupported = await session.evaluateAssertion(
    assertionRequest({ id: "other", type: "all_ok" }),
  );
  assert.equal(unsupported.status, "evidence_incomplete");

  const wrongCheckpoint = await session.evaluateAssertion(
    assertionRequest({
      id: "missing",
      type: "hilog_contains_marker",
      after_step: "not-captured",
    }),
  );
  assert.equal(wrongCheckpoint.status, "evidence_incomplete");
});

test("checkpoint 的标记缺失、截断、标准错误、非零和 HDC 错误均为证据不完整", async () => {
  const failures = [
    completed({ stdout: "marker-missing\n" }),
    completed({ stdout: "HCHECK_SMOKE_READY\n", stdoutTruncated: true }),
    completed({ stdout: "HCHECK_SMOKE_READY\n", stderr: "warning" }),
    completed({ stdout: "HCHECK_SMOKE_READY\n", exitCode: 1 }),
    completed({ stdout: "[E123456] HCHECK_SMOKE_READY\n" }),
    completed({ stdout: "[Fail] HCHECK_SMOKE_READY\n" }),
  ];

  for (const checkpointResult of failures) {
    const { session } = await readySession([
      completed({ stdout: "\tcom.example.other\n" }),
      completed({ stdout: "\tcom.example.other\n" }),
      completed(),
      installedBundleInfo(),
      completed(),
      checkpointResult,
    ]);
    await session.queryBundlePresence();
    assert.equal(
      (await session.performStep(stepRequest("install"))).status,
      "ok",
    );
    assert.equal(
      (await session.performStep(stepRequest("launch"))).status,
      "ok",
    );
    const checkpoint = await session.performStep(stepRequest("checkpoint"));
    assert.equal(checkpoint.status, "evidence_incomplete");
    assert.ok(!JSON.stringify(checkpoint).includes(RAW_KEY));
  }
});

test("预装、未知和未做 BM 查询均禁止安装且不会执行写命令", async () => {
  for (const bmResult of [
    undefined,
    completed({ stdout: "\tcom.example.hcheck.smoke\n" }),
    completed({ stdout: "" }),
  ]) {
    const { runner, session } = await readySession(
      bmResult === undefined ? [] : [bmResult],
    );
    if (bmResult !== undefined) await session.queryBundlePresence();
    const before = runner.requests.length;
    const result = await session.performStep(stepRequest("install"));
    assert.equal(result.status, "install_failed");
    assert.equal(runner.requests.length, before);
  }
});

test("不支持的 action、命令失败、目标不一致均失败且不泄漏 connect-key", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: `[Fail] ${RAW_KEY}` }),
    completed({ stdout: "\tcom.example.other\n" }),
  ]);
  await session.queryBundlePresence();

  const unsupported = await session.performStep(stepRequest("tap"));
  assert.equal(unsupported.status, "unsupported_device");

  const mismatch = await session.performStep(
    stepRequest("install", {
      artifact: { ...ARTIFACT, bundleName: "com.example.mismatch" },
    }),
  );
  assert.equal(mismatch.status, "environment_failed");

  for (const overrides of [
    { deviceId: "device:sha256:other" },
    { artifact: { ...ARTIFACT, uri: "artifacts/other.hap" } },
    {
      artifact: {
        ...ARTIFACT,
        sha256: `sha256:${"b".repeat(64)}` as const,
      },
    },
    { artifact: { ...ARTIFACT, versionName: "unexpected" } },
    {
      step: {
        id: "install",
        action: "install",
        package: "${not-artifact}",
      },
    },
  ] satisfies readonly Partial<RuntimeDeviceStepRequest>[]) {
    const calls = runner.requests.length;
    const rejected = await session.performStep(
      stepRequest("install", overrides),
    );
    assert.equal(rejected.status, "environment_failed");
    assert.equal(runner.requests.length, calls);
  }

  const before = runner.requests.length;
  const failed = await session.performStep(stepRequest("install"));
  assert.equal(failed.status, "install_failed");
  assert.equal(runner.requests.length, before + 3);
  assert.deepEqual(
    runner.requests.slice(before).map(({ args }) => args),
    [
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
      ["-t", RAW_KEY, "install", ARTIFACT.uri],
      ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
    ],
  );
  assert.ok(!JSON.stringify(failed).includes(RAW_KEY));
});

test("install 失败后 BM 证明已安装时记录归属并由 cleanup 卸载", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ exitCode: 1 }),
    completed({ stdout: "\tcom.example.hcheck.smoke\n" }),
    completed(),
  ]);
  await session.queryBundlePresence();

  const install = await session.performStep(stepRequest("install"));
  assert.equal(install.status, "install_failed");
  assert.deepEqual(session.state(), {
    bundlePresence: "installed",
    installAttempted: true,
    installationUncertain: false,
    installed: true,
    launchAttempted: false,
    started: false,
    stopped: false,
    uninstallUncertain: false,
    uninstalled: false,
  });
  const beforeLaunch = runner.requests.length;
  const launches = await Promise.all([
    session.performStep(stepRequest("launch")),
    session.performStep(stepRequest("launch")),
  ]);
  assert.deepEqual(
    launches.map(({ status }) => status),
    ["environment_failed", "environment_failed"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("start")).length,
    0,
  );
  assert.equal(runner.requests.length, beforeLaunch);
  assert.equal((await session.cleanup()).status, "ok");
  assert.deepEqual(runner.requests.slice(-1)[0]?.args, [
    "-t",
    RAW_KEY,
    "uninstall",
    ARTIFACT.bundleName,
  ]);
});

test("install 失败后 BM 仍 unknown 时 cleanup 明确失败且不误卸载", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ status: "timed_out", timedOut: true }),
    completed({ stdout: "" }),
  ]);
  await session.queryBundlePresence();

  const install = await session.performStep(stepRequest("install"));
  assert.equal(install.status, "install_failed");
  assert.equal(session.state().installAttempted, true);
  assert.equal(session.state().installationUncertain, true);
  const beforeCleanup = runner.requests.length;
  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal(runner.requests.length, beforeCleanup);
});

test("install runner 抛错后 BM 证明未安装时安全失败且 cleanup 不卸载", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    new Error(`runner failed ${RAW_KEY}`),
    completed({ stdout: "\tcom.example.other\n" }),
  ]);
  await session.queryBundlePresence();

  const install = await session.performStep(stepRequest("install"));
  assert.equal(install.status, "install_failed");
  assert.equal(session.state().installAttempted, true);
  assert.equal(session.state().installationUncertain, false);
  assert.equal(session.state().installed, false);
  assert.ok(!JSON.stringify(install).includes(RAW_KEY));
  const beforeCleanup = runner.requests.length;
  assert.equal((await session.cleanup()).status, "ok");
  assert.equal(runner.requests.length, beforeCleanup);
});

test("launch 超时后并发 cleanup 仍只执行一次 stop 和 uninstall", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed({ status: "timed_out", timedOut: true }),
    completed(),
    completed(),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));

  const launches = await Promise.all([
    session.performStep(stepRequest("launch")),
    session.performStep(stepRequest("launch")),
  ]);
  assert.deepEqual(
    launches.map(({ status }) => status),
    ["environment_failed", "environment_failed"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("start")).length,
    1,
  );
  assert.equal(session.state().launchAttempted, true);
  assert.equal(session.state().started, false);
  const cleanups = await Promise.all([session.cleanup(), session.cleanup()]);
  assert.deepEqual(
    cleanups.map(({ status }) => status),
    ["ok", "ok"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("force-stop")).length,
    1,
  );
  assert.equal(
    runner.requests.filter(({ args }) => args[2] === "uninstall").length,
    1,
  );
});

test("cleanup 只清理本会话安装目标且幂等", async () => {
  const untouched = await readySession();
  const untouchedBefore = untouched.runner.requests.length;
  assert.equal((await untouched.session.cleanup()).status, "ok");
  assert.equal(untouched.runner.requests.length, untouchedBefore);

  const active = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed(),
    completed(),
  ]);
  await active.session.queryBundlePresence();
  await active.session.performStep(stepRequest("install"));
  await active.session.performStep(stepRequest("launch"));
  assert.equal((await active.session.cleanup()).status, "ok");
  const afterFirstCleanup = active.runner.requests.length;
  assert.equal((await active.session.cleanup()).status, "ok");
  assert.equal(active.runner.requests.length, afterFirstCleanup);
  assert.deepEqual(
    active.runner.requests.slice(-2).map(({ args }) => args),
    [
      ["-t", RAW_KEY, "shell", "aa", "force-stop", ARTIFACT.bundleName],
      ["-t", RAW_KEY, "uninstall", ARTIFACT.bundleName],
    ],
  );
});

test("uninstall 抛错但 BM 证明缺席时同步当前状态且后续 cleanup 零写", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    new Error(`uninstall failed ${RAW_KEY}`),
    completed({ stdout: "\tcom.example.other\n" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));

  assert.equal((await session.cleanup()).status, "ok");
  assert.equal(session.state().bundlePresence, "not_installed");
  assert.equal(session.state().installed, false);
  assert.equal(session.state().uninstalled, true);
  const afterFirst = runner.requests.length;
  assert.equal((await session.cleanup()).status, "ok");
  assert.equal(runner.requests.length, afterFirst);
});

test("uninstall 失败且 BM 仍 installed 时只允许一次相邻复验后的有限重试", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed({ exitCode: 1 }),
    completed({ stdout: "\tcom.example.hcheck.smoke\n" }),
    completed({ stdout: "\tcom.example.hcheck.smoke\n" }),
    completed({ stdout: "[Fail]\n" }),
    completed({ stdout: "\tcom.example.hcheck.smoke\n" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));

  const firstWave = await Promise.all([session.cleanup(), session.cleanup()]);
  assert.deepEqual(
    firstWave.map(({ status }) => status),
    ["cleanup_failed", "cleanup_failed"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args[2] === "uninstall").length,
    1,
  );
  assert.equal(session.state().bundlePresence, "installed");
  assert.equal(session.state().installed, true);
  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal(
    runner.requests.filter(({ args }) => args[2] === "uninstall").length,
    2,
  );
  const afterRetry = runner.requests.length;
  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal(runner.requests.length, afterRetry);
});

test("uninstall 超时且 BM unknown 时进入终止态，后续 cleanup 禁止任何写命令", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed({ status: "timed_out", timedOut: true }),
    completed({ stdout: "" }),
  ]);
  await session.queryBundlePresence();
  await session.performStep(stepRequest("install"));

  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal(session.state().bundlePresence, "unknown");
  assert.equal(session.state().installed, false);
  assert.equal(session.state().uninstallUncertain, true);
  const afterUnknown = runner.requests.length;
  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal((await session.cleanup()).status, "cleanup_failed");
  assert.equal(runner.requests.length, afterUnknown);
});

test("并发 install 和并发 cleanup 在会话内串行且最多各执行一次写命令", async () => {
  const { runner, session } = await readySession([
    completed({ stdout: "\tcom.example.other\n" }),
    completed({ stdout: "\tcom.example.other\n" }),
    completed(),
    installedBundleInfo(),
    completed(),
    completed(),
    completed(),
  ]);
  await session.queryBundlePresence();

  const installs = await Promise.all([
    session.performStep(stepRequest("install")),
    session.performStep(stepRequest("install")),
  ]);
  assert.deepEqual(
    installs.map(({ status }) => status),
    ["ok", "install_failed"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args[2] === "install").length,
    1,
  );
  assert.equal((await session.performStep(stepRequest("launch"))).status, "ok");

  const cleanups = await Promise.all([session.cleanup(), session.cleanup()]);
  assert.deepEqual(
    cleanups.map(({ status }) => status),
    ["ok", "ok"],
  );
  assert.equal(
    runner.requests.filter(({ args }) => args.includes("force-stop")).length,
    1,
  );
  assert.equal(
    runner.requests.filter(({ args }) => args[2] === "uninstall").length,
    1,
  );
});

test("配置要求显式且安全的 challenge、模块、Ability、标签、标记和设备元数据", async () => {
  for (const overrides of [
    { challenge: "" },
    { challenge: "short" },
    { moduleName: "" },
    { moduleName: " entry" },
    { moduleName: "-entry" },
    { abilityName: "" },
    { abilityName: "EntryAbility\n" },
    { abilityName: "-EntryAbility" },
    { hilogTag: "" },
    { hilogTag: " tag" },
    { hilogTag: "-tag" },
    { hilogMarker: "" },
    { hilogMarker: " marker" },
    { hilogMarker: "marker\u0000" },
    { artifact: { ...ARTIFACT, bundleName: "-com.example.app" } },
    { artifact: { ...ARTIFACT, uri: "-other.hap" } },
    { artifact: { ...ARTIFACT, uri: "other.hap\n" } },
    { artifact: { ...ARTIFACT, uri: "other\tfile.hap" } },
    { artifact: { ...ARTIFACT, versionName: "" } },
    { artifact: { ...ARTIFACT, versionName: "1.2.3\ud800" } },
    { artifact: { ...ARTIFACT, versionCode: -1 } },
    { artifact: { ...ARTIFACT, versionCode: 4_294_967_296 } },
    {
      artifact: {
        uri: ARTIFACT.uri,
        sha256: ARTIFACT.sha256,
        bundleName: ARTIFACT.bundleName,
      } as HdcRuntimeDeviceOptions["artifact"],
    },
    {
      device: { kind: "unknown", model: "", osVersion: "x", capabilities: [] },
    },
  ] satisfies readonly Partial<HdcRuntimeDeviceOptions>[]) {
    await assert.rejects(
      createHdcRuntimeDeviceSession(options(new FakeRunner([]), overrides)),
      /配置无效/u,
    );
  }
});
