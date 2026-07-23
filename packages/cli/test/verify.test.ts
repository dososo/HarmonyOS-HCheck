import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rmdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type {
  HashPort,
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import { runVerify } from "../src/verify.js";
import type { DeviceVerificationPorts } from "../src/device-verification.js";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";
import { TEST_LEAF_CERTIFICATE_PEM } from "./test-leaf-certificate.js";

const SHA_A = `sha256:${"a".repeat(64)}` as const;
const BUNDLE = "com.example.hcheck.smoke";
const RAW_DEVICE = "192.0.2.10:8710";
const CHALLENGE = "hcheck-cli-challenge";
const RUN_ID = "run-cli-7d3";
const SIGNER_PEM = TEST_LEAF_CERTIFICATE_PEM;
const SIGNER_DER = new X509Certificate(SIGNER_PEM).raw;
const SMOKE_FLOW = Buffer.from(`id: device-smoke
version: 1
name: 设备冒烟
requires:
  clean_install: true
  network_observation: none
  test_account: false
variables:
  artifact: \${artifact}
steps:
  - id: install
    action: install
    package: \${artifact}
  - id: launch
    action: launch
  - id: checkpoint
    action: checkpoint
  - id: stop
    action: stop
  - id: uninstall
    action: uninstall
assertions:
  - id: marker
    type: hilog_contains_marker
    after_step: checkpoint
    severity: BLOCKER
evidence:
  screenshot: never
  video: never
  hilog: true
  network_timeline: none
  permission_timeline: false
`);
const HAP_BYTES = zip([
  {
    name: "module.json",
    content: JSON.stringify({
      app: { bundleName: BUNDLE, versionName: "1.2.3", versionCode: 7 },
      module: {
        name: "entry",
        type: "entry",
        packageName: "entry",
        deviceTypes: ["phone"],
      },
    }),
  },
]);
const JAR_BYTES = Buffer.from("fake-sign-tool");

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

type Outcome = ProcessRunResult | Error;
type RuntimeAction = "install" | "launch" | "checkpoint" | "stop" | "uninstall";

interface RunnerScenario {
  readonly verifyApp?: Outcome;
  readonly targets?: Outcome;
  readonly targetOutcomes?: readonly Outcome[];
  readonly challenge?: Outcome;
  readonly presence?: Outcome;
  readonly presenceOutcomes?: readonly Outcome[];
  readonly runtime?: Partial<Record<RuntimeAction, Outcome>>;
}

class PreflightFakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];
  private targetCalls = 0;
  private presenceCalls = 0;

  public constructor(private readonly scenario: RunnerScenario = {}) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    const [first, , third] = request.args;
    if (first === "-version") {
      return completed({ stderr: 'openjdk version "17.0.12"\n' });
    }
    if (first === "-jar" && third === "verify-app") {
      assert.ok(request.cwd);
      await writeFile(path.join(request.cwd, "cert-chain.cer"), SIGNER_PEM);
      await writeFile(path.join(request.cwd, "profile.p7b"), "signed-profile");
      return this.result(
        this.scenario.verifyApp ?? completed({ stdout: "[Success]" }),
      );
    }
    if (first === "-jar" && third === "verify-profile") {
      assert.ok(request.cwd);
      await writeFile(
        path.join(request.cwd, "profile-verification.json"),
        JSON.stringify({
          verifiedPassed: true,
          message: "OK",
          content: {
            type: "debug",
            validity: {
              "not-before": 1_700_000_000,
              "not-after": 2_000_000_000,
            },
            "bundle-info": {
              "bundle-name": BUNDLE,
              "development-certificate": SIGNER_DER.toString("base64"),
              "developer-id": "developer-secret-must-not-leak",
              "device-ids": ["device-secret-must-not-leak"],
            },
          },
        }),
      );
      return completed({ stdout: "[Success]" });
    }
    if (first === "-v") return completed({ stdout: "Ver: 3.1.0a\n" });
    if (first === "list") {
      return this.result(
        this.scenario.targetOutcomes?.[this.targetCalls++] ??
          this.scenario.targets ??
          completed({ stdout: `${RAW_DEVICE}\n` }),
      );
    }
    if (first === "-t" && request.args[3] === "echo") {
      return this.result(
        this.scenario.challenge ?? completed({ stdout: `${CHALLENGE}\n` }),
      );
    }
    if (
      first === "-t" &&
      request.args[3] === "bm" &&
      request.args[5] === "-a"
    ) {
      return this.result(
        this.scenario.presenceOutcomes?.[this.presenceCalls++] ??
          this.scenario.presence ??
          completed({ stdout: "\tcom.example.other\n" }),
      );
    }
    if (
      first === "-t" &&
      request.args[3] === "bm" &&
      request.args[5] === "-n"
    ) {
      return completed({
        stdout: `${BUNDLE}:\n${JSON.stringify({
          name: BUNDLE,
          versionCode: 7,
          versionName: "1.2.3",
          moduleNames: ["entry"],
        })}\n`,
      });
    }
    if (first === "-t" && request.args[2] === "install") {
      return this.result(
        this.scenario.runtime?.install ?? completed({ stdout: "Success\n" }),
      );
    }
    if (
      first === "-t" &&
      request.args[3] === "aa" &&
      request.args[4] === "start"
    ) {
      return this.result(
        this.scenario.runtime?.launch ?? completed({ stdout: "Success\n" }),
      );
    }
    if (
      first === "-t" &&
      request.args[3] === "aa" &&
      request.args[4] === "force-stop"
    ) {
      return this.result(
        this.scenario.runtime?.stop ?? completed({ stdout: "Success\n" }),
      );
    }
    if (first === "-t" && request.args[3] === "hilog") {
      return this.result(
        this.scenario.runtime?.checkpoint ??
          completed({ stdout: "HCHECK_SMOKE_OK\n" }),
      );
    }
    if (first === "-t" && request.args[2] === "uninstall") {
      return this.result(
        this.scenario.runtime?.uninstall ?? completed({ stdout: "Success\n" }),
      );
    }
    throw new Error(`测试未允许的进程调用：${request.args.join(" ")}`);
  }

  private result(outcome: Outcome): ProcessRunResult {
    if (outcome instanceof Error) throw outcome;
    return outcome;
  }
}

class MemoryDeviceFiles {
  public constructor(private readonly files: ReadonlyMap<string, Uint8Array>) {}

  public async readFile(file: string): Promise<Uint8Array> {
    const bytes = this.files.get(file);
    if (bytes === undefined) throw new Error("缺少测试输入。");
    return bytes;
  }
}

class TestHash implements HashPort {
  public async sha256(
    content: string | Uint8Array,
  ): Promise<`sha256:${string}`> {
    return `sha256:${createHash("sha256").update(content).digest("hex")}`;
  }
}

function deviceRunArguments(
  mode: "--dry-run" | "--preflight-only" | "--confirm-device-actions",
  extras: readonly string[] = [],
): string[] {
  return [
    "verify",
    "run",
    "--flow",
    "/private/flow.yml",
    "--artifact",
    "/private/app.hap",
    "--bundle",
    BUNDLE,
    "--ability",
    "EntryAbility",
    "--module",
    "entry",
    "--version-name",
    "1.2.3",
    "--version-code",
    "7",
    "--device-kind",
    "physical",
    "--hilog-tag",
    "HCHECK",
    "--hilog-marker",
    "HCHECK_SMOKE_OK",
    "--hdc",
    "/private/hdc",
    "--java",
    "/private/java",
    "--hap-sign-tool",
    "/private/hap-sign-tool.jar",
    mode,
    ...extras,
  ];
}

function devicePorts(
  root: string,
  runner: ProcessRunnerPort,
  options: {
    readonly flow?: Buffer;
    readonly hap?: Buffer;
    readonly jar?: Buffer;
    readonly clock?: DeviceVerificationPorts["clock"];
    readonly runtimeFlow?: DeviceVerificationPorts["runtimeFlow"];
  } = {},
): DeviceVerificationPorts {
  return {
    fs: new MemoryDeviceFiles(
      new Map([
        ["/private/flow.yml", options.flow ?? SMOKE_FLOW],
        ["/private/app.hap", options.hap ?? HAP_BYTES],
        ["/private/hap-sign-tool.jar", options.jar ?? JAR_BYTES],
      ]),
    ),
    runner,
    hash: new TestHash(),
    clock: options.clock ?? { now: () => new Date("2026-07-15T12:00:00.000Z") },
    runId: { next: () => RUN_ID },
    challenge: { next: () => CHALLENGE },
    workspaceRoot: root,
    temporaryParent: root,
    ...(options.runtimeFlow === undefined
      ? {}
      : { runtimeFlow: options.runtimeFlow }),
  };
}

async function invokeDeviceCli(
  args: readonly string[],
  ports: DeviceVerificationPorts,
): Promise<{
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}> {
  let stdout = "";
  let stderr = "";
  const code = await runVerify(args, {
    fs: { readText: async () => "unexpected" },
    deviceVerification: ports,
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
  });
  return { code, stdout, stderr };
}

async function createCliPreflight(root: string): Promise<{
  readonly path: string;
  readonly sha256: string;
}> {
  const result = await invokeDeviceCli(
    deviceRunArguments("--preflight-only", ["--format", "json"]),
    devicePorts(root, new PreflightFakeRunner()),
  );
  assert.equal(result.code, 0);
  assert.equal(result.stderr, "");
  return (
    JSON.parse(result.stdout) as {
      preflight: { path: string; sha256: string };
    }
  ).preflight;
}

function confirmArguments(preflight: {
  readonly path: string;
  readonly sha256: string;
}): string[] {
  return deviceRunArguments("--confirm-device-actions", [
    "--preflight",
    preflight.path,
    "--preflight-sha256",
    preflight.sha256,
    "--format",
    "json",
  ]);
}

function assertSafeDeviceCliOutput(
  result: { readonly stdout: string; readonly stderr: string },
  root: string,
): void {
  for (const sensitive of [
    root,
    "/private/",
    RAW_DEVICE,
    "developer-secret-must-not-leak",
    "device-secret-must-not-leak",
    "PRIVATE_TOOL_LOG",
  ]) {
    assert.ok(!result.stdout.includes(sensitive), sensitive);
    assert.ok(!result.stderr.includes(sensitive), sensitive);
  }
}

async function cleanupDeviceWorkspace(root: string): Promise<void> {
  await unlink(
    path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json"),
  ).catch(() => undefined);
  await unlink(
    path.join(root, ".hcheck", "evidence", RUN_ID, "hilog", "checkpoint.log"),
  ).catch(() => undefined);
  await rmdir(path.join(root, ".hcheck", "evidence", RUN_ID, "hilog")).catch(
    () => undefined,
  );
  await rmdir(path.join(root, ".hcheck", "evidence", RUN_ID)).catch(
    () => undefined,
  );
  await rmdir(path.join(root, ".hcheck", "evidence")).catch(() => undefined);
  await unlink(path.join(root, ".hcheck", "preflight", `${RUN_ID}.json`)).catch(
    () => undefined,
  );
  await rmdir(path.join(root, ".hcheck", "preflight")).catch(() => undefined);
  await rmdir(path.join(root, ".hcheck")).catch(() => undefined);
  await rmdir(root);
}

function replayManifest() {
  return {
    schemaVersion: "1.0.0",
    runId: "run-replay-cli",
    flow: { id: "account-delete", version: 1 },
    hcheckVersion: "0.6.0",
    rulePackVersion: "hcheck-p0@0.6.0",
    artifact: {
      uri: "artifacts/account-delete.hap",
      sha256: SHA_A,
      bundleName: "com.example.account",
    },
    device: {
      id: "device:account-stub",
      model: "Replay Test",
      osVersion: "HarmonyOS NEXT test",
      capabilities: ["hilog", "screenshot", "test_account_stub"],
    },
    archiveRoot: ".hcheck/runtime/run-replay-cli",
    timeline: [
      {
        stepId: "request-account-delete",
        action: "invoke_test_hook",
        attempts: 1,
        status: "PASSED",
        result: "ok",
        summary: "本地测试桩接受注销请求。",
      },
    ],
    assertions: [
      {
        id: "old-token-rejected",
        type: "old_token_invalidated",
        status: "PASSED",
        summary: "旧会话摘要已被拒绝。",
      },
    ],
    files: [
      {
        path: "runtime/account-delete.log",
        mediaType: "text/plain",
        sizeBytes: 42,
        sha256: SHA_A,
        redacted: true,
        sourceStepId: "request-account-delete",
      },
    ],
    redaction: {
      applied: true,
      totalReplacements: 0,
      categories: {},
    },
    startedAt: "2026-07-11T00:00:00Z",
    completedAt: "2026-07-11T00:00:00Z",
  };
}

test("verify replay 只读渲染运行回放 JSON 且不泄露路径或秘密", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-replay-"));
  const manifest = path.join(directory, "manifest.json");
  try {
    await writeFile(manifest, JSON.stringify(replayManifest(), null, 2));
    let stdout = "",
      stderr = "";

    const code = await runVerify(
      ["verify", "replay", manifest, "--format", "json"],
      {
        fs: new NodeFileSystem(),
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );

    const replay = JSON.parse(stdout) as {
      readOnly: boolean;
      runId: string;
      flow: { id: string };
      summary: { evidenceFiles: number };
      evidenceFiles: readonly { path: string }[];
    };
    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.equal(replay.readOnly, true);
    assert.equal(replay.runId, "run-replay-cli");
    assert.equal(replay.flow.id, "account-delete");
    assert.equal(replay.summary.evidenceFiles, 1);
    assert.equal(replay.evidenceFiles[0]?.path, "runtime/account-delete.log");
    assert.ok(!stdout.includes(directory));
    assert.ok(!stdout.includes("token="));
  } finally {
    await unlink(manifest);
    await rmdir(directory);
  }
});

test("verify replay 拒绝不安全 manifest 且错误不回显本机路径", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-replay-bad-"));
  const manifest = path.join(directory, "manifest.json");
  try {
    await writeFile(
      manifest,
      JSON.stringify({
        ...replayManifest(),
        device: { ...replayManifest().device, id: "RAW-SERIAL" },
      }),
    );
    let stdout = "",
      stderr = "";

    const code = await runVerify(["verify", "replay", manifest], {
      fs: new NodeFileSystem(),
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });

    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.match(stderr, /脱敏|设备/u);
    assert.ok(!stderr.includes(directory));
  } finally {
    await unlink(manifest);
    await rmdir(directory);
  }
});

test("verify run dry-run 复用既有零外部调用计划", async () => {
  const flow = `id: device-smoke
version: 1
name: 设备冒烟验收
requires:
  clean_install: true
  network_observation: none
  test_account: false
variables:
  artifact: \${artifact}
steps:
  - id: install
    action: install
    package: \${artifact}
  - id: launch
    action: launch
  - id: checkpoint
    action: checkpoint
  - id: stop
    action: stop
  - id: uninstall
    action: uninstall
assertions:
  - id: hilog-marker
    type: hilog_contains_marker
    after_step: checkpoint
    severity: BLOCKER
evidence:
  screenshot: never
  video: never
  hilog: true
  network_timeline: none
  permission_timeline: false
`;
  let stdout = "";
  let stderr = "";

  const code = await runVerify(
    [
      "verify",
      "run",
      "--flow",
      "device-smoke.yml",
      "--artifact",
      "device-smoke.hap",
      "--bundle",
      "com.example.hcheck.smoke",
      "--ability",
      "EntryAbility",
      "--module",
      "entry",
      "--version-name",
      "1.2.3",
      "--version-code",
      "7",
      "--device-kind",
      "emulator",
      "--hilog-tag",
      "HCHECK",
      "--hilog-marker",
      "HCHECK_SMOKE_OK",
      "--hdc",
      "/private/hdc",
      "--java",
      "/private/java",
      "--hap-sign-tool",
      "/private/hap-sign-tool.jar",
      "--dry-run",
      "--format",
      "json",
    ],
    {
      fs: { readText: async () => flow },
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    },
  );

  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(JSON.parse(stdout).mode, "dry_run");
  assert.ok(!stdout.includes("/private/"));
});

test("verify run 在未注入设备端口时拒绝 preflight 与 confirm，且不读取输入", async () => {
  const common = [
    "verify",
    "run",
    "--flow",
    "/private/device-smoke.yml",
    "--artifact",
    "/private/device-smoke.hap",
    "--bundle",
    "com.example.hcheck.smoke",
    "--ability",
    "EntryAbility",
    "--module",
    "entry",
    "--version-name",
    "1.2.3",
    "--version-code",
    "7",
    "--device-kind",
    "emulator",
    "--hilog-tag",
    "HCHECK",
    "--hilog-marker",
    "HCHECK_SMOKE_OK",
    "--hdc",
    "/private/hdc",
    "--java",
    "/private/java",
    "--hap-sign-tool",
    "/private/hap-sign-tool.jar",
  ];

  for (const args of [
    [...common, "--preflight-only"],
    [
      ...common,
      "--preflight",
      ".hcheck/preflight/run-1.json",
      "--preflight-sha256",
      `sha256:${"a".repeat(64)}`,
      "--confirm-device-actions",
    ],
  ]) {
    let reads = 0;
    let stdout = "";
    let stderr = "";

    const code = await runVerify(args, {
      fs: {
        readText: async () => {
          reads += 1;
          return "unexpected";
        },
      },
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });

    assert.equal(code, 4);
    assert.equal(reads, 0);
    assert.equal(stdout, "");
    assert.match(stderr, /受控设备验证端口/u);
    assert.ok(!stderr.includes("/private/"));
  }
});

test("verify run preflight 经 FakeRunner 写入后只公开相对路径、哈希和过期时间", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-preflight-"));
  const runner = new PreflightFakeRunner();
  let stdout = "";
  let stderr = "";
  try {
    const code = await runVerify(
      deviceRunArguments("--preflight-only", ["--format", "json"]),
      {
        fs: {
          readText: async () => {
            throw new Error("preflight 不应通过 replay 文件端口读取。");
          },
        },
        deviceVerification: devicePorts(root, runner),
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );

    const result = JSON.parse(stdout) as {
      mode: string;
      preflight: { path: string; sha256: string; expiresAt: string };
    };
    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.deepEqual(Object.keys(result), ["mode", "preflight"]);
    assert.equal(result.mode, "preflight_only");
    assert.deepEqual(Object.keys(result.preflight), [
      "path",
      "sha256",
      "expiresAt",
    ]);
    assert.equal(result.preflight.path, `.hcheck/preflight/${RUN_ID}.json`);
    assert.match(result.preflight.sha256, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(result.preflight.expiresAt, "2026-07-15T12:15:00.000Z");
    assert.equal(
      runner.requests.some(({ args }) =>
        args.some((value) =>
          ["install", "start", "force-stop", "uninstall", "hilog"].includes(
            value,
          ),
        ),
      ),
      false,
    );
    for (const sensitive of [
      root,
      "/private/",
      RAW_DEVICE,
      "developer-secret-must-not-leak",
      "device-secret-must-not-leak",
    ]) {
      assert.ok(!stdout.includes(sensitive));
    }
  } finally {
    await unlink(
      path.join(root, ".hcheck", "preflight", `${RUN_ID}.json`),
    ).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck", "preflight")).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck")).catch(() => undefined);
    await rmdir(root);
  }
});

test("verify run confirm 经第二个 FakeRunner 返回最小 PASS 状态与退出码", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-confirm-"));
  let preflightOutput = "";
  let stdout = "";
  let stderr = "";
  const preflightRunner = new PreflightFakeRunner();
  const confirmationRunner = new PreflightFakeRunner();
  try {
    const preflightCode = await runVerify(
      deviceRunArguments("--preflight-only", ["--format", "json"]),
      {
        fs: { readText: async () => "unexpected" },
        deviceVerification: devicePorts(root, preflightRunner),
        stdout: (value) => {
          preflightOutput += value;
        },
        stderr: () => undefined,
      },
    );
    const preflight = JSON.parse(preflightOutput) as {
      preflight: { path: string; sha256: string };
    };
    assert.equal(preflightCode, 0);

    const code = await runVerify(
      deviceRunArguments("--confirm-device-actions", [
        "--preflight",
        preflight.preflight.path,
        "--preflight-sha256",
        preflight.preflight.sha256,
        "--format",
        "json",
      ]),
      {
        fs: { readText: async () => "unexpected" },
        deviceVerification: devicePorts(root, confirmationRunner),
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );

    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.deepEqual(JSON.parse(stdout), {
      mode: "confirm_device_actions",
      status: "PASS",
      exitCode: 0,
    });
    for (const action of [
      "install",
      "start",
      "hilog",
      "force-stop",
      "uninstall",
    ]) {
      assert.ok(
        confirmationRunner.requests.some(({ args }) => args.includes(action)),
        action,
      );
    }
    for (const sensitive of [root, "/private/", RAW_DEVICE]) {
      assert.ok(!stdout.includes(sensitive));
      assert.ok(!stderr.includes(sensitive));
    }
  } finally {
    await unlink(
      path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json"),
    ).catch(() => undefined);
    await unlink(
      path.join(root, ".hcheck", "evidence", RUN_ID, "hilog", "checkpoint.log"),
    ).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck", "evidence", RUN_ID, "hilog")).catch(
      () => undefined,
    );
    await rmdir(path.join(root, ".hcheck", "evidence", RUN_ID)).catch(
      () => undefined,
    );
    await rmdir(path.join(root, ".hcheck", "evidence")).catch(() => undefined);
    await unlink(
      path.join(root, ".hcheck", "preflight", `${RUN_ID}.json`),
    ).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck", "preflight")).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck")).catch(() => undefined);
    await rmdir(root);
  }
});

test("verify run preflight 对验签和包元数据失败仅返回安全失败结果", async () => {
  const cases: readonly [string, (root: string) => DeviceVerificationPorts][] =
    [
      [
        "验签伪成功",
        (root) =>
          devicePorts(
            root,
            new PreflightFakeRunner({
              verifyApp: completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" }),
            }),
          ),
      ],
      [
        "包元数据损坏",
        (root) =>
          devicePorts(root, new PreflightFakeRunner(), {
            hap: Buffer.from("not-a-hap"),
          }),
      ],
    ];

  for (const [label, createPorts] of cases) {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "hcheck-cli-preflight-red-"),
    );
    try {
      const result = await invokeDeviceCli(
        deviceRunArguments("--preflight-only", ["--format", "json"]),
        createPorts(root),
      );
      assert.equal(result.code, 4, label);
      assert.equal(result.stdout, "", label);
      assert.equal(result.stderr, "设备预检未完成。\n", label);
      assertSafeDeviceCliOutput(result, root);
    } finally {
      await cleanupDeviceWorkspace(root);
    }
  }
});

test("verify run confirm 的绑定、设备、Bundle、断线、运行异常和清理失败均收敛为最小 INCOMPLETE", async () => {
  const cases: readonly [
    string,
    (preflight: { readonly path: string; readonly sha256: string }) => string[],
    (root: string) => DeviceVerificationPorts,
  ][] = [
    [
      "预检哈希替换",
      (preflight) =>
        confirmArguments({
          ...preflight,
          sha256: `sha256:${"f".repeat(64)}`,
        }),
      (root) => devicePorts(root, new PreflightFakeRunner()),
    ],
    [
      "预检过期",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(root, new PreflightFakeRunner(), {
          clock: { now: () => new Date("2026-07-15T12:15:00.001Z") },
        }),
    ],
    [
      "Flow 替换",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(root, new PreflightFakeRunner(), {
          flow: Buffer.from("invalid: [flow"),
        }),
    ],
    [
      "HAP 替换",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(root, new PreflightFakeRunner(), {
          hap: Buffer.from("replacement-hap"),
        }),
    ],
    [
      "JAR 替换",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(root, new PreflightFakeRunner(), {
          jar: Buffer.from("replacement-jar"),
        }),
    ],
    [
      "设备替换",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(
          root,
          new PreflightFakeRunner({
            targets: completed({ stdout: "198.51.100.20:8710\n" }),
          }),
        ),
    ],
    [
      "Bundle 已存在",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(
          root,
          new PreflightFakeRunner({
            presence: completed({ stdout: `\t${BUNDLE}\n` }),
          }),
        ),
    ],
    [
      "目标断线",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(
          root,
          new PreflightFakeRunner({
            targets: completed({ stdout: "[Empty]\n" }),
          }),
        ),
    ],
    [
      "运行时异常",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(root, new PreflightFakeRunner(), {
          runtimeFlow: async () => {
            throw new Error("PRIVATE_TOOL_LOG runtime");
          },
        }),
    ],
    [
      "清理后的最终状态查询失败",
      (preflight) => confirmArguments(preflight),
      (root) =>
        devicePorts(
          root,
          new PreflightFakeRunner({
            presenceOutcomes: [
              completed({ stdout: "\tcom.example.other\n" }),
              completed({ stdout: "\tcom.example.other\n" }),
              completed({ exitCode: 1, stderr: "PRIVATE_TOOL_LOG final" }),
            ],
          }),
        ),
    ],
  ];

  for (const [label, createArgs, createPorts] of cases) {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "hcheck-cli-confirm-red-"),
    );
    try {
      const preflight = await createCliPreflight(root);
      const result = await invokeDeviceCli(
        createArgs(preflight),
        createPorts(root),
      );
      assert.equal(result.code, 4, label);
      assert.equal(result.stderr, "", label);
      assert.deepEqual(JSON.parse(result.stdout), {
        mode: "confirm_device_actions",
        status: "INCOMPLETE",
        exitCode: 4,
      });
      assertSafeDeviceCliOutput(result, root);
    } finally {
      await cleanupDeviceWorkspace(root);
    }
  }
});

test("verify run confirm 对五个动作的 [Fail] 与标准 HDC 错误码均返回安全 INCOMPLETE", async () => {
  const failures: readonly [RuntimeAction, string, ProcessRunResult][] = [
    [
      "install",
      "exit0+[Fail]",
      completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" }),
    ],
    [
      "install",
      "exit1+[E123456]",
      completed({ exitCode: 1, stderr: "[E123456] PRIVATE_TOOL_LOG" }),
    ],
    [
      "launch",
      "exit0+[Fail]",
      completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" }),
    ],
    [
      "launch",
      "exit1+[E123456]",
      completed({ exitCode: 1, stderr: "[E123456] PRIVATE_TOOL_LOG" }),
    ],
    [
      "checkpoint",
      "exit0+[Fail]",
      completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" }),
    ],
    [
      "checkpoint",
      "exit1+[E123456]",
      completed({ exitCode: 1, stderr: "[E123456] PRIVATE_TOOL_LOG" }),
    ],
    ["stop", "exit0+[Fail]", completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" })],
    [
      "stop",
      "exit1+[E123456]",
      completed({ exitCode: 1, stderr: "[E123456] PRIVATE_TOOL_LOG" }),
    ],
    [
      "uninstall",
      "exit0+[Fail]",
      completed({ stdout: "[Fail] PRIVATE_TOOL_LOG" }),
    ],
    [
      "uninstall",
      "exit1+[E123456]",
      completed({ exitCode: 1, stderr: "[E123456] PRIVATE_TOOL_LOG" }),
    ],
  ];

  for (const [action, shape, failure] of failures) {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "hcheck-cli-action-red-"),
    );
    try {
      const preflight = await createCliPreflight(root);
      const runner = new PreflightFakeRunner({
        runtime: { [action]: failure },
      });
      const result = await invokeDeviceCli(
        confirmArguments(preflight),
        devicePorts(root, runner),
      );
      assert.equal(result.code, 4, `${action}/${shape}`);
      assert.equal(result.stderr, "", `${action}/${shape}`);
      assert.deepEqual(JSON.parse(result.stdout), {
        mode: "confirm_device_actions",
        status: "INCOMPLETE",
        exitCode: 4,
      });
      assert.ok(
        runner.requests.some(({ args }) =>
          args.some((value) =>
            action === "launch"
              ? value === "start"
              : action === "checkpoint"
                ? value === "hilog"
                : action === "stop"
                  ? value === "force-stop"
                  : value === action,
          ),
        ),
        `${action}/${shape}`,
      );
      assertSafeDeviceCliOutput(result, root);
    } finally {
      await cleanupDeviceWorkspace(root);
    }
  }
});

test("verify run confirm 在已安装后 session cleanup 卸载失败时不写 manifest", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-cleanup-red-"));
  const runner = new PreflightFakeRunner({
    runtime: {
      launch: completed({ stdout: "[Fail] PRIVATE_TOOL_LOG launch" }),
      uninstall: completed({
        exitCode: 1,
        stderr: "[E123456] PRIVATE_TOOL_LOG cleanup",
      }),
    },
    presenceOutcomes: [
      completed({ stdout: "\tcom.example.other\n" }),
      completed({ stdout: "\tcom.example.other\n" }),
      completed({ stdout: "\tcom.example.other\n" }),
      completed({ stdout: `\t${BUNDLE}\n` }),
      completed({ stdout: "\tcom.example.other\n" }),
    ],
  });
  try {
    const preflight = await createCliPreflight(root);
    const result = await invokeDeviceCli(
      confirmArguments(preflight),
      devicePorts(root, runner),
    );

    assert.equal(result.code, 4);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      mode: "confirm_device_actions",
      status: "INCOMPLETE",
      exitCode: 4,
    });
    assert.ok(
      runner.requests.some(
        ({ args }) => args.includes("start") && args.includes("aa"),
      ),
    );
    assert.ok(runner.requests.some(({ args }) => args.includes("uninstall")));
    await assert.rejects(
      readFile(path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json")),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
    assertSafeDeviceCliOutput(result, root);
  } finally {
    await cleanupDeviceWorkspace(root);
  }
});

interface ZipEntry {
  readonly name: string;
  readonly content: string | Uint8Array;
}

function zip(entries: readonly ZipEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name);
    const content = Buffer.from(entry.content);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(content.length, 18);
    local.writeUInt32LE(content.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, content);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(content.length, 20);
    central.writeUInt32LE(content.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);
    offset += local.length + name.length + content.length;
  }
  const centralSize = centralParts.reduce((sum, part) => sum + part.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, ...centralParts, end]);
}
