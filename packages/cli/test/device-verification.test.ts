import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rmdir,
  stat,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type {
  HashPort,
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
  RuntimeFlowRunResult,
} from "@hcheck/core";
import {
  collectDevicePreflightBinding,
  DeviceVerificationError,
  exitCodeForDeviceRuntimeStatus,
  runDeviceConfirmation,
  runDevicePreflight,
  type DeviceVerificationPorts,
} from "../src/device-verification.js";
import type { VerifyRunArguments } from "../src/verify-run.js";
import { TEST_LEAF_CERTIFICATE_PEM } from "./test-leaf-certificate.js";

const FLOW_PATH = "/private/SECRET/device-smoke.yml";
const HAP_PATH = "/private/SECRET/release.hap";
const JAR_PATH = "/private/SECRET/hap-sign-tool.jar";
const RAW_KEY = "192.0.2.10:8710";
const CHANGED_RAW_KEY = "198.51.100.9:8710";
const CHALLENGE = "hcheck-challenge-0123456789abcdef";
const RUN_ID = "run-7d1-001";
const BUNDLE = "com.example.hcheck.smoke";
const SIGNER_PEM = TEST_LEAF_CERTIFICATE_PEM;
const SIGNER_DER = new X509Certificate(SIGNER_PEM).raw;
const NOW = new Date("2026-07-15T12:00:00.000Z");
const NOT_BEFORE = 1_700_000_000;
const NOT_AFTER = 2_000_000_000;
const JAR_BYTES = Buffer.from("stable-hap-sign-tool");
const FLOW_BYTES = Buffer.from(`id: device-smoke
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

interface RunnerScenario {
  readonly javaVersion?: Outcome;
  readonly verifyApp?: Outcome;
  readonly verifyProfile?: Outcome;
  readonly hdcVersion?: Outcome;
  readonly targets?: Outcome;
  readonly targetOutcomes?: readonly Outcome[];
  readonly challenge?: Outcome;
  readonly presence?: Outcome;
  readonly presenceOutcomes?: readonly Outcome[];
  readonly runtime?: Partial<Record<RuntimeAction, Outcome>>;
  readonly replaceRuntimeArtifact?: boolean;
  readonly profileBytes?: string;
}

type RuntimeAction = "install" | "launch" | "checkpoint" | "stop" | "uninstall";

class FakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];
  public readonly signatureInputs: Array<{
    readonly hap: Buffer;
    readonly jar: Buffer;
  }> = [];
  public readonly runtimeArtifacts: Array<{
    readonly hap: Buffer;
    readonly mode: number;
    readonly directoryMode: number;
    readonly cwd: string;
  }> = [];
  private targetCalls = 0;
  private presenceCalls = 0;

  public constructor(private readonly scenario: RunnerScenario = {}) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    const [first, second, third] = request.args;
    let outcome: Outcome;
    if (first === "-version") {
      outcome =
        this.scenario.javaVersion ??
        completed({ stderr: 'openjdk version "17.0.12" 2024-07-16\n' });
    } else if (first === "-jar" && third === "verify-app") {
      assert.ok(request.cwd);
      this.signatureInputs.push({
        hap: await readFile(path.join(request.cwd, "artifact.hap")),
        jar: await readFile(path.join(request.cwd, "hap-sign-tool.jar")),
      });
      await writeFile(path.join(request.cwd, "cert-chain.cer"), SIGNER_PEM);
      await writeFile(
        path.join(request.cwd, "profile.p7b"),
        this.scenario.profileBytes ?? "signed-profile",
      );
      outcome = this.scenario.verifyApp ?? completed({ stdout: "[Success]" });
    } else if (first === "-jar" && third === "verify-profile") {
      assert.ok(request.cwd);
      await writeFile(
        path.join(request.cwd, "profile-verification.json"),
        JSON.stringify({
          verifiedPassed: true,
          message: "OK",
          content: {
            type: "debug",
            validity: {
              "not-before": NOT_BEFORE,
              "not-after": NOT_AFTER,
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
      outcome =
        this.scenario.verifyProfile ?? completed({ stdout: "[Success]" });
    } else if (first === "-v") {
      outcome =
        this.scenario.hdcVersion ?? completed({ stdout: "Ver: 3.1.0a\n" });
    } else if (first === "list" && second === "targets") {
      outcome =
        this.scenario.targetOutcomes?.[this.targetCalls++] ??
        this.scenario.targets ??
        completed({ stdout: `${RAW_KEY}\n` });
    } else if (first === "-t" && third === "shell") {
      if (request.args[3] === "echo") {
        outcome =
          this.scenario.challenge ?? completed({ stdout: `${CHALLENGE}\n` });
      } else if (
        request.args[3] === "bm" &&
        request.args[4] === "dump" &&
        request.args[5] === "-n"
      ) {
        outcome = completed({
          stdout: `${BUNDLE}:\n${JSON.stringify({
            name: BUNDLE,
            versionCode: 7,
            versionName: "1.2.3",
            moduleNames: ["entry"],
          })}\n`,
        });
      } else if (request.args[3] === "hilog") {
        outcome =
          this.scenario.runtime?.checkpoint ??
          completed({ stdout: `${CHALLENGE} ${"HCHECK_SMOKE_OK"}\n` });
      } else if (request.args[3] === "aa" && request.args[4] === "start") {
        outcome =
          this.scenario.runtime?.launch ?? completed({ stdout: "Success\n" });
      } else if (request.args[3] === "aa" && request.args[4] === "force-stop") {
        outcome =
          this.scenario.runtime?.stop ?? completed({ stdout: "Success\n" });
      } else {
        outcome =
          this.scenario.presenceOutcomes?.[this.presenceCalls++] ??
          this.scenario.presence ??
          completed({ stdout: "\tcom.example.other\n" });
      }
    } else if (first === "-t" && second === RAW_KEY && third === "install") {
      assert.deepEqual(request.args, [
        "-t",
        RAW_KEY,
        "install",
        "artifact.hap",
      ]);
      assert.ok(request.cwd);
      const details = await stat(path.join(request.cwd, "artifact.hap"));
      this.runtimeArtifacts.push({
        hap: await readFile(path.join(request.cwd, "artifact.hap")),
        mode: details.mode & 0o777,
        directoryMode: (await stat(request.cwd)).mode & 0o777,
        cwd: request.cwd,
      });
      if (this.scenario.replaceRuntimeArtifact === true) {
        await unlink(path.join(request.cwd, "artifact.hap"));
        await writeFile(path.join(request.cwd, "artifact.hap"), "replacement");
      }
      outcome =
        this.scenario.runtime?.install ?? completed({ stdout: "Success\n" });
    } else if (
      first === "-t" &&
      second === RAW_KEY &&
      (third === "uninstall" || (third === "shell" && request.args[3] === "aa"))
    ) {
      outcome =
        third === "uninstall"
          ? (this.scenario.runtime?.uninstall ??
            completed({ stdout: "Success\n" }))
          : completed({ stdout: "Success\n" });
    } else {
      throw new Error(`测试不允许的命令：${request.args.join(" ")}`);
    }
    if (outcome instanceof Error) throw outcome;
    return outcome;
  }
}

class ReadOnceFileSystem {
  public readonly reads = new Map<string, number>();

  public constructor(private readonly files: ReadonlyMap<string, Uint8Array>) {}

  public async readFile(file: string): Promise<Uint8Array> {
    this.reads.set(file, (this.reads.get(file) ?? 0) + 1);
    const bytes = this.files.get(file);
    if (bytes === undefined) throw new Error(`secret missing path: ${file}`);
    return bytes;
  }
}

class RecordingHash implements HashPort {
  public readonly inputs: Buffer[] = [];

  public async sha256(
    content: string | Uint8Array,
  ): Promise<`sha256:${string}`> {
    const bytes = Buffer.from(content);
    this.inputs.push(bytes);
    return digest(bytes);
  }
}

function digest(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function failedRuntimeResult(): RuntimeFlowRunResult {
  return {
    status: "FAILED",
    failure: {
      kind: "FLOW_ASSERTION_FAILED",
      assertionId: "marker",
      summary: "业务断言失败。",
    },
    timeline: [],
    assertions: [],
    evidenceManifest: {
      schemaVersion: "1.0.0",
      runId: RUN_ID,
      flow: { id: "device-smoke", version: 1 },
      hcheckVersion: "0.6.0",
      rulePackVersion: "device-smoke-1",
      artifact: {
        uri: "artifact.hap",
        sha256: digest(validHap()),
        bundleName: BUNDLE,
        versionName: "1.2.3",
        versionCode: 7,
      },
      device: {
        id: `device:sha256:${createHash("sha256").update(RAW_KEY).digest("hex")}`,
        kind: "physical",
        model: "HCheck runtime device",
        osVersion: "unknown",
        capabilities: [],
      },
      archiveRoot: `.hcheck/evidence/${RUN_ID}`,
      files: [],
      redaction: { applied: true, totalReplacements: 0, categories: {} },
      startedAt: NOW.toISOString(),
      completedAt: NOW.toISOString(),
    },
  };
}

function validHap(
  overrides: {
    readonly bundleName?: string;
    readonly versionName?: string;
    readonly versionCode?: number;
    readonly moduleName?: string;
    readonly incomplete?: boolean;
  } = {},
): Buffer {
  if (overrides.incomplete === true) {
    return zip([{ name: "README.txt", content: "missing manifest" }]);
  }
  return zip([
    {
      name: "module.json",
      content: JSON.stringify({
        app: {
          bundleName: overrides.bundleName ?? BUNDLE,
          versionName: overrides.versionName ?? "1.2.3",
          versionCode: overrides.versionCode ?? 7,
        },
        module: {
          name: overrides.moduleName ?? "entry",
          type: "entry",
          packageName: "entry",
          deviceTypes: ["phone"],
        },
      }),
    },
  ]);
}

function argumentsFor(
  overrides: Partial<VerifyRunArguments> = {},
): VerifyRunArguments {
  return {
    mode: "preflight_only",
    flowPath: FLOW_PATH,
    artifactPath: HAP_PATH,
    bundleName: BUNDLE,
    abilityName: "EntryAbility",
    moduleName: "entry",
    versionName: "1.2.3",
    versionCode: 7,
    deviceKind: "physical",
    hilogTag: "HCHECK",
    hilogMarker: "HCHECK_SMOKE_OK",
    hdcPath: "/safe/hdc",
    javaPath: "/safe/java",
    hapSignToolPath: JAR_PATH,
    format: "json",
    ...overrides,
  };
}

function portsFor(
  root: string,
  runner: ProcessRunnerPort,
  options: {
    readonly hap?: Buffer;
    readonly flow?: Buffer;
    readonly jar?: Buffer;
    readonly fs?: ReadOnceFileSystem;
    readonly hash?: RecordingHash;
    readonly workspaceRoot?: string;
    readonly clock?: DeviceVerificationPorts["clock"];
  } = {},
): DeviceVerificationPorts & {
  readonly fs: ReadOnceFileSystem;
  readonly hash: RecordingHash;
} {
  const fs =
    options.fs ??
    new ReadOnceFileSystem(
      new Map([
        [FLOW_PATH, options.flow ?? FLOW_BYTES],
        [HAP_PATH, options.hap ?? validHap()],
        [JAR_PATH, options.jar ?? JAR_BYTES],
      ]),
    );
  const hash = options.hash ?? new RecordingHash();
  return {
    fs,
    runner,
    hash,
    clock: options.clock ?? { now: () => new Date(NOW) },
    runId: { next: () => RUN_ID },
    challenge: { next: () => CHALLENGE },
    workspaceRoot: options.workspaceRoot ?? root,
    temporaryParent: root,
  };
}

async function createRoot(label: string): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), `hcheck-7d1-${label}-`));
}

async function cleanupRoot(root: string, runId?: string): Promise<void> {
  if (runId !== undefined) {
    await unlink(
      path.join(root, ".hcheck", "evidence", runId, "manifest.json"),
    ).catch(() => undefined);
    await unlink(
      path.join(root, ".hcheck", "evidence", runId, "hilog", "checkpoint.log"),
    ).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck", "evidence", runId, "hilog")).catch(
      () => undefined,
    );
    await rmdir(path.join(root, ".hcheck", "evidence", runId)).catch(
      () => undefined,
    );
    await rmdir(path.join(root, ".hcheck", "evidence")).catch(() => undefined);
    await unlink(
      path.join(root, ".hcheck", "preflight", `${runId}.json`),
    ).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck", "preflight")).catch(() => undefined);
    await rmdir(path.join(root, ".hcheck")).catch(() => undefined);
  }
  assert.deepEqual(await readdir(root), []);
  await rmdir(root);
}

function hasDeviceWrite(runner: FakeRunner): boolean {
  return runner.requests.some(({ args }) =>
    args.some((value) =>
      ["install", "start", "force-stop", "uninstall", "hilog"].includes(value),
    ),
  );
}

function hasRuntimeAction(runner: FakeRunner, action: RuntimeAction): boolean {
  const expected =
    action === "launch"
      ? "start"
      : action === "checkpoint"
        ? "hilog"
        : action === "stop"
          ? "force-stop"
          : action;
  return runner.requests.some(({ args }) => args.includes(expected));
}

function bundleQueryCount(runner: FakeRunner): number {
  return runner.requests.filter(
    ({ args }) =>
      args.includes("bm") && args.includes("dump") && args.includes("-a"),
  ).length;
}

test("runDevicePreflight 单次读取三输入，按固定只读顺序形成完整安全绑定并写入记录", async () => {
  const root = await createRoot("success");
  const runner = new FakeRunner();
  const ports = portsFor(root, runner);
  try {
    const result = await runDevicePreflight(argumentsFor(), ports);

    assert.deepEqual(
      [...ports.fs.reads.entries()],
      [
        [FLOW_PATH, 1],
        [HAP_PATH, 1],
        [JAR_PATH, 1],
      ],
    );
    assert.deepEqual(ports.hash.inputs, [FLOW_BYTES, validHap(), JAR_BYTES]);
    assert.deepEqual(runner.signatureInputs, [
      { hap: validHap(), jar: JAR_BYTES },
    ]);
    assert.deepEqual(
      runner.requests.map(({ executable, args }) => ({ executable, args })),
      [
        { executable: "/safe/java", args: ["-version"] },
        {
          executable: "/safe/java",
          args: [
            "-jar",
            "hap-sign-tool.jar",
            "verify-app",
            "-inFile",
            "artifact.hap",
            "-outCertChain",
            "cert-chain.cer",
            "-outProfile",
            "profile.p7b",
          ],
        },
        {
          executable: "/safe/java",
          args: [
            "-jar",
            "hap-sign-tool.jar",
            "verify-profile",
            "-inFile",
            "profile.p7b",
            "-outFile",
            "profile-verification.json",
          ],
        },
        { executable: "/safe/hdc", args: ["-v"] },
        { executable: "/safe/hdc", args: ["list", "targets"] },
        {
          executable: "/safe/hdc",
          args: ["-t", RAW_KEY, "shell", "echo", CHALLENGE],
        },
        {
          executable: "/safe/hdc",
          args: ["-t", RAW_KEY, "shell", "bm", "dump", "-a"],
        },
      ],
    );
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
    assert.deepEqual(result.record.binding, {
      flow: {
        id: "device-smoke",
        version: 1,
        sha256: digest(FLOW_BYTES),
      },
      artifact: {
        sha256: digest(validHap()),
        bundleName: BUNDLE,
        versionName: "1.2.3",
        versionCode: 7,
        moduleNames: ["entry"],
        selectedModule: "entry",
      },
      hapSignTool: {
        sha256: digest(JAR_BYTES),
        javaVersion: "17.0.12",
      },
      signature: {
        profileSha256: digest(Buffer.from("signed-profile")),
        signerCertificateSha256: digest(SIGNER_DER),
        type: "debug",
        validity: { notBefore: NOT_BEFORE, notAfter: NOT_AFTER },
        trustBoundary:
          "仅证明验签工具自包含证书链与 Profile 内容签名一致，不证明 AGC/平台根信任或证书撤销状态。",
      },
      hdcVersion: "3.1.0a",
      device: {
        id: `device:sha256:${createHash("sha256").update(RAW_KEY).digest("hex")}`,
        kind: "physical",
      },
      abilityName: "EntryAbility",
      hilogTag: "HCHECK",
      hilogMarker: "HCHECK_SMOKE_OK",
      bundlePresence: "not_installed",
      actions: ["install", "launch", "checkpoint", "stop", "uninstall"],
    });
    assert.deepEqual(result.written, {
      relativePath: `.hcheck/preflight/${RUN_ID}.json`,
      sha256: digest(
        Buffer.from(`${JSON.stringify(result.record, null, 2)}\n`, "utf8"),
      ),
      expiresAt: "2026-07-15T12:15:00.000Z",
    });
    const publicResult = JSON.stringify(result);
    for (const secret of [
      "/private/SECRET",
      RAW_KEY,
      "developer-secret-must-not-leak",
      "device-secret-must-not-leak",
    ]) {
      assert.ok(!publicResult.includes(secret));
    }
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 首先校验 preflight，路径不存在时零 Runner 调用", async () => {
  const root = await createRoot("confirm-preflight-first");
  const runner = new FakeRunner();
  try {
    assert.deepEqual(
      await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: ".hcheck/preflight/missing.json",
          preflightSha256: digest(Buffer.from("declared")),
        }),
        portsFor(root, runner),
      ),
      { status: "INCOMPLETE", exitCode: 4 },
    );
    assert.equal(runner.requests.length, 0);
  } finally {
    await cleanupRoot(root);
  }
});

test("runDeviceConfirmation 初始 preflight 的用户哈希、TTL 或相对路径无效时零 Runner 调用", async () => {
  const cases: readonly [
    string,
    () => Partial<VerifyRunArguments>,
    (root: string, runner: FakeRunner) => DeviceVerificationPorts,
  ][] = [
    [
      "用户哈希不符",
      () => ({ preflightSha256: digest(Buffer.from("wrong-hash")) }),
      (root, runner) => portsFor(root, runner),
    ],
    [
      "TTL 过期",
      () => ({}),
      (root, runner) =>
        portsFor(root, runner, {
          clock: { now: () => new Date("2026-07-15T12:15:00.001Z") },
        }),
    ],
    [
      "非法相对路径",
      () => ({ preflightPath: "../preflight.json" }),
      (root, runner) => portsFor(root, runner),
    ],
  ];
  for (const [label, override, createPorts] of cases) {
    const root = await createRoot(`confirm-initial-preflight-${label}`);
    try {
      const preflight = await runDevicePreflight(
        argumentsFor(),
        portsFor(root, new FakeRunner()),
      );
      const runner = new FakeRunner();
      const result = await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: preflight.written.relativePath,
          preflightSha256: preflight.written.sha256,
          ...override(),
        }),
        createPorts(root, runner),
      );

      assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 }, label);
      assert.equal(runner.requests.length, 0, label);
    } finally {
      await cleanupRoot(root, RUN_ID);
    }
  }
});

test("exitCodeForDeviceRuntimeStatus 将业务 FAILED 映射为 1", () => {
  assert.equal(exitCodeForDeviceRuntimeStatus("PASS"), 0);
  assert.equal(exitCodeForDeviceRuntimeStatus("FAILED"), 1);
  assert.equal(exitCodeForDeviceRuntimeStatus("INCOMPLETE"), 4);
});

test("runDeviceConfirmation 用第二会话执行固定五步，清理后写 manifest 并返回 PASS", async () => {
  const root = await createRoot("confirm-pass");
  const runner = new FakeRunner();
  const ports = portsFor(root, runner);
  try {
    const preflight = await runDevicePreflight(argumentsFor(), ports);

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      ports,
    );

    assert.deepEqual(result, { status: "PASS", exitCode: 0 });
    assert.deepEqual(runner.runtimeArtifacts, [
      {
        hap: validHap(),
        mode: 0o600,
        directoryMode: 0o700,
        cwd: runner.runtimeArtifacts[0]?.cwd as string,
      },
    ]);
    assert.equal(
      await readFile(
        path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json"),
        "utf8",
      ).then((value) => JSON.parse(value).artifact.uri),
      "artifact.hap",
    );
    await assert.rejects(
      readdir(runner.runtimeArtifacts[0]?.cwd as string),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
    assert.ok(
      runner.requests.filter(({ args }) => args[0] === "-v").length >= 2,
    );
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 的 Runtime 抛错仍清理、终态查询且不写 manifest", async () => {
  const root = await createRoot("confirm-runtime-throw");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner();
    const ports = {
      ...portsFor(root, runner),
      runtimeFlow: async (): Promise<never> => {
        throw new Error(`PRIVATE_RUNTIME_${RAW_KEY}`);
      },
    };

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      ports,
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(hasRuntimeAction(runner, "install"), false);
    assert.equal(bundleQueryCount(runner), 3);
    await assert.rejects(
      readFile(path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json")),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
    assert.ok(
      !(await readdir(root)).some((entry) =>
        entry.startsWith("hcheck-runtime-"),
      ),
    );
    assert.ok(!JSON.stringify(result).includes(RAW_KEY));
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在清理完成后将真实 Runtime FAILED 闭环映射为 1 并写 manifest", async () => {
  const root = await createRoot("confirm-runtime-failed");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner();
    const ports = {
      ...portsFor(root, runner),
      runtimeFlow: async (): Promise<RuntimeFlowRunResult> =>
        failedRuntimeResult(),
    };

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      ports,
    );

    assert.deepEqual(result, { status: "FAILED", exitCode: 1 });
    assert.equal(bundleQueryCount(runner), 3);
    assert.equal(hasRuntimeAction(runner, "install"), false);
    assert.equal(
      JSON.parse(
        await readFile(
          path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json"),
          "utf8",
        ),
      ).artifact.uri,
      "artifact.hap",
    );
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在首次现场绑定漂移时返回 INCOMPLETE 且不写设备", async () => {
  const root = await createRoot("confirm-binding-drift");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner({
      targets: completed({ stdout: `${CHANGED_RAW_KEY}\n` }),
    });

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      portsFor(root, runner),
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(hasDeviceWrite(runner), false);
    assert.ok(!JSON.stringify(result).includes(CHANGED_RAW_KEY));
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在第二会话设备变化时清理会话并禁止写命令", async () => {
  const root = await createRoot("confirm-second-session-drift");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner({
      targetOutcomes: [
        completed({ stdout: `${RAW_KEY}\n` }),
        completed({ stdout: `${CHANGED_RAW_KEY}\n` }),
      ],
    });

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      portsFor(root, runner),
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(hasDeviceWrite(runner), false);
    assert.ok(!JSON.stringify(result).includes(CHANGED_RAW_KEY));
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在 Bundle 已安装或未知时禁止设备写命令", async () => {
  const cases: readonly [string, Outcome][] = [
    ["已安装", completed({ stdout: `\t${BUNDLE}\n` })],
    ["未知", completed({ stdout: "malformed\n" })],
  ];
  for (const [label, presence] of cases) {
    const root = await createRoot(`confirm-presence-${label}`);
    try {
      const preflight = await runDevicePreflight(
        argumentsFor(),
        portsFor(root, new FakeRunner()),
      );
      const runner = new FakeRunner({ presence });

      const result = await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: preflight.written.relativePath,
          preflightSha256: preflight.written.sha256,
        }),
        portsFor(root, runner),
      );

      assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 }, label);
      assert.equal(hasDeviceWrite(runner), false, label);
    } finally {
      await cleanupRoot(root, RUN_ID);
    }
  }
});

test("runDeviceConfirmation 对每类绑定漂移均在首写前返回 INCOMPLETE", async () => {
  const changedBundle = "com.example.hcheck.changed";
  const changedFlow = Buffer.from(
    FLOW_BYTES.toString("utf8").replace("version: 1\n", "version: 2\n"),
  );
  const changedActions = Buffer.from(
    FLOW_BYTES.toString("utf8").replace("action: stop", "action: launch"),
  );
  const cases: readonly {
    readonly label: string;
    readonly arguments?: Partial<VerifyRunArguments>;
    readonly ports?: {
      readonly flow?: Buffer;
      readonly hap?: Buffer;
      readonly jar?: Buffer;
    };
    readonly runner?: RunnerScenario;
  }[] = [
    { label: "Flow", ports: { flow: changedFlow } },
    {
      label: "HAP",
      arguments: { versionName: "1.2.4" },
      ports: { hap: validHap({ versionName: "1.2.4" }) },
    },
    { label: "JAR", ports: { jar: Buffer.from("changed-hap-sign-tool") } },
    {
      label: "Java",
      runner: { javaVersion: completed({ stderr: 'openjdk version "18"\n' }) },
    },
    { label: "Profile", runner: { profileBytes: "changed-profile" } },
    {
      label: "HDC版本",
      runner: { hdcVersion: completed({ stdout: "Ver: 3.1.1a\n" }) },
    },
    {
      label: "设备",
      runner: { targets: completed({ stdout: `${CHANGED_RAW_KEY}\n` }) },
    },
    {
      label: "Bundle",
      arguments: { bundleName: changedBundle },
      ports: { hap: validHap({ bundleName: changedBundle }) },
    },
    { label: "Ability", arguments: { abilityName: "ChangedAbility" } },
    {
      label: "Module",
      arguments: { moduleName: "feature" },
      ports: { hap: validHap({ moduleName: "feature" }) },
    },
    { label: "Hilog", arguments: { hilogMarker: "HCHECK_CHANGED" } },
    { label: "动作", ports: { flow: changedActions } },
  ];
  for (const item of cases) {
    const root = await createRoot(`confirm-binding-${item.label}`);
    try {
      const preflight = await runDevicePreflight(
        argumentsFor(),
        portsFor(root, new FakeRunner()),
      );
      const runner = new FakeRunner(item.runner);

      const result = await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: preflight.written.relativePath,
          preflightSha256: preflight.written.sha256,
          ...item.arguments,
        }),
        portsFor(root, runner, item.ports),
      );

      assert.deepEqual(
        result,
        { status: "INCOMPLETE", exitCode: 4 },
        item.label,
      );
      assert.equal(hasDeviceWrite(runner), false, item.label);
      assert.ok(!JSON.stringify(result).includes(CHANGED_RAW_KEY), item.label);
    } finally {
      await cleanupRoot(root, RUN_ID);
    }
  }
});

test("runDeviceConfirmation 在写命令前复验 preflight 过期时清理副本并返回 INCOMPLETE", async () => {
  const root = await createRoot("confirm-preflight-expired");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner();
    let reads = 0;
    const ports = portsFor(root, runner, {
      clock: {
        now: () => {
          reads += 1;
          return new Date(reads >= 3 ? "2026-07-15T12:15:00.001Z" : NOW);
        },
      },
    });

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      ports,
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(hasDeviceWrite(runner), false);
    assert.equal(runner.runtimeArtifacts.length, 0);
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 对固定五步中每一项失败均安全返回 INCOMPLETE", async () => {
  const actions: readonly RuntimeAction[] = [
    "install",
    "launch",
    "checkpoint",
    "stop",
    "uninstall",
  ];
  for (const action of actions) {
    const root = await createRoot(`confirm-action-${action}`);
    try {
      const preflight = await runDevicePreflight(
        argumentsFor(),
        portsFor(root, new FakeRunner()),
      );
      const runner = new FakeRunner({
        runtime: {
          [action]: completed({
            exitCode: 9,
            stderr: `PRIVATE_${action}_ERROR`,
          }),
        },
      });

      const result = await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: preflight.written.relativePath,
          preflightSha256: preflight.written.sha256,
        }),
        portsFor(root, runner),
      );

      assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 }, action);
      assert.ok(hasRuntimeAction(runner, action), action);
      assert.ok(!JSON.stringify(result).includes(`PRIVATE_${action}_ERROR`));
    } finally {
      await cleanupRoot(root, RUN_ID);
    }
  }
});

test("runDeviceConfirmation 最终 Bundle 复现时只返回 4 且不再次卸载", async () => {
  const root = await createRoot("confirm-final-bundle");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const runner = new FakeRunner({
      presenceOutcomes: [
        completed({ stdout: "\tcom.example.other\n" }),
        completed({ stdout: "\tcom.example.other\n" }),
        completed({ stdout: "\tcom.example.other\n" }),
        completed({ stdout: `\t${BUNDLE}\n` }),
      ],
    });

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      portsFor(root, runner),
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(
      runner.requests.filter(({ args }) => args.includes("uninstall")).length,
      1,
    );
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在 cleanup 或最终 Bundle 查询失败时不写 manifest 且不重复卸载", async () => {
  const cases: readonly [string, RunnerScenario][] = [
    [
      "cleanup 失败",
      {
        runtime: {
          stop: completed({ exitCode: 9, stderr: "PRIVATE_CLEANUP_FAILURE" }),
        },
      },
    ],
    [
      "最终 BM 查询失败",
      {
        presenceOutcomes: [
          completed({ stdout: "\tcom.example.other\n" }),
          completed({ stdout: "\tcom.example.other\n" }),
          completed({ stdout: "\tcom.example.other\n" }),
          completed({ exitCode: 9, stderr: "PRIVATE_FINAL_BM_FAILURE" }),
        ],
      },
    ],
  ];
  for (const [label, scenario] of cases) {
    const root = await createRoot(`confirm-cleanup-final-${label}`);
    try {
      const preflight = await runDevicePreflight(
        argumentsFor(),
        portsFor(root, new FakeRunner()),
      );
      const runner = new FakeRunner(scenario);

      const result = await runDeviceConfirmation(
        argumentsFor({
          mode: "confirm_device_actions",
          preflightPath: preflight.written.relativePath,
          preflightSha256: preflight.written.sha256,
        }),
        portsFor(root, runner),
      );

      assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 }, label);
      assert.equal(
        runner.requests.filter(({ args }) => args.includes("uninstall")).length,
        1,
        label,
      );
      await assert.rejects(
        readFile(
          path.join(root, ".hcheck", "evidence", RUN_ID, "manifest.json"),
        ),
        (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      );
    } finally {
      await cleanupRoot(root, RUN_ID);
    }
  }
});

test("runDeviceConfirmation 的私有 HAP 文件身份变化时拒绝删除未知文件并返回 4", async () => {
  const root = await createRoot("confirm-private-artifact");
  const runner = new FakeRunner({ replaceRuntimeArtifact: true });
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      portsFor(root, runner),
    );

    const retained = runner.runtimeArtifacts[0]?.cwd as string;
    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(
      await readFile(path.join(retained, "artifact.hap"), "utf8"),
      "replacement",
    );
    assert.ok(!JSON.stringify(result).includes(retained));
    await unlink(path.join(retained, "artifact.hap"));
    await rmdir(retained);
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("runDeviceConfirmation 在 manifest 独占写入失败时返回 INCOMPLETE", async () => {
  const root = await createRoot("confirm-manifest-failure");
  try {
    const preflight = await runDevicePreflight(
      argumentsFor(),
      portsFor(root, new FakeRunner()),
    );
    const archive = path.join(root, ".hcheck", "evidence", RUN_ID);
    await mkdir(archive, { recursive: true, mode: 0o700 });
    await writeFile(path.join(archive, "manifest.json"), "preexisting", {
      mode: 0o600,
    });

    const result = await runDeviceConfirmation(
      argumentsFor({
        mode: "confirm_device_actions",
        preflightPath: preflight.written.relativePath,
        preflightSha256: preflight.written.sha256,
      }),
      portsFor(root, new FakeRunner()),
    );

    assert.deepEqual(result, { status: "INCOMPLETE", exitCode: 4 });
    assert.equal(
      await readFile(path.join(archive, "manifest.json"), "utf8"),
      "preexisting",
    );
  } finally {
    await cleanupRoot(root, RUN_ID);
  }
});

test("collectDevicePreflightBinding 在包身份不完整或漂移时零 Runner 调用", async () => {
  const cases: readonly [string, Buffer][] = [
    ["bundle 漂移", validHap({ bundleName: "com.example.other" })],
    ["版本名称漂移", validHap({ versionName: "9.9.9" })],
    ["版本号漂移", validHap({ versionCode: 8 })],
    ["模块漂移", validHap({ moduleName: "feature" })],
    ["元数据不完整", validHap({ incomplete: true })],
  ];
  for (const [label, hap] of cases) {
    const root = await createRoot("package-mismatch");
    const runner = new FakeRunner();
    try {
      await assert.rejects(
        collectDevicePreflightBinding(
          argumentsFor(),
          portsFor(root, runner, { hap }),
        ),
        DeviceVerificationError,
        label,
      );
      assert.equal(runner.requests.length, 0, label);
    } finally {
      await cleanupRoot(root);
    }
  }
});

test("Java 版本探测只接受单一输出流中的标准首行并在失败后停止", async () => {
  const invalidResults: readonly [string, Outcome][] = [
    [
      "双输出流",
      completed({ stdout: 'openjdk version "17"\n', stderr: "extra" }),
    ],
    ["格式错误", completed({ stderr: "OpenJDK 17.0.12\n" })],
    ["非法版本", completed({ stderr: 'openjdk version "17 secret"\n' })],
    ["非零退出", completed({ exitCode: 1, stderr: "private tool log" })],
    ["超时", completed({ status: "timed_out", timedOut: true })],
    ["截断", completed({ stderrTruncated: true })],
    ["信号", completed({ signal: "SIGTERM" })],
    ["Runner 错误", new Error("/private/SECRET java log")],
  ];
  for (const [label, javaVersion] of invalidResults) {
    const root = await createRoot("java-failure");
    const runner = new FakeRunner({ javaVersion });
    try {
      await assert.rejects(
        collectDevicePreflightBinding(argumentsFor(), portsFor(root, runner)),
        (error: unknown) => {
          assert.ok(error instanceof DeviceVerificationError, label);
          assert.ok(!error.message.includes("SECRET"), label);
          assert.ok(!error.message.includes("private tool log"), label);
          assert.equal("cause" in error, false, label);
          return true;
        },
      );
      assert.equal(runner.requests.length, 1, label);
      assert.deepEqual(runner.requests[0], {
        executable: "/safe/java",
        args: ["-version"],
        timeoutMs: 10_000,
        maxStdoutBytes: 8 * 1024,
        maxStderrBytes: 8 * 1024,
      });
    } finally {
      await cleanupRoot(root);
    }
  }
});

test("验签失败不会继续 HDC，错误不回显工具日志", async () => {
  const root = await createRoot("signature-failure");
  const runner = new FakeRunner({
    verifyApp: completed({ exitCode: 9, stderr: "/private/SECRET sign log" }),
  });
  try {
    await assert.rejects(
      collectDevicePreflightBinding(argumentsFor(), portsFor(root, runner)),
      (error: unknown) => {
        assert.ok(error instanceof DeviceVerificationError);
        assert.equal(error.message, "HAP 验签失败。");
        assert.ok(!JSON.stringify(error).includes("SECRET"));
        return true;
      },
    );
    assert.equal(runner.requests.length, 2);
  } finally {
    await cleanupRoot(root);
  }
});

test("HDC 版本、枚举、挑战与安装状态任一失败都拒绝预检且不执行设备写操作", async () => {
  const cases: readonly [string, RunnerScenario, number][] = [
    [
      "版本失败",
      { hdcVersion: completed({ exitCode: 1, stderr: "secret hdc log" }) },
      4,
    ],
    ["无设备", { targets: completed({ stdout: "[Empty]\n" }) }, 5],
    ["挑战失败", { challenge: completed({ stdout: "wrong\n" }) }, 6],
    ["已安装", { presence: completed({ stdout: `\t${BUNDLE}\n` }) }, 7],
    ["状态未知", { presence: completed({ stdout: "malformed\n" }) }, 7],
  ];
  for (const [label, scenario, requestCount] of cases) {
    const root = await createRoot("hdc-failure");
    const runner = new FakeRunner(scenario);
    try {
      await assert.rejects(
        collectDevicePreflightBinding(argumentsFor(), portsFor(root, runner)),
        DeviceVerificationError,
        label,
      );
      assert.equal(runner.requests.length, requestCount, label);
      assert.equal(
        runner.requests.some(({ args }) =>
          args.some((value) =>
            ["install", "start", "force-stop", "uninstall", "hilog"].includes(
              value,
            ),
          ),
        ),
        false,
        label,
      );
    } finally {
      await cleanupRoot(root);
    }
  }
});

test("HDC 成功形状伴随 signal 或 errorMessage 时拒绝预检且不泄漏", async () => {
  const cases: readonly [string, RunnerScenario, number, string][] = [
    [
      "枚举 signal",
      { targets: completed({ stdout: `${RAW_KEY}\n`, signal: "SIGTERM" }) },
      5,
      "SIGTERM",
    ],
    [
      "枚举 errorMessage",
      {
        targets: completed({
          stdout: `${RAW_KEY}\n`,
          errorMessage: "token=SECRET /Users/private/hdc",
        }),
      },
      5,
      "token=SECRET /Users/private/hdc",
    ],
    [
      "挑战 signal",
      {
        challenge: completed({
          stdout: `${CHALLENGE}\n`,
          signal: "SIGTERM",
        }),
      },
      6,
      "SIGTERM",
    ],
    [
      "挑战 errorMessage",
      {
        challenge: completed({
          stdout: `${CHALLENGE}\n`,
          errorMessage: "token=SECRET /Users/private/hdc",
        }),
      },
      6,
      "token=SECRET /Users/private/hdc",
    ],
    [
      "安装状态 signal",
      {
        presence: completed({
          stdout: "\tcom.example.other\n",
          signal: "SIGTERM",
        }),
      },
      7,
      "SIGTERM",
    ],
    [
      "安装状态 errorMessage",
      {
        presence: completed({
          stdout: "\tcom.example.other\n",
          errorMessage: "token=SECRET /Users/private/hdc",
        }),
      },
      7,
      "token=SECRET /Users/private/hdc",
    ],
  ];

  for (const [label, scenario, requestCount, sensitive] of cases) {
    const root = await createRoot("hdc-signal-error");
    const runner = new FakeRunner(scenario);
    try {
      await assert.rejects(
        collectDevicePreflightBinding(argumentsFor(), portsFor(root, runner)),
        (error: unknown) => {
          assert.ok(error instanceof DeviceVerificationError, label);
          assert.ok(!error.message.includes(sensitive), label);
          assert.equal("cause" in error, false, label);
          return true;
        },
      );
      assert.equal(runner.requests.length, requestCount, label);
      assert.equal(
        runner.requests.some(({ args }) =>
          args.some((value) =>
            ["install", "start", "force-stop", "uninstall", "hilog"].includes(
              value,
            ),
          ),
        ),
        false,
        label,
      );
    } finally {
      await cleanupRoot(root);
    }
  }
});

test("非 preflight_only 模式在任何读取和外部调用前失败", async () => {
  const root = await createRoot("mode");
  const runner = new FakeRunner();
  const ports = portsFor(root, runner);
  try {
    await assert.rejects(
      collectDevicePreflightBinding(argumentsFor({ mode: "dry_run" }), ports),
      DeviceVerificationError,
    );
    assert.deepEqual([...ports.fs.reads], []);
    assert.equal(runner.requests.length, 0);
  } finally {
    await cleanupRoot(root);
  }
});

test("预检记录写失败时不伪造 written，且不泄露路径、连接键或日志", async () => {
  const temporaryParent = await createRoot("write-failure-temp");
  const workspaceParent = await createRoot("write-failure-workspace");
  const workspaceFile = path.join(workspaceParent, "not-a-workspace");
  await writeFile(workspaceFile, "file");
  const runner = new FakeRunner();
  try {
    await assert.rejects(
      runDevicePreflight(
        argumentsFor(),
        portsFor(temporaryParent, runner, { workspaceRoot: workspaceFile }),
      ),
      (error: unknown) => {
        assert.ok(error instanceof DeviceVerificationError);
        assert.equal(error.message, "预检记录写入失败。");
        const serialized = JSON.stringify(error);
        assert.ok(!serialized.includes(workspaceFile));
        assert.ok(!serialized.includes(RAW_KEY));
        assert.ok(!serialized.includes("developer-secret"));
        return true;
      },
    );
  } finally {
    await cleanupRoot(temporaryParent);
    await unlink(workspaceFile);
    await cleanupRoot(workspaceParent);
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
