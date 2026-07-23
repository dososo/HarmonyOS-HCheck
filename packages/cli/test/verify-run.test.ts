import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import { parseVerifyRunArguments, runVerifyRun } from "../src/verify-run.js";

const PREFLIGHT_HASH = `sha256:${"a".repeat(64)}`;

const commonArguments = [
  "verify",
  "run",
  "--flow",
  "examples/device-smoke.yml",
  "--artifact",
  "fixtures/device-smoke.hap",
  "--bundle",
  "com.example.hcheck.smoke",
  "--ability",
  "EntryAbility",
  "--module",
  "entry",
  "--version-name",
  "1.0.0",
  "--version-code",
  "1",
  "--device-kind",
  "emulator",
  "--hilog-tag",
  "HCHECK_SMOKE",
  "--hilog-marker",
  "HCHECK_SMOKE_READY",
  "--hdc",
  "/opt/deveco/hdc",
  "--java",
  "/opt/deveco/java",
  "--hap-sign-tool",
  "/opt/deveco/hap-sign-tool.jar",
] as const;

const validFlow = `id: device-smoke
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

class MemoryReader {
  public reads = 0;

  public constructor(private readonly text: string) {}

  public async readText(): Promise<string> {
    this.reads += 1;
    return this.text;
  }
}

class CountingRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    throw new Error("dry-run 不应请求外部进程。");
  }
}

function args(
  mode: "--dry-run" | "--preflight-only" | "--confirm-device-actions",
  extras: readonly string[] = [],
): string[] {
  return [
    ...commonArguments,
    ...(mode === "--confirm-device-actions"
      ? [
          "--preflight",
          ".hcheck/preflight/run.json",
          "--preflight-sha256",
          PREFLIGHT_HASH,
        ]
      : []),
    mode,
    ...extras,
  ];
}

test("parseVerifyRunArguments 解析三种互斥模式和默认格式", () => {
  const dryRun = parseVerifyRunArguments(args("--dry-run"));
  assert.equal(dryRun.mode, "dry_run");
  assert.equal(dryRun.format, "terminal");
  assert.equal(dryRun.versionCode, 1);
  assert.equal(dryRun.deviceKind, "emulator");

  const preflight = parseVerifyRunArguments(
    args("--preflight-only", ["--format", "json"]),
  );
  assert.equal(preflight.mode, "preflight_only");
  assert.equal(preflight.format, "json");

  const confirm = parseVerifyRunArguments(args("--confirm-device-actions"));
  assert.equal(confirm.mode, "confirm_device_actions");
  assert.equal(confirm.preflightSha256, PREFLIGHT_HASH);
});

test("parseVerifyRunArguments 拒绝命令前缀、未知、重复、缺值、伪装值和模式冲突", () => {
  const invalidArguments = [
    ["run", "verify", ...args("--dry-run").slice(2)],
    [...args("--dry-run"), "--unknown", "value"],
    [...args("--dry-run"), "--bundle", "com.example.other"],
    args("--dry-run").filter((value) => value !== "/opt/deveco/hdc"),
    args("--dry-run").map((value) =>
      value === "fixtures/device-smoke.hap" ? "--preflight-only" : value,
    ),
    [...args("--dry-run"), "--preflight-only"],
    [...commonArguments],
  ];

  for (const candidate of invalidArguments) {
    assert.throws(
      () => parseVerifyRunArguments(candidate),
      /verify run|参数|模式|缺少/u,
    );
  }
});

test("parseVerifyRunArguments 拒绝所有必填项缺失和不安全标量", () => {
  const valueFlags = [
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
  ];

  for (const flag of valueFlags) {
    const index = commonArguments.indexOf(flag);
    const candidate = args("--dry-run");
    candidate.splice(index, 2);
    assert.throws(() => parseVerifyRunArguments(candidate), /缺少|参数/u);
  }

  for (const unsafe of [
    "bad\0value",
    "bad\nvalue",
    "bad\tvalue",
    "bad\u007fvalue",
  ]) {
    const candidate = args("--dry-run");
    candidate[candidate.indexOf("com.example.hcheck.smoke")] = unsafe;
    assert.throws(() => parseVerifyRunArguments(candidate), /参数/u);
  }
});

test("parseVerifyRunArguments 严格校验 HAP、uint32、设备类别、格式和 confirm 绑定", () => {
  const replacements: readonly [string, string][] = [
    ["fixtures/device-smoke.hap", "fixtures/device-smoke.app"],
    ["1", "-1"],
    ["1", "4294967296"],
    ["1", "1.5"],
    ["emulator", "unknown"],
  ];
  for (const [before, after] of replacements) {
    const candidate = args("--dry-run");
    candidate[candidate.indexOf(before)] = after;
    assert.throws(
      () => parseVerifyRunArguments(candidate),
      /参数|HAP|hap|版本|设备/u,
    );
  }
  const zeroVersionCode = args("--dry-run");
  zeroVersionCode[zeroVersionCode.indexOf("1")] = "0";
  assert.equal(parseVerifyRunArguments(zeroVersionCode).versionCode, 0);
  assert.throws(
    () => parseVerifyRunArguments(args("--dry-run", ["--format", "xml"])),
    /格式/u,
  );
  assert.throws(
    () =>
      parseVerifyRunArguments([...commonArguments, "--confirm-device-actions"]),
    /preflight/u,
  );
  assert.throws(
    () =>
      parseVerifyRunArguments(
        args("--confirm-device-actions").map((value) =>
          value === PREFLIGHT_HASH ? `sha256:${"A".repeat(64)}` : value,
        ),
      ),
    /SHA-256|preflight/u,
  );
  assert.throws(
    () =>
      parseVerifyRunArguments([
        ...commonArguments,
        "--preflight",
        ".hcheck/preflight/run.json",
        "--preflight-sha256",
        PREFLIGHT_HASH,
        "--dry-run",
      ]),
    /preflight|模式/u,
  );
});

test("runVerifyRun dry-run JSON 只读校验并保持零外部调用、零写入", async () => {
  const fs = new MemoryReader(validFlow);
  const runner = new CountingRunner();
  let stdout = "";
  let stderr = "";

  const code = await runVerifyRun(args("--dry-run", ["--format", "json"]), {
    fs,
    runner,
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
  });

  const result = JSON.parse(stdout) as {
    mode: string;
    flow: { id: string; version: number };
    plan: {
      actions: readonly string[];
      evidence: Record<string, unknown>;
      cleanup: readonly string[];
    };
    verification: Record<string, string>;
    externalCalls: number;
    writes: number;
  };
  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(fs.reads, 1);
  assert.equal(runner.requests.length, 0);
  assert.equal(result.mode, "dry_run");
  assert.deepEqual(result.flow, { id: "device-smoke", version: 1 });
  assert.deepEqual(result.plan.actions, [
    "install",
    "launch",
    "checkpoint",
    "stop",
    "uninstall",
  ]);
  assert.deepEqual(result.plan.evidence, {
    screenshot: "never",
    video: "never",
    hilog: true,
    network_timeline: "none",
    permission_timeline: false,
  });
  assert.deepEqual(result.plan.cleanup, [
    "stop_if_started",
    "uninstall_if_installed_by_this_run",
  ]);
  assert.deepEqual(result.verification, {
    signature: "not_verified",
    device: "not_verified",
    bundlePresence: "not_verified",
  });
  assert.equal(result.externalCalls, 0);
  assert.equal(result.writes, 0);
  for (const secret of [
    "/opt/deveco/hdc",
    "/opt/deveco/java",
    "/opt/deveco/hap-sign-tool.jar",
    "fixtures/device-smoke.hap",
    "examples/device-smoke.yml",
  ]) {
    assert.ok(!stdout.includes(secret));
  }
});

test("runVerifyRun dry-run terminal 明确列出动作、证据、清理和未验证边界", async () => {
  let stdout = "";
  const code = await runVerifyRun(args("--dry-run"), {
    fs: new MemoryReader(validFlow),
    runner: new CountingRunner(),
    stdout: (value) => {
      stdout += value;
    },
    stderr: () => undefined,
  });

  assert.equal(code, 0);
  assert.match(stdout, /install → launch → checkpoint → stop → uninstall/u);
  assert.match(stdout, /Hilog/u);
  assert.match(stdout, /停止.*卸载/u);
  assert.match(stdout, /签名.*未验证/u);
  assert.match(stdout, /设备.*未验证/u);
  assert.match(stdout, /Bundle.*未验证/u);
});

test("runVerifyRun 拒绝 Flow 结构、动作、断言、证据和 requires 偏差且不泄露输入", async () => {
  const invalidFlows = [
    validFlow.replace("action: checkpoint", "action: tap"),
    validFlow.replace("action: launch", "action: launch\n    timeout_ms: 1"),
    validFlow.replace("package: ${artifact}", "package: wrong.hap"),
    validFlow.replace("after_step: checkpoint", "after_step: launch"),
    validFlow.replace("type: hilog_contains_marker", "type: app_not_crashed"),
    validFlow.replace("screenshot: never", "screenshot: on_failure"),
    validFlow.replace("video: never", "video: always"),
    validFlow.replace("hilog: true", "hilog: false"),
    validFlow.replace(
      "network_timeline: none",
      "network_timeline: metadata_only",
    ),
    validFlow.replace(
      "permission_timeline: false",
      "permission_timeline: true",
    ),
    validFlow.replace("clean_install: true", "clean_install: false"),
    validFlow.replace(
      "network_observation: none",
      "network_observation: metadata_only",
    ),
    validFlow.replace("test_account: false", "test_account: true"),
    validFlow.replace(
      "  test_account: false",
      "  test_account: false\n  device_capabilities: [screenshot]",
    ),
    `${validFlow}\nunknown: SECRET_FLOW_VALUE\n`,
    "not: [valid",
  ];

  for (const flow of invalidFlows) {
    const runner = new CountingRunner();
    let stdout = "";
    let stderr = "";
    const code = await runVerifyRun(args("--dry-run"), {
      fs: new MemoryReader(flow),
      runner,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });
    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.equal(runner.requests.length, 0);
    assert.match(stderr, /Flow|流程/u);
    assert.ok(!stderr.includes("SECRET_FLOW_VALUE"));
    assert.ok(!stderr.includes("examples/device-smoke.yml"));
  }
});

test("runVerifyRun 拒绝 YAML alias 和重复键且保持零外部调用与输入脱敏", async () => {
  const invalidYaml = [
    {
      secret: "SECRET_ALIAS_VALUE",
      flow: validFlow.replace(
        "name: 设备冒烟验收",
        "name: &unsafe SECRET_ALIAS_VALUE\ndescription: *unsafe",
      ),
    },
    {
      secret: "SECRET_DUPLICATE_VALUE",
      flow: validFlow.replace(
        "name: 设备冒烟验收",
        "name: 设备冒烟验收\nname: SECRET_DUPLICATE_VALUE",
      ),
    },
  ];

  for (const { flow, secret } of invalidYaml) {
    const runner = new CountingRunner();
    let stdout = "";
    let stderr = "";
    const code = await runVerifyRun(args("--dry-run"), {
      fs: new MemoryReader(flow),
      runner,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });

    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.equal(runner.requests.length, 0);
    assert.match(stderr, /Flow|流程/u);
    assert.ok(!stderr.includes(secret));
  }
});

test("preflight 和 confirm 本切片明确返回未实现，不伪装可用且不调用外部进程", async () => {
  for (const mode of [
    "--preflight-only",
    "--confirm-device-actions",
  ] as const) {
    const runner = new CountingRunner();
    let stdout = "";
    let stderr = "";
    const code = await runVerifyRun(args(mode), {
      fs: new MemoryReader(validFlow),
      runner,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });
    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.equal(runner.requests.length, 0);
    assert.match(stderr, /尚未实现/u);
  }
});

test("真实 examples/device-smoke.yml 可通过同一 Flow 合同", async () => {
  const source = await readFile(
    new URL("../../../examples/device-smoke.yml", import.meta.url),
    "utf8",
  );
  let stdout = "";
  const code = await runVerifyRun(args("--dry-run", ["--format", "json"]), {
    fs: new MemoryReader(source),
    runner: new CountingRunner(),
    stdout: (value) => {
      stdout += value;
    },
    stderr: () => undefined,
  });
  assert.equal(code, 0);
  assert.equal(JSON.parse(stdout).flow.id, "device-smoke");
});
