import assert from "node:assert/strict";
import test from "node:test";
import cliPackage from "../package.json" with { type: "json" };
import { HCHECK_VERSION, main } from "../src/index.js";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";
import { NodeProcessRunner } from "../src/infrastructure/node-process-runner.js";

test("未知命令返回不支持退出码", async () => {
  const originalError = console.error;
  console.error = () => undefined;
  try {
    assert.equal(await main(["unknown"]), 8);
  } finally {
    console.error = originalError;
  }
});

test("帮助和版本仅在精确顶层形态生效", async () => {
  const originalLog = console.log;
  const originalWrite = process.stderr.write;
  let logs = 0;
  let stderr = "";
  console.log = () => {
    logs += 1;
  };
  process.stderr.write = ((value: string | Uint8Array) => {
    stderr += String(value);
    return true;
  }) as typeof process.stderr.write;
  try {
    assert.equal(await main(["--help"]), 0);
    assert.equal(await main(["--version"]), 0);
    assert.equal(logs, 2);
    assert.equal(await main(["scan", ".", "--help"]), 3);
    assert.equal(await main(["scan", ".", "--version"]), 3);
    assert.equal(logs, 2);
    assert.match(stderr, /未知扫描参数/u);
  } finally {
    console.log = originalLog;
    process.stderr.write = originalWrite;
  }
});

test("CLI、包元数据和报告共享同一个正式版本", async () => {
  const originalLog = console.log;
  const logs: string[] = [];
  console.log = (value?: unknown) => logs.push(String(value));
  try {
    assert.equal(HCHECK_VERSION, "0.6.0");
    assert.equal(cliPackage.version, HCHECK_VERSION);
    assert.equal(await main(["--version"]), 0);
    assert.equal(logs.at(-1), HCHECK_VERSION);
    assert.equal(await main(["--help"]), 0);
    assert.match(
      logs.at(-1) ?? "",
      new RegExp(`鸿鉴 HCheck ${HCHECK_VERSION}`),
    );
  } finally {
    console.log = originalLog;
  }
});

test("帮助将 verify run 列为可用命令而非后续目标", async () => {
  const originalLog = console.log;
  const logs: string[] = [];
  console.log = (value?: unknown) => logs.push(String(value));
  try {
    assert.equal(await main(["--help"]), 0);
    const help = logs.at(-1) ?? "";
    assert.match(help, /hcheck verify run .*--dry-run/u);
    assert.doesNotMatch(help, /后续目标命令[\s\S]*hcheck verify run/u);
  } finally {
    console.log = originalLog;
  }
});

test("main 仅通过可选测试端口转发 verify run，默认路径不需要 Runner", async () => {
  const flow = `id: device-smoke
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
`;
  let stdout = "";
  let stderr = "";

  const code = await main(
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
      verify: {
        fs: { readText: async () => flow },
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    },
  );

  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.equal(JSON.parse(stdout).mode, "dry_run");
});

test("main 默认 verify preflight/confirm 未注入端口时零读取、零 Runner 调用", async () => {
  const common = [
    "verify",
    "run",
    "--flow",
    "/private/flow.yml",
    "--artifact",
    "/private/app.hap",
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
  ];
  const originalReadText = NodeFileSystem.prototype.readText;
  const originalRun = NodeProcessRunner.prototype.run;
  const originalStdout = process.stdout.write;
  const originalStderr = process.stderr.write;
  let reads = 0;
  let runnerCalls = 0;
  let stdout = "";
  let stderr = "";
  NodeFileSystem.prototype.readText = async () => {
    reads += 1;
    return "unexpected";
  };
  NodeProcessRunner.prototype.run = async () => {
    runnerCalls += 1;
    throw new Error("默认 verify 不得调用 Runner。");
  };
  process.stdout.write = ((value: string | Uint8Array) => {
    stdout += String(value);
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((value: string | Uint8Array) => {
    stderr += String(value);
    return true;
  }) as typeof process.stderr.write;
  try {
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
      assert.equal(await main(args), 4);
    }
    assert.equal(reads, 0);
    assert.equal(runnerCalls, 0);
    assert.equal(stdout, "");
    assert.match(stderr, /未注入受控设备验证端口/u);
    assert.ok(!stderr.includes("/private/"));
  } finally {
    NodeFileSystem.prototype.readText = originalReadText;
    NodeProcessRunner.prototype.run = originalRun;
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
  }
});
