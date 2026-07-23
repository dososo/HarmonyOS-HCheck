import assert from "node:assert/strict";
import test from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtemp, rmdir, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import type { Finding } from "@hcheck/core";
import {
  MAX_READ_BYTES,
  NodeFileSystem,
} from "../src/infrastructure/node-filesystem.js";
import { NodeHash } from "../src/infrastructure/node-hash.js";
import { RandomRunId } from "../src/infrastructure/random-run-id.js";
import { SystemClock } from "../src/infrastructure/system-clock.js";
import { evaluateGate, parseScanArguments, runScan } from "../src/scan.js";

const finding = (
  severity: Finding["severity"],
  confidence: Finding["confidence"],
  applicability: Finding["applicability"],
): Finding => ({ severity, confidence, applicability }) as Finding;

test("scan 默认 quick/terminal 并解析覆盖项", () => {
  assert.deepEqual(parseScanArguments(["scan", "."]), {
    path: ".",
    mode: "quick",
    format: "terminal",
    rules: [],
  });
  assert.deepEqual(
    parseScanArguments([
      "scan",
      ".",
      "--format",
      "agent-json",
      "--fail-on",
      "high",
      "--confidence",
      "possible",
      "--rules",
      "A,B",
    ]),
    {
      path: ".",
      mode: "quick",
      format: "agent-json",
      failOn: "high",
      minimumConfidence: "possible",
      rules: ["A", "B"],
    },
  );
});

test("拒绝未实现模式和未知参数", () => {
  assert.throws(
    () => parseScanArguments(["scan", ".", "--mode", "release"]),
    /仅支持 quick/u,
  );
  assert.throws(
    () => parseScanArguments(["scan", ".", "--wat"]),
    /未知扫描参数/u,
  );
  assert.throws(() => parseScanArguments(["scan"]), /目录/u);
});

test("未知参数不会在错误中回显秘密或绝对路径", async () => {
  for (const unsafe of [
    "--api-token=HCHECK_SUPER_SECRET",
    "--/Users/private/secret",
  ]) {
    let stderr = "";
    const code = await runScan(["scan", ".", unsafe], {
      fs: new NodeFileSystem(),
      hash: new NodeHash(),
      clock: new SystemClock(),
      runId: new RandomRunId(),
      repositoryRoot,
      stdout: () => undefined,
      stderr: (value) => {
        stderr += value;
      },
      environment: {},
    });
    assert.equal(code, 3);
    assert.equal(stderr, "存在未知扫描参数。\n");
    assert.ok(
      !stderr.includes("HCHECK_SUPER_SECRET") &&
        !stderr.includes("/Users/private"),
    );
  }
});

test("门禁同时要求严重性、置信度和适用性", () => {
  assert.equal(
    evaluateGate(
      [finding("HIGH", "PROBABLE", "APPLICABLE")],
      "high",
      "probable",
    ),
    true,
  );
  assert.equal(
    evaluateGate(
      [finding("MEDIUM", "PROBABLE", "APPLICABLE")],
      "high",
      "probable",
    ),
    false,
  );
  assert.equal(
    evaluateGate(
      [finding("HIGH", "POSSIBLE", "APPLICABLE")],
      "high",
      "probable",
    ),
    false,
  );
  assert.equal(
    evaluateGate([finding("HIGH", "PROBABLE", "UNKNOWN")], "high", "probable"),
    false,
  );
  assert.equal(
    evaluateGate(
      [finding("BLOCKER", "CONFIRMED", "APPLICABLE")],
      "none",
      "confirmed",
    ),
    false,
  );
});

test("置信度门槛集合边界固定", () => {
  const values: Finding["confidence"][] = [
    "CONFIRMED",
    "PROBABLE",
    "POSSIBLE",
    "MANUAL",
  ];
  assert.deepEqual(
    values.map((v) =>
      evaluateGate([finding("HIGH", v, "APPLICABLE")], "high", "confirmed"),
    ),
    [true, false, false, false],
  );
  assert.deepEqual(
    values.map((v) =>
      evaluateGate([finding("HIGH", v, "APPLICABLE")], "high", "probable"),
    ),
    [true, true, false, false],
  );
  assert.deepEqual(
    values.map((v) =>
      evaluateGate([finding("HIGH", v, "APPLICABLE")], "high", "possible"),
    ),
    [true, true, true, false],
  );
  assert.deepEqual(
    values.map((v) =>
      evaluateGate([finding("HIGH", v, "APPLICABLE")], "high", "manual"),
    ),
    [true, true, true, true],
  );
});

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
async function scanFixture(name: string, extra: readonly string[] = []) {
  const result = await scanFixtureRaw(name, extra);
  return {
    ...result,
    report: JSON.parse(result.stdout) as {
      run: { id: string };
      completeness: string;
      summary: { total: number; gate: string };
      findings: readonly {
        fingerprint: string;
        ruleId: string;
        status: string;
        baseline?: { present?: boolean; reference?: string };
      }[];
    },
  };
}

async function scanFixtureRaw(name: string, extra: readonly string[] = []) {
  let stdout = "",
    stderr = "";
  const code = await runScan(
    [
      "scan",
      path.join(repositoryRoot, "fixtures", name),
      "--format",
      "json",
      "--fail-on",
      "high",
      "--confidence",
      "probable",
      ...extra,
    ],
    {
      fs: new NodeFileSystem(),
      hash: new NodeHash(),
      clock: new SystemClock(),
      runId: new RandomRunId(),
      repositoryRoot,
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
      environment: {},
    },
  );
  return {
    code,
    stderr,
    stdout,
  };
}

function baselineJson(
  findings: readonly {
    readonly fingerprint: string;
    readonly ruleId: string;
    readonly title?: string;
    readonly severity?: string;
  }[],
): string {
  return `${JSON.stringify(
    {
      schemaVersion: "1.0.0",
      hcheckVersion: "0.6.0",
      createdAt: "2026-07-11T00:00:00Z",
      reference: "baseline/main",
      findings: findings.map((finding) => ({
        fingerprint: finding.fingerprint,
        ruleId: finding.ruleId,
        title: finding.title ?? "基线问题",
        severity: finding.severity ?? "BLOCKER",
      })),
    },
    null,
    2,
  )}\n`;
}

test("真实正向与干净 fixture 分别触发门禁和通过", async () => {
  const positive = await scanFixture("placeholder-metadata");
  const clean = await scanFixture("clean-stage-app");
  assert.deepEqual(
    [
      positive.code,
      positive.report.completeness,
      positive.report.summary.gate,
      positive.report.summary.total,
      positive.stderr,
    ],
    [1, "COMPLETE", "FAIL", 1, ""],
  );
  assert.deepEqual(
    [
      clean.code,
      clean.report.completeness,
      clean.report.summary.gate,
      clean.report.summary.total,
      clean.stderr,
    ],
    [0, "COMPLETE", "PASS", 0, ""],
  );
});

test("真实测试地址 fixture 只触发 HOS-PKG-007 且报告不泄露本地地址", async () => {
  const result = await scanFixture("test-endpoint", ["--rules", "HOS-PKG-007"]);

  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  assert.equal(result.report.completeness, "COMPLETE");
  assert.equal(result.report.summary.gate, "FAIL");
  assert.equal(result.report.summary.total, 1);
  assert.deepEqual(
    result.report.findings.map((finding) => finding.ruleId),
    ["HOS-PKG-007"],
  );
  assert.doesNotMatch(result.stdout, /localhost|127\.0\.0\.1/u);
});

test("真实缺权限 fixture 只触发 HOS-PERM-001 且报告不泄露源码行", async () => {
  const result = await scanFixture("missing-permission", [
    "--rules",
    "HOS-PERM-001",
  ]);

  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  assert.equal(result.report.completeness, "COMPLETE");
  assert.equal(result.report.summary.gate, "FAIL");
  assert.equal(result.report.summary.total, 1);
  assert.deepEqual(
    result.report.findings.map((finding) => finding.ruleId),
    ["HOS-PERM-001"],
  );
  assert.doesNotMatch(
    result.stdout,
    /return geoLocationManager\.getCurrentLocation/u,
  );
});

test("真实 Bundle 不一致 fixture 只触发 HOS-PKG-001", async () => {
  const result = await scanFixture("bundle-mismatch", [
    "--rules",
    "HOS-PKG-001",
  ]);

  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  assert.equal(result.report.completeness, "COMPLETE");
  assert.equal(result.report.summary.gate, "FAIL");
  assert.equal(result.report.summary.total, 1);
  assert.deepEqual(
    result.report.findings.map((finding) => finding.ruleId),
    ["HOS-PKG-001"],
  );
  assert.ok(!result.stdout.includes(repositoryRoot));
});

test("真实 Debug 产物 fixture 只触发 HOS-PKG-006", async () => {
  const result = await scanFixture("debug-release-artifact", [
    "--rules",
    "HOS-PKG-006",
  ]);

  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  assert.equal(result.report.completeness, "COMPLETE");
  assert.equal(result.report.summary.gate, "FAIL");
  assert.equal(result.report.summary.total, 1);
  assert.deepEqual(
    result.report.findings.map((finding) => finding.ruleId),
    ["HOS-PKG-006"],
  );
  assert.ok(!result.stdout.includes(repositoryRoot));
});

test("真实未披露 SDK fixture 只触发 HOS-PRIV-002", async () => {
  const result = await scanFixture("undisclosed-sdk", [
    "--rules",
    "HOS-PRIV-002",
  ]);

  assert.equal(result.code, 1);
  assert.equal(result.stderr, "");
  assert.equal(result.report.completeness, "COMPLETE");
  assert.equal(result.report.summary.gate, "FAIL");
  assert.equal(result.report.summary.total, 1);
  assert.deepEqual(
    result.report.findings.map((finding) => finding.ruleId),
    ["HOS-PRIV-002"],
  );
  assert.ok(!result.stdout.includes(repositoryRoot));
});

test("scan 支持 SARIF、JUnit、HTML 和 Agent JSON 输出且不泄露本地路径", async () => {
  const sarif = await scanFixtureRaw("missing-permission", [
    "--format",
    "sarif",
    "--rules",
    "HOS-PERM-001",
  ]);
  assert.equal(sarif.code, 1);
  assert.equal(sarif.stderr, "");
  assert.ok(!sarif.stdout.includes(repositoryRoot));
  assert.equal(JSON.parse(sarif.stdout).version, "2.1.0");

  const junit = await scanFixtureRaw("missing-permission", [
    "--format",
    "junit",
    "--rules",
    "HOS-PERM-001",
  ]);
  assert.equal(junit.code, 1);
  assert.equal(junit.stderr, "");
  assert.ok(!junit.stdout.includes(repositoryRoot));
  assert.match(junit.stdout, /<testsuite name="hcheck"/u);
  assert.match(junit.stdout, /HOS-PERM-001/u);

  const html = await scanFixtureRaw("missing-permission", [
    "--format",
    "html",
    "--rules",
    "HOS-PERM-001",
  ]);
  assert.equal(html.code, 1);
  assert.equal(html.stderr, "");
  assert.ok(!html.stdout.includes(repositoryRoot));
  assert.match(html.stdout, /^<!doctype html>/iu);
  assert.ok(!html.stdout.includes("<script"));
  assert.ok(!html.stdout.includes("https://"));

  const agent = await scanFixtureRaw("missing-permission", [
    "--format",
    "agent-json",
    "--rules",
    "HOS-PERM-001",
  ]);
  assert.equal(agent.code, 1);
  assert.equal(agent.stderr, "");
  assert.ok(!agent.stdout.includes(repositoryRoot));
  const agentJson = JSON.parse(agent.stdout) as {
    schemaVersion: string;
    actions: readonly {
      ruleId: string;
      verificationCommands: readonly string[];
    }[];
    safety: {
      allowedPaths: readonly string[];
      forbiddenPaths: readonly string[];
    };
  };
  assert.equal(agentJson.schemaVersion, "1.0.0");
  assert.equal(agentJson.actions[0]?.ruleId, "HOS-PERM-001");
  assert.ok(agentJson.actions[0]?.verificationCommands.includes("pnpm check"));
  assert.deepEqual(agentJson.safety.forbiddenPaths, [
    ".git",
    "build",
    "node_modules",
    "oh_modules",
  ]);
});

test("基线 diff 只让新增阻断问题返回退出码 2，既有问题不阻断", async () => {
  const seed = await scanFixture("missing-permission", [
    "--rules",
    "HOS-PERM-001",
  ]);
  const finding = seed.report.findings[0];
  assert.ok(finding !== undefined);

  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-baseline-"));
  const emptyBaseline = path.join(directory, "empty-baseline.json");
  const matchingBaseline = path.join(directory, "matching-baseline.json");
  try {
    await writeFile(emptyBaseline, baselineJson([]));
    await writeFile(matchingBaseline, baselineJson([finding]));

    const newRun = await scanFixture("missing-permission", [
      "--rules",
      "HOS-PERM-001",
      "--baseline",
      emptyBaseline,
    ]);
    assert.equal(newRun.code, 2);
    assert.equal(newRun.report.summary.gate, "FAIL");
    assert.equal(newRun.report.findings[0]?.status, "new");
    assert.deepEqual(newRun.report.findings[0]?.baseline, {
      present: false,
      reference: "baseline/main",
    });
    assert.ok(!newRun.stdout.includes(directory));

    const existingRun = await scanFixture("missing-permission", [
      "--rules",
      "HOS-PERM-001",
      "--baseline",
      matchingBaseline,
    ]);
    assert.equal(existingRun.code, 0);
    assert.equal(existingRun.report.summary.gate, "PASS");
    assert.equal(existingRun.report.findings[0]?.status, "existing");
    assert.deepEqual(existingRun.report.findings[0]?.baseline, {
      present: true,
      reference: "baseline/main",
    });
    assert.ok(!existingRun.stdout.includes(directory));
  } finally {
    await unlink(emptyBaseline);
    await unlink(matchingBaseline);
    await rmdir(directory);
  }
});

test("有效抑制让匹配 Finding 不阻断，过期或无理由抑制由配置错误拒绝", async () => {
  const seed = await scanFixture("missing-permission", [
    "--rules",
    "HOS-PERM-001",
  ]);
  const finding = seed.report.findings[0];
  assert.ok(finding !== undefined);

  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-suppress-"));
  const suppression = path.join(directory, "suppressions.json");
  const expired = path.join(directory, "expired-suppressions.json");
  try {
    await writeFile(
      suppression,
      `${JSON.stringify({
        schemaVersion: "1.0.0",
        suppressions: [
          {
            fingerprint: finding.fingerprint,
            ruleId: finding.ruleId,
            reason: "测试负责人确认该结构样例可接受。",
            expiresAt: "2099-01-01T00:00:00Z",
          },
        ],
      })}\n`,
    );
    await writeFile(
      expired,
      `${JSON.stringify({
        schemaVersion: "1.0.0",
        suppressions: [
          {
            fingerprint: finding.fingerprint,
            ruleId: finding.ruleId,
            reason: "已过期。",
            expiresAt: "2020-01-01T00:00:00Z",
          },
        ],
      })}\n`,
    );

    const suppressed = await scanFixture("missing-permission", [
      "--rules",
      "HOS-PERM-001",
      "--suppressions",
      suppression,
    ]);
    assert.equal(suppressed.code, 0);
    assert.equal(suppressed.report.summary.gate, "PASS");
    assert.equal(suppressed.report.findings[0]?.status, "suppressed");
    assert.ok(!suppressed.stdout.includes(directory));

    const rejected = await scanFixtureRaw("missing-permission", [
      "--rules",
      "HOS-PERM-001",
      "--suppressions",
      expired,
    ]);
    assert.equal(rejected.code, 3);
    assert.equal(rejected.stdout, "");
    assert.match(rejected.stderr, /CONFIGURATION_ERROR/u);
  } finally {
    await unlink(suppression);
    await unlink(expired);
    await rmdir(directory);
  }
});

test("生产运行 ID 每次唯一且 Finding 指纹稳定", async () => {
  const first = await scanFixture("placeholder-metadata");
  const second = await scanFixture("placeholder-metadata");
  assert.notEqual(first.report.run.id, second.report.run.id);
  assert.deepEqual(
    first.report.findings.map(({ fingerprint }) => fingerprint),
    second.report.findings.map(({ fingerprint }) => fingerprint),
  );
});

test("Node 文件系统在读取前拒绝超限文件", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const file = path.join(directory, "oversized.txt");
  try {
    await writeFile(file, Buffer.alloc(MAX_READ_BYTES + 1, 97));
    await assert.rejects(new NodeFileSystem().readText(file), /安全读取限制/u);
  } finally {
    await unlink(file);
    await rmdir(directory);
  }
});

test("Node 文件系统不跟随符号链接读取文本", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const target = path.join(directory, "target.txt");
  const link = path.join(directory, "link.txt");
  try {
    await writeFile(target, "safe");
    await symlink(target, link);
    await assert.rejects(new NodeFileSystem().readText(link), /安全读取限制/u);
  } finally {
    await unlink(link);
    await unlink(target);
    await rmdir(directory);
  }
});

test("Node 文件系统不跟随符号链接读取二进制文件", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const target = path.join(directory, "target.hap");
  const link = path.join(directory, "link.hap");
  try {
    await writeFile(target, Buffer.from([1, 2, 3]));
    await symlink(target, link);
    await assert.rejects(new NodeFileSystem().readFile(link), /安全读取限制/u);
  } finally {
    await unlink(link);
    await unlink(target);
    await rmdir(directory);
  }
});

test("--rules 与配置排除同一规则时返回配置错误", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const config = path.join(directory, "conflict.yml");
  try {
    await writeFile(config, "scan:\n  exclude:\n    rules: [HOS-META-003]\n");
    let stdout = "",
      stderr = "";
    const code = await runScan(
      [
        "scan",
        path.join(repositoryRoot, "fixtures", "placeholder-metadata"),
        "--config",
        config,
        "--rules",
        "HOS-META-003",
      ],
      {
        fs: new NodeFileSystem(),
        hash: new NodeHash(),
        clock: new SystemClock(),
        runId: new RandomRunId(),
        repositoryRoot,
        environment: {},
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.match(stderr, /CONFIGURATION_ERROR/u);
  } finally {
    await unlink(config);
    await rmdir(directory);
  }
});

test("--rules 实际选择规则，配置 exclude 实际禁用规则", async () => {
  const selected = await scanFixture("placeholder-metadata", [
    "--rules",
    "HOS-META-003",
  ]);
  assert.equal(selected.code, 1);
  assert.equal(selected.report.summary.total, 1);

  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const config = path.join(directory, "exclude.yml");
  try {
    await writeFile(config, "scan:\n  exclude:\n    rules: [HOS-META-003]\n");
    const excluded = await scanFixture("placeholder-metadata", [
      "--config",
      config,
    ]);
    assert.equal(excluded.code, 0);
    assert.equal(excluded.report.summary.total, 0);
    assert.equal(excluded.report.summary.gate, "PASS");
  } finally {
    await unlink(config);
    await rmdir(directory);
  }
});

test("CLI 将超限显式配置映射为安全配置错误", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-cli-"));
  const config = path.join(directory, "oversized.yml");
  try {
    await writeFile(config, Buffer.alloc(MAX_READ_BYTES + 1, 97));
    let stdout = "",
      stderr = "";
    const code = await runScan(
      [
        "scan",
        path.join(repositoryRoot, "fixtures", "clean-stage-app"),
        "--config",
        config,
      ],
      {
        fs: new NodeFileSystem(),
        hash: new NodeHash(),
        clock: new SystemClock(),
        runId: new RandomRunId(),
        repositoryRoot,
        environment: {},
        stdout: (value) => {
          stdout += value;
        },
        stderr: (value) => {
          stderr += value;
        },
      },
    );
    assert.equal(code, 3);
    assert.equal(stdout, "");
    assert.equal(stderr, "[CONFIGURATION_ERROR] 配置无效。\n");
  } finally {
    await unlink(config);
    await rmdir(directory);
  }
});
