import assert from "node:assert/strict";
import { ChildProcess } from "node:child_process";
import { mkdtempSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { NodeProcessRunner } from "../src/infrastructure/node-process-runner.js";

const NODE = process.execPath;

test("NodeProcessRunner 使用参数数组执行成功进程，并支持环境白名单和显式覆盖", async () => {
  const runner = new NodeProcessRunner({
    baseEnvironment: {
      PATH: process.env.PATH ?? "",
      SECRET_TOKEN: "不应透传",
    },
    environmentAllowList: ["PATH"],
  });

  const result = await runner.run({
    executable: NODE,
    args: [
      "-e",
      "process.stdout.write(`${process.env.HCHECK_SAFE}:${process.env.SECRET_TOKEN ?? ''}`)",
    ],
    env: { HCHECK_SAFE: "ok" },
  });

  assert.equal(result.status, "completed");
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "ok:");
  assert.equal(result.stderr, "");
});

test("NodeProcessRunner 对非零退出只返回状态，不抛出异常", async () => {
  const runner = new NodeProcessRunner();

  const result = await runner.run({
    executable: NODE,
    args: ["-e", "process.stderr.write('构建失败'); process.exit(7)"],
  });

  assert.equal(result.status, "completed");
  assert.equal(result.exitCode, 7);
  assert.equal(result.stderr, "构建失败");
});

test("NodeProcessRunner 超时后终止进程并返回 timed_out", async () => {
  const runner = new NodeProcessRunner({ defaultTimeoutMs: 50 });

  const result = await runner.run({
    executable: NODE,
    args: ["-e", "setTimeout(() => process.stdout.write('late'), 1_000)"],
  });

  assert.equal(result.status, "timed_out");
  assert.equal(result.timedOut, true);
  assert.equal(result.stdout, "");
});

test(
  "NodeProcessRunner 对忽略 SIGTERM 的进程在宽限期后强制终止",
  { timeout: 4_000 },
  async () => {
    const runner = new NodeProcessRunner({
      defaultTimeoutMs: 300,
      terminationGraceMs: 100,
    });
    const startedAt = Date.now();

    const result = await runner.run({
      executable: NODE,
      args: [
        "-e",
        [
          "process.on('SIGTERM', () => process.stdout.write('TAIL_AFTER_TERM\\n'));",
          "setInterval(() => {}, 1_000);",
          "setTimeout(() => process.exit(0), 2_500);",
        ].join(" "),
      ],
    });

    assert.equal(result.status, "timed_out");
    assert.equal(result.timedOut, true);
    assert.equal(result.signal, "SIGKILL");
    assert.match(result.stdout, /TAIL_AFTER_TERM/u);
    assert.ok(Date.now() - startedAt < 2_000);
  },
);

test(
  "NodeProcessRunner 超时后忽略终止信号触发的 error 并继续强制终止",
  { timeout: 4_000 },
  async () => {
    const originalKill = ChildProcess.prototype.kill;
    ChildProcess.prototype.kill = function (signal): boolean {
      if (signal === "SIGTERM" || signal === "SIGKILL") {
        setImmediate(() => {
          this.emit(
            "error",
            Object.assign(new Error(`模拟 ${String(signal)} 发送失败`), {
              code: "ESRCH",
            }),
          );
        });
        return false;
      }
      return originalKill.call(this, signal);
    };

    try {
      const runner = new NodeProcessRunner({
        defaultTimeoutMs: 100,
        terminationGraceMs: 100,
      });
      const result = await runner.run({
        executable: NODE,
        args: [
          "-e",
          "setInterval(() => {}, 1_000); setTimeout(() => process.exit(0), 1_500)",
        ],
      });

      assert.equal(result.status, "timed_out");
      assert.equal(result.timedOut, true);
      assert.equal(result.signal, undefined);
    } finally {
      ChildProcess.prototype.kill = originalKill;
    }
  },
);

test("NodeProcessRunner 拒绝非法的终止宽限期", () => {
  for (const terminationGraceMs of [-1, 1.5, 10_001]) {
    assert.throws(
      () => new NodeProcessRunner({ terminationGraceMs }),
      /终止宽限期/u,
    );
  }
  assert.doesNotThrow(() => new NodeProcessRunner({ terminationGraceMs: 0 }));
  assert.doesNotThrow(
    () => new NodeProcessRunner({ terminationGraceMs: 10_000 }),
  );
});

test("NodeProcessRunner 正常完成后结果不受超时定时器影响", async () => {
  const runner = new NodeProcessRunner({
    defaultTimeoutMs: 150,
    terminationGraceMs: 25,
  });
  const result = await runner.run({
    executable: NODE,
    args: ["-e", "process.stdout.write('done')"],
  });

  await new Promise((resolve) => setTimeout(resolve, 250));
  assert.equal(result.status, "completed");
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, undefined);
  assert.equal(result.stdout, "done");
});

test("NodeProcessRunner 将启动失败分类为 start_failed 且不泄露工作目录", async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "hcheck-runner-"));
  try {
    const runner = new NodeProcessRunner();

    const result = await runner.run({
      executable: "hcheck-definitely-missing-command",
      args: [],
      cwd,
    });

    assert.equal(result.status, "start_failed");
    assert.ok(result.errorMessage?.includes("启动外部进程失败"));
    assert.ok(!JSON.stringify(result).includes(cwd));
  } finally {
    rmdirSync(cwd);
  }
});

test("NodeProcessRunner 限制 stdout/stderr 字节并标记截断", async () => {
  const runner = new NodeProcessRunner({
    defaultMaxStdoutBytes: 3,
    defaultMaxStderrBytes: 4,
  });

  const result = await runner.run({
    executable: NODE,
    args: [
      "-e",
      "process.stdout.write('abcdef'); process.stderr.write('123456')",
    ],
  });

  assert.equal(result.stdout, "abc");
  assert.equal(result.stderr, "1234");
  assert.equal(result.stdoutTruncated, true);
  assert.equal(result.stderrTruncated, true);
});

test("NodeProcessRunner 不通过 shell 拼接，元字符作为 argv 原样传入", async () => {
  const runner = new NodeProcessRunner();

  const result = await runner.run({
    executable: NODE,
    args: [
      "-e",
      "process.stdout.write(process.argv[1])",
      "safe; echo injected",
    ],
  });

  assert.equal(result.status, "completed");
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "safe; echo injected");
});

test("NodeProcessRunner 脱敏敏感环境值和当前工作目录输出", async () => {
  const cwd = mkdtempSync(path.join(tmpdir(), "hcheck-runner-"));
  try {
    const runner = new NodeProcessRunner({
      baseEnvironment: { PATH: process.env.PATH ?? "" },
      environmentAllowList: ["PATH"],
    });

    const result = await runner.run({
      executable: NODE,
      args: [
        "-e",
        "process.stdout.write(`${process.env.API_TOKEN}:${process.cwd()}`)",
      ],
      cwd,
      env: { API_TOKEN: "super-secret-token" },
    });

    assert.equal(result.status, "completed");
    assert.ok(!result.stdout.includes("super-secret-token"));
    assert.ok(!result.stdout.includes(cwd));
    assert.ok(result.stdout.includes("[REDACTED_SECRET]"));
    assert.ok(result.stdout.includes("[REDACTED_PATH]"));
  } finally {
    rmdirSync(cwd);
  }
});
