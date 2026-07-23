import assert from "node:assert/strict";
import test from "node:test";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import {
  probeHdcDeviceDetails,
  probeHdcDevices,
  probeHdcVersion,
} from "../src/index.js";

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

class FakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];

  public constructor(private readonly result: ProcessRunResult) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    this.requests.push(request);
    return this.result;
  }
}

test("probeHdcDevices 工具缺失和无设备时不伪造成功", async () => {
  const missingRunner = new FakeRunner(
    completed({ status: "start_failed", errorMessage: "ENOENT /Users/me/hdc" }),
  );

  const missing = await probeHdcDevices({ runner: missingRunner });

  assert.equal(missing.status, "unavailable");
  assert.equal(missing.available, false);
  assert.equal(missing.devices.length, 0);
  assert.deepEqual(missingRunner.requests[0]?.args, ["list", "targets"]);
  assert.ok(!JSON.stringify(missing).includes("/Users/me"));

  const empty = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "[Empty]" })),
  });

  assert.equal(empty.status, "no_devices");
  assert.equal(empty.available, true);
  assert.equal(empty.devices.length, 0);
});

test("probeHdcDevices 区分多设备、离线、未授权、超时和命令失败", async () => {
  const multiple = await probeHdcDevices({
    runner: new FakeRunner(
      completed({
        stdout: ["ABC123", "DEF456"].join("\n"),
      }),
    ),
  });
  assert.equal(multiple.status, "multiple_devices");
  assert.deepEqual(
    multiple.devices.map((device) => device.state),
    ["connected", "connected"],
  );

  const offline = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "ABC123\toffline" })),
  });
  assert.equal(offline.status, "offline");
  assert.equal(offline.devices[0]?.state, "offline");

  const unauthorized = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "ABC123\tunauthorized" })),
  });
  assert.equal(unauthorized.status, "unauthorized");
  assert.equal(unauthorized.devices[0]?.state, "unauthorized");

  const timedOut = await probeHdcDevices({
    runner: new FakeRunner(completed({ status: "timed_out", timedOut: true })),
  });
  assert.equal(timedOut.status, "timed_out");

  const failed = await probeHdcDevices({
    runner: new FakeRunner(
      completed({ exitCode: 1, stderr: "failed apiToken=SECRET /Users/me" }),
    ),
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.exitCode, 1);
  assert.ok(!JSON.stringify(failed).includes("SECRET"));
  assert.ok(!JSON.stringify(failed).includes("/Users/me"));
});

test("自动枚举只使用 plain 参数，详细探测明确标记为仅展示", async () => {
  const plainRunner = new FakeRunner(
    completed({ stdout: "ABC123 USB Ready Phone hdc-label" }),
  );
  const plain = await probeHdcDevices({ runner: plainRunner });

  assert.deepEqual(plainRunner.requests[0]?.args, ["list", "targets"]);
  assert.equal(plain.status, "failed");
  assert.equal(plain.available, false);

  const detailRunner = new FakeRunner(
    completed({ stdout: "ABC123 USB Ready Phone hdc-label" }),
  );
  const detail = await probeHdcDeviceDetails({ runner: detailRunner });

  assert.deepEqual(detailRunner.requests[0]?.args, ["list", "targets", "-v"]);
  assert.equal(detail.displayOnly, true);
  assert.equal(detail.status, "available");
  assert.equal(detail.available, true);
  assert.equal(detail.devices[0]?.state, "connected");
  assert.ok(!JSON.stringify(detail).includes("ABC123"));
});

test("plain 和 detail 枚举捕获 runner 抛错且公开命令不泄漏执行路径", async () => {
  const secret = "/Users/private/SECRET/hdc";
  const throwingRunner: ProcessRunnerPort = {
    async run() {
      throw new Error(`spawn ${secret} failed`);
    },
  };

  const plain = await probeHdcDevices({
    runner: throwingRunner,
    executable: secret,
    cwd: "/Users/private/SECRET",
  });
  const detail = await probeHdcDeviceDetails({
    runner: throwingRunner,
    executable: secret,
    cwd: "/Users/private/SECRET",
  });

  assert.deepEqual(plain, {
    available: false,
    status: "unavailable",
    devices: [],
    command: { args: ["list", "targets"] },
    reason: "hdc 不可用。",
  });
  assert.deepEqual(detail, {
    available: false,
    status: "unavailable",
    devices: [],
    command: { args: ["list", "targets", "-v"] },
    reason: "hdc 不可用。",
    displayOnly: true,
  });
  assert.ok(!JSON.stringify({ plain, detail }).includes("SECRET"));
  assert.ok(!JSON.stringify({ plain, detail }).includes("/Users"));
});

test("详细探测严格规范化官方五种设备状态", async () => {
  const cases = [
    { raw: "Ready", normalized: "connected", status: "available" },
    { raw: "cOnNeCtEd", normalized: "connected", status: "available" },
    { raw: "OFFLINE", normalized: "offline", status: "offline" },
    {
      raw: "Unauthorized",
      normalized: "unauthorized",
      status: "unauthorized",
    },
  ] as const;

  for (const [index, item] of cases.entries()) {
    const result = await probeHdcDeviceDetails({
      runner: new FakeRunner(
        completed({
          stdout: `KEY${index} ${index % 2 === 0 ? "USB" : "tcp"} ${item.raw} Phone hdc-label`,
        }),
      ),
    });

    assert.equal(result.status, item.status);
    assert.equal(result.available, item.status !== "failed");
    assert.equal(result.devices[0]?.state, item.normalized);
  }

  const unknown = await probeHdcDeviceDetails({
    runner: new FakeRunner(
      completed({ stdout: "UNKNOWN-KEY USB unknown Phone hdc-label" }),
    ),
  });
  assert.equal(unknown.status, "failed");
  assert.equal(unknown.available, false);
  assert.deepEqual(unknown.devices, []);
});

test("未知行、异常 token、空 connect-key 和重复 key 整体失败且不部分成功", async () => {
  const malformedOutputs = [
    "ABC123 connected unexpected",
    "ABC123\nABC123",
    "ABC123\nDEF456 connected unexpected",
  ];

  for (const stdout of malformedOutputs) {
    const result = await probeHdcDevices({
      runner: new FakeRunner(completed({ stdout })),
    });
    assert.equal(result.status, "failed");
    assert.equal(result.available, false);
    assert.deepEqual(result.devices, []);
    assert.ok(!JSON.stringify(result).includes("ABC123"));
    assert.ok(!JSON.stringify(result).includes("DEF456"));
  }

  const emptyKey = await probeHdcDeviceDetails({
    runner: new FakeRunner(
      completed({ stdout: "\tUSB Ready Phone hdc-label" }),
    ),
  });
  assert.equal(emptyKey.status, "failed");
  assert.deepEqual(emptyKey.devices, []);
});

test("任一输出截断都整体失败", async () => {
  for (const fields of [
    { stdoutTruncated: true, stdout: "ABC123" },
    { stderrTruncated: true, stdout: "ABC123" },
  ]) {
    const result = await probeHdcDevices({
      runner: new FakeRunner(completed(fields)),
    });
    assert.equal(result.status, "failed");
    assert.equal(result.available, false);
    assert.deepEqual(result.devices, []);
    assert.ok(!JSON.stringify(result).includes("ABC123"));
  }
});

test("退出码为零时仍拒绝标准错误码和 Fail 标志", async () => {
  const outputs = [
    { stdout: "[E000000] ABC123" },
    { stderr: "[E123456] DEF456", stdout: "ABC123" },
    { stdout: "[Fail] ABC123" },
    { stderr: "[fAiL] DEF456", stdout: "ABC123" },
  ];

  for (const fields of outputs) {
    const result = await probeHdcDevices({
      runner: new FakeRunner(completed(fields)),
    });
    assert.equal(result.status, "failed");
    assert.equal(result.available, false);
    assert.deepEqual(result.devices, []);
    assert.ok(!JSON.stringify(result).includes("ABC123"));
    assert.ok(!JSON.stringify(result).includes("DEF456"));
  }
});

test("plain 和 detail 枚举拒绝带 signal 或 errorMessage 的成功形状结果", async () => {
  const cases = [
    { fields: { signal: "SIGTERM" }, sensitive: "SIGTERM" },
    {
      fields: { errorMessage: "token=SECRET /Users/private/hdc" },
      sensitive: "token=SECRET /Users/private/hdc",
    },
  ] as const;

  for (const { fields, sensitive } of cases) {
    const plain = await probeHdcDevices({
      runner: new FakeRunner(completed({ stdout: "ABC123", ...fields })),
    });
    const detail = await probeHdcDeviceDetails({
      runner: new FakeRunner(
        completed({
          stdout: "ABC123 USB Ready Phone hdc-label",
          ...fields,
        }),
      ),
    });

    for (const result of [plain, detail]) {
      assert.equal(result.status, "failed");
      assert.equal(result.available, false);
      assert.deepEqual(result.devices, []);
      assert.ok(!JSON.stringify(result).includes(sensitive));
      assert.ok(!JSON.stringify(result).includes("ABC123"));
    }
  }
});

test("plain 和 detail 枚举拒绝普通 stderr 且不泄露", async () => {
  const plain = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "ABC123", stderr: "warning" })),
  });
  const detail = await probeHdcDeviceDetails({
    runner: new FakeRunner(
      completed({
        stdout: "ABC123 USB Ready Phone hdc-label",
        stderr: "warning",
      }),
    ),
  });

  for (const result of [plain, detail]) {
    assert.equal(result.status, "failed");
    assert.equal(result.available, false);
    assert.deepEqual(result.devices, []);
    assert.ok(!JSON.stringify(result).includes("warning"));
  }
});

test("裸 E 加六位数字可以作为合法 connect-key", async () => {
  const result = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "E123456" })),
  });

  assert.equal(result.status, "available");
  assert.equal(result.available, true);
  assert.equal(result.devices.length, 1);
  assert.equal(result.devices[0]?.state, "connected");
  assert.ok(!JSON.stringify(result).includes("E123456"));
});

test("设备 ID 是基于原始 connect-key 的稳定 SHA-256 且不泄露 key", async () => {
  const first = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "ABC123" })),
  });
  const reordered = await probeHdcDevices({
    runner: new FakeRunner(completed({ stdout: "DEF456\nABC123" })),
  });

  const abcId =
    "device:sha256:e0bebd22819993425814866b62701e2919ea26f1370499c1037b53b9d49c2c8a";
  const defId =
    "device:sha256:651988b99369e25ccd366a86e658450f0d2c6d112a4fa7b421a67084b3063013";
  assert.equal(first.devices[0]?.id, abcId);
  assert.deepEqual(
    reordered.devices.map((device) => device.id),
    [defId, abcId],
  );
  assert.equal(reordered.status, "multiple_devices");
  assert.ok(!JSON.stringify(first).includes("ABC123"));
  assert.ok(!JSON.stringify(reordered).includes("ABC123"));
  assert.ok(!JSON.stringify(reordered).includes("DEF456"));
});

test("probeHdcVersion 固定使用 -v 并严格解析官方单行版本", async () => {
  for (const stdout of ["Ver: 3.1.0e", "Ver: 3.1.0e\n", "Ver: 3.1.0e\r\n"]) {
    const runner = new FakeRunner(completed({ stdout }));
    const result = await probeHdcVersion({ runner });

    assert.deepEqual(runner.requests[0]?.args, ["-v"]);
    assert.deepEqual(result, {
      available: true,
      status: "available",
      version: "3.1.0e",
      command: { args: ["-v"] },
    });
  }
});

test("probeHdcVersion 区分工具缺失、超时和普通失败且不泄漏诊断原文", async () => {
  const cases = [
    {
      result: completed({
        status: "start_failed",
        errorMessage: "ENOENT /Users/private/SECRET/hdc",
      }),
      status: "unavailable",
    },
    {
      result: completed({
        status: "timed_out",
        timedOut: true,
        stdout: "Ver: 3.1.0e",
      }),
      status: "timed_out",
    },
    {
      result: completed({ exitCode: 1, stderr: "token=SECRET" }),
      status: "failed",
    },
  ] as const;

  for (const item of cases) {
    const result = await probeHdcVersion({
      runner: new FakeRunner(item.result),
      executable: "/Users/private/SECRET/hdc",
      cwd: "/Users/private/SECRET",
    });
    assert.equal(result.available, false);
    assert.equal(result.status, item.status);
    assert.equal("version" in result, false);
    assert.ok(!JSON.stringify(result).includes("SECRET"));
    assert.ok(!JSON.stringify(result).includes("/Users"));
  }

  const thrown = await probeHdcVersion({
    runner: {
      async run() {
        throw new Error("spawn /Users/private/SECRET/hdc failed");
      },
    },
    executable: "/Users/private/SECRET/hdc",
  });
  assert.equal(thrown.available, false);
  assert.equal(thrown.status, "unavailable");
  assert.ok(!JSON.stringify(thrown).includes("SECRET"));
  assert.ok(!JSON.stringify(thrown).includes("/Users"));
});

test("probeHdcVersion 拒绝成功退出码中的 signal 或 errorMessage", async () => {
  const cases = [
    {
      fields: { signal: "SIGTERM" },
      sensitive: "SIGTERM",
    },
    {
      fields: { errorMessage: "token=SECRET /Users/private/hdc" },
      sensitive: "token=SECRET /Users/private/hdc",
    },
  ] as const;

  for (const item of cases) {
    const result = await probeHdcVersion({
      runner: new FakeRunner(
        completed({ stdout: "Ver: 3.1.0e", ...item.fields }),
      ),
    });

    assert.equal(result.available, false);
    assert.equal(result.status, "failed");
    assert.equal("version" in result, false);
    assert.ok(!JSON.stringify(result).includes(item.sensitive));
  }
});

test("probeHdcVersion 拒绝截断、stderr、错误标志和非精确版本输出", async () => {
  const failures = [
    completed({ stdout: "Ver: 3.1.0e", stdoutTruncated: true }),
    completed({ stdout: "Ver: 3.1.0e", stderrTruncated: true }),
    completed({ stdout: "Ver: 3.1.0e", stderr: "warning" }),
    completed({ stdout: "[E123456] Ver: 3.1.0e" }),
    completed({ stdout: "[Fail] Ver: 3.1.0e" }),
    completed({ stdout: "" }),
    completed({ stdout: "Ver: 3.1.0e\nextra" }),
    completed({ stdout: "prefix Ver: 3.1.0e\n" }),
    completed({ stdout: "Ver: 3.1.0e\n\n" }),
    completed({ stdout: "Ver: 3.1.0" }),
    completed({ stdout: "Ver: 03.1.0e" }),
  ];

  for (const failure of failures) {
    const result = await probeHdcVersion({ runner: new FakeRunner(failure) });
    assert.equal(result.available, false);
    assert.equal(result.status, "failed");
    assert.equal("version" in result, false);
  }
});
