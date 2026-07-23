import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import {
  appendFile,
  mkdtemp,
  open,
  readFile,
  readdir,
  rmdir,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { rootCertificates } from "node:tls";
import test from "node:test";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import {
  HapSignatureVerificationError,
  type HapSignatureVerificationOptions,
  verifyHapSignature,
} from "../src/hap-signature.js";
import { TEST_LEAF_CERTIFICATE_PEM } from "./test-leaf-certificate.js";

const HAP_BYTES = Buffer.from("stable-hap");
const JAR_BYTES = Buffer.from("stable-hap-sign-tool");
const BUNDLE = "com.example.hcheck.smoke";
const NOT_BEFORE = 1_610_519_532;
const NOT_AFTER = 1_705_127_532;
const NOW = new Date(1_650_000_000 * 1000);
const SIGNER_PEM = TEST_LEAF_CERTIFICATE_PEM;
const OTHER_PEM = rootCertificates[0] as string;
const SIGNER_DER = new X509Certificate(SIGNER_PEM).raw;
const OTHER_DER = new X509Certificate(OTHER_PEM).raw;
const OFFICIAL_STYLE_SIGNER_PEM = ` \n${SIGNER_PEM.split("\n")
  .map((line) =>
    line.startsWith("-----") || line.length === 0 ? line : `  ${line}`,
  )
  .join("\n")}\n\t`;
const WORKSPACE_PREFIX = "hcheck-signature-";

const sha256 = (bytes: Uint8Array): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

const completed = (
  fields: Partial<ProcessRunResult> = {},
): ProcessRunResult => ({
  status: "completed",
  exitCode: 0,
  timedOut: false,
  stdout: "[Success] verified",
  stderr: "",
  stdoutTruncated: false,
  stderrTruncated: false,
  ...fields,
});

interface ProfileFields {
  readonly verifiedPassed?: unknown;
  readonly message?: unknown;
  readonly type?: unknown;
  readonly notBefore?: unknown;
  readonly notAfter?: unknown;
  readonly bundleName?: unknown;
  readonly developmentCertificate?: unknown;
}

function profileJson(fields: ProfileFields = {}): string {
  return JSON.stringify({
    verifiedPassed: fields.verifiedPassed ?? true,
    message: fields.message ?? "OK",
    content: {
      type: fields.type ?? "debug",
      validity: {
        "not-before": fields.notBefore ?? NOT_BEFORE,
        "not-after": fields.notAfter ?? NOT_AFTER,
      },
      "bundle-info": {
        "bundle-name": fields.bundleName ?? BUNDLE,
        "development-certificate":
          fields.developmentCertificate ?? SIGNER_DER.toString("base64"),
        "developer-id": "不得泄漏",
        "device-id-type": ["不得泄漏"],
        "device-ids": ["不得泄漏"],
      },
    },
  });
}

type Phase = 0 | 1;
type Outcome = ProcessRunResult | Error;
type PreparePhase = (cwd: string) => Promise<void>;

interface RunnerScenario {
  readonly outcomes?: readonly [Outcome?, Outcome?];
  readonly prepareFirst?: PreparePhase;
  readonly prepareSecond?: PreparePhase;
}

class FakeRunner implements ProcessRunnerPort {
  public readonly requests: ProcessRunRequest[] = [];
  public readonly jarHashes: string[] = [];
  public readonly workspaceModes: number[] = [];
  public readonly inputModes: number[][] = [];

  public constructor(private readonly scenario: RunnerScenario = {}) {}

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    const phase = this.requests.length as Phase;
    this.requests.push(request);
    assert.ok(request.cwd);
    this.jarHashes.push(
      sha256(await readFile(path.join(request.cwd, "hap-sign-tool.jar"))),
    );
    this.workspaceModes.push((await stat(request.cwd)).mode & 0o777);
    this.inputModes.push(
      await Promise.all(
        ["artifact.hap", "hap-sign-tool.jar"].map(
          async (name) =>
            (await stat(path.join(request.cwd as string, name))).mode & 0o777,
        ),
      ),
    );
    if (phase === 0) {
      if (this.scenario.prepareFirst === undefined) {
        await writeDefaultFirstOutputs(request.cwd);
      } else {
        await this.scenario.prepareFirst(request.cwd);
      }
    } else if (this.scenario.prepareSecond === undefined) {
      await writeDefaultSecondOutput(request.cwd);
    } else {
      await this.scenario.prepareSecond(request.cwd);
    }
    const outcome = this.scenario.outcomes?.[phase] ?? completed();
    if (outcome instanceof Error) throw outcome;
    return outcome;
  }
}

async function writeDefaultFirstOutputs(cwd: string): Promise<void> {
  await writeFile(path.join(cwd, "cert-chain.cer"), SIGNER_PEM);
  await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
}

async function writeDefaultSecondOutput(cwd: string): Promise<void> {
  await writeFile(path.join(cwd, "profile-verification.json"), profileJson());
}

function options(
  runner: ProcessRunnerPort,
  temporaryParent: string,
  overrides: Partial<HapSignatureVerificationOptions> = {},
): HapSignatureVerificationOptions {
  return {
    runner,
    javaExecutable: "/safe/java",
    hapBytes: HAP_BYTES,
    expectedHapSha256: sha256(HAP_BYTES),
    hapSignToolJarBytes: JAR_BYTES,
    expectedHapSignToolSha256: sha256(JAR_BYTES),
    bundleName: BUNDLE,
    clock: { now: () => NOW },
    temporaryParent,
    ...overrides,
  };
}

async function createParent(label: string): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), `hcheck-signature-${label}-`));
}

async function assertParentEmptyAndRemove(parent: string): Promise<void> {
  assert.deepEqual(await readdir(parent), []);
  await rmdir(parent);
}

async function expectFailureAndCleanup(
  scenario: RunnerScenario,
  expected: RegExp,
): Promise<FakeRunner> {
  const parent = await createParent("failure");
  const runner = new FakeRunner(scenario);
  try {
    await assert.rejects(verifyHapSignature(options(runner, parent)), expected);
    assert.deepEqual(await readdir(parent), []);
    return runner;
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
}

test("verifyHapSignature 使用同一私有 JAR 精确验签并只返回安全摘要", async () => {
  const parent = await createParent("success");
  const runner = new FakeRunner();
  try {
    const summary = await verifyHapSignature(options(runner, parent));

    assert.equal(runner.requests.length, 2);
    assert.deepEqual(runner.requests[0], {
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
      cwd: runner.requests[0]?.cwd,
      timeoutMs: 30_000,
      maxStdoutBytes: 64 * 1024,
      maxStderrBytes: 64 * 1024,
    });
    assert.deepEqual(runner.requests[1], {
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
      cwd: runner.requests[0]?.cwd,
      timeoutMs: 30_000,
      maxStdoutBytes: 64 * 1024,
      maxStderrBytes: 64 * 1024,
    });
    assert.deepEqual(runner.jarHashes, [sha256(JAR_BYTES), sha256(JAR_BYTES)]);
    if (process.platform !== "win32") {
      assert.deepEqual(runner.workspaceModes, [0o700, 0o700]);
      assert.deepEqual(runner.inputModes, [
        [0o600, 0o600],
        [0o600, 0o600],
      ]);
    }
    assert.deepEqual(summary, {
      hapSha256: sha256(HAP_BYTES),
      hapSignToolSha256: sha256(JAR_BYTES),
      profileSha256: sha256(Buffer.from("signed-profile")),
      signerCertificateSha256: sha256(SIGNER_DER),
      bundleName: BUNDLE,
      profileType: "debug",
      validity: { notBefore: NOT_BEFORE, notAfter: NOT_AFTER },
      trustBoundary:
        "仅证明验签工具自包含证书链与 Profile 内容签名一致，不证明 AGC/平台根信任或证书撤销状态。",
    });
    assert.ok(!JSON.stringify(summary).includes("不得泄漏"));
    assert.ok(!JSON.stringify(summary).includes(parent));
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 接受官方 epoch 秒和带空白 PEM 并保持摘要最小化", async () => {
  const parent = await createParent("pem");
  const runner = new FakeRunner({
    prepareSecond: async (cwd) =>
      writeFile(
        path.join(cwd, "profile-verification.json"),
        profileJson({ developmentCertificate: OFFICIAL_STYLE_SIGNER_PEM }),
      ),
  });
  try {
    const summary = await verifyHapSignature(options(runner, parent));
    assert.equal(summary.signerCertificateSha256, sha256(SIGNER_DER));
    assert.ok(!JSON.stringify(summary).includes("BEGIN CERTIFICATE"));
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 接受 hap-sign-tool 唯一的 outproof 缺参警告", async () => {
  const parent = await createParent("outproof-warning");
  const runner = new FakeRunner({
    outcomes: [
      completed({
        stderr: "07-22 15:52:25.416  WARN - Missing parameter: outproof\n",
      }),
    ],
  });
  try {
    const summary = await verifyHapSignature(options(runner, parent));
    assert.equal(summary.profileType, "debug");
    assert.equal(runner.requests.length, 2);
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 在 HAP/JAR 哈希不匹配时零调用且不创建工作区", async () => {
  for (const overrides of [
    { expectedHapSha256: `sha256:${"0".repeat(64)}` as const },
    { expectedHapSignToolSha256: `sha256:${"0".repeat(64)}` as const },
  ]) {
    const parent = await createParent("hash");
    const runner = new FakeRunner();
    try {
      await assert.rejects(
        verifyHapSignature(options(runner, parent, overrides)),
        /哈希/u,
      );
      assert.equal(runner.requests.length, 0);
      assert.deepEqual(await readdir(parent), []);
    } finally {
      await assertParentEmptyAndRemove(parent);
    }
  }
});

const unsafeProcessResults = [
  ["非零退出", completed({ exitCode: 9 })],
  [
    "超时",
    completed({ status: "timed_out", timedOut: true, exitCode: undefined }),
  ],
  ["输出截断", completed({ stdoutTruncated: true })],
  ["信号终止", completed({ signal: "SIGTERM" })],
  ["Fail 标记", completed({ stdout: "[Fail] signature invalid" })],
  ["Error 标记", completed({ stdout: "[Error] E123" })],
  ["标准错误", completed({ stderr: "private tool details" })],
] as const;

for (const phase of [0, 1] as const) {
  for (const [label, result] of unsafeProcessResults) {
    test(`verifyHapSignature 拒绝第 ${phase + 1} 个命令的${label}并清理`, async () => {
      const outcomes: [Outcome?, Outcome?] = [];
      outcomes[phase] = result;
      const runner = await expectFailureAndCleanup(
        { outcomes },
        /验签工具未安全完成/u,
      );
      assert.equal(runner.requests.length, phase + 1);
    });
  }
}

test("verifyHapSignature 屏蔽 Runner 抛出的原始路径与日志并清理", async () => {
  const runner = await expectFailureAndCleanup(
    { outcomes: [new Error("/private/path secret tool log")] },
    /验签工具执行失败/u,
  );
  assert.equal(runner.requests.length, 1);
});

const unsafeOutputScenarios: readonly [string, RunnerScenario, RegExp][] = [
  [
    "缺失输出",
    {
      prepareFirst: async (cwd) =>
        writeFile(path.join(cwd, "profile.p7b"), "signed-profile"),
    },
    /输出文件不安全/u,
  ],
  [
    "第二命令缺失输出",
    { prepareSecond: async () => Promise.resolve() },
    /输出文件不安全/u,
  ],
  [
    "符号链接输出",
    {
      prepareFirst: async (cwd) => {
        await symlink("hap-sign-tool.jar", path.join(cwd, "cert-chain.cer"));
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /输出文件不安全/u,
  ],
  [
    "预先存在的后续输出",
    {
      prepareFirst: async (cwd) => {
        await writeDefaultFirstOutputs(cwd);
        await writeDefaultSecondOutput(cwd);
      },
    },
    /调用前已存在/u,
  ],
  [
    "超限输出",
    {
      prepareFirst: async (cwd) => {
        await writeFile(
          path.join(cwd, "cert-chain.cer"),
          Buffer.alloc(256 * 1024 + 1),
        );
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /输出文件不安全/u,
  ],
  [
    "无效 JSON",
    {
      prepareSecond: async (cwd) =>
        writeFile(path.join(cwd, "profile-verification.json"), "{invalid"),
    },
    /不是有效 JSON/u,
  ],
];

for (const [label, scenario, expected] of unsafeOutputScenarios) {
  test(`verifyHapSignature 拒绝${label}并逐项清理`, async () => {
    await expectFailureAndCleanup(scenario, expected);
  });
}

test("verifyHapSignature 拒绝验签期间被替换的 JAR", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeDefaultFirstOutputs(cwd);
        const jar = path.join(cwd, "hap-sign-tool.jar");
        await unlink(jar);
        await writeFile(jar, JAR_BYTES);
      },
    },
    /被替换/u,
  );
});

test("verifyHapSignature 拒绝第二命令期间被替换的 Profile 输出", async () => {
  await expectFailureAndCleanup(
    {
      prepareSecond: async (cwd) => {
        const profile = path.join(cwd, "profile.p7b");
        await unlink(profile);
        await writeFile(profile, "signed-profile");
        await writeDefaultSecondOutput(cwd);
      },
    },
    /被替换/u,
  );
});

const invalidProfileCases: readonly [string, ProfileFields, RegExp][] = [
  ["CMS false", { verifiedPassed: false }, /CMS 验签未通过/u],
  ["非 OK message", { message: "FAILED" }, /CMS 验签未通过/u],
  ["release 类型", { type: "release" }, /仅允许 debug/u],
  ["Bundle 不符", { bundleName: "com.example.other" }, /Bundle 名称不匹配/u],
  ["尚未生效", { notBefore: 1_650_000_001 }, /不在有效期/u],
  ["已经过期", { notAfter: 1_649_999_999 }, /不在有效期/u],
  ["负数有效期", { notBefore: -1 }, /有效期无效/u],
  ["小数有效期", { notBefore: 1.5 }, /有效期无效/u],
  ["字符串有效期", { notBefore: "1610519532" }, /有效期无效/u],
  [
    "超出安全整数有效期",
    { notAfter: Number.MAX_SAFE_INTEGER + 1 },
    /有效期无效/u,
  ],
  ["非法开发证书", { developmentCertificate: "not-base64" }, /开发证书无效/u],
];

for (const [label, fields, expected] of invalidProfileCases) {
  test(`verifyHapSignature 拒绝 Profile ${label}并清理`, async () => {
    await expectFailureAndCleanup(
      {
        prepareSecond: async (cwd) =>
          writeFile(
            path.join(cwd, "profile-verification.json"),
            profileJson(fields),
          ),
      },
      expected,
    );
  });
}

test("verifyHapSignature 拒绝开发证书与 HAP signer 零匹配", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeFile(path.join(cwd, "cert-chain.cer"), OTHER_PEM);
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /不唯一匹配/u,
  );
});

test("verifyHapSignature 拒绝开发证书与 HAP signer 多匹配", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeFile(
          path.join(cwd, "cert-chain.cer"),
          `${SIGNER_PEM}\n${SIGNER_PEM}`,
        );
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /不唯一匹配/u,
  );
});

test("verifyHapSignature 接受 DevEco 根到叶子的证书链并定位唯一非 CA 开发证书", async () => {
  const parent = await createParent("deveco-root-to-leaf");
  const runner = new FakeRunner({
    prepareFirst: async (cwd) => {
      await writeFile(
        path.join(cwd, "cert-chain.cer"),
        `CN=HCheck Root CA\n${OTHER_PEM}\nCN=hcheck-test-leaf\n${SIGNER_PEM}`,
      );
      await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
    },
  });
  try {
    const summary = await verifyHapSignature(options(runner, parent));
    assert.equal(summary.signerCertificateSha256, sha256(SIGNER_DER));
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 拒绝 Profile 开发证书匹配 CA 证书", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeFile(path.join(cwd, "cert-chain.cer"), OTHER_PEM);
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
      prepareSecond: async (cwd) =>
        writeFile(
          path.join(cwd, "profile-verification.json"),
          profileJson({ developmentCertificate: OTHER_DER.toString("base64") }),
        ),
    },
    /非 CA 叶子/u,
  );
});

test("verifyHapSignature 接受证书块外的官方 SubjectDN 行", async () => {
  const parent = await createParent("subject-dn");
  const runner = new FakeRunner({
    prepareFirst: async (cwd) => {
      await writeFile(
        path.join(cwd, "cert-chain.cer"),
        `SubjectDN: CN=Signer\n${SIGNER_PEM}`,
      );
      await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
    },
  });
  try {
    const summary = await verifyHapSignature(options(runner, parent));
    assert.equal(summary.signerCertificateSha256, sha256(SIGNER_DER));
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 拒绝证书块外的非官方杂项文本", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeFile(
          path.join(cwd, "cert-chain.cer"),
          `${SIGNER_PEM}\nuntrusted-junk`,
        );
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /证书链格式无效/u,
  );
});

test("verifyHapSignature 对同 inode 扩展只读取初始长度加一字节", async () => {
  const parent = await createParent("same-inode-growth");
  const probePath = path.join(parent, "probe");
  await writeFile(probePath, "probe");
  const probeHandle = await open(probePath, "r");
  type FileHandle = typeof probeHandle;
  type PositionalRead = (
    this: FileHandle,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ) => Promise<{ bytesRead: number; buffer: Uint8Array }>;
  const prototype = Object.getPrototypeOf(probeHandle) as {
    read: FileHandle["read"];
  };
  const originalRead = prototype.read as unknown as PositionalRead;
  await probeHandle.close();
  await unlink(probePath);

  const originalLength = Buffer.byteLength("signed-profile");
  let target: { path: string; ino: number | bigint } | undefined;
  let extended = false;
  let maximumRequested = 0;
  const replacementRead: PositionalRead = async function (
    buffer,
    offset,
    length,
    position,
  ) {
    const details = await this.stat();
    if (target !== undefined && details.ino === target.ino && !extended) {
      extended = true;
      maximumRequested = Math.max(maximumRequested, length);
      await appendFile(target.path, Buffer.alloc(1024 * 1024));
    }
    return originalRead.call(this, buffer, offset, length, position);
  };
  prototype.read = replacementRead as unknown as FileHandle["read"];

  const runner = new FakeRunner({
    prepareSecond: async (cwd) => {
      const profilePath = path.join(cwd, "profile.p7b");
      target = { path: profilePath, ino: (await stat(profilePath)).ino };
      await writeDefaultSecondOutput(cwd);
    },
  });
  try {
    await assert.rejects(
      verifyHapSignature(options(runner, parent)),
      /输出文件不安全|发生变化/u,
    );
    assert.equal(extended, true);
    assert.ok(maximumRequested <= originalLength + 1);
    assert.deepEqual(await readdir(parent), []);
  } finally {
    prototype.read = originalRead as unknown as FileHandle["read"];
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 拒绝夹带未闭合证书块的 HAP 证书链", async () => {
  await expectFailureAndCleanup(
    {
      prepareFirst: async (cwd) => {
        await writeFile(
          path.join(cwd, "cert-chain.cer"),
          `${SIGNER_PEM}\n-----BEGIN CERTIFICATE-----\nbroken`,
        );
        await writeFile(path.join(cwd, "profile.p7b"), "signed-profile");
      },
    },
    /证书链/u,
  );
});

test("verifyHapSignature 清理遇到未知文件时拒绝冒充通过且不递归删除", async () => {
  const parent = await createParent("cleanup");
  const runner = new FakeRunner({
    prepareSecond: async (cwd) => {
      await writeDefaultSecondOutput(cwd);
      await writeFile(path.join(cwd, "unexpected.txt"), "must-not-delete");
    },
  });
  try {
    await assert.rejects(
      verifyHapSignature(options(runner, parent)),
      /工作区清理失败/u,
    );
    const entries = await readdir(parent);
    assert.equal(entries.length, 1);
    assert.ok(entries[0]?.startsWith(WORKSPACE_PREFIX));
    const workspace = path.join(parent, entries[0] as string);
    assert.deepEqual(await readdir(workspace), ["unexpected.txt"]);
    await unlink(path.join(workspace, "unexpected.txt"));
    await rmdir(workspace);
  } finally {
    await assertParentEmptyAndRemove(parent);
  }
});

test("verifyHapSignature 拒绝符号链接临时父目录且零调用", async () => {
  const base = await createParent("parent-link");
  const actual = path.join(base, "actual");
  const linked = path.join(base, "linked");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(actual));
  await symlink(actual, linked, "dir");
  const runner = new FakeRunner();
  try {
    await assert.rejects(
      verifyHapSignature(options(runner, linked)),
      /父目录不安全/u,
    );
    assert.equal(runner.requests.length, 0);
    assert.deepEqual(await readdir(actual), []);
  } finally {
    await unlink(linked);
    await rmdir(actual);
    await rmdir(base);
  }
});

test("HapSignatureVerificationError 不携带底层 cause", () => {
  const error = new HapSignatureVerificationError("安全消息");
  assert.equal(error.message, "安全消息");
  assert.equal(error.cause, undefined);
});
