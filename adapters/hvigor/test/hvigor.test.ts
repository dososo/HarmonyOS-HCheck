import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import test from "node:test";
import type {
  HashPort,
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import {
  createArtifactManifest,
  probeHvigor,
  runCleanReleaseBuild,
  type HvigorBuildConfig,
  type HvigorBuildRun,
  type HvigorFileSystemPort,
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

class FakeFs implements HvigorFileSystemPort {
  public constructor(
    private readonly existing: readonly string[],
    private readonly files: readonly string[] = [],
    private readonly artifacts: Readonly<
      Record<
        string,
        {
          readonly content?: string;
          readonly isSymbolicLink?: boolean;
          readonly readError?: boolean;
        }
      >
    > = {},
  ) {}

  public async exists(file: string): Promise<boolean> {
    return this.existing.includes(file);
  }

  public async listFiles(): Promise<readonly string[]> {
    return this.files;
  }

  public async statFile(file: string): Promise<{
    readonly size: number;
    readonly isFile: boolean;
    readonly isSymbolicLink: boolean;
  }> {
    const artifact = this.artifacts[file];
    return {
      size: Buffer.byteLength(artifact?.content ?? ""),
      isFile: artifact !== undefined,
      isSymbolicLink: artifact?.isSymbolicLink === true,
    };
  }

  public async readFile(file: string): Promise<Uint8Array> {
    const artifact = this.artifacts[file];
    if (artifact?.readError === true) throw new Error("read failed");
    return Buffer.from(artifact?.content ?? "");
  }
}

const releaseBuildConfig: HvigorBuildConfig = {
  profile: "release",
  clean: true,
  command: "./hvigorw assembleApp",
  artifact: {
    include: ["**/*.app", "**/*.hap"],
    exclude: ["**/*-unsigned.hap"],
  },
};

const hash: HashPort = {
  async sha256(content) {
    const hex = Buffer.from(content).toString("hex").padEnd(64, "0");
    return `sha256:${hex.slice(0, 64)}` as `sha256:${string}`;
  },
};

const cryptographicHash: HashPort = {
  async sha256(content) {
    return sha256Digest(content);
  },
};

function sha256Digest(content: Uint8Array | string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

test("probeHvigor 未发现项目 wrapper 时返回 unavailable 且不执行进程", async () => {
  const runner = new FakeRunner(completed());

  const capability = await probeHvigor({
    projectRoot: "/repo/app",
    fs: new FakeFs([]),
    runner,
    platform: "linux",
  });

  assert.equal(capability.status, "unavailable");
  assert.equal(capability.available, false);
  assert.equal(capability.reason, "项目根目录未发现 hvigorw wrapper。");
  assert.equal(runner.requests.length, 0);
});

test("probeHvigor 使用项目 wrapper 查询版本并返回脱敏能力摘要", async () => {
  const projectRoot = "/repo/app";
  const runner = new FakeRunner(
    completed({ stdout: "Hvigor 6.0.6\n/path/should-not-leak" }),
  );

  const capability = await probeHvigor({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw")]),
    runner,
    platform: "linux",
  });

  assert.equal(capability.status, "available");
  assert.equal(capability.available, true);
  assert.equal(capability.version, "Hvigor 6.0.6");
  assert.deepEqual(capability.command, {
    executable: "hvigorw",
    args: ["--version"],
  });
  assert.deepEqual(
    runner.requests.map(({ cwd, args }) => ({ cwd, args })),
    [{ cwd: projectRoot, args: ["--version"] }],
  );
  assert.ok(!JSON.stringify(capability).includes(projectRoot));
});

test("probeHvigor 在 Windows 优先识别 hvigorw.bat", async () => {
  const projectRoot = "C:\\repo\\app";
  const runner = new FakeRunner(completed({ stdout: "Hvigor 5.18.6" }));

  const capability = await probeHvigor({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw.bat")]),
    runner,
    platform: "win32",
  });

  assert.equal(capability.status, "available");
  assert.equal(capability.command.executable, "hvigorw.bat");
});

test("probeHvigor 将超时和非零退出明确分类且摘要不泄露秘密", async () => {
  const projectRoot = "/repo/app";
  const timedOut = await probeHvigor({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw")]),
    runner: new FakeRunner(completed({ status: "timed_out", timedOut: true })),
    platform: "linux",
  });
  assert.equal(timedOut.status, "timed_out");
  assert.equal(timedOut.reason, "hvigorw --version 执行超时。");

  const failed = await probeHvigor({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw")]),
    runner: new FakeRunner(
      completed({
        exitCode: 2,
        stderr: "apiToken=secret-value /repo/app",
      }),
    ),
    platform: "linux",
  });
  assert.equal(failed.status, "failed");
  assert.equal(failed.exitCode, 2);
  assert.equal(failed.reason, "hvigorw --version 返回非零退出码。");
  assert.ok(!JSON.stringify(failed).includes("secret-value"));
  assert.ok(!JSON.stringify(failed).includes(projectRoot));
});

test("probeHvigor 将启动失败归类为 unavailable", async () => {
  const projectRoot = "/repo/app";

  const capability = await probeHvigor({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw")]),
    runner: new FakeRunner(
      completed({
        status: "start_failed",
        errorMessage: "启动外部进程失败：ENOENT",
      }),
    ),
    platform: "linux",
  });

  assert.equal(capability.status, "unavailable");
  assert.equal(capability.reason, "无法启动 hvigorw wrapper。");
});

test("runCleanReleaseBuild 使用参数数组编排 clean release 构建并发现产物候选", async () => {
  const projectRoot = "/repo/app";
  const runner = new FakeRunner(completed());

  const build = await runCleanReleaseBuild({
    projectRoot,
    fs: new FakeFs(
      [path.join(projectRoot, "hvigorw")],
      [
        "entry/build/default/outputs/default/app/release/clean.app",
        "entry/build/default/outputs/default/hap/release/entry-default-signed.hap",
        "entry/build/default/outputs/default/hap/release/entry-default-unsigned.hap",
        "entry/build/tmp/debug.txt",
      ],
    ),
    runner,
    platform: "linux",
    build: releaseBuildConfig,
  });

  assert.equal(build.status, "success");
  assert.deepEqual(build.command, {
    executable: "hvigorw",
    args: ["clean", "assembleApp", "-p", "buildMode=release"],
  });
  assert.deepEqual(
    runner.requests.map(({ cwd, args }) => ({ cwd, args })),
    [
      {
        cwd: projectRoot,
        args: ["clean", "assembleApp", "-p", "buildMode=release"],
      },
    ],
  );
  assert.deepEqual(build.artifacts, [
    {
      relativePath: "entry/build/default/outputs/default/app/release/clean.app",
      type: "app",
    },
    {
      relativePath:
        "entry/build/default/outputs/default/hap/release/entry-default-signed.hap",
      type: "hap",
    },
  ]);
  assert.ok(!JSON.stringify(build).includes(projectRoot));
});

test("runCleanReleaseBuild 无 wrapper 时返回工具不可用且不执行构建", async () => {
  const runner = new FakeRunner(completed());

  const build = await runCleanReleaseBuild({
    projectRoot: "/repo/app",
    fs: new FakeFs([]),
    runner,
    platform: "linux",
    build: releaseBuildConfig,
  });

  assert.equal(build.status, "unavailable");
  assert.equal(build.errorCode, "TOOL_UNAVAILABLE");
  assert.equal(runner.requests.length, 0);
});

test("runCleanReleaseBuild 非零退出返回 BUILD_FAILED，不能伪装为空成功", async () => {
  const projectRoot = "/repo/app";

  const build = await runCleanReleaseBuild({
    projectRoot,
    fs: new FakeFs(
      [path.join(projectRoot, "hvigorw")],
      ["entry/build/default/outputs/default/app/release/clean.app"],
    ),
    runner: new FakeRunner(
      completed({
        exitCode: 1,
        stderr: "build failed /repo/app",
      }),
    ),
    platform: "linux",
    build: releaseBuildConfig,
  });

  assert.equal(build.status, "build_failed");
  assert.equal(build.errorCode, "BUILD_FAILED");
  assert.equal(build.exitCode, 1);
  assert.deepEqual(build.artifacts, []);
  assert.ok(!JSON.stringify(build).includes(projectRoot));
});

test("runCleanReleaseBuild 拒绝带 shell 元字符的构建命令", async () => {
  const projectRoot = "/repo/app";
  const runner = new FakeRunner(completed());

  const build = await runCleanReleaseBuild({
    projectRoot,
    fs: new FakeFs([path.join(projectRoot, "hvigorw")]),
    runner,
    platform: "linux",
    build: {
      ...releaseBuildConfig,
      command: "./hvigorw assembleApp && rm -rf build",
    },
  });

  assert.equal(build.status, "failed");
  assert.equal(build.errorCode, "TOOL_EXECUTION_ERROR");
  assert.equal(build.reason, "构建命令包含不支持的 shell 语法。");
  assert.equal(runner.requests.length, 0);
});

test("createArtifactManifest 为构建产物生成稳定哈希清单", async () => {
  const projectRoot = "/repo/app";
  const build: HvigorBuildRun = {
    status: "success",
    command: {
      executable: "hvigorw",
      args: ["clean", "assembleApp", "-p", "buildMode=release"],
    },
    artifacts: [
      {
        relativePath:
          "entry/build/default/outputs/default/hap/release/entry-default-signed.hap",
        type: "hap",
      },
      {
        relativePath:
          "entry/build/default/outputs/default/app/release/clean.app",
        type: "app",
      },
    ],
  };

  const manifest = await createArtifactManifest({
    projectRoot,
    fs: new FakeFs([], [], {
      [path.join(
        projectRoot,
        "entry/build/default/outputs/default/app/release/clean.app",
      )]: { content: "app" },
      [path.join(
        projectRoot,
        "entry/build/default/outputs/default/hap/release/entry-default-signed.hap",
      )]: { content: "hap" },
    }),
    hash,
    build,
    runId: "run-test",
    hvigorVersion: "Hvigor 6.0.6",
  });

  assert.equal(manifest.completeness, "COMPLETE");
  assert.deepEqual(manifest.build.command, build.command);
  assert.deepEqual(manifest.run, {
    id: "run-test",
    hvigorVersion: "Hvigor 6.0.6",
  });
  assert.deepEqual(
    manifest.artifacts.map(({ relativePath, type, sizeBytes, sha256 }) => ({
      relativePath,
      type,
      sizeBytes,
      sha256,
    })),
    [
      {
        relativePath:
          "entry/build/default/outputs/default/app/release/clean.app",
        type: "app",
        sizeBytes: 3,
        sha256:
          "sha256:6170700000000000000000000000000000000000000000000000000000000000",
      },
      {
        relativePath:
          "entry/build/default/outputs/default/hap/release/entry-default-signed.hap",
        type: "hap",
        sizeBytes: 3,
        sha256:
          "sha256:6861700000000000000000000000000000000000000000000000000000000000",
      },
    ],
  );
  assert.equal(manifest.errors.length, 0);
  assert.doesNotThrow(() => JSON.stringify(manifest));
  assert.ok(!JSON.stringify(manifest).includes(projectRoot));
});

test("显式矩阵配置稳定发现 APP、HAP、HSP、HAR 并生成完整哈希清单", async () => {
  const projectRoot = "/repo/p4-package-matrix";
  const artifacts = [
    {
      relativePath:
        "entry/build/default/outputs/default/app/release/p4-package-matrix.app",
      type: "app",
      content: "app-content",
    },
    {
      relativePath:
        "entry/build/default/outputs/default/hap/release/entry-default.hap",
      type: "hap",
      content: "hap-content",
    },
    {
      relativePath: "har/build/default/outputs/default/har/release/har.har",
      type: "har",
      content: "har-content",
    },
    {
      relativePath:
        "shared/build/default/outputs/default/hsp/release/shared-default.hsp",
      type: "hsp",
      content: "hsp-content",
    },
  ] as const;
  const fs = new FakeFs(
    [path.join(projectRoot, "hvigorw")],
    [
      artifacts[3].relativePath,
      artifacts[1].relativePath,
      artifacts[2].relativePath,
      artifacts[0].relativePath,
    ],
    Object.fromEntries(
      artifacts.map(({ relativePath, content }) => [
        path.join(projectRoot, relativePath),
        { content },
      ]),
    ),
  );
  const build = await runCleanReleaseBuild({
    projectRoot,
    fs,
    runner: new FakeRunner(completed()),
    platform: "linux",
    build: {
      ...releaseBuildConfig,
      artifact: {
        include: ["**/*.app", "**/*.hap", "**/*.hsp", "**/*.har"],
        exclude: [],
      },
    },
  });

  assert.equal(build.status, "success");
  assert.deepEqual(
    build.artifacts,
    artifacts.map(({ relativePath, type }) => ({ relativePath, type })),
  );

  const manifest = await createArtifactManifest({
    projectRoot,
    fs,
    hash: cryptographicHash,
    build,
    runId: "p4-package-matrix-contract",
    requiredTypes: ["app", "hap", "hsp", "har"],
  });

  assert.equal(manifest.completeness, "COMPLETE");
  assert.deepEqual(
    manifest.artifacts.map(({ relativePath, type, sizeBytes, sha256 }) => ({
      relativePath,
      type,
      sizeBytes,
      sha256,
    })),
    artifacts.map(({ relativePath, type, content }) => ({
      relativePath,
      type,
      sizeBytes: Buffer.byteLength(content),
      sha256: sha256Digest(content),
    })),
  );
  assert.equal(manifest.errors.length, 0);
  assert.ok(!JSON.stringify({ build, manifest }).includes(projectRoot));
});

for (const missingType of ["app", "hap", "hsp", "har"] as const) {
  test(`P4-3 必需类型合同缺少 ${missingType.toUpperCase()} 时清单为 INCOMPLETE`, async () => {
    const projectRoot = `/repo/p4-package-matrix-${missingType}-secret`;
    const artifacts = ["app", "hap", "hsp", "har"]
      .filter((type) => type !== missingType)
      .map((type) => ({
        relativePath: `build/release/artifact.${type}`,
        type: type as "app" | "hap" | "hsp" | "har",
      }));
    const manifest = await createArtifactManifest({
      projectRoot,
      fs: new FakeFs(
        [],
        [],
        Object.fromEntries(
          artifacts.map(({ relativePath, type }) => [
            path.join(projectRoot, relativePath),
            { content: `${type}-content` },
          ]),
        ),
      ),
      hash: cryptographicHash,
      build: {
        status: "success",
        artifacts,
      },
      runId: `p4-package-matrix-missing-${missingType}`,
      requiredTypes: ["har", "app", "hsp", "hap", "har"],
    });

    assert.equal(manifest.completeness, "INCOMPLETE");
    assert.deepEqual(manifest.errors, [
      {
        kind: "MISSING_ARTIFACT_TYPE",
        message: `缺少必需的 ${missingType.toUpperCase()} 产物。`,
      },
    ]);
    assert.ok(!JSON.stringify(manifest).includes(projectRoot));
  });
}

test("P4-3 必需类型合同对多个缺失类型稳定排序并去重", async () => {
  const projectRoot = "/repo/p4-package-matrix-order-secret";
  const relativePath = "build/release/artifact.app";
  const manifest = await createArtifactManifest({
    projectRoot,
    fs: new FakeFs([], [], {
      [path.join(projectRoot, relativePath)]: { content: "app-content" },
    }),
    hash: cryptographicHash,
    build: {
      status: "success",
      artifacts: [{ relativePath, type: "app" }],
    },
    runId: "p4-package-matrix-missing-multiple",
    requiredTypes: ["hsp", "har", "hap", "hsp"],
  });

  assert.equal(manifest.completeness, "INCOMPLETE");
  assert.deepEqual(manifest.errors, [
    {
      kind: "MISSING_ARTIFACT_TYPE",
      message: "缺少必需的 HAP 产物。",
    },
    {
      kind: "MISSING_ARTIFACT_TYPE",
      message: "缺少必需的 HAR 产物。",
    },
    {
      kind: "MISSING_ARTIFACT_TYPE",
      message: "缺少必需的 HSP 产物。",
    },
  ]);
  assert.ok(!JSON.stringify(manifest).includes(projectRoot));
});

test("createArtifactManifest 无产物时返回 INCOMPLETE 而不是空成功", async () => {
  const manifest = await createArtifactManifest({
    projectRoot: "/repo/app",
    fs: new FakeFs([]),
    hash,
    build: {
      status: "success",
      command: { executable: "hvigorw", args: ["assembleApp"] },
      artifacts: [],
    },
    runId: "run-test",
  });

  assert.equal(manifest.completeness, "INCOMPLETE");
  assert.deepEqual(
    manifest.errors.map(({ kind }) => kind),
    ["NO_ARTIFACTS"],
  );
});

test("createArtifactManifest 拒绝越界或绝对产物路径且不泄露根目录", async () => {
  const projectRoot = "/repo/app";

  const manifest = await createArtifactManifest({
    projectRoot,
    fs: new FakeFs([]),
    hash,
    build: {
      status: "success",
      command: { executable: "hvigorw", args: ["assembleApp"] },
      artifacts: [
        { relativePath: "../outside.app", type: "app" },
        { relativePath: "/repo/app/build/app-release.app", type: "app" },
      ],
    },
    runId: "run-test",
  });

  assert.equal(manifest.completeness, "INCOMPLETE");
  assert.deepEqual(
    manifest.errors.map(({ kind }) => kind),
    ["UNSAFE_ARTIFACT_PATH", "UNSAFE_ARTIFACT_PATH"],
  );
  assert.ok(!JSON.stringify(manifest).includes(projectRoot));
});

test("createArtifactManifest 对符号链接和读取失败给出明确错误", async () => {
  const projectRoot = "/repo/app";

  const manifest = await createArtifactManifest({
    projectRoot,
    fs: new FakeFs([], [], {
      [path.join(projectRoot, "build/link.app")]: {
        content: "link",
        isSymbolicLink: true,
      },
      [path.join(projectRoot, "build/broken.hap")]: {
        content: "broken",
        readError: true,
      },
    }),
    hash,
    build: {
      status: "success",
      command: { executable: "hvigorw", args: ["assembleApp"] },
      artifacts: [
        { relativePath: "build/link.app", type: "app" },
        { relativePath: "build/broken.hap", type: "hap" },
      ],
    },
    runId: "run-test",
  });

  assert.equal(manifest.completeness, "INCOMPLETE");
  assert.deepEqual(
    manifest.errors.map(({ kind }) => kind),
    ["ARTIFACT_READ_FAILED", "SYMLINK_ARTIFACT"],
  );
});
