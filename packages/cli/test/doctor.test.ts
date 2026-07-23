import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { ProcessRunRequest, ProcessRunResult } from "@hcheck/core";
import { parseDoctorArguments, runDoctor } from "../src/doctor.js";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";

class FakeRunner {
  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    if (request.executable === "pnpm") {
      return completed("10.34.0\n");
    }
    if (request.executable.endsWith("hvigorw")) {
      return completed(`Hvigor 5.0.0 ${request.cwd ?? ""} TOKEN=SECRET\n`);
    }
    return {
      status: "start_failed",
      timedOut: false,
      stdout: "",
      stderr: "",
      stdoutTruncated: false,
      stderrTruncated: false,
      errorMessage: "未找到工具",
    };
  }
}

function completed(stdout: string): ProcessRunResult {
  return {
    status: "completed",
    exitCode: 0,
    timedOut: false,
    stdout,
    stderr: "",
    stdoutTruncated: false,
    stderrTruncated: false,
  };
}

async function createDoctorProject(): Promise<string> {
  const base = await mkdtemp(path.join(os.tmpdir(), "hcheck-doctor-"));
  const root = path.join(base, "带 空格 的项目");
  await mkdir(path.join(root, "AppScope"), { recursive: true });
  await mkdir(path.join(root, "entry/src/main"), { recursive: true });
  await writeFile(
    path.join(root, "AppScope/app.json5"),
    `{ app: { bundleName: 'com.example.doctor', versionCode: 1, versionName: '1.0.0' } }`,
  );
  await writeFile(
    path.join(root, "build-profile.json5"),
    `{ app: { products: [{ name: 'default', compatibleSdkVersion: 12, targetSdkVersion: 12 }] }, modules: [{ name: 'entry', srcPath: './entry' }] }`,
  );
  await writeFile(
    path.join(root, "entry/src/main/module.json5"),
    `{ module: { name: 'entry', type: 'entry', deviceTypes: ['phone'] } }`,
  );
  await writeFile(
    path.join(root, "oh-package.json5"),
    `{ dependencies: { '@vendor/analytics': '1.2.3' } }`,
  );
  await writeFile(
    path.join(root, "oh-package-lock.json5"),
    `{ packages: { '@vendor/analytics@1.2.3': { version: '1.2.3' } } }`,
  );
  await writeFile(path.join(root, "hvigorw"), "#!/bin/sh\n");
  return root;
}

test("parseDoctorArguments 解析默认目录和 JSON 输出", () => {
  assert.deepEqual(parseDoctorArguments(["doctor"]), {
    path: ".",
    format: "terminal",
  });
  assert.deepEqual(
    parseDoctorArguments(["doctor", "app", "--format", "json"]),
    {
      path: "app",
      format: "json",
    },
  );
  assert.throws(
    () => parseDoctorArguments(["doctor", "app", "--token=SECRET"]),
    /未知 doctor 参数/u,
  );
});

test("doctor 输出构建目标、依赖和工具诊断且不泄露绝对路径或秘密", async () => {
  const root = await createDoctorProject();
  let stdout = "";
  let stderr = "";

  const code = await runDoctor(["doctor", root, "--format", "json"], {
    fs: new NodeFileSystem(),
    runner: new FakeRunner(),
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
    environment: { PATH: "/usr/bin", HCHECK_TOKEN: "SECRET" },
  });

  assert.equal(code, 0);
  assert.equal(stderr, "");
  assert.ok(!stdout.includes(root));
  assert.ok(!stdout.includes("SECRET"));
  const report = JSON.parse(stdout) as {
    readonly status: string;
    readonly project: { readonly bundleName: string };
    readonly build: { readonly api: { readonly minimum: number } };
    readonly dependencies: { readonly directDependencies: readonly unknown[] };
    readonly tools: readonly { readonly id: string; readonly status: string }[];
  };
  assert.equal(report.status, "warning");
  assert.equal(report.project.bundleName, "com.example.doctor");
  assert.equal(report.build.api.minimum, 12);
  assert.equal(report.dependencies.directDependencies.length, 1);
  assert.deepEqual(
    report.tools.map(({ id, status }) => ({ id, status })),
    [
      { id: "node", status: "available" },
      { id: "path", status: "available" },
      { id: "pnpm", status: "available" },
      { id: "ohpm", status: "unavailable" },
      { id: "hvigorw", status: "available" },
      { id: "hdc", status: "unavailable" },
      { id: "harmonyos-sdk", status: "unavailable" },
      { id: "agc", status: "unknown" },
    ],
  );
});

test("doctor 要求 SDK 环境变量指向包含完整版本包的根目录", async () => {
  const root = await createDoctorProject();
  const sdkRoot = path.join(root, "sdk");
  const versionRoot = path.join(sdkRoot, "default");
  for (const directory of [
    "openharmony/ets",
    "openharmony/toolchains",
    "hms/ets",
    "hms/toolchains",
  ]) {
    await mkdir(path.join(versionRoot, directory), { recursive: true });
  }
  await writeFile(path.join(versionRoot, "sdk-pkg.json"), "{}");
  await writeFile(
    path.join(versionRoot, "openharmony/ets/oh-uni-package.json"),
    "{}",
  );
  await writeFile(
    path.join(versionRoot, "openharmony/toolchains/oh-uni-package.json"),
    "{}",
  );
  await writeFile(path.join(versionRoot, "hms/ets/uni-package.json"), "{}");
  await writeFile(
    path.join(versionRoot, "hms/toolchains/uni-package.json"),
    "{}",
  );

  const probe = async (sdkHome: string) => {
    let stdout = "";
    const code = await runDoctor(["doctor", root, "--format", "json"], {
      fs: new NodeFileSystem(),
      runner: new FakeRunner(),
      stdout: (value) => {
        stdout += value;
      },
      stderr: () => {},
      environment: { PATH: "/usr/bin", DEVECO_SDK_HOME: sdkHome },
    });
    const report = JSON.parse(stdout) as {
      readonly tools: readonly {
        readonly id: string;
        readonly status: string;
        readonly reason?: string;
      }[];
    };
    return {
      code,
      sdk: report.tools.find(({ id }) => id === "harmonyos-sdk"),
    };
  };

  const wrongLevel = await probe(versionRoot);
  assert.equal(wrongLevel.code, 0);
  assert.equal(wrongLevel.sdk?.status, "unavailable");
  assert.match(wrongLevel.sdk?.reason ?? "", /SDK 根目录/u);

  const incompleteRoot = path.join(root, "incomplete-sdk");
  await mkdir(path.join(incompleteRoot, "default"), { recursive: true });
  await writeFile(path.join(incompleteRoot, "default/sdk-pkg.json"), "{}");
  const incomplete = await probe(incompleteRoot);
  assert.equal(incomplete.code, 0);
  assert.equal(incomplete.sdk?.status, "unavailable");
  assert.match(incomplete.sdk?.reason ?? "", /构建组件不完整/u);

  const completeRoot = await probe(sdkRoot);
  assert.equal(completeRoot.code, 0);
  assert.equal(completeRoot.sdk?.status, "available");
});
