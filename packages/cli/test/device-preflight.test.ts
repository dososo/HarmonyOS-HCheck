import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rmdir,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertDevicePreflightBinding,
  createDevicePreflightRecord,
  DevicePreflightError,
  readAndVerifyDevicePreflightRecord,
  serializeDevicePreflightRecord,
  type PreflightBinding,
  writeDevicePreflightRecord,
} from "../src/device-preflight.js";

const CREATED_AT = new Date("2026-07-15T12:00:00.000Z");
const HASH_A = `sha256:${"a".repeat(64)}` as const;
const HASH_B = `sha256:${"b".repeat(64)}` as const;
const HASH_C = `sha256:${"c".repeat(64)}` as const;
const HASH_D = `sha256:${"d".repeat(64)}` as const;
const HASH_E = `sha256:${"e".repeat(64)}` as const;
const ACTIONS = [
  "install",
  "launch",
  "checkpoint",
  "stop",
  "uninstall",
] as const;

function validBinding(): PreflightBinding {
  return {
    flow: { id: "device-smoke", version: 1, sha256: HASH_A },
    artifact: {
      sha256: HASH_B,
      bundleName: "com.example.hcheck.smoke",
      versionName: "1.0.0",
      versionCode: 1,
      moduleNames: ["entry"],
      selectedModule: "entry",
    },
    hapSignTool: { sha256: HASH_C, javaVersion: "17.0.12" },
    signature: {
      profileSha256: HASH_D,
      signerCertificateSha256: HASH_E,
      type: "debug",
      validity: { notBefore: 1_768_435_200, notAfter: 1_768_521_600 },
      trustBoundary:
        "仅证明验签工具自包含证书链与 Profile 内容签名一致，不证明 AGC/平台根信任或证书撤销状态。",
    },
    hdcVersion: "3.1.0a",
    device: {
      id: `device:sha256:${"f".repeat(64)}`,
      kind: "physical",
    },
    abilityName: "EntryAbility",
    hilogTag: "HCHECK",
    hilogMarker: "HCHECK_SMOKE_OK",
    bundlePresence: "not_installed",
    actions: [...ACTIONS],
  };
}

function createRecord(
  binding: PreflightBinding = validBinding(),
  runId = "run-001",
) {
  return createDevicePreflightRecord({
    runId,
    createdAt: CREATED_AT,
    binding,
  });
}

function digest(bytes: Uint8Array): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function removeFileIfPresent(target: string): Promise<void> {
  await unlink(target).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function removeDirectoryIfEmpty(target: string): Promise<void> {
  await rmdir(target).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function cleanupPreflightWorkspace(
  workspace: string,
  runIds: readonly string[],
): Promise<void> {
  for (const runId of runIds) {
    await removeFileIfPresent(
      path.join(workspace, ".hcheck", "preflight", `${runId}.json`),
    );
  }
  await removeDirectoryIfEmpty(path.join(workspace, ".hcheck", "preflight"));
  await removeDirectoryIfEmpty(path.join(workspace, ".hcheck"));
  await removeDirectoryIfEmpty(workspace);
}

test("createDevicePreflightRecord 生成固定 15 分钟 TTL 的规范深冻结记录", () => {
  const input = validBinding();
  const record = createDevicePreflightRecord({
    runId: "run-001",
    createdAt: CREATED_AT,
    binding: input,
  });

  input.artifact.moduleNames[0] = "mutated";
  assert.equal(record.schemaVersion, "1.0.0");
  assert.equal(record.createdAt, "2026-07-15T12:00:00.000Z");
  assert.equal(record.expiresAt, "2026-07-15T12:15:00.000Z");
  assert.deepEqual(record.binding.artifact.moduleNames, ["entry"]);
  assert.ok(Object.isFrozen(record));
  assert.ok(Object.isFrozen(record.binding));
  assert.ok(Object.isFrozen(record.binding.artifact.moduleNames));

  const serialized = serializeDevicePreflightRecord(record).toString("utf8");
  assert.ok(serialized.endsWith("\n"));
  assert.equal(serialized, `${JSON.stringify(record, null, 2)}\n`);
});

test("createDevicePreflightRecord 接受固定非敏感句子型 Hilog 标记", () => {
  const record = createRecord({
    ...validBinding(),
    hilogMarker: "Succeeded in loading the content.",
  });

  assert.equal(record.binding.hilogMarker, "Succeeded in loading the content.");
});

test("createDevicePreflightRecord 严格拒绝非法字段、额外字段和敏感字段", () => {
  const invalidCases: unknown[] = [
    {
      ...validBinding(),
      flow: { id: "bad\nflow", version: 1, sha256: HASH_A },
    },
    { ...validBinding(), flow: { id: "flow", version: 0, sha256: HASH_A } },
    {
      ...validBinding(),
      flow: { id: "flow", version: 1, sha256: `sha256:${"A".repeat(64)}` },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, versionCode: 0x1_0000_0000 },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, moduleNames: ["entry", "entry"] },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, selectedModule: "missing" },
    },
    {
      ...validBinding(),
      hapSignTool: { ...validBinding().hapSignTool, javaVersion: "17\ud800" },
    },
    {
      ...validBinding(),
      signature: {
        ...validBinding().signature,
        validity: { notBefore: -1, notAfter: 10 },
      },
    },
    {
      ...validBinding(),
      signature: {
        ...validBinding().signature,
        validity: {
          notBefore: 1_768_435_200_000,
          notAfter: 1_768_521_600_000,
        },
      },
    },
    {
      ...validBinding(),
      signature: {
        ...validBinding().signature,
        validity: { notBefore: 10, notAfter: 10 },
      },
    },
    {
      ...validBinding(),
      device: { id: "127.0.0.1:5555", kind: "physical" },
    },
    { ...validBinding(), bundlePresence: "installed" },
    { ...validBinding(), actions: [...ACTIONS].reverse() },
    { ...validBinding(), artifactPath: "/secret/app.hap" },
    {
      ...validBinding(),
      signature: { ...validBinding().signature, developerId: "secret" },
    },
  ];

  for (const binding of invalidCases) {
    assert.throws(() =>
      createDevicePreflightRecord({
        runId: "run-001",
        createdAt: CREATED_AT,
        binding: binding as PreflightBinding,
      }),
    );
  }
  for (const runId of ["../run", "run/001", "run\n001", "run\ud800"]) {
    assert.throws(() =>
      createDevicePreflightRecord({
        runId,
        createdAt: CREATED_AT,
        binding: validBinding(),
      }),
    );
  }
  assert.throws(() =>
    createDevicePreflightRecord({
      runId: "run-001",
      createdAt: new Date(Number.NaN),
      binding: validBinding(),
    }),
  );
  assert.throws(
    () =>
      createDevicePreflightRecord({
        runId: "run-001",
        createdAt: "not-a-date" as unknown as Date,
        binding: validBinding(),
      }),
    DevicePreflightError,
  );
});

test("createDevicePreflightRecord 对字段使用专用格式并完整接受 uint32 边界", () => {
  for (const versionCode of [0, 0xffff_ffff]) {
    const binding = validBinding();
    (binding.artifact as { versionCode: number }).versionCode = versionCode;
    assert.equal(
      createRecord(binding).binding.artifact.versionCode,
      versionCode,
    );
  }
  const officialCase = validBinding();
  (officialCase.artifact as { bundleName: string }).bundleName =
    "com.OpenHarmony.HCheck";
  (officialCase as { hdcVersion: string }).hdcVersion = "3.1.0A";
  assert.equal(
    createRecord(officialCase).binding.artifact.bundleName,
    "com.OpenHarmony.HCheck",
  );

  const invalidBindings: PreflightBinding[] = [
    { ...validBinding(), flow: { ...validBinding().flow, id: "Device-Smoke" } },
    {
      ...validBinding(),
      flow: { ...validBinding().flow, id: "device--smoke" },
    },
    {
      ...validBinding(),
      artifact: {
        ...validBinding().artifact,
        bundleName: "com.example.bad_name",
      },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, bundleName: "example" },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, versionName: ".1.0" },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, versionName: "1.0 beta" },
    },
    {
      ...validBinding(),
      artifact: { ...validBinding().artifact, moduleNames: ["entry/path"] },
    },
    {
      ...validBinding(),
      artifact: {
        ...validBinding().artifact,
        moduleNames: ["entry", "password"],
      },
    },
    {
      ...validBinding(),
      hapSignTool: { ...validBinding().hapSignTool, javaVersion: "openjdk 17" },
    },
    {
      ...validBinding(),
      hapSignTool: { ...validBinding().hapSignTool, javaVersion: "/opt/java" },
    },
    { ...validBinding(), hdcVersion: "Ver: 3.1.0a" },
    { ...validBinding(), hdcVersion: "3.1.0" },
    { ...validBinding(), abilityName: "Entry Ability" },
    { ...validBinding(), hilogTag: "127.0.0.1:5555" },
    { ...validBinding(), hilogMarker: "raw-connect-key" },
    {
      ...validBinding(),
      signature: {
        ...validBinding().signature,
        trustBoundary: "已通过 AGC/平台根信任与证书撤销验证。",
      },
    },
    ...[-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY].map((versionCode) => ({
      ...validBinding(),
      artifact: { ...validBinding().artifact, versionCode },
    })),
  ];

  for (const binding of invalidBindings) {
    assert.throws(() => createRecord(binding), DevicePreflightError);
  }
});

test("createDevicePreflightRecord 拒绝所有 Unicode Cf/Bidi 与零宽控制字符", () => {
  for (const unsafe of ["\u200b", "\u200d", "\u202e", "\u2066", "\ufeff"]) {
    const binding = validBinding();
    (binding.artifact as { versionName: string }).versionName = `1.0${unsafe}`;
    assert.throws(() => createRecord(binding), DevicePreflightError);
  }
});

test("writeDevicePreflightRecord 以私有权限独占写入固定路径并返回最小摘要", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-write-"),
  );
  const record = createRecord();
  const target = path.join(workspace, ".hcheck", "preflight", "run-001.json");
  try {
    const result = await writeDevicePreflightRecord({
      workspaceRoot: workspace,
      record,
    });
    const bytes = await readFile(target);

    assert.deepEqual(result, {
      relativePath: ".hcheck/preflight/run-001.json",
      sha256: digest(bytes),
      expiresAt: record.expiresAt,
    });
    assert.deepEqual(Object.keys(result), [
      "relativePath",
      "sha256",
      "expiresAt",
    ]);
    if (process.platform !== "win32") {
      assert.equal((await stat(path.dirname(target))).mode & 0o777, 0o700);
      assert.equal((await stat(target)).mode & 0o777, 0o600);
    }
    await assert.rejects(
      writeDevicePreflightRecord({ workspaceRoot: workspace, record }),
    );
    assert.deepEqual(await readFile(target), bytes);
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test("writeDevicePreflightRecord 拒绝伪造 TTL 且不创建记录文件", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-forged-"),
  );
  const target = path.join(workspace, ".hcheck", "preflight", "run-001.json");
  const forged = {
    ...createRecord(),
    expiresAt: "2026-07-15T12:14:59.999Z",
  };
  try {
    await assert.rejects(
      writeDevicePreflightRecord({
        workspaceRoot: workspace,
        record: forged,
      }),
    );
    await assert.rejects(readFile(target), { code: "ENOENT" });
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test(
  "writeDevicePreflightRecord 在严格 umask 下仍通过句柄收紧到 0600",
  { skip: process.platform === "win32" },
  async () => {
    const workspace = await mkdtemp(
      path.join(os.tmpdir(), "hcheck-preflight-umask-"),
    );
    const target = path.join(workspace, ".hcheck", "preflight", "run-001.json");
    const previousUmask = process.umask(0o777);
    try {
      await writeDevicePreflightRecord({
        workspaceRoot: workspace,
        record: createRecord(),
      });
      assert.equal((await stat(target)).mode & 0o777, 0o600);
    } finally {
      process.umask(previousUmask);
      await cleanupPreflightWorkspace(workspace, ["run-001"]);
    }
  },
);

test("writeDevicePreflightRecord 拒绝工作区、.hcheck、preflight 或目标符号链接", async () => {
  const base = await mkdtemp(path.join(os.tmpdir(), "hcheck-preflight-links-"));
  const actual = path.join(base, "actual");
  const linked = path.join(base, "linked");
  const external = path.join(base, "external");
  const hcheck = path.join(actual, ".hcheck");
  const preflight = path.join(hcheck, "preflight");
  const target = path.join(preflight, "run-001.json");
  await mkdir(actual);
  await mkdir(external);
  await symlink(actual, linked, "dir");
  try {
    await assert.rejects(
      writeDevicePreflightRecord({
        workspaceRoot: linked,
        record: createRecord(),
      }),
    );
    await symlink(external, hcheck, "dir");
    await assert.rejects(
      writeDevicePreflightRecord({
        workspaceRoot: actual,
        record: createRecord(),
      }),
    );
    await unlink(hcheck);
    await mkdir(hcheck, { mode: 0o700 });
    await symlink(external, preflight, "dir");
    await assert.rejects(
      writeDevicePreflightRecord({
        workspaceRoot: actual,
        record: createRecord(),
      }),
    );
    await unlink(preflight);
    await mkdir(preflight, { mode: 0o700 });
    const externalFile = path.join(external, "outside.json");
    await writeFile(externalFile, "outside");
    await symlink(externalFile, target, "file");
    await assert.rejects(
      writeDevicePreflightRecord({
        workspaceRoot: actual,
        record: createRecord(),
      }),
    );
    assert.equal(await readFile(externalFile, "utf8"), "outside");
    await unlink(target);
    await unlink(externalFile);
  } finally {
    await removeFileIfPresent(target);
    await removeFileIfPresent(linked);
    await removeDirectoryIfEmpty(preflight);
    await removeDirectoryIfEmpty(hcheck);
    await removeDirectoryIfEmpty(external);
    await removeDirectoryIfEmpty(actual);
    await removeDirectoryIfEmpty(base);
  }
});

test("预检目录绑定兼容稳定的祖先符号链接但仍固定首次 realpath", async () => {
  const base = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-ancestor-"),
  );
  const actualParent = path.join(base, "actual-parent");
  const linkedParent = path.join(base, "linked-parent");
  const actualWorkspace = path.join(actualParent, "workspace");
  const linkedWorkspace = path.join(linkedParent, "workspace");
  await mkdir(actualParent);
  await mkdir(actualWorkspace);
  await symlink(actualParent, linkedParent, "dir");
  try {
    const written = await writeDevicePreflightRecord({
      workspaceRoot: linkedWorkspace,
      record: createRecord(),
    });
    const restored = await readAndVerifyDevicePreflightRecord({
      workspaceRoot: linkedWorkspace,
      relativePath: written.relativePath,
      sha256: written.sha256,
      now: CREATED_AT,
    });
    assert.equal(restored.runId, "run-001");
  } finally {
    await cleanupPreflightWorkspace(actualWorkspace, ["run-001"]);
    await removeFileIfPresent(linkedParent);
    await removeDirectoryIfEmpty(actualParent);
    await removeDirectoryIfEmpty(base);
  }
});

test("readAndVerifyDevicePreflightRecord 先验哈希、TTL 和规范字节后返回深冻结记录", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-read-"),
  );
  try {
    const written = await writeDevicePreflightRecord({
      workspaceRoot: workspace,
      record: createRecord(),
    });
    const record = await readAndVerifyDevicePreflightRecord({
      workspaceRoot: workspace,
      relativePath: written.relativePath,
      sha256: written.sha256,
      now: new Date("2026-07-15T12:14:59.999Z"),
    });
    assert.equal(record.runId, "run-001");
    assert.ok(Object.isFrozen(record));
    assert.ok(Object.isFrozen(record.binding.artifact.moduleNames));

    const atExpiry = await readAndVerifyDevicePreflightRecord({
      workspaceRoot: workspace,
      relativePath: written.relativePath,
      sha256: written.sha256,
      now: new Date("2026-07-15T12:15:00.000Z"),
    });
    assert.equal(atExpiry.runId, "run-001");
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test("readAndVerifyDevicePreflightRecord 拒绝路径穿越、大小写哈希、错哈希、过期和未来记录", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-reject-"),
  );
  try {
    const written = await writeDevicePreflightRecord({
      workspaceRoot: workspace,
      record: createRecord(),
    });
    const base = {
      workspaceRoot: workspace,
      relativePath: written.relativePath,
      sha256: written.sha256,
      now: CREATED_AT,
    };
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        ...base,
        relativePath: "../run-001.json",
      }),
    );
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        ...base,
        sha256: written.sha256.toUpperCase() as `sha256:${string}`,
      }),
    );
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({ ...base, sha256: HASH_E }),
    );
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        ...base,
        now: new Date("2026-07-15T11:59:59.999Z"),
      }),
    );
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        ...base,
        now: new Date("2026-07-15T12:15:00.001Z"),
      }),
    );
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        ...base,
        now: "not-a-date" as unknown as Date,
      }),
      DevicePreflightError,
    );
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test("readAndVerifyDevicePreflightRecord 拒绝弱权限、变动、非规范、额外字段、错误 TTL 和 runId", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-bytes-"),
  );
  const directory = path.join(workspace, ".hcheck", "preflight");
  const target = path.join(directory, "run-001.json");
  await mkdir(path.join(workspace, ".hcheck"), { mode: 0o700 });
  await mkdir(directory, { mode: 0o700 });

  const cases: unknown[] = [
    { ...createRecord(), expiresAt: "2026-07-15T12:14:59.999Z" },
    { ...createRecord(), createdAt: "2026-07-15T12:00:00Z" },
    { ...createRecord(), runId: "run-002" },
    { ...createRecord(), token: "不得泄漏" },
  ];
  try {
    await writeFile(target, serializeDevicePreflightRecord(createRecord()), {
      mode: 0o644,
    });
    const weakBytes = await readFile(target);
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        workspaceRoot: workspace,
        relativePath: ".hcheck/preflight/run-001.json",
        sha256: digest(weakBytes),
        now: CREATED_AT,
      }),
    );
    await chmod(target, 0o600);
    await writeFile(target, "changed");
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        workspaceRoot: workspace,
        relativePath: ".hcheck/preflight/run-001.json",
        sha256: digest(weakBytes),
        now: CREATED_AT,
      }),
    );

    const nonCanonical = Buffer.from(JSON.stringify(createRecord()), "utf8");
    await writeFile(target, nonCanonical);
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        workspaceRoot: workspace,
        relativePath: ".hcheck/preflight/run-001.json",
        sha256: digest(nonCanonical),
        now: CREATED_AT,
      }),
    );

    for (const value of cases) {
      const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
      await writeFile(target, bytes);
      await assert.rejects(
        readAndVerifyDevicePreflightRecord({
          workspaceRoot: workspace,
          relativePath: ".hcheck/preflight/run-001.json",
          sha256: digest(bytes),
          now: CREATED_AT,
        }),
      );
    }
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test("readAndVerifyDevicePreflightRecord 拒绝超过固定上限的记录", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-preflight-oversize-"),
  );
  const directory = path.join(workspace, ".hcheck", "preflight");
  const target = path.join(directory, "run-001.json");
  await mkdir(path.join(workspace, ".hcheck"), { mode: 0o700 });
  await mkdir(directory, { mode: 0o700 });
  try {
    const bytes = Buffer.alloc(256 * 1024 + 1, 0x20);
    await writeFile(target, bytes, { mode: 0o600 });
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        workspaceRoot: workspace,
        relativePath: ".hcheck/preflight/run-001.json",
        sha256: digest(bytes),
        now: CREATED_AT,
      }),
    );
  } finally {
    await cleanupPreflightWorkspace(workspace, ["run-001"]);
  }
});

test("assertDevicePreflightBinding 对所有现场绑定漂移统一失败且不比较时间和 runId", () => {
  const record = createRecord();
  assert.doesNotThrow(() =>
    assertDevicePreflightBinding(record, validBinding()),
  );

  const mutations: Array<(value: PreflightBinding) => void> = [
    (value) => ((value.flow as { id: string }).id = "other"),
    (value) => ((value.flow as { version: number }).version = 2),
    (value) => ((value.flow as { sha256: string }).sha256 = HASH_E),
    (value) => ((value.artifact as { sha256: string }).sha256 = HASH_E),
    (value) =>
      ((value.artifact as { bundleName: string }).bundleName = "other"),
    (value) =>
      ((value.artifact as { versionName: string }).versionName = "2.0"),
    (value) => ((value.artifact as { versionCode: number }).versionCode = 2),
    (value) => ((value.artifact.moduleNames as string[])[0] = "feature"),
    (value) =>
      ((value.artifact as { selectedModule: string }).selectedModule =
        "feature"),
    (value) => ((value.hapSignTool as { sha256: string }).sha256 = HASH_E),
    (value) =>
      ((value.hapSignTool as { javaVersion: string }).javaVersion = "21"),
    (value) =>
      ((value.signature as { profileSha256: string }).profileSha256 = HASH_E),
    (value) =>
      ((
        value.signature as { signerCertificateSha256: string }
      ).signerCertificateSha256 = HASH_D),
    (value) => ((value.signature as { type: string }).type = "release"),
    (value) =>
      ((value.signature.validity as { notBefore: number }).notBefore += 1),
    (value) =>
      ((value.signature.validity as { notAfter: number }).notAfter += 1),
    (value) =>
      ((value.signature as { trustBoundary: string }).trustBoundary = "other"),
    (value) => ((value as { hdcVersion: string }).hdcVersion = "3.1.1a"),
    (value) =>
      ((value.device as { id: string }).id = `device:sha256:${"1".repeat(64)}`),
    (value) => ((value.device as { kind: string }).kind = "emulator"),
    (value) =>
      ((value as { abilityName: string }).abilityName = "OtherAbility"),
    (value) => ((value as { hilogTag: string }).hilogTag = "OTHER"),
    (value) => ((value as { hilogMarker: string }).hilogMarker = "OTHER_OK"),
    (value) =>
      ((value as { bundlePresence: string }).bundlePresence = "installed"),
    (value) => ((value.actions as string[])[0] = "launch"),
  ];

  for (const mutate of mutations) {
    const changed = structuredClone(validBinding()) as PreflightBinding;
    mutate(changed);
    assert.throws(
      () => assertDevicePreflightBinding(record, changed),
      /^DevicePreflightError: 现场状态与预检绑定不一致。$/u,
    );
  }
});

test("预检错误不泄漏绝对路径或敏感输入", async () => {
  const sensitive = "raw-device-token-password";
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), `hcheck-${sensitive}-`),
  );
  try {
    await assert.rejects(
      readAndVerifyDevicePreflightRecord({
        workspaceRoot: workspace,
        relativePath: `.hcheck/preflight/${sensitive}.json`,
        sha256: HASH_A,
        now: CREATED_AT,
      }),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.equal(error.message.includes(workspace), false);
        assert.equal(error.message.includes(sensitive), false);
        return true;
      },
    );
  } finally {
    await removeDirectoryIfEmpty(workspace);
  }
});
