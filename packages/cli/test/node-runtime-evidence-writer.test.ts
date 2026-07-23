import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
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
import { NodeRuntimeEvidenceWriter } from "../src/infrastructure/node-runtime-evidence-writer.js";

test("NodeRuntimeEvidenceWriter 在工作区内原样写入证据且可复验大小与 SHA-256", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-evidence-writer-"),
  );
  const archiveDirectory = path.join(
    workspace,
    ".hcheck",
    "evidence",
    "run-001",
  );
  const capturesDirectory = path.join(archiveDirectory, "captures");
  const evidenceFile = path.join(capturesDirectory, "runtime.bin");
  const bytes = new Uint8Array([0, 1, 2, 255, 10]);

  try {
    const writer = new NodeRuntimeEvidenceWriter({ workspaceRoot: workspace });
    await writer.write({
      archiveRoot: ".hcheck/evidence/run-001",
      relativePath: "captures/runtime.bin",
      bytes,
    });

    const actual = await readFile(evidenceFile);
    assert.deepEqual(actual, Buffer.from(bytes));
    assert.equal((await stat(evidenceFile)).size, bytes.byteLength);
    assert.equal(
      createHash("sha256").update(actual).digest("hex"),
      createHash("sha256").update(bytes).digest("hex"),
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(evidenceFile)).mode & 0o777, 0o600);
    }
  } finally {
    await removeFileIfPresent(evidenceFile);
    await removeDirectoryIfEmpty(capturesDirectory);
    await removeDirectoryIfEmpty(archiveDirectory);
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck", "evidence"));
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck"));
    await removeDirectoryIfEmpty(workspace);
  }
});

test("NodeRuntimeEvidenceWriter 拒绝不安全归档根和相对路径且不创建目标", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-evidence-path-"),
  );
  const writer = new NodeRuntimeEvidenceWriter({ workspaceRoot: workspace });
  const unsafeRequests = [
    { archiveRoot: ".hcheck/runtime/run-001", relativePath: "safe.log" },
    { archiveRoot: ".hcheck/evidence/../run-001", relativePath: "safe.log" },
    { archiveRoot: ".hcheck/evidence/run/extra", relativePath: "safe.log" },
    { archiveRoot: ".hcheck/evidence/.", relativePath: "safe.log" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "/tmp/x" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "C:/tmp/x" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "a\\b.log" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "a//b.log" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "a/./b.log" },
    { archiveRoot: ".hcheck/evidence/run-001", relativePath: "a/../b.log" },
  ] as const;

  try {
    for (const request of unsafeRequests) {
      await assert.rejects(
        writer.write({ ...request, bytes: new TextEncoder().encode("secret") }),
      );
    }
    await assert.rejects(lstat(path.join(workspace, ".hcheck")), {
      code: "ENOENT",
    });
  } finally {
    await removeDirectoryIfEmpty(workspace);
  }
});

test("NodeRuntimeEvidenceWriter 拒绝符号链接工作区和已存在的中间符号链接", async () => {
  const base = await mkdtemp(path.join(os.tmpdir(), "hcheck-evidence-link-"));
  const actualWorkspace = path.join(base, "actual-workspace");
  const linkedWorkspace = path.join(base, "linked-workspace");
  const externalDirectory = path.join(base, "external");
  const hcheckDirectory = path.join(actualWorkspace, ".hcheck");
  const evidenceLink = path.join(hcheckDirectory, "evidence");
  const escapedFile = path.join(externalDirectory, "run-001", "capture.log");

  await mkdir(actualWorkspace);
  await mkdir(externalDirectory);
  await symlink(actualWorkspace, linkedWorkspace, "dir");
  try {
    await assert.rejects(
      new NodeRuntimeEvidenceWriter({ workspaceRoot: linkedWorkspace }).write({
        archiveRoot: ".hcheck/evidence/run-001",
        relativePath: "capture.log",
        bytes: new Uint8Array([1]),
      }),
    );

    await mkdir(hcheckDirectory);
    await symlink(externalDirectory, evidenceLink, "dir");
    await assert.rejects(
      new NodeRuntimeEvidenceWriter({ workspaceRoot: actualWorkspace }).write({
        archiveRoot: ".hcheck/evidence/run-001",
        relativePath: "capture.log",
        bytes: new Uint8Array([1]),
      }),
    );
    await assert.rejects(lstat(escapedFile), { code: "ENOENT" });
  } finally {
    await removeFileIfPresent(evidenceLink);
    await removeDirectoryIfEmpty(hcheckDirectory);
    await removeFileIfPresent(linkedWorkspace);
    await removeDirectoryIfEmpty(externalDirectory);
    await removeDirectoryIfEmpty(actualWorkspace);
    await removeDirectoryIfEmpty(base);
  }
});

test("NodeRuntimeEvidenceWriter 不覆盖已有文件或最终符号链接，失败不消耗文件预算", async () => {
  const base = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-evidence-exclusive-"),
  );
  const workspace = path.join(base, "workspace");
  const externalFile = path.join(base, "external.log");
  const archiveDirectory = path.join(
    workspace,
    ".hcheck",
    "evidence",
    "run-001",
  );
  const existingFile = path.join(archiveDirectory, "existing.log");
  const linkedFile = path.join(archiveDirectory, "linked.log");
  const successfulFile = path.join(archiveDirectory, "success.log");

  await mkdir(workspace);
  await mkdir(path.join(workspace, ".hcheck"));
  await mkdir(path.join(workspace, ".hcheck", "evidence"));
  await mkdir(archiveDirectory);
  await writeFile(existingFile, "original");
  await writeFile(externalFile, "external");
  await symlink(externalFile, linkedFile, "file");

  try {
    const writer = new NodeRuntimeEvidenceWriter({
      workspaceRoot: workspace,
      maximumFiles: 1,
    });
    await assert.rejects(
      writer.write({
        archiveRoot: ".hcheck/evidence/run-001",
        relativePath: "existing.log",
        bytes: new TextEncoder().encode("replacement"),
      }),
    );
    await assert.rejects(
      writer.write({
        archiveRoot: ".hcheck/evidence/run-001",
        relativePath: "linked.log",
        bytes: new TextEncoder().encode("replacement"),
      }),
    );
    assert.equal(await readFile(existingFile, "utf8"), "original");
    assert.equal(await readFile(externalFile, "utf8"), "external");

    await writer.write({
      archiveRoot: ".hcheck/evidence/run-001",
      relativePath: "success.log",
      bytes: new TextEncoder().encode("success"),
    });
    assert.equal(await readFile(successfulFile, "utf8"), "success");
  } finally {
    await removeFileIfPresent(successfulFile);
    await removeFileIfPresent(linkedFile);
    await removeFileIfPresent(existingFile);
    await removeDirectoryIfEmpty(archiveDirectory);
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck", "evidence"));
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck"));
    await removeDirectoryIfEmpty(workspace);
    await removeFileIfPresent(externalFile);
    await removeDirectoryIfEmpty(base);
  }
});

test("NodeRuntimeEvidenceWriter 在写前执行单文件、总量和文件数预算，失败不消耗预算", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-evidence-budget-"),
  );
  const archiveDirectory = path.join(
    workspace,
    ".hcheck",
    "evidence",
    "run-budget",
  );
  const firstFile = path.join(archiveDirectory, "first.bin");
  const secondFile = path.join(archiveDirectory, "second.bin");

  try {
    const writer = new NodeRuntimeEvidenceWriter({
      workspaceRoot: workspace,
      maximumFiles: 2,
      maximumFileBytes: 4,
      maximumTotalBytes: 5,
    });
    await assert.rejects(
      writer.write({
        archiveRoot: ".hcheck/evidence/run-budget",
        relativePath: "oversized.bin",
        bytes: new Uint8Array(5),
      }),
    );
    await assert.rejects(lstat(path.join(workspace, ".hcheck")), {
      code: "ENOENT",
    });

    await writer.write({
      archiveRoot: ".hcheck/evidence/run-budget",
      relativePath: "first.bin",
      bytes: new Uint8Array(4),
    });
    await assert.rejects(
      writer.write({
        archiveRoot: ".hcheck/evidence/run-budget",
        relativePath: "total-overflow.bin",
        bytes: new Uint8Array(2),
      }),
    );
    await writer.write({
      archiveRoot: ".hcheck/evidence/run-budget",
      relativePath: "second.bin",
      bytes: new Uint8Array(1),
    });
    await assert.rejects(
      writer.write({
        archiveRoot: ".hcheck/evidence/run-budget",
        relativePath: "file-count-overflow.bin",
        bytes: new Uint8Array(0),
      }),
    );
    assert.equal((await stat(firstFile)).size, 4);
    assert.equal((await stat(secondFile)).size, 1);
  } finally {
    await removeFileIfPresent(secondFile);
    await removeFileIfPresent(firstFile);
    await removeDirectoryIfEmpty(archiveDirectory);
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck", "evidence"));
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck"));
    await removeDirectoryIfEmpty(workspace);
  }
});

test("NodeRuntimeEvidenceWriter 未取得新文件身份时拒绝按路径删除", async () => {
  const workspace = await mkdtemp(
    path.join(os.tmpdir(), "hcheck-evidence-unknown-identity-"),
  );
  const archiveDirectory = path.join(
    workspace,
    ".hcheck",
    "evidence",
    "run-unknown-identity",
  );
  const evidenceFile = path.join(archiveDirectory, "capture.log");
  const probeFile = path.join(workspace, "probe.tmp");
  const probeHandle = await open(probeFile, "wx", 0o600);
  const prototype = Object.getPrototypeOf(probeHandle) as object;
  const originalDescriptor = Object.getOwnPropertyDescriptor(prototype, "stat");
  await probeHandle.close();
  await unlink(probeFile);
  assert.ok(originalDescriptor !== undefined);

  try {
    Object.defineProperty(prototype, "stat", {
      ...originalDescriptor,
      value: async () => {
        throw new Error("受控 stat 失败");
      },
    });
    await assert.rejects(
      new NodeRuntimeEvidenceWriter({ workspaceRoot: workspace }).write({
        archiveRoot: ".hcheck/evidence/run-unknown-identity",
        relativePath: "capture.log",
        bytes: new Uint8Array([1]),
      }),
    );
    assert.equal((await lstat(evidenceFile)).isFile(), true);
  } finally {
    Object.defineProperty(prototype, "stat", originalDescriptor);
    await removeFileIfPresent(evidenceFile);
    await removeDirectoryIfEmpty(archiveDirectory);
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck", "evidence"));
    await removeDirectoryIfEmpty(path.join(workspace, ".hcheck"));
    await removeDirectoryIfEmpty(workspace);
  }
});

async function removeFileIfPresent(file: string): Promise<void> {
  await unlink(file).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}

async function removeDirectoryIfEmpty(directory: string): Promise<void> {
  await rmdir(directory).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
  });
}
