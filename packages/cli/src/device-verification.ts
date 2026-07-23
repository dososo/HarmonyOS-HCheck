import { constants } from "node:fs";
import { chmod, lstat, mkdtemp, open, rmdir, unlink } from "node:fs/promises";
import path from "node:path";
import {
  createHdcRuntimeDeviceSession,
  probeHdcVersion,
  type HdcRuntimeDeviceSession,
} from "@hcheck/adapter-hdc";
import type {
  HashPort,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";
import { runRuntimeFlow, type RuntimeFlowRunResult } from "@hcheck/core";
import {
  readHarmonyPackage,
  type PackageFileSystemPort,
} from "@hcheck/project-model";
import {
  assertDevicePreflightBinding,
  createDevicePreflightRecord,
  readAndVerifyDevicePreflightRecord,
  writeDevicePreflightRecord,
  type DevicePreflightRecord,
  type PreflightBinding,
  type WrittenDevicePreflightRecord,
} from "./device-preflight.js";
import { verifyHapSignature } from "./hap-signature.js";
import { NodeRuntimeEvidenceWriter } from "./infrastructure/node-runtime-evidence-writer.js";
import { parseDeviceSmokeFlow, type VerifyRunArguments } from "./verify-run.js";

const JAVA_TIMEOUT_MS = 10_000;
const JAVA_OUTPUT_BYTES = 8 * 1024;
const JAVA_VERSION =
  /^(?:openjdk|java) version "([0-9]+(?:\.[0-9]+){0,3}(?:_[0-9]+)?(?:[-+][0-9A-Za-z][0-9A-Za-z._-]*)?)"(?: [^\r\n]*)?$/u;
const DEVICE_HASH = /^device:sha256:[0-9a-f]{64}$/u;

export interface DeviceVerificationPorts {
  readonly fs: {
    readFile(file: string): Promise<Uint8Array>;
  };
  readonly runner: ProcessRunnerPort;
  readonly hash: HashPort;
  readonly clock: {
    now(): Date;
  };
  readonly runId: {
    next(): string;
  };
  readonly challenge: {
    next(): string;
  };
  readonly workspaceRoot: string;
  readonly temporaryParent: string;
  /** 仅用于编排层的受控运行器替换；生产调用未提供时固定使用 core runtime。 */
  readonly runtimeFlow?: typeof runRuntimeFlow;
}

export interface DevicePreflightResult {
  readonly record: DevicePreflightRecord;
  readonly written: WrittenDevicePreflightRecord;
}

export interface DeviceConfirmationResult {
  readonly status: "PASS" | "FAILED" | "INCOMPLETE";
  readonly exitCode: 0 | 1 | 4;
}

export class DeviceVerificationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "DeviceVerificationError";
    delete this.stack;
  }
}

export async function collectDevicePreflightBinding(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
): Promise<PreflightBinding> {
  if (args.mode !== "preflight_only") {
    throw new DeviceVerificationError("设备预检仅支持 preflight_only 模式。");
  }

  try {
    return await collectBinding(args, ports);
  } catch (error) {
    if (error instanceof DeviceVerificationError) throw error;
    throw new DeviceVerificationError("设备预检绑定失败。");
  }
}

export async function runDevicePreflight(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
): Promise<DevicePreflightResult> {
  const binding = await collectDevicePreflightBinding(args, ports);
  let record: DevicePreflightRecord;
  try {
    record = createDevicePreflightRecord({
      runId: ports.runId.next(),
      createdAt: ports.clock.now(),
      binding,
    });
  } catch {
    throw new DeviceVerificationError("预检记录创建失败。");
  }

  try {
    const written = await writeDevicePreflightRecord({
      workspaceRoot: ports.workspaceRoot,
      record,
    });
    return { record, written };
  } catch {
    throw new DeviceVerificationError("预检记录写入失败。");
  }
}

export async function runDeviceConfirmation(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
): Promise<DeviceConfirmationResult> {
  if (
    args.mode !== "confirm_device_actions" ||
    args.preflightPath === undefined ||
    args.preflightSha256 === undefined
  ) {
    return incompleteConfirmation();
  }

  let record: DevicePreflightRecord;
  try {
    record = await readAndVerifyDevicePreflightRecord({
      workspaceRoot: ports.workspaceRoot,
      relativePath: args.preflightPath,
      sha256: args.preflightSha256,
      now: ports.clock.now(),
    });
  } catch {
    return incompleteConfirmation();
  }

  let runtimeArtifact: RuntimeArtifactDirectory | undefined;
  let session: HdcRuntimeDeviceSession | undefined;
  let runtime: RuntimeFlowRunResult | undefined;
  let writer: NodeRuntimeEvidenceWriter | undefined;
  try {
    const inputs = await readStableInputs(args, ports);
    const binding = await collectBinding(args, ports, inputs);
    assertDevicePreflightBinding(record, binding);

    runtimeArtifact = await createRuntimeArtifactDirectory(
      ports.temporaryParent,
      inputs.hapBytes,
    );
    const opened = await openConfirmedRuntimeSession({
      args,
      ports,
      record,
      artifactDirectory: runtimeArtifact.directory,
    });
    session = opened.session;
    await verifyConfirmedRuntimeSession(args, record, session);

    await readAndVerifyDevicePreflightRecord({
      workspaceRoot: ports.workspaceRoot,
      relativePath: args.preflightPath,
      sha256: args.preflightSha256,
      now: ports.clock.now(),
    });

    writer = new NodeRuntimeEvidenceWriter({
      workspaceRoot: ports.workspaceRoot,
    });
    runtime = await (ports.runtimeFlow ?? runRuntimeFlow)(
      inputs.flow,
      session,
      {
        runId: record.runId,
        hcheckVersion: "0.6.0",
        rulePackVersion: "device-smoke-1",
        artifact: {
          uri: "artifact.hap",
          sha256: record.binding.artifact.sha256,
          bundleName: args.bundleName,
          versionName: args.versionName,
          versionCode: args.versionCode,
        },
        deviceId: record.binding.device.id,
        startedAt: ports.clock.now().toISOString(),
        hash: ports.hash,
        timing: {
          now: () => ports.clock.now().toISOString(),
          sleep: async () => undefined,
        },
        evidenceWriter: writer,
      },
    );
  } catch {
    // 所有运行环境、工具及设备错误均收敛为安全的 INCOMPLETE 结果。
  } finally {
    const cleanupComplete = await cleanupConfirmedRuntime(
      session,
      runtimeArtifact,
    );
    if (!cleanupComplete) runtime = undefined;
  }

  if (runtime === undefined || writer === undefined)
    return incompleteConfirmation();

  try {
    await writer.write({
      archiveRoot: runtime.evidenceManifest.archiveRoot,
      relativePath: "manifest.json",
      bytes: Buffer.from(
        `${JSON.stringify(runtime.evidenceManifest, null, 2)}\n`,
        "utf8",
      ),
    });
  } catch {
    return incompleteConfirmation();
  }

  return confirmationResultForRuntimeStatus(runtime.status);
}

interface StableInputs {
  readonly flowBytes: Buffer;
  readonly hapBytes: Buffer;
  readonly jarBytes: Buffer;
  readonly flow: ReturnType<typeof parseDeviceSmokeFlow>;
}

interface RuntimeArtifactDirectory {
  readonly directory: string;
  readonly artifactPath: string;
  readonly identity: FileIdentity;
}

interface FileIdentity {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
}

function incompleteConfirmation(): DeviceConfirmationResult {
  return { status: "INCOMPLETE", exitCode: 4 };
}

function confirmationResultForRuntimeStatus(
  status: RuntimeFlowRunResult["status"],
): DeviceConfirmationResult {
  return { status, exitCode: exitCodeForDeviceRuntimeStatus(status) };
}

export function exitCodeForDeviceRuntimeStatus(
  status: RuntimeFlowRunResult["status"],
): 0 | 1 | 4 {
  if (status === "PASS") return 0;
  if (status === "FAILED") return 1;
  return 4;
}

async function readStableInputs(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
): Promise<StableInputs> {
  const flowBytes = await readInput(args.flowPath, ports);
  const hapBytes = await readInput(args.artifactPath, ports);
  const jarBytes = await readInput(args.hapSignToolPath, ports);
  return { flowBytes, hapBytes, jarBytes, flow: parseFlow(flowBytes) };
}

async function createRuntimeArtifactDirectory(
  temporaryParent: string,
  hapBytes: Uint8Array,
): Promise<RuntimeArtifactDirectory> {
  let directory: string | undefined;
  let artifactPath: string | undefined;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  let identity: FileIdentity | undefined;
  try {
    directory = await mkdtemp(path.join(temporaryParent, "hcheck-runtime-"));
    await chmod(directory, 0o700);
    artifactPath = path.join(directory, "artifact.hap");
    handle = await open(
      artifactPath,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const details = await handle.stat();
    identity = { dev: details.dev, ino: details.ino };
    await handle.writeFile(hapBytes);
    await handle.chmod(0o600);
    await handle.close();
    handle = undefined;
    return { directory, artifactPath, identity };
  } catch {
    await handle?.close().catch(() => undefined);
    if (artifactPath !== undefined && identity !== undefined) {
      await unlinkRuntimeArtifact(artifactPath, identity).catch(
        () => undefined,
      );
    }
    if (directory !== undefined) await rmdir(directory).catch(() => undefined);
    throw new DeviceVerificationError("运行产物副本创建失败。");
  }
}

async function openConfirmedRuntimeSession({
  args,
  ports,
  record,
  artifactDirectory,
}: {
  readonly args: VerifyRunArguments;
  readonly ports: DeviceVerificationPorts;
  readonly record: DevicePreflightRecord;
  readonly artifactDirectory: string;
}): Promise<{ readonly session: HdcRuntimeDeviceSession }> {
  const version = await probeHdcVersion({
    runner: ports.runner,
    executable: args.hdcPath,
  });
  if (!version.available || version.version !== record.binding.hdcVersion) {
    throw new DeviceVerificationError("HDC 运行时复验失败。");
  }

  const opened = await createHdcRuntimeDeviceSession({
    runner: ports.runner,
    challenge: ports.challenge.next(),
    artifact: {
      uri: "artifact.hap",
      sha256: record.binding.artifact.sha256,
      bundleName: args.bundleName,
      versionName: args.versionName,
      versionCode: args.versionCode,
    },
    abilityName: args.abilityName,
    moduleName: args.moduleName,
    hilogTag: args.hilogTag,
    hilogMarker: args.hilogMarker,
    device: {
      kind: args.deviceKind,
      model: "HCheck runtime device",
      osVersion: "unknown",
      capabilities: [],
    },
    executable: args.hdcPath,
    cwd: artifactDirectory,
  });
  if (opened.status !== "ready") {
    throw new DeviceVerificationError("HDC 运行时会话建立失败。");
  }
  return { session: opened.session };
}

async function verifyConfirmedRuntimeSession(
  args: VerifyRunArguments,
  record: DevicePreflightRecord,
  session: HdcRuntimeDeviceSession,
): Promise<void> {
  const binding = session.binding();
  if (
    binding.deviceId !== record.binding.device.id ||
    binding.artifactSha256 !== record.binding.artifact.sha256 ||
    binding.bundleName !== args.bundleName ||
    binding.moduleName !== args.moduleName ||
    binding.abilityName !== args.abilityName ||
    binding.hilogTag !== args.hilogTag ||
    binding.hilogMarker !== args.hilogMarker
  ) {
    throw new DeviceVerificationError("运行时会话绑定复验失败。");
  }
  if ((await session.queryBundlePresence()) !== "not_installed") {
    throw new DeviceVerificationError("运行时安装状态复验失败。");
  }
}

async function cleanupConfirmedRuntime(
  session: HdcRuntimeDeviceSession | undefined,
  artifact: RuntimeArtifactDirectory | undefined,
): Promise<boolean> {
  let complete = true;
  if (session !== undefined) {
    try {
      if ((await session.cleanup()).status !== "ok") complete = false;
    } catch {
      complete = false;
    }
    try {
      if ((await session.queryBundlePresence()) !== "not_installed") {
        complete = false;
      }
    } catch {
      complete = false;
    }
  }
  if (artifact !== undefined) {
    if (
      !(await unlinkRuntimeArtifact(artifact.artifactPath, artifact.identity))
    ) {
      complete = false;
    }
    try {
      await rmdir(artifact.directory);
    } catch {
      complete = false;
    }
  }
  return complete;
}

async function unlinkRuntimeArtifact(
  artifactPath: string,
  expected: FileIdentity,
): Promise<boolean> {
  try {
    const details = await lstat(artifactPath);
    if (
      details.isSymbolicLink() ||
      !details.isFile() ||
      details.dev !== expected.dev ||
      details.ino !== expected.ino
    ) {
      return false;
    }
    await unlink(artifactPath);
    return true;
  } catch {
    return false;
  }
}

async function collectBinding(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
  stableInputs?: StableInputs,
): Promise<PreflightBinding> {
  const inputs = stableInputs ?? (await readStableInputs(args, ports));
  const artifact = await inspectHap(args, inputs.hapBytes);
  const flowSha256 = await ports.hash.sha256(inputs.flowBytes);
  const hapSha256 = await ports.hash.sha256(inputs.hapBytes);
  const jarSha256 = await ports.hash.sha256(inputs.jarBytes);
  const javaVersion = await collectJavaVersion(args.javaPath, ports.runner);
  const signature = await collectSignature({
    args,
    ports,
    hapBytes: inputs.hapBytes,
    hapSha256,
    jarBytes: inputs.jarBytes,
    jarSha256,
  });
  const device = await collectDevice(args, ports, hapSha256);

  return {
    flow: {
      id: inputs.flow.id,
      version: inputs.flow.version,
      sha256: flowSha256,
    },
    artifact: {
      sha256: hapSha256,
      bundleName: args.bundleName,
      versionName: args.versionName,
      versionCode: args.versionCode,
      moduleNames: artifact.moduleNames,
      selectedModule: args.moduleName,
    },
    hapSignTool: {
      sha256: jarSha256,
      javaVersion,
    },
    signature: {
      profileSha256: signature.profileSha256,
      signerCertificateSha256: signature.signerCertificateSha256,
      type: signature.profileType,
      validity: signature.validity,
      trustBoundary: signature.trustBoundary,
    },
    hdcVersion: device.hdcVersion,
    device: {
      id: device.id,
      kind: args.deviceKind,
    },
    abilityName: args.abilityName,
    hilogTag: args.hilogTag,
    hilogMarker: args.hilogMarker,
    bundlePresence: "not_installed",
    actions: ["install", "launch", "checkpoint", "stop", "uninstall"],
  };
}

async function readInput(
  file: string,
  ports: DeviceVerificationPorts,
): Promise<Buffer> {
  try {
    return Buffer.from(await ports.fs.readFile(file));
  } catch {
    throw new DeviceVerificationError("预检输入读取失败。");
  }
}

function parseFlow(bytes: Uint8Array) {
  try {
    return parseDeviceSmokeFlow(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    throw new DeviceVerificationError("Flow 配置不符合设备冒烟合同。");
  }
}

async function inspectHap(
  args: VerifyRunArguments,
  hapBytes: Uint8Array,
): Promise<{ readonly moduleNames: readonly string[] }> {
  const fs = memoryHapFileSystem(args.artifactPath, hapBytes);
  try {
    const snapshot = await readHarmonyPackage(args.artifactPath, { fs });
    const moduleNames = snapshot.modules.map(({ name }) => name);
    if (
      snapshot.artifact.type !== "hap" ||
      snapshot.completeness !== "COMPLETE" ||
      snapshot.bundleName !== args.bundleName ||
      snapshot.version?.name !== args.versionName ||
      snapshot.version?.code !== args.versionCode ||
      moduleNames.length !== 1 ||
      moduleNames[0] !== args.moduleName
    ) {
      throw new Error("HAP identity mismatch");
    }
    return { moduleNames };
  } catch {
    throw new DeviceVerificationError("HAP 身份校验失败。");
  }
}

function memoryHapFileSystem(
  artifactPath: string,
  bytes: Uint8Array,
): PackageFileSystemPort {
  return {
    async kind(file: string) {
      return file === artifactPath ? "file" : "other";
    },
    async size(file: string) {
      if (file !== artifactPath) throw new Error("unknown in-memory artifact");
      return bytes.byteLength;
    },
    async readFile(file: string) {
      if (file !== artifactPath) throw new Error("unknown in-memory artifact");
      return bytes;
    },
  };
}

async function collectJavaVersion(
  executable: string,
  runner: ProcessRunnerPort,
): Promise<string> {
  let result: ProcessRunResult;
  try {
    result = await runner.run({
      executable,
      args: ["-version"],
      timeoutMs: JAVA_TIMEOUT_MS,
      maxStdoutBytes: JAVA_OUTPUT_BYTES,
      maxStderrBytes: JAVA_OUTPUT_BYTES,
    });
  } catch {
    throw new DeviceVerificationError("Java 版本探测失败。");
  }

  if (
    result.status !== "completed" ||
    result.exitCode !== 0 ||
    result.timedOut ||
    result.stdoutTruncated ||
    result.stderrTruncated ||
    result.errorMessage !== undefined ||
    result.signal !== undefined
  ) {
    throw new DeviceVerificationError("Java 版本探测失败。");
  }

  const output = selectSingleOutput(result);
  const firstLine = output === undefined ? undefined : firstOutputLine(output);
  const match =
    firstLine === undefined ? undefined : JAVA_VERSION.exec(firstLine);
  if (match?.[1] === undefined) {
    throw new DeviceVerificationError("Java 版本探测失败。");
  }
  return match[1];
}

function selectSingleOutput(result: ProcessRunResult): string | undefined {
  if (result.stdout.length > 0 && result.stderr.length === 0)
    return result.stdout;
  if (result.stderr.length > 0 && result.stdout.length === 0)
    return result.stderr;
  return undefined;
}

function firstOutputLine(output: string): string | undefined {
  const normalized = output.replaceAll("\r\n", "\n");
  if (normalized.includes("\r")) return undefined;
  const [firstLine] = normalized.split("\n");
  if (
    firstLine === undefined ||
    Array.from(firstLine).some((character) => {
      const codePoint = character.codePointAt(0) as number;
      return codePoint <= 0x1f || codePoint === 0x7f;
    })
  ) {
    return undefined;
  }
  return firstLine;
}

async function collectSignature({
  args,
  ports,
  hapBytes,
  hapSha256,
  jarBytes,
  jarSha256,
}: {
  readonly args: VerifyRunArguments;
  readonly ports: DeviceVerificationPorts;
  readonly hapBytes: Uint8Array;
  readonly hapSha256: `sha256:${string}`;
  readonly jarBytes: Uint8Array;
  readonly jarSha256: `sha256:${string}`;
}) {
  try {
    return await verifyHapSignature({
      runner: ports.runner,
      javaExecutable: args.javaPath,
      hapBytes,
      expectedHapSha256: hapSha256,
      hapSignToolJarBytes: jarBytes,
      expectedHapSignToolSha256: jarSha256,
      bundleName: args.bundleName,
      clock: ports.clock,
      temporaryParent: ports.temporaryParent,
    });
  } catch {
    throw new DeviceVerificationError("HAP 验签失败。");
  }
}

async function collectDevice(
  args: VerifyRunArguments,
  ports: DeviceVerificationPorts,
  hapSha256: `sha256:${string}`,
): Promise<{
  readonly hdcVersion: string;
  readonly id: `device:sha256:${string}`;
}> {
  const version = await probeHdcVersion({
    runner: ports.runner,
    executable: args.hdcPath,
  });
  if (!version.available) {
    throw new DeviceVerificationError("HDC 版本探测失败。");
  }

  let opened;
  try {
    opened = await createHdcRuntimeDeviceSession({
      runner: ports.runner,
      challenge: ports.challenge.next(),
      artifact: {
        uri: args.artifactPath,
        sha256: hapSha256,
        bundleName: args.bundleName,
        versionName: args.versionName,
        versionCode: args.versionCode,
      },
      abilityName: args.abilityName,
      moduleName: args.moduleName,
      hilogTag: args.hilogTag,
      hilogMarker: args.hilogMarker,
      device: {
        kind: args.deviceKind,
        model: "HCheck preflight device",
        osVersion: "unknown",
        capabilities: [],
      },
      executable: args.hdcPath,
    });
  } catch {
    throw new DeviceVerificationError("HDC 设备会话建立失败。");
  }
  if (opened.status !== "ready") {
    throw new DeviceVerificationError("HDC 设备会话建立失败。");
  }

  let presence: string;
  try {
    presence = await opened.session.queryBundlePresence();
  } catch {
    throw new DeviceVerificationError("HDC 安装状态校验失败。");
  }
  if (presence !== "not_installed" || !isDeviceHash(opened.device.id)) {
    throw new DeviceVerificationError("HDC 安装状态校验失败。");
  }
  return { hdcVersion: version.version, id: opened.device.id };
}

function isDeviceHash(value: string): value is `device:sha256:${string}` {
  return DEVICE_HASH.test(value);
}
