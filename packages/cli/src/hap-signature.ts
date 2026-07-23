import { constants } from "node:fs";
import { createHash, X509Certificate } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  open,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import path from "node:path";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const PEM_BLOCK_PATTERN =
  /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu;
const BASE64_DER_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const MAX_CERT_CHAIN_BYTES = 256 * 1024;
const MAX_PROFILE_BYTES = 1024 * 1024;
const MAX_PROFILE_JSON_BYTES = 1024 * 1024;
const PROCESS_TIMEOUT_MS = 30_000;
const PROCESS_OUTPUT_BYTES = 64 * 1024;
const OUTPROOF_WARNING =
  /^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} {2}WARN - Missing parameter: outproof\r?\n?$/u;
const TRUST_BOUNDARY =
  "仅证明验签工具自包含证书链与 Profile 内容签名一致，不证明 AGC/平台根信任或证书撤销状态。";
const CLEANUP_NAMES = [
  "profile-verification.json",
  "profile.p7b",
  "cert-chain.cer",
  "artifact.hap",
  "hap-sign-tool.jar",
] as const;

type Sha256 = `sha256:${string}`;

export interface HapSignatureClock {
  now(): Date;
}

export interface HapSignatureVerificationOptions {
  readonly runner: ProcessRunnerPort;
  readonly javaExecutable: string;
  readonly hapBytes: Uint8Array;
  readonly expectedHapSha256: Sha256;
  readonly hapSignToolJarBytes: Uint8Array;
  readonly expectedHapSignToolSha256: Sha256;
  readonly bundleName: string;
  readonly clock: HapSignatureClock;
  readonly temporaryParent: string;
}

export interface HapSignatureVerificationSummary {
  readonly hapSha256: Sha256;
  readonly hapSignToolSha256: Sha256;
  readonly profileSha256: Sha256;
  readonly signerCertificateSha256: Sha256;
  readonly bundleName: string;
  readonly profileType: "debug";
  readonly validity: {
    readonly notBefore: number;
    readonly notAfter: number;
  };
  readonly trustBoundary: typeof TRUST_BOUNDARY;
}

export class HapSignatureVerificationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "HapSignatureVerificationError";
  }
}

interface FileIdentity {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
}

interface StableFile {
  readonly bytes: Buffer;
  readonly identity: FileIdentity;
}

interface PrivateWorkspace {
  readonly directory: string;
  readonly identity: FileIdentity;
}

interface ParentIdentity extends FileIdentity {
  readonly realPath: string;
}

interface ParsedProfile {
  readonly type: "debug";
  readonly notBefore: number;
  readonly notAfter: number;
  readonly developmentCertificate: X509Certificate;
}

export async function verifyHapSignature(
  options: HapSignatureVerificationOptions,
): Promise<HapSignatureVerificationSummary> {
  const hapBytes = Buffer.from(options.hapBytes);
  const jarBytes = Buffer.from(options.hapSignToolJarBytes);
  const hapSha256 = digest(hapBytes);
  const jarSha256 = digest(jarBytes);
  requireExpectedHash(options.expectedHapSha256, hapSha256, "HAP 哈希不匹配。");
  requireExpectedHash(
    options.expectedHapSignToolSha256,
    jarSha256,
    "验签工具哈希不匹配。",
  );
  requireSafeText(options.bundleName, "Bundle 名称无效。");
  requireSafeText(options.javaExecutable, "Java 可执行文件无效。");

  let workspace: PrivateWorkspace | undefined;
  let operationResult: HapSignatureVerificationSummary | undefined;
  let operationError: HapSignatureVerificationError | undefined;

  try {
    workspace = await createPrivateWorkspace(options.temporaryParent);
    operationResult = await verifyInWorkspace(
      options,
      workspace.directory,
      hapBytes,
      jarBytes,
      hapSha256,
      jarSha256,
    );
  } catch (error) {
    operationError = safeError(error);
  }

  const cleanupError = await cleanupWorkspace(workspace);
  if (cleanupError !== undefined) throw cleanupError;
  if (operationError !== undefined) throw operationError;
  if (operationResult === undefined) {
    throw new HapSignatureVerificationError("HAP 验签未生成安全摘要。");
  }
  return operationResult;
}

async function verifyInWorkspace(
  options: HapSignatureVerificationOptions,
  workspace: string,
  hapBytes: Uint8Array,
  jarBytes: Uint8Array,
  hapSha256: Sha256,
  jarSha256: Sha256,
): Promise<HapSignatureVerificationSummary> {
  const artifactPath = path.join(workspace, "artifact.hap");
  const jarPath = path.join(workspace, "hap-sign-tool.jar");
  const certChainPath = path.join(workspace, "cert-chain.cer");
  const profilePath = path.join(workspace, "profile.p7b");
  const profileJsonPath = path.join(workspace, "profile-verification.json");

  const artifactIdentity = await writePrivateNewFile(artifactPath, hapBytes);
  const jarIdentity = await writePrivateNewFile(jarPath, jarBytes);

  await requireUnchangedFile(
    artifactPath,
    artifactIdentity,
    hapSha256,
    hapBytes.byteLength,
  );
  await requireUnchangedFile(
    jarPath,
    jarIdentity,
    jarSha256,
    jarBytes.byteLength,
  );
  await requireAbsent(certChainPath);
  await requireAbsent(profilePath);
  await runTool(options.runner, {
    executable: options.javaExecutable,
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
    cwd: workspace,
    timeoutMs: PROCESS_TIMEOUT_MS,
    maxStdoutBytes: PROCESS_OUTPUT_BYTES,
    maxStderrBytes: PROCESS_OUTPUT_BYTES,
  });
  await requireUnchangedFile(
    artifactPath,
    artifactIdentity,
    hapSha256,
    hapBytes.byteLength,
  );
  await requireUnchangedFile(
    jarPath,
    jarIdentity,
    jarSha256,
    jarBytes.byteLength,
  );
  const certChain = await readStableFile(certChainPath, MAX_CERT_CHAIN_BYTES);
  const profile = await readStableFile(profilePath, MAX_PROFILE_BYTES);

  await requireAbsent(profileJsonPath);
  await runTool(options.runner, {
    executable: options.javaExecutable,
    args: [
      "-jar",
      "hap-sign-tool.jar",
      "verify-profile",
      "-inFile",
      "profile.p7b",
      "-outFile",
      "profile-verification.json",
    ],
    cwd: workspace,
    timeoutMs: PROCESS_TIMEOUT_MS,
    maxStdoutBytes: PROCESS_OUTPUT_BYTES,
    maxStderrBytes: PROCESS_OUTPUT_BYTES,
  });
  await requireUnchangedFile(
    artifactPath,
    artifactIdentity,
    hapSha256,
    hapBytes.byteLength,
  );
  await requireUnchangedFile(
    jarPath,
    jarIdentity,
    jarSha256,
    jarBytes.byteLength,
  );
  await requireUnchangedFile(
    certChainPath,
    certChain.identity,
    digest(certChain.bytes),
    certChain.bytes.byteLength,
  );
  await requireUnchangedFile(
    profilePath,
    profile.identity,
    digest(profile.bytes),
    profile.bytes.byteLength,
  );
  const profileJson = await readStableFile(
    profileJsonPath,
    MAX_PROFILE_JSON_BYTES,
  );

  const parsed = parseProfile(
    profileJson.bytes,
    options.bundleName,
    options.clock.now(),
  );
  const signerCertificateSha256 = matchSignerCertificate(
    certChain.bytes,
    parsed.developmentCertificate,
  );

  return {
    hapSha256,
    hapSignToolSha256: jarSha256,
    profileSha256: digest(profile.bytes),
    signerCertificateSha256,
    bundleName: options.bundleName,
    profileType: parsed.type,
    validity: {
      notBefore: parsed.notBefore,
      notAfter: parsed.notAfter,
    },
    trustBoundary: TRUST_BOUNDARY,
  };
}

async function createPrivateWorkspace(
  parent: string,
): Promise<PrivateWorkspace> {
  const parentIdentity = await readParentIdentity(parent);
  if (parentIdentity === undefined) {
    throw new HapSignatureVerificationError("验签临时父目录不安全。");
  }
  let directory: string | undefined;
  let createdIdentity: FileIdentity | undefined;
  try {
    directory = await mkdtemp(path.join(parent, "hcheck-signature-"));
    const created = await lstat(directory);
    if (created.isSymbolicLink() || !created.isDirectory()) {
      throw new Error("unsafe workspace");
    }
    createdIdentity = { dev: created.dev, ino: created.ino };
    await requireUnchangedParent(parent, parentIdentity);
    if (path.dirname(await realpath(directory)) !== parentIdentity.realPath) {
      throw new Error("workspace escaped parent");
    }
    await chmod(directory, 0o700);
    const details = await lstat(directory);
    if (
      details.isSymbolicLink() ||
      !details.isDirectory() ||
      details.dev !== createdIdentity.dev ||
      details.ino !== createdIdentity.ino ||
      (process.platform !== "win32" && (details.mode & 0o777) !== 0o700)
    ) {
      throw new Error("unsafe workspace");
    }
    await requireUnchangedParent(parent, parentIdentity);
    return {
      directory,
      identity: { dev: details.dev, ino: details.ino },
    };
  } catch {
    if (directory !== undefined) {
      if (
        createdIdentity === undefined ||
        !(await removeCreatedWorkspace(directory, createdIdentity))
      ) {
        throw new HapSignatureVerificationError("验签私有工作区清理失败。");
      }
    }
    throw new HapSignatureVerificationError("验签私有工作区创建失败。");
  }
}

async function readParentIdentity(
  parent: string,
): Promise<ParentIdentity | undefined> {
  if (!path.isAbsolute(parent)) return undefined;
  try {
    const details = await lstat(parent);
    if (details.isSymbolicLink() || !details.isDirectory()) return undefined;
    return {
      dev: details.dev,
      ino: details.ino,
      realPath: await realpath(parent),
    };
  } catch {
    return undefined;
  }
}

async function requireUnchangedParent(
  parent: string,
  expected: ParentIdentity,
): Promise<void> {
  const actual = await readParentIdentity(parent);
  if (
    actual === undefined ||
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.realPath !== expected.realPath
  ) {
    throw new HapSignatureVerificationError("验签临时父目录发生变化。");
  }
}

async function removeCreatedWorkspace(
  directory: string,
  expected: FileIdentity,
): Promise<boolean> {
  try {
    const details = await lstat(directory);
    if (
      details.isSymbolicLink() ||
      !details.isDirectory() ||
      details.dev !== expected.dev ||
      details.ino !== expected.ino
    ) {
      return false;
    }
    await rmdir(directory);
    return true;
  } catch {
    return false;
  }
}

async function writePrivateNewFile(
  target: string,
  bytes: Uint8Array,
): Promise<FileIdentity> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(bytes);
    const details = await handle.stat();
    if (
      !details.isFile() ||
      (process.platform !== "win32" && (details.mode & 0o777) !== 0o600)
    ) {
      throw new Error("unsafe input");
    }
    return { dev: details.dev, ino: details.ino };
  } catch {
    throw new HapSignatureVerificationError("验签输入副本写入失败。");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function requireAbsent(target: string): Promise<void> {
  try {
    await lstat(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw new HapSignatureVerificationError("验签输出路径检查失败。");
  }
  throw new HapSignatureVerificationError("验签输出文件在调用前已存在。");
}

async function runTool(
  runner: ProcessRunnerPort,
  request: ProcessRunRequest,
): Promise<void> {
  let result: ProcessRunResult;
  try {
    result = await runner.run(request);
  } catch {
    throw new HapSignatureVerificationError("验签工具执行失败。");
  }
  if (
    result.status !== "completed" ||
    result.exitCode !== 0 ||
    result.timedOut ||
    result.stdoutTruncated ||
    result.stderrTruncated ||
    result.errorMessage !== undefined ||
    result.signal !== undefined ||
    !isAcceptedToolStderr(result.stderr) ||
    /\[(?:Fail|Error)\]|\b(?:FAILED|ERROR)\b/iu.test(result.stdout)
  ) {
    throw new HapSignatureVerificationError("验签工具未安全完成。");
  }
}

function isAcceptedToolStderr(stderr: string): boolean {
  return stderr.length === 0 || OUTPROOF_WARNING.test(stderr);
}

async function readStableFile(
  target: string,
  maximumBytes: number,
): Promise<StableFile> {
  const before = await safeFileDetails(target, maximumBytes);
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(
      target,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const opened = await handle.stat();
    requireSameFileState(before, opened);
    const bytes = await readAtMost(handle, before.size);
    const afterRead = await handle.stat();
    requireSameFileState(before, afterRead);
    if (
      bytes.byteLength === 0 ||
      bytes.byteLength !== before.size ||
      bytes.byteLength > maximumBytes
    ) {
      throw new Error("unsafe output size");
    }
    const after = await safeFileDetails(target, maximumBytes);
    requireSameFileState(before, after);
    return {
      bytes,
      identity: { dev: before.dev, ino: before.ino },
    };
  } catch {
    throw new HapSignatureVerificationError("验签输出文件不安全。");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function readAtMost(
  handle: Awaited<ReturnType<typeof open>>,
  maximumBytes: number,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
    throw new HapSignatureVerificationError("验签输出文件不安全。");
  }
  const chunks: Buffer[] = [];
  let position = 0;
  const readLimit = maximumBytes + 1;
  while (position < readLimit) {
    const length = Math.min(64 * 1024, readLimit - position);
    const buffer = Buffer.allocUnsafe(length);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead === 0) break;
    chunks.push(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  if (position > maximumBytes) {
    throw new HapSignatureVerificationError("验签输出文件不安全。");
  }
  return Buffer.concat(chunks, position);
}

async function safeFileDetails(target: string, maximumBytes: number) {
  const details = await lstat(target).catch(() => undefined);
  if (
    details === undefined ||
    details.isSymbolicLink() ||
    !details.isFile() ||
    details.size <= 0 ||
    details.size > maximumBytes
  ) {
    throw new HapSignatureVerificationError("验签输出文件不安全。");
  }
  return details;
}

function requireSameIdentity(
  expected: FileIdentity,
  actual: FileIdentity,
): void {
  if (expected.dev !== actual.dev || expected.ino !== actual.ino) {
    throw new HapSignatureVerificationError("验签文件在校验期间被替换。");
  }
}

function requireSameFileState(
  expected: FileIdentity & { readonly size: number },
  actual: FileIdentity & { readonly size: number },
): void {
  requireSameIdentity(expected, actual);
  if (expected.size !== actual.size) {
    throw new HapSignatureVerificationError("验签文件在校验期间发生变化。");
  }
}

async function requireUnchangedFile(
  target: string,
  expectedIdentity: FileIdentity,
  expectedHash: Sha256,
  expectedLength: number,
): Promise<void> {
  const file = await readStableFile(target, expectedLength);
  requireSameIdentity(expectedIdentity, file.identity);
  if (
    file.bytes.byteLength !== expectedLength ||
    digest(file.bytes) !== expectedHash
  ) {
    throw new HapSignatureVerificationError("验签文件在校验期间发生变化。");
  }
}

function parseProfile(
  bytes: Uint8Array,
  expectedBundle: string,
  now: Date,
): ParsedProfile {
  if (!Number.isFinite(now.getTime())) {
    throw new HapSignatureVerificationError("验签时钟无效。");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new HapSignatureVerificationError("Profile 验签结果不是有效 JSON。");
  }
  const root = requireRecord(value, "Profile 验签结果结构无效。");
  if (root.verifiedPassed !== true || root.message !== "OK") {
    throw new HapSignatureVerificationError("Profile CMS 验签未通过。");
  }
  const content = requireRecord(root.content, "Profile 验签内容结构无效。");
  if (content.type !== "debug") {
    throw new HapSignatureVerificationError("仅允许 debug Profile。");
  }
  const validity = requireRecord(content.validity, "Profile 有效期结构无效。");
  const notBefore = requireEpochSeconds(validity["not-before"]);
  const notAfter = requireEpochSeconds(validity["not-after"]);
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (notBefore > notAfter || nowSeconds < notBefore || nowSeconds > notAfter) {
    throw new HapSignatureVerificationError("Profile 不在有效期内。");
  }
  const bundleInfo = requireRecord(
    content["bundle-info"],
    "Profile Bundle 信息结构无效。",
  );
  if (bundleInfo["bundle-name"] !== expectedBundle) {
    throw new HapSignatureVerificationError("Profile Bundle 名称不匹配。");
  }
  return {
    type: "debug",
    notBefore,
    notAfter,
    developmentCertificate: parseDevelopmentCertificate(
      bundleInfo["development-certificate"],
    ),
  };
}

function requireRecord(
  value: unknown,
  message: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new HapSignatureVerificationError(message);
  }
  return value as Record<string, unknown>;
}

function requireEpochSeconds(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new HapSignatureVerificationError("Profile 有效期无效。");
  }
  return value as number;
}

function parseDevelopmentCertificate(value: unknown): X509Certificate {
  if (typeof value !== "string" || value.length === 0) {
    throw new HapSignatureVerificationError("Profile 开发证书无效。");
  }
  try {
    const trimmed = value.trim();
    const pemBlocks = trimmed.match(PEM_BLOCK_PATTERN) ?? [];
    if (pemBlocks.length > 0) {
      if (pemBlocks.length !== 1 || pemBlocks[0] !== trimmed) {
        throw new Error("invalid PEM envelope");
      }
      return new X509Certificate(trimmed);
    }
    if (
      !BASE64_DER_PATTERN.test(value) ||
      value.length % 4 !== 0 ||
      Buffer.from(value, "base64").toString("base64") !== value
    ) {
      throw new Error("invalid base64");
    }
    return new X509Certificate(Buffer.from(value, "base64"));
  } catch {
    throw new HapSignatureVerificationError("Profile 开发证书无效。");
  }
}

function matchSignerCertificate(
  chainBytes: Uint8Array,
  developmentCertificate: X509Certificate,
): Sha256 {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(chainBytes);
  } catch {
    throw new HapSignatureVerificationError("HAP 证书链格式无效。");
  }
  const matches = [...text.matchAll(PEM_BLOCK_PATTERN)];
  const blocks = matches.map((match) => match[0]);
  const beginMarkers = text.match(/-----BEGIN CERTIFICATE-----/gu) ?? [];
  const endMarkers = text.match(/-----END CERTIFICATE-----/gu) ?? [];
  if (blocks.length === 0) {
    throw new HapSignatureVerificationError("HAP 证书链为空。");
  }
  if (
    beginMarkers.length !== blocks.length ||
    endMarkers.length !== blocks.length ||
    !hasOnlyOfficialChainEnvelope(text, matches)
  ) {
    throw new HapSignatureVerificationError("HAP 证书链格式无效。");
  }
  const certificates = blocks.map((block) => {
    try {
      return new X509Certificate(block);
    } catch {
      throw new HapSignatureVerificationError("HAP 证书链格式无效。");
    }
  });
  const expected = digest(developmentCertificate.raw);
  const matchingCertificates = certificates.filter(
    (certificate) => digest(certificate.raw) === expected,
  );
  if (matchingCertificates.length !== 1) {
    throw new HapSignatureVerificationError(
      "Profile 开发证书与 HAP signer 证书不唯一匹配。",
    );
  }
  const nonCaLeafCertificates = certificates.filter(
    (certificate) => certificate.ca === false,
  );
  if (
    nonCaLeafCertificates.length !== 1 ||
    digest((nonCaLeafCertificates[0] as X509Certificate).raw) !== expected
  ) {
    throw new HapSignatureVerificationError(
      "Profile 开发证书与 HAP 唯一非 CA 叶子证书不匹配。",
    );
  }
  return expected;
}

function hasOnlyOfficialChainEnvelope(
  text: string,
  matches: readonly RegExpMatchArray[],
): boolean {
  let cursor = 0;
  for (const match of matches) {
    const index = match.index as number;
    if (!isOfficialChainGap(text.slice(cursor, index))) return false;
    cursor = index + match[0].length;
  }
  return isOfficialChainGap(text.slice(cursor));
}

function isOfficialChainGap(gap: string): boolean {
  const lines = gap
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return lines.length <= 1 && lines.every(isOfficialSubjectLine);
}

function isOfficialSubjectLine(line: string): boolean {
  const subject = line.startsWith("SubjectDN: ")
    ? line.slice("SubjectDN: ".length)
    : line.startsWith("CN=")
      ? line.slice("CN=".length)
      : undefined;
  return (
    subject !== undefined &&
    subject.length > 0 &&
    Array.from(subject).every((character) => {
      const point = character.codePointAt(0) as number;
      return point > 0x1f && point !== 0x7f;
    })
  );
}

function requireExpectedHash(
  expected: string,
  actual: Sha256,
  message: string,
): void {
  if (!HASH_PATTERN.test(expected) || expected !== actual) {
    throw new HapSignatureVerificationError(message);
  }
}

function requireSafeText(value: string, message: string): void {
  if (
    value.length === 0 ||
    Array.from(value).some((character) => {
      const point = character.codePointAt(0) as number;
      return point <= 0x1f || point === 0x7f;
    })
  ) {
    throw new HapSignatureVerificationError(message);
  }
}

function digest(bytes: Uint8Array): Sha256 {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function cleanupWorkspace(
  workspace: PrivateWorkspace | undefined,
): Promise<HapSignatureVerificationError | undefined> {
  if (workspace === undefined) return undefined;
  const details = await lstat(workspace.directory).catch(() => undefined);
  if (
    details === undefined ||
    details.isSymbolicLink() ||
    !details.isDirectory() ||
    details.dev !== workspace.identity.dev ||
    details.ino !== workspace.identity.ino
  ) {
    return new HapSignatureVerificationError("验签私有工作区清理失败。");
  }
  let failed = false;
  for (const name of CLEANUP_NAMES) {
    try {
      await unlink(path.join(workspace.directory, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") failed = true;
    }
  }
  try {
    await rmdir(workspace.directory);
  } catch {
    failed = true;
  }
  return failed
    ? new HapSignatureVerificationError("验签私有工作区清理失败。")
    : undefined;
}

function safeError(error: unknown): HapSignatureVerificationError {
  return error instanceof HapSignatureVerificationError
    ? error
    : new HapSignatureVerificationError("HAP 验签失败。");
}
