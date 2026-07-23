import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, realpath } from "node:fs/promises";
import path from "node:path";

export type Sha256 = `sha256:${string}`;
export type DeviceIdHash = `device:sha256:${string}`;
export type PreflightDeviceKind = "physical" | "emulator" | "harmonyos_pc";
export type PreflightAction =
  "install" | "launch" | "checkpoint" | "stop" | "uninstall";

export interface PreflightBinding {
  readonly flow: {
    readonly id: string;
    readonly version: number;
    readonly sha256: Sha256;
  };
  readonly artifact: {
    readonly sha256: Sha256;
    readonly bundleName: string;
    readonly versionName: string;
    readonly versionCode: number;
    readonly moduleNames: readonly string[];
    readonly selectedModule: string;
  };
  readonly hapSignTool: {
    readonly sha256: Sha256;
    readonly javaVersion: string;
  };
  readonly signature: {
    readonly profileSha256: Sha256;
    readonly signerCertificateSha256: Sha256;
    readonly type: "debug";
    readonly validity: {
      readonly notBefore: number;
      readonly notAfter: number;
    };
    readonly trustBoundary: string;
  };
  readonly hdcVersion: string;
  readonly device: {
    readonly id: DeviceIdHash;
    readonly kind: PreflightDeviceKind;
  };
  readonly abilityName: string;
  readonly hilogTag: string;
  readonly hilogMarker: string;
  readonly bundlePresence: "not_installed";
  readonly actions: readonly PreflightAction[];
}

export interface DevicePreflightRecord {
  readonly schemaVersion: "1.0.0";
  readonly runId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly binding: PreflightBinding;
}

export interface CreateDevicePreflightRecordOptions {
  readonly runId: string;
  readonly createdAt: Date;
  readonly binding: PreflightBinding;
}

export interface WriteDevicePreflightRecordOptions {
  readonly workspaceRoot: string;
  readonly record: DevicePreflightRecord;
}

export interface WrittenDevicePreflightRecord {
  readonly relativePath: string;
  readonly sha256: Sha256;
  readonly expiresAt: string;
}

export interface ReadDevicePreflightRecordOptions {
  readonly workspaceRoot: string;
  readonly relativePath: string;
  readonly sha256: Sha256;
  readonly now: Date;
}

export class DevicePreflightError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "DevicePreflightError";
  }
}

const SCHEMA_VERSION = "1.0.0" as const;
const PREFLIGHT_TTL_MS = 15 * 60 * 1000;
const MAX_PREFLIGHT_BYTES = 256 * 1024;
const MAX_EPOCH_SECONDS = 253_402_300_799;
const SAFE_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const FLOW_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const BUNDLE_NAME_PATTERN =
  /^[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+$/u;
const SAFE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$/u;
const VERSION_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/u;
const JAVA_VERSION_PATTERN =
  /^[0-9]+(?:\.[0-9]+){0,3}(?:_[0-9]+)?(?:[-+][0-9A-Za-z][0-9A-Za-z._-]*)?$/u;
const HDC_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z]$/u;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const DEVICE_HASH_PATTERN = /^device:sha256:[0-9a-f]{64}$/u;
const SENSITIVE_TEXT_PATTERN =
  /(?:password|passwd|token|secret|connect[-_.]?key)/iu;
const FORMAT_CONTROL_PATTERN = /\p{Cf}/u;
const TRUST_BOUNDARY =
  "仅证明验签工具自包含证书链与 Profile 内容签名一致，不证明 AGC/平台根信任或证书撤销状态。";
const ACTIONS = Object.freeze([
  "install",
  "launch",
  "checkpoint",
  "stop",
  "uninstall",
] as const);

interface FileIdentity {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
}

interface StableFileSnapshot extends FileIdentity {
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
  readonly mode: number;
}

interface DirectoryIdentity extends FileIdentity {
  readonly realPath: string;
}

interface GuardedDirectory {
  readonly directory: string;
  readonly requirePrivateMode: boolean;
  readonly identity: DirectoryIdentity;
}

interface DirectoryHierarchyGuard {
  readonly directories: readonly GuardedDirectory[];
  readonly preflightHandle: Awaited<ReturnType<typeof open>>;
}

export function createDevicePreflightRecord(
  options: CreateDevicePreflightRecordOptions,
): DevicePreflightRecord {
  const runId = requireRunId(options.runId);
  const createdTime = requireDateTime(options.createdAt);
  const expiresTime = createdTime + PREFLIGHT_TTL_MS;
  if (!Number.isFinite(new Date(expiresTime).getTime())) invalidRecord();
  const createdAt = new Date(createdTime).toISOString();
  const expiresAt = new Date(expiresTime).toISOString();
  const binding = parseBinding(options.binding);
  return deepFreeze({
    schemaVersion: SCHEMA_VERSION,
    runId,
    createdAt,
    expiresAt,
    binding,
  });
}

export function serializeDevicePreflightRecord(
  record: DevicePreflightRecord,
): Buffer {
  const parsed = parseRecord(record);
  return Buffer.from(`${JSON.stringify(parsed, null, 2)}\n`, "utf8");
}

export async function writeDevicePreflightRecord(
  options: WriteDevicePreflightRecordOptions,
): Promise<WrittenDevicePreflightRecord> {
  const record = parseRecord(options.record);
  const bytes = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  if (bytes.byteLength > MAX_PREFLIGHT_BYTES) invalidRecord();

  const workspace = await requireWorkspace(options.workspaceRoot);
  const hcheckDirectory = path.join(workspace, ".hcheck");
  const preflightDirectory = path.join(hcheckDirectory, "preflight");
  await ensureDirectory(hcheckDirectory, false);
  await ensureDirectory(preflightDirectory, true);

  const relativePath = `.hcheck/preflight/${record.runId}.json`;
  const target = path.join(preflightDirectory, `${record.runId}.json`);
  const guard = await openDirectoryHierarchy(
    workspace,
    hcheckDirectory,
    preflightDirectory,
  );
  try {
    await writePrivateNewFile(target, bytes, guard);
  } finally {
    await guard.preflightHandle.close().catch(() => undefined);
  }
  return Object.freeze({
    relativePath,
    sha256: digest(bytes),
    expiresAt: record.expiresAt,
  });
}

export async function readAndVerifyDevicePreflightRecord(
  options: ReadDevicePreflightRecordOptions,
): Promise<DevicePreflightRecord> {
  const runId = requirePreflightRelativePath(options.relativePath);
  requireSha256(options.sha256);
  const now = requireDateTime(options.now);

  const workspace = await requireWorkspace(options.workspaceRoot);
  const hcheckDirectory = path.join(workspace, ".hcheck");
  const preflightDirectory = path.join(hcheckDirectory, "preflight");
  await requireDirectory(hcheckDirectory, false);
  await requireDirectory(preflightDirectory, true);
  const target = path.join(preflightDirectory, `${runId}.json`);
  const guard = await openDirectoryHierarchy(
    workspace,
    hcheckDirectory,
    preflightDirectory,
  );
  let bytes: Buffer;
  try {
    bytes = await readStablePrivateFile(target, guard);
  } finally {
    await guard.preflightHandle.close().catch(() => undefined);
  }

  if (digest(bytes) !== options.sha256) {
    throw new DevicePreflightError("预检记录哈希校验失败。");
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    invalidRecord();
  }
  const record = parseRecord(parsedJson);
  if (record.runId !== runId) invalidRecord();
  const canonical = Buffer.from(`${JSON.stringify(record, null, 2)}\n`, "utf8");
  if (!bytes.equals(canonical)) invalidRecord();

  const createdAt = Date.parse(record.createdAt);
  const expiresAt = Date.parse(record.expiresAt);
  if (
    expiresAt - createdAt !== PREFLIGHT_TTL_MS ||
    now < createdAt ||
    now > expiresAt
  ) {
    throw new DevicePreflightError("预检记录不在有效期内。");
  }
  return deepFreeze(record);
}

export function assertDevicePreflightBinding(
  record: DevicePreflightRecord,
  recomputed: PreflightBinding,
): void {
  try {
    const expected = parseRecord(record).binding;
    const actual = parseBinding(recomputed);
    if (sameBinding(expected, actual)) return;
  } catch {
    // 所有现场漂移和无效现场数据都使用同一条安全错误。
  }
  throw new DevicePreflightError("现场状态与预检绑定不一致。");
}

function parseRecord(value: unknown): DevicePreflightRecord {
  const record = requireObject(value, [
    "schemaVersion",
    "runId",
    "createdAt",
    "expiresAt",
    "binding",
  ]);
  if (record.schemaVersion !== SCHEMA_VERSION) invalidRecord();
  const runId = requireRunId(record.runId);
  const createdAt = requireCanonicalIso(record.createdAt);
  const expiresAt = requireCanonicalIso(record.expiresAt);
  if (Date.parse(expiresAt) - Date.parse(createdAt) !== PREFLIGHT_TTL_MS) {
    invalidRecord();
  }
  const binding = parseBinding(record.binding);
  return {
    schemaVersion: SCHEMA_VERSION,
    runId,
    createdAt,
    expiresAt,
    binding,
  };
}

function parseBinding(value: unknown): PreflightBinding {
  const binding = requireObject(value, [
    "flow",
    "artifact",
    "hapSignTool",
    "signature",
    "hdcVersion",
    "device",
    "abilityName",
    "hilogTag",
    "hilogMarker",
    "bundlePresence",
    "actions",
  ]);
  const flow = requireObject(binding.flow, ["id", "version", "sha256"]);
  const artifact = requireObject(binding.artifact, [
    "sha256",
    "bundleName",
    "versionName",
    "versionCode",
    "moduleNames",
    "selectedModule",
  ]);
  const hapSignTool = requireObject(binding.hapSignTool, [
    "sha256",
    "javaVersion",
  ]);
  const signature = requireObject(binding.signature, [
    "profileSha256",
    "signerCertificateSha256",
    "type",
    "validity",
    "trustBoundary",
  ]);
  const validity = requireObject(signature.validity, ["notBefore", "notAfter"]);
  const device = requireObject(binding.device, ["id", "kind"]);

  const moduleNames = requireSafeUniqueTokens(artifact.moduleNames);
  const selectedModule = requireSafeToken(artifact.selectedModule);
  if (!moduleNames.includes(selectedModule)) invalidRecord();
  const notBefore = requireNonNegativeSafeInteger(validity.notBefore);
  const notAfter = requireNonNegativeSafeInteger(validity.notAfter);
  if (notBefore >= notAfter) invalidRecord();

  if (signature.type !== "debug") invalidRecord();
  if (
    device.kind !== "physical" &&
    device.kind !== "emulator" &&
    device.kind !== "harmonyos_pc"
  ) {
    invalidRecord();
  }
  if (typeof device.id !== "string" || !DEVICE_HASH_PATTERN.test(device.id)) {
    invalidRecord();
  }
  if (binding.bundlePresence !== "not_installed") invalidRecord();
  const actions = requireActions(binding.actions);

  return {
    flow: {
      id: requirePatternText(flow.id, FLOW_ID_PATTERN, 128),
      version: requirePositiveUint32(flow.version),
      sha256: requireSha256(flow.sha256),
    },
    artifact: {
      sha256: requireSha256(artifact.sha256),
      bundleName: requirePatternText(
        artifact.bundleName,
        BUNDLE_NAME_PATTERN,
        255,
      ),
      versionName: requirePatternText(
        artifact.versionName,
        VERSION_NAME_PATTERN,
        128,
      ),
      versionCode: requireUint32(artifact.versionCode),
      moduleNames,
      selectedModule,
    },
    hapSignTool: {
      sha256: requireSha256(hapSignTool.sha256),
      javaVersion: requirePatternText(
        hapSignTool.javaVersion,
        JAVA_VERSION_PATTERN,
        128,
      ),
    },
    signature: {
      profileSha256: requireSha256(signature.profileSha256),
      signerCertificateSha256: requireSha256(signature.signerCertificateSha256),
      type: "debug",
      validity: { notBefore, notAfter },
      trustBoundary: requireTrustBoundary(signature.trustBoundary),
    },
    hdcVersion: requirePatternText(binding.hdcVersion, HDC_VERSION_PATTERN, 64),
    device: {
      id: device.id as DeviceIdHash,
      kind: device.kind,
    },
    abilityName: requireSafeToken(binding.abilityName),
    hilogTag: requireSafeToken(binding.hilogTag),
    hilogMarker: requireSafeMarker(binding.hilogMarker),
    bundlePresence: "not_installed",
    actions,
  };
}

function sameBinding(
  expected: PreflightBinding,
  actual: PreflightBinding,
): boolean {
  return (
    expected.flow.id === actual.flow.id &&
    expected.flow.version === actual.flow.version &&
    expected.flow.sha256 === actual.flow.sha256 &&
    expected.artifact.sha256 === actual.artifact.sha256 &&
    expected.artifact.bundleName === actual.artifact.bundleName &&
    expected.artifact.versionName === actual.artifact.versionName &&
    expected.artifact.versionCode === actual.artifact.versionCode &&
    sameStrings(expected.artifact.moduleNames, actual.artifact.moduleNames) &&
    expected.artifact.selectedModule === actual.artifact.selectedModule &&
    expected.hapSignTool.sha256 === actual.hapSignTool.sha256 &&
    expected.hapSignTool.javaVersion === actual.hapSignTool.javaVersion &&
    expected.signature.profileSha256 === actual.signature.profileSha256 &&
    expected.signature.signerCertificateSha256 ===
      actual.signature.signerCertificateSha256 &&
    expected.signature.type === actual.signature.type &&
    expected.signature.validity.notBefore ===
      actual.signature.validity.notBefore &&
    expected.signature.validity.notAfter ===
      actual.signature.validity.notAfter &&
    expected.signature.trustBoundary === actual.signature.trustBoundary &&
    expected.hdcVersion === actual.hdcVersion &&
    expected.device.id === actual.device.id &&
    expected.device.kind === actual.device.kind &&
    expected.abilityName === actual.abilityName &&
    expected.hilogTag === actual.hilogTag &&
    expected.hilogMarker === actual.hilogMarker &&
    expected.bundlePresence === actual.bundlePresence &&
    sameStrings(expected.actions, actual.actions)
  );
}

function sameStrings(
  expected: readonly string[],
  actual: readonly string[],
): boolean {
  return (
    expected.length === actual.length &&
    expected.every((value, index) => actual[index] === value)
  );
}

function requireObject(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    invalidRecord();
  }
  const keys = Object.keys(value);
  if (
    keys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(value, key))
  ) {
    invalidRecord();
  }
  return value as Record<string, unknown>;
}

function requireSafeText(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    hasUnsafeCodePoint(value)
  ) {
    invalidRecord();
  }
  return value;
}

function requirePatternText(
  value: unknown,
  pattern: RegExp,
  maximumLength: number,
): string {
  const text = requireSafeText(value);
  if (
    text.length > maximumLength ||
    !pattern.test(text) ||
    path.posix.isAbsolute(text) ||
    path.win32.isAbsolute(text) ||
    SENSITIVE_TEXT_PATTERN.test(text)
  ) {
    invalidRecord();
  }
  return text;
}

function requireSafeToken(value: unknown): string {
  return requirePatternText(value, SAFE_TOKEN_PATTERN, 256);
}

function requireSafeMarker(value: unknown): string {
  const marker = requireSafeText(value);
  if (
    marker.length > 128 ||
    marker.trim() !== marker ||
    marker.startsWith("-") ||
    path.posix.isAbsolute(marker) ||
    path.win32.isAbsolute(marker) ||
    SENSITIVE_TEXT_PATTERN.test(marker)
  ) {
    invalidRecord();
  }
  return marker;
}

function requireTrustBoundary(value: unknown): string {
  if (value !== TRUST_BOUNDARY) invalidRecord();
  return TRUST_BOUNDARY;
}

function hasUnsafeCodePoint(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return FORMAT_CONTROL_PATTERN.test(value);
}

function requireSafeUniqueTokens(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    invalidRecord();
  }
  const strings = value.map((item) => requireSafeToken(item));
  if (new Set(strings).size !== strings.length) invalidRecord();
  return strings;
}

function requireActions(value: unknown): readonly PreflightAction[] {
  if (
    !Array.isArray(value) ||
    value.length !== ACTIONS.length ||
    ACTIONS.some((action, index) => value[index] !== action)
  ) {
    invalidRecord();
  }
  return [...ACTIONS];
}

function requireRunId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !SAFE_RUN_ID.test(value) ||
    SENSITIVE_TEXT_PATTERN.test(value)
  ) {
    invalidRecord();
  }
  return value;
}

function requireSha256(value: unknown): Sha256 {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) invalidRecord();
  return value as Sha256;
}

function requireUint32(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > 0xffff_ffff
  ) {
    invalidRecord();
  }
  return value;
}

function requirePositiveUint32(value: unknown): number {
  const result = requireUint32(value);
  if (result === 0) invalidRecord();
  return result;
}

function requireNonNegativeSafeInteger(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > MAX_EPOCH_SECONDS
  ) {
    invalidRecord();
  }
  return value;
}

function requireCanonicalIso(value: unknown): string {
  if (typeof value !== "string") invalidRecord();
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    invalidRecord();
  }
  return value;
}

function requireDateTime(value: unknown): number {
  if (!(value instanceof Date)) invalidRecord();
  const time = value.getTime();
  if (!Number.isFinite(time)) invalidRecord();
  return time;
}

function requirePreflightRelativePath(value: string): string {
  const match =
    /^\.hcheck\/preflight\/([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\.json$/u.exec(
      value,
    );
  if (match?.[1] === undefined) {
    throw new DevicePreflightError("预检记录相对路径不安全。");
  }
  return match[1];
}

async function requireWorkspace(value: string): Promise<string> {
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    throw new DevicePreflightError("预检工作区不安全。");
  }
  await requireDirectory(value, false);
  return value;
}

async function requireDirectory(
  directory: string,
  requirePrivateMode: boolean,
): Promise<void> {
  const details = await lstat(directory).catch(() => undefined);
  if (
    details === undefined ||
    details.isSymbolicLink() ||
    !details.isDirectory() ||
    (requirePrivateMode &&
      process.platform !== "win32" &&
      (details.mode & 0o777) !== 0o700)
  ) {
    throw new DevicePreflightError("预检目录不安全。");
  }
}

async function ensureDirectory(
  directory: string,
  requirePrivateMode: boolean,
): Promise<void> {
  const existing = await lstat(directory).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw new DevicePreflightError("预检目录检查失败。");
    },
  );
  if (existing !== undefined) {
    await requireDirectory(directory, requirePrivateMode);
    return;
  }
  let created = false;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = true;
    if (process.platform !== "win32") await chmod(directory, 0o700);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw new DevicePreflightError("预检目录创建失败。");
    }
  }
  if (created && process.platform !== "win32") {
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await openDirectory(directory);
      await handle.chmod(0o700);
      const details = await handle.stat();
      if (!details.isDirectory() || (details.mode & 0o777) !== 0o700) {
        throw new DevicePreflightError("预检目录不安全。");
      }
    } catch {
      throw new DevicePreflightError("预检目录不安全。");
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  await requireDirectory(directory, requirePrivateMode);
}

async function openDirectoryHierarchy(
  workspace: string,
  hcheckDirectory: string,
  preflightDirectory: string,
): Promise<DirectoryHierarchyGuard> {
  // Node 标准 API 没有 openat；目录句柄加逐层身份复验是可验证的最小防线，
  // 不能声称可抵抗同 UID 攻击者在每次复验间隙持续主动竞争。
  const directories = [
    await captureDirectory(workspace, false),
    await captureDirectory(hcheckDirectory, false),
    await captureDirectory(preflightDirectory, true),
  ];
  let preflightHandle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    preflightHandle = await openDirectory(preflightDirectory);
    const opened = await preflightHandle.stat();
    const expected = directories[2]?.identity;
    if (
      expected === undefined ||
      !opened.isDirectory() ||
      opened.dev !== expected.dev ||
      opened.ino !== expected.ino ||
      (process.platform !== "win32" && (opened.mode & 0o777) !== 0o700)
    ) {
      throw new DevicePreflightError("预检目录不安全。");
    }
    const guard = { directories, preflightHandle };
    await assertDirectoryHierarchy(guard);
    return guard;
  } catch {
    await preflightHandle?.close().catch(() => undefined);
    throw new DevicePreflightError("预检目录不安全。");
  }
}

async function openDirectory(
  directory: string,
): Promise<Awaited<ReturnType<typeof open>>> {
  return open(
    directory,
    constants.O_RDONLY |
      (constants.O_DIRECTORY ?? 0) |
      (constants.O_NOFOLLOW ?? 0),
  );
}

async function captureDirectory(
  directory: string,
  requirePrivateMode: boolean,
): Promise<GuardedDirectory> {
  const details = await lstat(directory).catch(() => undefined);
  const resolved = await realpath(directory).catch(() => undefined);
  if (
    details === undefined ||
    details.isSymbolicLink() ||
    !details.isDirectory() ||
    resolved === undefined ||
    (requirePrivateMode &&
      process.platform !== "win32" &&
      (details.mode & 0o777) !== 0o700)
  ) {
    throw new DevicePreflightError("预检目录不安全。");
  }
  return {
    directory,
    requirePrivateMode,
    identity: { dev: details.dev, ino: details.ino, realPath: resolved },
  };
}

async function assertDirectoryHierarchy(
  guard: DirectoryHierarchyGuard,
): Promise<void> {
  try {
    for (const expected of guard.directories) {
      const current = await captureDirectory(
        expected.directory,
        expected.requirePrivateMode,
      );
      if (
        current.identity.dev !== expected.identity.dev ||
        current.identity.ino !== expected.identity.ino ||
        current.identity.realPath !== expected.identity.realPath
      ) {
        throw new DevicePreflightError("预检目录发生变化。");
      }
    }
    const opened = await guard.preflightHandle.stat();
    const expectedPreflight = guard.directories[2]?.identity;
    if (
      expectedPreflight === undefined ||
      !opened.isDirectory() ||
      opened.dev !== expectedPreflight.dev ||
      opened.ino !== expectedPreflight.ino ||
      (process.platform !== "win32" && (opened.mode & 0o777) !== 0o700)
    ) {
      throw new DevicePreflightError("预检目录发生变化。");
    }
  } catch {
    throw new DevicePreflightError("预检目录发生变化。");
  }
}

async function writePrivateNewFile(
  target: string,
  bytes: Uint8Array,
  guard: DirectoryHierarchyGuard,
): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await assertDirectoryHierarchy(guard);
    handle = await open(
      target,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    if (process.platform !== "win32") await handle.chmod(0o600);
    const opened = await handle.stat();
    const identity = { dev: opened.dev, ino: opened.ino };
    if (
      !opened.isFile() ||
      (process.platform !== "win32" && (opened.mode & 0o777) !== 0o600)
    ) {
      throw new DevicePreflightError("预检记录文件不安全。");
    }
    await assertDirectoryHierarchy(guard);
    await handle.writeFile(bytes);
    await handle.sync();
    const completed = await handle.stat();
    if (
      !completed.isFile() ||
      completed.dev !== identity.dev ||
      completed.ino !== identity.ino ||
      completed.size !== bytes.byteLength ||
      (process.platform !== "win32" && (completed.mode & 0o777) !== 0o600)
    ) {
      throw new DevicePreflightError("预检记录写入不稳定。");
    }
    await assertDirectoryHierarchy(guard);
    await handle.close();
    handle = undefined;
    const targetDetails = await lstat(target);
    if (
      targetDetails.isSymbolicLink() ||
      !targetDetails.isFile() ||
      targetDetails.dev !== identity.dev ||
      targetDetails.ino !== identity.ino ||
      targetDetails.size !== bytes.byteLength ||
      (process.platform !== "win32" && (targetDetails.mode & 0o777) !== 0o600)
    ) {
      throw new DevicePreflightError("预检记录写入不稳定。");
    }
    await assertDirectoryHierarchy(guard);
  } catch {
    await handle?.close().catch(() => undefined);
    throw new DevicePreflightError("预检记录写入失败。");
  }
}

async function readStablePrivateFile(
  target: string,
  guard: DirectoryHierarchyGuard,
): Promise<Buffer> {
  await assertDirectoryHierarchy(guard);
  const pathDetails = await lstat(target).catch(() => undefined);
  if (
    pathDetails === undefined ||
    pathDetails.isSymbolicLink() ||
    !pathDetails.isFile() ||
    pathDetails.size > MAX_PREFLIGHT_BYTES ||
    (process.platform !== "win32" && (pathDetails.mode & 0o777) !== 0o600)
  ) {
    throw new DevicePreflightError("预检记录文件不安全。");
  }

  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await assertDirectoryHierarchy(guard);
    handle = await open(
      target,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    const before = snapshot(await handle.stat());
    if (
      !sameSnapshot(snapshot(pathDetails), before) ||
      (process.platform !== "win32" && (before.mode & 0o777) !== 0o600)
    ) {
      throw new DevicePreflightError("预检记录读取不稳定。");
    }
    await assertDirectoryHierarchy(guard);
    const bytes = await readBoundedFile(handle);
    const after = snapshot(await handle.stat());
    await assertDirectoryHierarchy(guard);
    await handle.close();
    handle = undefined;
    const finalDetails = await lstat(target);
    if (
      bytes.byteLength > MAX_PREFLIGHT_BYTES ||
      !sameSnapshot(before, after) ||
      (process.platform !== "win32" && (after.mode & 0o777) !== 0o600) ||
      finalDetails.isSymbolicLink() ||
      !finalDetails.isFile() ||
      !sameSnapshot(after, snapshot(finalDetails))
    ) {
      throw new DevicePreflightError("预检记录读取不稳定。");
    }
    await assertDirectoryHierarchy(guard);
    return bytes;
  } catch {
    await handle?.close().catch(() => undefined);
    throw new DevicePreflightError("预检记录读取失败。");
  }
}

async function readBoundedFile(
  handle: Awaited<ReturnType<typeof open>>,
): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(MAX_PREFLIGHT_BYTES + 1);
  let offset = 0;
  while (offset < buffer.byteLength) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.byteLength - offset,
      offset,
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return buffer.subarray(0, offset);
}

function snapshot(details: {
  readonly dev: number | bigint;
  readonly ino: number | bigint;
  readonly size: number;
  readonly mtimeMs: number;
  readonly ctimeMs: number;
  readonly mode: number;
}): StableFileSnapshot {
  return {
    dev: details.dev,
    ino: details.ino,
    size: details.size,
    mtimeMs: details.mtimeMs,
    ctimeMs: details.ctimeMs,
    mode: details.mode,
  };
}

function sameSnapshot(
  left: StableFileSnapshot,
  right: StableFileSnapshot,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs &&
    left.mode === right.mode
  );
}

function digest(bytes: Uint8Array): Sha256 {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return value;
  }
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invalidRecord(): never {
  throw new DevicePreflightError("预检记录格式无效。");
}
