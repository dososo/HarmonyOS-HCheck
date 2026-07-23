import { gunzipSync, inflateRawSync } from "node:zlib";
import { HCheckError, compareCodePoints } from "@hcheck/core";
import { parseJson5 } from "./json5.js";

export { HCheckError } from "@hcheck/core";

export interface PackageFileSystemPort {
  kind(file: string): Promise<"file" | "directory" | "symlink" | "other">;
  size(file: string): Promise<number>;
  readFile(file: string): Promise<Uint8Array>;
}

export type HarmonyPackageType = "app" | "hap" | "hsp" | "har";

export interface HarmonyPackageEntry {
  readonly path: string;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly compressionMethod: "stored" | "deflated";
}

export interface HarmonyPackageModuleMetadata {
  readonly name: string;
  readonly type?: string;
  readonly packageName?: string;
  readonly deviceTypes: readonly string[];
  readonly requestPermissions: readonly string[];
  readonly debug?: boolean;
  readonly source: string;
}

export interface HarmonyPackageSnapshot {
  readonly schemaVersion: "1.0.0";
  readonly artifact: {
    readonly type: HarmonyPackageType;
    readonly sizeBytes: number;
  };
  readonly entries: readonly HarmonyPackageEntry[];
  readonly modules: readonly HarmonyPackageModuleMetadata[];
  readonly bundleName?: string;
  readonly version?: {
    readonly code?: number;
    readonly name?: string;
  };
  readonly permissions: readonly string[];
  readonly debug: {
    readonly enabledModules: readonly string[];
    readonly markerFiles: readonly string[];
  };
  readonly completeness: "COMPLETE" | "INCOMPLETE";
  readonly issues: readonly string[];
}

export interface ReadHarmonyPackageOptions {
  readonly fs: PackageFileSystemPort;
  readonly maxPackageBytes?: number;
  readonly maxEntryBytes?: number;
  readonly maxTotalUncompressedBytes?: number;
  readonly maxEntries?: number;
  readonly maxCompressionRatio?: number;
}

type PackageReaderLimits = Required<Omit<ReadHarmonyPackageOptions, "fs">> &
  Pick<ReadHarmonyPackageOptions, "fs">;

type ModulePackageType = "hap" | "hsp";
type HarmonyPackageVersion = NonNullable<HarmonyPackageSnapshot["version"]>;

interface ArchiveBudget {
  entryCount: number;
  totalUncompressedBytes: number;
}

interface ZipEntry {
  readonly path: string;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly compressionMethod: 0 | 8;
  readonly generalPurposeFlag: number;
  readonly crc32: number;
  readonly localHeaderOffset: number;
  readonly externalAttributes: number;
}

interface ParsedModuleArchive {
  readonly entries: readonly HarmonyPackageEntry[];
  readonly modules: readonly HarmonyPackageModuleMetadata[];
  readonly declaredBundleNames: readonly string[];
  readonly bundleName?: string;
  readonly version?: HarmonyPackageVersion;
  readonly markerFiles: readonly string[];
  readonly issues: readonly string[];
}

interface ParsedPackInfo {
  readonly bundleName: string;
  readonly version?: HarmonyPackageVersion;
}

interface TarEntry {
  readonly path: string;
  readonly size: number;
  readonly content: Buffer;
  readonly type: "file" | "directory";
}

const DEFAULT_LIMITS = Object.freeze({
  maxPackageBytes: 64 * 1024 * 1024,
  maxEntryBytes: 8 * 1024 * 1024,
  maxTotalUncompressedBytes: 32 * 1024 * 1024,
  maxEntries: 2_000,
  maxCompressionRatio: 100,
});
const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const LOCAL_SIGNATURE = 0x04034b50;
const ZIP64_LOCATOR_SIGNATURE = 0x07064b50;
const ZIP64_ENTRY_COUNT_SENTINEL = 0xffff;
const ZIP64_SENTINEL = 0xffffffff;
const ZIP64_EXTRA_FIELD_ID = 0x0001;
const TAR_BLOCK_SIZE = 512;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });
const DEBUG_MARKER =
  /(?:^|\/)(?:hcheck-debug-marker|debug|test|mock|fixture)(?:[-_./]|$)/iu;
const MODULE_MANIFEST_PATHS: ReadonlySet<string> = new Set([
  "module.json",
  "module.json5",
]);
const HAR_MANIFEST_PATHS: ReadonlySet<string> = new Set([
  "package/src/main/module.json",
  "package/src/main/module.json5",
]);
const APP_METADATA_PATHS: ReadonlySet<string> = new Set(["pack.info"]);

export async function readHarmonyPackage(
  artifactPath: string,
  options: ReadHarmonyPackageOptions,
): Promise<HarmonyPackageSnapshot> {
  const type = packageType(artifactPath);
  const kind = await options.fs.kind(artifactPath);
  if (kind !== "file") {
    throw artifactError("产物必须是普通文件，不能是目录或符号链接。");
  }
  const sizeBytes = await options.fs.size(artifactPath);
  const limits = { ...DEFAULT_LIMITS, ...options };
  if (
    !Number.isSafeInteger(sizeBytes) ||
    sizeBytes < 0 ||
    sizeBytes > limits.maxPackageBytes
  ) {
    throw artifactError("产物超过安全读取上限。");
  }
  const bytes = await options.fs.readFile(artifactPath);
  if (bytes.byteLength !== sizeBytes) {
    throw artifactError("产物读取前后大小不一致。");
  }
  return parseHarmonyPackage(bytes, type, sizeBytes, limits);
}

function parseHarmonyPackage(
  bytes: Uint8Array,
  type: HarmonyPackageType,
  sizeBytes: number,
  limits: PackageReaderLimits,
): HarmonyPackageSnapshot {
  const buffer = Buffer.from(bytes);
  const budget: ArchiveBudget = {
    entryCount: 0,
    totalUncompressedBytes: 0,
  };
  if (type === "app") {
    return parseAppArchive(buffer, sizeBytes, limits, budget);
  }
  if (type === "har") {
    return parseHarArchive(buffer, sizeBytes, limits);
  }
  const parsed = parseModuleArchive(buffer, type, limits, budget);
  return createSnapshot(type, sizeBytes, parsed);
}

function parseModuleArchive(
  buffer: Buffer,
  type: ModulePackageType,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
  sourcePrefix = "",
): ParsedModuleArchive {
  const entries = readCentralDirectory(
    buffer,
    limits,
    budget,
    MODULE_MANIFEST_PATHS,
  );
  const manifestEntries = entries.filter(({ path }) =>
    MODULE_MANIFEST_PATHS.has(path),
  );
  const manifests = manifestEntries.map((entry) =>
    readModuleManifest(buffer, entry, sourcePrefix, limits, budget),
  );
  const modules = manifests.map(({ metadata }) => metadata);
  const markerFiles = entries
    .map(({ path }) => path)
    .filter((entryPath) => DEBUG_MARKER.test(entryPath))
    .map((entryPath) => `${sourcePrefix}${entryPath}`)
    .sort(compareCodePoints);
  const declaredBundleNames = manifests
    .map(({ bundleName }) => bundleName)
    .filter((bundleName): bundleName is string => bundleName !== undefined);
  const bundleName =
    declaredBundleNames[0] ??
    (type === "hap"
      ? modules.find(({ packageName }) => packageName !== undefined)
          ?.packageName
      : undefined);
  const version = manifests.find(
    ({ version }) => version !== undefined,
  )?.version;
  const issues =
    manifestEntries.length === 0
      ? ["产物根目录中未发现 module.json/module.json5。"]
      : manifestEntries.length > 1
        ? ["产物根目录中的 module.json/module.json5 必须唯一。"]
        : [];
  return {
    entries: toHarmonyPackageEntries(entries),
    modules,
    declaredBundleNames,
    ...(bundleName === undefined ? {} : { bundleName }),
    ...(version === undefined ? {} : { version }),
    markerFiles,
    issues,
  };
}

function parseHarArchive(
  buffer: Buffer,
  sizeBytes: number,
  limits: PackageReaderLimits,
): HarmonyPackageSnapshot {
  const tarBuffer = gunzipHar(buffer, limits);
  const tarEntries = readTarEntries(tarBuffer, limits);
  const manifestPathEntries = tarEntries.filter((entry) =>
    HAR_MANIFEST_PATHS.has(entry.path),
  );
  const manifestEntries = manifestPathEntries.filter(
    (entry) => entry.type === "file",
  );
  const manifests = manifestEntries.map((entry) =>
    readModuleManifestContent(entry.content, entry.path),
  );
  const modules = manifests.map(({ metadata }) => metadata);
  const bundleName = manifests.find(
    ({ bundleName }) => bundleName !== undefined,
  )?.bundleName;
  const markerFiles = tarEntries
    .map(({ path }) => path)
    .filter((entryPath) => DEBUG_MARKER.test(entryPath))
    .sort(compareCodePoints);
  const issues =
    manifestPathEntries.length === 0
      ? ["HAR 中未发现 package/src/main/module.json/module.json5。"]
      : manifestPathEntries.length > 1
        ? ["HAR 的 package/src/main/module.json/module.json5 必须唯一。"]
        : manifestEntries.length === 0
          ? [
              "HAR 的 package/src/main/module.json/module.json5 必须是普通文件。",
            ]
          : [];
  return createSnapshot("har", sizeBytes, {
    entries: tarEntries.map(({ path, size }) => ({
      path,
      compressedSize: size,
      uncompressedSize: size,
      compressionMethod: "stored",
    })),
    modules,
    ...(bundleName === undefined ? {} : { bundleName }),
    markerFiles,
    issues,
  });
}

function gunzipHar(buffer: Buffer, limits: PackageReaderLimits): Buffer {
  let content: Buffer;
  try {
    content = gunzipSync(buffer, {
      maxOutputLength: limits.maxTotalUncompressedBytes,
    });
  } catch {
    throw artifactError("HAR GZIP 解压失败或超过总解压量限制。");
  }
  if (content.byteLength > limits.maxTotalUncompressedBytes) {
    throw artifactError("HAR GZIP 总解压量超过安全限制。");
  }
  if (
    buffer.byteLength === 0 ||
    content.byteLength / buffer.byteLength > limits.maxCompressionRatio
  ) {
    throw artifactError("HAR GZIP 压缩比超过安全限制。");
  }
  return content;
}

function readTarEntries(
  buffer: Buffer,
  limits: PackageReaderLimits,
): readonly TarEntry[] {
  if (buffer.byteLength % TAR_BLOCK_SIZE !== 0) {
    throw artifactError("HAR TAR 结构未按 512 字节块对齐。");
  }
  const entries: TarEntry[] = [];
  let offset = 0;
  let totalUncompressedBytes = 0;
  let foundEnd = false;
  const seenPaths = new Set<string>();
  while (offset < buffer.byteLength) {
    requireTarRange(buffer, offset, TAR_BLOCK_SIZE);
    const header = buffer.subarray(offset, offset + TAR_BLOCK_SIZE);
    if (isZeroBlock(header)) {
      requireTarRange(buffer, offset + TAR_BLOCK_SIZE, TAR_BLOCK_SIZE);
      const secondEndBlock = buffer.subarray(
        offset + TAR_BLOCK_SIZE,
        offset + TAR_BLOCK_SIZE * 2,
      );
      if (!isZeroBlock(secondEndBlock)) {
        throw artifactError("HAR TAR 结束块损坏。");
      }
      if (
        buffer.subarray(offset + TAR_BLOCK_SIZE * 2).some((byte) => byte !== 0)
      ) {
        throw artifactError("HAR TAR 结束块后包含非零数据。");
      }
      foundEnd = true;
      break;
    }
    validateTarChecksum(header);
    const path = readTarPath(header);
    if (seenPaths.has(path)) {
      throw artifactError("HAR TAR 包含归一化后重复的条目路径。");
    }
    seenPaths.add(path);
    const size = readTarOctal(header.subarray(124, 136), "size");
    const typeFlag = header[156] ?? 0;
    let type: TarEntry["type"];
    if (typeFlag === 0 || typeFlag === 0x30) {
      type = "file";
    } else if (typeFlag === 0x35) {
      type = "directory";
    } else if (typeFlag === 0x31 || typeFlag === 0x32) {
      throw artifactError("HAR TAR 不允许符号链接或硬链接条目。");
    } else {
      throw artifactError("HAR TAR 包含不支持的条目类型。");
    }
    if (entries.length + 1 > limits.maxEntries) {
      throw artifactError("HAR TAR 条目数量超过安全限制。");
    }
    if (size > limits.maxEntryBytes) {
      throw artifactError("HAR TAR 单条目大小超过安全限制。");
    }
    if (totalUncompressedBytes + size > limits.maxTotalUncompressedBytes) {
      throw artifactError("HAR TAR 条目总解压量超过安全限制。");
    }
    if (type === "directory" && size !== 0) {
      throw artifactError("HAR TAR 目录条目不能包含内容。");
    }
    const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
    if (!Number.isSafeInteger(paddedSize)) {
      throw artifactError("HAR TAR 条目大小无效。");
    }
    const contentOffset = offset + TAR_BLOCK_SIZE;
    requireTarRange(buffer, contentOffset, paddedSize);
    const contentEnd = contentOffset + size;
    if (
      buffer
        .subarray(contentEnd, contentOffset + paddedSize)
        .some((byte) => byte !== 0)
    ) {
      throw artifactError("HAR TAR 条目填充区域不是全零。");
    }
    entries.push({
      path,
      size,
      content: buffer.subarray(contentOffset, contentEnd),
      type,
    });
    totalUncompressedBytes += size;
    offset = contentOffset + paddedSize;
  }
  if (!foundEnd) {
    throw artifactError("HAR TAR 缺少标准结束块。");
  }
  return entries.sort((left, right) =>
    compareCodePoints(left.path, right.path),
  );
}

function validateTarChecksum(header: Buffer): void {
  const expected = readTarOctal(header.subarray(148, 156), "checksum");
  let actual = 0;
  for (let index = 0; index < header.byteLength; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : (header[index] ?? 0);
  }
  if (actual !== expected) {
    throw artifactError("HAR TAR 头部校验和不匹配。");
  }
}

function readTarOctal(field: Buffer, fieldName: string): number {
  let start = 0;
  let end = field.byteLength;
  while (start < end && field[start] === 0x20) start += 1;
  while (end > start && (field[end - 1] === 0 || field[end - 1] === 0x20)) {
    end -= 1;
  }
  if (start === end) return 0;
  const digits = field.subarray(start, end);
  if (digits.some((byte) => byte < 0x30 || byte > 0x37)) {
    throw artifactError(`HAR TAR ${fieldName} 不是有效八进制数。`);
  }
  const value = Number.parseInt(digits.toString("ascii"), 8);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw artifactError(`HAR TAR ${fieldName} 超出安全整数范围。`);
  }
  return value;
}

function readTarPath(header: Buffer): string {
  const name = readTarPathField(header.subarray(0, 100));
  if (name.byteLength === 0) {
    throw artifactError("HAR TAR 条目路径无效。");
  }
  const prefixEnd = header[475] === 0 ? 475 : 500;
  const prefix = readTarPathField(header.subarray(345, prefixEnd));
  const combined =
    prefix.byteLength === 0
      ? name
      : Buffer.concat([prefix, Buffer.from("/"), name]);
  return normalizeArchiveEntryName(combined);
}

function readTarPathField(field: Buffer): Buffer {
  const terminator = field.indexOf(0);
  if (terminator === -1) return field;
  if (field.subarray(terminator + 1).some((byte) => byte !== 0)) {
    throw artifactError("HAR TAR 路径包含嵌入 NUL 字节。");
  }
  return field.subarray(0, terminator);
}

function isZeroBlock(block: Buffer): boolean {
  return block.every((byte) => byte === 0);
}

function requireTarRange(buffer: Buffer, offset: number, length: number): void {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset + length > buffer.byteLength
  ) {
    throw artifactError("HAR TAR 结构越界或损坏。");
  }
}

function parseAppArchive(
  buffer: Buffer,
  sizeBytes: number,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): HarmonyPackageSnapshot {
  const entries = readCentralDirectory(
    buffer,
    limits,
    budget,
    APP_METADATA_PATHS,
  );
  const packEntries = entries.filter(({ path }) => path === "pack.info");
  const packEntry = packEntries.length === 1 ? packEntries[0] : undefined;
  const packInfo =
    packEntry === undefined
      ? undefined
      : readPackInfo(buffer, packEntry, limits, budget);
  const embeddedEntries = entries.filter(({ path }) =>
    /^[^/]+\.(?:hap|hsp)$/iu.test(path),
  );
  const parsedPackages = embeddedEntries.map((entry) => {
    const type: ModulePackageType = entry.path.toLowerCase().endsWith(".hsp")
      ? "hsp"
      : "hap";
    return {
      type,
      parsed: parseModuleArchive(
        readEntryContent(buffer, entry, limits, budget),
        type,
        limits,
        budget,
        `${entry.path}!/`,
      ),
    };
  });
  const modules = parsedPackages.flatMap(({ parsed }) => parsed.modules);
  const declaredBundleNames = parsedPackages.flatMap(({ type, parsed }) => {
    if (parsed.declaredBundleNames.length > 0) {
      return parsed.declaredBundleNames;
    }
    return type === "hap" && parsed.bundleName !== undefined
      ? [parsed.bundleName]
      : [];
  });
  const markerFiles = [
    ...entries
      .map(({ path }) => path)
      .filter((entryPath) => DEBUG_MARKER.test(entryPath)),
    ...parsedPackages.flatMap(({ parsed }) => parsed.markerFiles),
  ].sort(compareCodePoints);
  const issues: string[] = [];
  if (packEntries.length === 0) {
    issues.push("APP 中未发现有效的 pack.info 应用摘要。");
  } else if (packEntries.length > 1) {
    issues.push("APP 中的 pack.info 重复，无法确定唯一应用摘要。");
  } else if (packInfo === undefined) {
    issues.push("APP 中未发现有效的 pack.info 应用摘要。");
  }
  if (embeddedEntries.length === 0) {
    issues.push("APP 根目录未发现内嵌 HAP/HSP。");
  } else if (parsedPackages.some(({ parsed }) => parsed.issues.length > 0)) {
    issues.push("APP 内嵌 HAP/HSP 中存在不完整或不唯一的模块清单。");
  }
  const distinctBundleNames = [...new Set(declaredBundleNames)];
  if (distinctBundleNames.length > 1) {
    issues.push("APP 内嵌模块的 Bundle 声明互相冲突。");
  }
  if (
    packInfo !== undefined &&
    declaredBundleNames.some((bundleName) => bundleName !== packInfo.bundleName)
  ) {
    issues.push("APP pack.info 与内嵌模块的 Bundle 声明不一致。");
  }
  return createSnapshot("app", sizeBytes, {
    entries: toHarmonyPackageEntries(entries),
    modules,
    ...(packInfo === undefined
      ? {}
      : {
          bundleName: packInfo.bundleName,
          ...(packInfo.version === undefined
            ? {}
            : { version: packInfo.version }),
        }),
    markerFiles,
    issues,
  });
}

function createSnapshot(
  type: HarmonyPackageType,
  sizeBytes: number,
  parsed: Omit<ParsedModuleArchive, "declaredBundleNames">,
): HarmonyPackageSnapshot {
  const permissions = [
    ...new Set(
      parsed.modules.flatMap(({ requestPermissions }) => requestPermissions),
    ),
  ].sort(compareCodePoints);
  const enabledModules = parsed.modules
    .filter(({ debug }) => debug === true)
    .map(({ name }) => name)
    .sort(compareCodePoints);
  const snapshot: HarmonyPackageSnapshot = {
    schemaVersion: "1.0.0",
    artifact: { type, sizeBytes },
    entries: parsed.entries,
    modules: parsed.modules,
    ...(parsed.bundleName === undefined
      ? {}
      : { bundleName: parsed.bundleName }),
    ...(parsed.version === undefined ? {} : { version: parsed.version }),
    permissions,
    debug: {
      enabledModules,
      markerFiles: parsed.markerFiles,
    },
    completeness: parsed.issues.length === 0 ? "COMPLETE" : "INCOMPLETE",
    issues: parsed.issues,
  };
  return deepFreeze(snapshot);
}

function toHarmonyPackageEntries(
  entries: readonly ZipEntry[],
): readonly HarmonyPackageEntry[] {
  return entries.map((entry) => ({
    path: entry.path,
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize,
    compressionMethod: entry.compressionMethod === 0 ? "stored" : "deflated",
  }));
}

function readCentralDirectory(
  buffer: Buffer,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
  allowedDuplicatePaths?: ReadonlySet<string>,
): readonly ZipEntry[] {
  const eocdOffset = findEndOfCentralDirectory(buffer);
  if (
    eocdOffset >= 20 &&
    buffer.readUInt32LE(eocdOffset - 20) === ZIP64_LOCATOR_SIGNATURE
  ) {
    throw artifactError("ZIP64 产物暂不支持。");
  }
  const diskEntryCount = buffer.readUInt16LE(eocdOffset + 8);
  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  const centralSize = buffer.readUInt32LE(eocdOffset + 12);
  const centralOffset = buffer.readUInt32LE(eocdOffset + 16);
  if (
    diskEntryCount === ZIP64_ENTRY_COUNT_SENTINEL ||
    entryCount === ZIP64_ENTRY_COUNT_SENTINEL
  ) {
    throw artifactError("ZIP64 产物暂不支持。");
  }
  if (
    budget.entryCount + entryCount > limits.maxEntries ||
    centralSize === ZIP64_SENTINEL ||
    centralOffset === ZIP64_SENTINEL ||
    centralOffset + centralSize > buffer.length
  ) {
    throw artifactError("ZIP 中央目录超过安全限制。");
  }
  budget.entryCount += entryCount;
  const entries: ZipEntry[] = [];
  const seenPaths = new Set<string>();
  let offset = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    requireRange(buffer, offset, 46);
    if (buffer.readUInt32LE(offset) !== CENTRAL_SIGNATURE) {
      throw artifactError("ZIP 中央目录损坏。");
    }
    const generalPurposeFlag = buffer.readUInt16LE(offset + 8);
    if ((generalPurposeFlag & 1) !== 0) {
      throw artifactError("ZIP 加密条目不受支持。");
    }
    const compressionMethod = buffer.readUInt16LE(offset + 10);
    if (compressionMethod !== 0 && compressionMethod !== 8) {
      throw artifactError("ZIP 条目使用了不支持的压缩方法。");
    }
    const crc32 = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    if (
      compressedSize === ZIP64_SENTINEL ||
      uncompressedSize === ZIP64_SENTINEL ||
      localHeaderOffset === ZIP64_SENTINEL
    ) {
      throw artifactError("ZIP64 产物暂不支持。");
    }
    requireSafeEntryBudget(
      compressedSize,
      uncompressedSize,
      budget.totalUncompressedBytes,
      limits,
    );
    budget.totalUncompressedBytes += uncompressedSize;
    const nameStart = offset + 46;
    const nameEnd = nameStart + fileNameLength;
    requireRange(
      buffer,
      nameStart,
      fileNameLength + extraLength + commentLength,
    );
    const entryPath = normalizeArchiveEntryName(
      buffer.subarray(nameStart, nameEnd),
    );
    requireSafeZipExtraFields(buffer, nameEnd, extraLength);
    if (seenPaths.has(entryPath) && !allowedDuplicatePaths?.has(entryPath)) {
      throw artifactError("ZIP 包含归一化后重复的条目路径。");
    }
    seenPaths.add(entryPath);
    if (isSymlink(externalAttributes)) {
      throw artifactError("ZIP 条目不能是符号链接。");
    }
    const entry: ZipEntry = {
      path: entryPath,
      compressedSize,
      uncompressedSize,
      compressionMethod,
      generalPurposeFlag,
      crc32,
      localHeaderOffset,
      externalAttributes,
    };
    requireMatchingLocalHeader(buffer, entry);
    entries.push(entry);
    offset = nameEnd + extraLength + commentLength;
  }
  return entries.sort((left, right) =>
    compareCodePoints(left.path, right.path),
  );
}

function readModuleManifest(
  buffer: Buffer,
  entry: ZipEntry,
  sourcePrefix: string,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): {
  readonly metadata: HarmonyPackageModuleMetadata;
  readonly bundleName?: string;
  readonly version?: HarmonyPackageVersion;
} {
  return readModuleManifestContent(
    readEntryContent(buffer, entry, limits, budget),
    `${sourcePrefix}${entry.path}`,
  );
}

function readModuleManifestContent(
  content: Buffer,
  source: string,
): {
  readonly metadata: HarmonyPackageModuleMetadata;
  readonly bundleName?: string;
  readonly version?: HarmonyPackageVersion;
} {
  const raw = parseJson5(readUtf8Text(content), source);
  const root = asRecord(raw);
  const app = asRecord(root.app);
  const module = asRecord(root.module ?? root);
  const bundleName = readString(app.bundleName);
  const name = readString(module.name) ?? "unknown-module";
  const type = readString(module.type);
  const packageName = readString(module.packageName);
  const deviceTypes = readStringArray(module.deviceTypes);
  const requestPermissions = readPermissions(module.requestPermissions);
  const moduleDebug =
    typeof module.debug === "boolean" ? module.debug : undefined;
  const appDebug = typeof app.debug === "boolean" ? app.debug : undefined;
  const debug = moduleDebug ?? appDebug;
  const version = readVersion(app.versionCode, app.versionName);
  return {
    metadata: {
      name,
      ...(type === undefined ? {} : { type }),
      ...(packageName === undefined ? {} : { packageName }),
      deviceTypes,
      requestPermissions,
      ...(debug === undefined ? {} : { debug }),
      source,
    },
    ...(bundleName === undefined ? {} : { bundleName }),
    ...(version === undefined ? {} : { version }),
  };
}

function readPackInfo(
  buffer: Buffer,
  entry: ZipEntry,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): ParsedPackInfo | undefined {
  const text = readEntryText(buffer, entry, limits, budget);
  let raw: unknown;
  try {
    raw = parseJson5(text, entry.path);
  } catch (error) {
    if (error instanceof HCheckError && error.code === "ARTIFACT_PARSE_ERROR") {
      return undefined;
    }
    throw error;
  }
  const app = asRecord(asRecord(asRecord(raw).summary).app);
  const bundleName = readString(app.bundleName);
  if (bundleName === undefined) return undefined;
  const versionRecord = asRecord(app.version);
  const version = readVersion(versionRecord.code, versionRecord.name);
  return {
    bundleName,
    ...(version === undefined ? {} : { version }),
  };
}

function readEntryText(
  buffer: Buffer,
  entry: ZipEntry,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): string {
  return readUtf8Text(readEntryContent(buffer, entry, limits, budget));
}

function readUtf8Text(content: Buffer): string {
  try {
    return TEXT_DECODER.decode(content);
  } catch {
    throw artifactError("归档条目文本不是有效 UTF-8。");
  }
}

function requireSafeZipExtraFields(
  buffer: Buffer,
  offset: number,
  length: number,
): void {
  requireRange(buffer, offset, length);
  const end = offset + length;
  let fieldOffset = offset;
  while (fieldOffset < end) {
    if (end - fieldOffset < 4) {
      if (buffer.subarray(fieldOffset, end).every((byte) => byte === 0)) {
        return;
      }
      throw artifactError("ZIP extra field 损坏。");
    }
    const headerId = buffer.readUInt16LE(fieldOffset);
    const fieldLength = buffer.readUInt16LE(fieldOffset + 2);
    fieldOffset += 4;
    if (fieldOffset + fieldLength > end) {
      throw artifactError("ZIP extra field 损坏。");
    }
    if (headerId === ZIP64_EXTRA_FIELD_ID) {
      throw artifactError("ZIP64 产物暂不支持。");
    }
    fieldOffset += fieldLength;
  }
}

function requireMatchingLocalHeader(buffer: Buffer, entry: ZipEntry): void {
  const offset = entry.localHeaderOffset;
  requireRange(buffer, offset, 30);
  if (buffer.readUInt32LE(offset) !== LOCAL_SIGNATURE) {
    throw artifactError("ZIP 本地文件头损坏。");
  }
  const localGeneralPurposeFlag = buffer.readUInt16LE(offset + 6);
  if ((localGeneralPurposeFlag & 1) !== 0) {
    throw artifactError("ZIP 加密条目不受支持。");
  }
  const usesDataDescriptor = (entry.generalPurposeFlag & (1 << 3)) !== 0;
  if (((localGeneralPurposeFlag & (1 << 3)) !== 0) !== usesDataDescriptor) {
    throw artifactError(
      "ZIP 本地文件头与中央目录的 data descriptor bit3 不一致。",
    );
  }
  if (buffer.readUInt16LE(offset + 8) !== entry.compressionMethod) {
    throw artifactError("ZIP 本地文件头与中央目录的压缩方法不一致。");
  }
  const localCrc32 = buffer.readUInt32LE(offset + 14);
  const localCompressedSize = buffer.readUInt32LE(offset + 18);
  const localUncompressedSize = buffer.readUInt32LE(offset + 22);
  if (
    localCompressedSize === ZIP64_SENTINEL ||
    localUncompressedSize === ZIP64_SENTINEL
  ) {
    throw artifactError("ZIP64 产物暂不支持。");
  }
  if (usesDataDescriptor) {
    if (
      (localCrc32 !== 0 && localCrc32 !== entry.crc32) ||
      (localCompressedSize !== 0 &&
        localCompressedSize !== entry.compressedSize) ||
      (localUncompressedSize !== 0 &&
        localUncompressedSize !== entry.uncompressedSize)
    ) {
      throw artifactError(
        "ZIP data descriptor 条目的本地 CRC32 或大小与中央目录不一致。",
      );
    }
  } else if (
    localCrc32 !== entry.crc32 ||
    localCompressedSize !== entry.compressedSize ||
    localUncompressedSize !== entry.uncompressedSize
  ) {
    throw artifactError("ZIP 本地文件头的 CRC32 或大小与中央目录不一致。");
  }
  const fileNameLength = buffer.readUInt16LE(offset + 26);
  const extraLength = buffer.readUInt16LE(offset + 28);
  const nameStart = offset + 30;
  requireRange(buffer, nameStart, fileNameLength + extraLength);
  requireSafeZipExtraFields(buffer, nameStart + fileNameLength, extraLength);
  const path = normalizeArchiveEntryName(
    buffer.subarray(nameStart, nameStart + fileNameLength),
  );
  if (path !== entry.path) {
    throw artifactError("ZIP 本地文件头与中央目录的条目路径不一致。");
  }
}

function readEntryContent(
  buffer: Buffer,
  entry: ZipEntry,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): Buffer {
  const offset = entry.localHeaderOffset;
  requireMatchingLocalHeader(buffer, entry);
  const fileNameLength = buffer.readUInt16LE(offset + 26);
  const extraLength = buffer.readUInt16LE(offset + 28);
  const dataStart = offset + 30 + fileNameLength + extraLength;
  requireRange(buffer, dataStart, entry.compressedSize);
  const compressed = buffer.subarray(
    dataStart,
    dataStart + entry.compressedSize,
  );
  const content =
    entry.compressionMethod === 0
      ? compressed
      : inflateEntry(
          compressed,
          maximumInflatedEntryBytes(entry, limits, budget),
        );
  if (content.byteLength !== entry.uncompressedSize) {
    throw artifactError("ZIP 条目大小与中央目录不一致。");
  }
  return content;
}

function inflateEntry(content: Buffer, maxOutputLength: number): Buffer {
  try {
    return inflateRawSync(content, { maxOutputLength });
  } catch {
    throw artifactError("ZIP 条目解压失败或超过安全上限。");
  }
}

function maximumInflatedEntryBytes(
  entry: ZipEntry,
  limits: PackageReaderLimits,
  budget: ArchiveBudget,
): number {
  const remainingTotal =
    limits.maxTotalUncompressedBytes -
    (budget.totalUncompressedBytes - entry.uncompressedSize);
  const maximum = Math.floor(
    Math.min(entry.uncompressedSize, limits.maxEntryBytes, remainingTotal),
  );
  if (!Number.isSafeInteger(maximum) || maximum < 0) {
    throw artifactError("ZIP 条目解压上限无效。");
  }
  return Math.max(1, maximum);
}

function findEndOfCentralDirectory(buffer: Buffer): number {
  const minimum = Math.max(0, buffer.length - (0xffff + 22));
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) === EOCD_SIGNATURE) return offset;
  }
  throw artifactError("产物不是有效 ZIP。");
}

function requireSafeEntryBudget(
  compressedSize: number,
  uncompressedSize: number,
  totalUncompressed: number,
  limits: PackageReaderLimits,
): void {
  if (
    uncompressedSize > limits.maxEntryBytes ||
    totalUncompressed + uncompressedSize > limits.maxTotalUncompressedBytes
  ) {
    throw artifactError("ZIP 条目超过安全解包上限。");
  }
  if (compressedSize === 0 && uncompressedSize > 0) {
    throw artifactError("ZIP 条目压缩大小异常。");
  }
  if (
    compressedSize > 0 &&
    uncompressedSize / compressedSize > limits.maxCompressionRatio
  ) {
    throw artifactError("ZIP 条目压缩比异常。");
  }
}

function normalizeArchiveEntryName(nameBytes: Buffer): string {
  let name: string;
  try {
    name = TEXT_DECODER.decode(nameBytes);
  } catch {
    throw artifactError("归档条目名称不是有效 UTF-8。");
  }
  if (name.length === 0) {
    throw artifactError("归档条目路径无效。");
  }
  if (name.includes("\0")) {
    throw artifactError("归档条目路径不能包含 NUL 字节。");
  }
  if (name.includes("\\")) {
    throw artifactError("归档条目路径不能包含反斜线。");
  }
  const normalized = name.replace(/\/{2,}/gu, "/");
  if (
    normalized.startsWith("/") ||
    normalized.startsWith("//") ||
    /^[A-Za-z]:/u.test(normalized)
  ) {
    throw artifactError("归档条目不能使用绝对路径。");
  }
  const parts = normalized.split("/").filter((part) => part.length > 0);
  if (
    parts.length === 0 ||
    parts.some((part) => part === "." || part === "..")
  ) {
    throw artifactError("归档条目不能越界。");
  }
  return normalized.endsWith("/") ? `${parts.join("/")}/` : parts.join("/");
}

function packageType(file: string): HarmonyPackageType {
  const lower = file.toLowerCase();
  if (lower.endsWith(".app")) return "app";
  if (lower.endsWith(".hap")) return "hap";
  if (lower.endsWith(".hsp")) return "hsp";
  if (lower.endsWith(".har")) return "har";
  throw artifactError("仅支持 APP/HAP/HSP/HAR 产物。");
}

function requireRange(buffer: Buffer, offset: number, length: number): void {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset + length > buffer.length
  ) {
    throw artifactError("ZIP 结构越界或损坏。");
  }
}

function isSymlink(externalAttributes: number): boolean {
  return ((externalAttributes >>> 16) & 0o170000) === 0o120000;
}

function readPermissions(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  const names = value
    .map((item) => readString(asRecord(item).name))
    .filter((name): name is string => name !== undefined);
  return [...new Set(names)].sort(compareCodePoints);
}

function readStringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(readString)
    .filter((item): item is string => item !== undefined)
    .sort(compareCodePoints);
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readVersion(
  codeValue: unknown,
  nameValue: unknown,
): HarmonyPackageVersion | undefined {
  const code =
    typeof codeValue === "number" && Number.isSafeInteger(codeValue)
      ? codeValue
      : undefined;
  const name = readString(nameValue);
  if (code === undefined && name === undefined) return undefined;
  return {
    ...(code === undefined ? {} : { code }),
    ...(name === undefined ? {} : { name }),
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function artifactError(message: string): HCheckError {
  return new HCheckError("ARTIFACT_PARSE_ERROR", message);
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}
