import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, join, posix, win32 } from "node:path";
import { HCheckError, normalizeRelativeUri } from "@hcheck/core";
import {
  Ajv2020,
  type ErrorObject,
  type ValidateFunction,
} from "ajv/dist/2020.js";
import { parse } from "yaml";

export type FailOn = "blocker" | "high" | "medium" | "low" | "none";
export type MinimumConfidence =
  "confirmed" | "probable" | "possible" | "manual";

export interface ScanModeConfig {
  readonly build?: boolean;
  readonly package?: boolean;
  readonly agc?: boolean;
  readonly runtime?: boolean;
}

export interface ScanConfig {
  readonly modes: Readonly<Record<string, ScanModeConfig>>;
  readonly exclude: {
    readonly paths: readonly string[];
    readonly rules: readonly string[];
  };
  readonly fail_on: FailOn;
  readonly minimum_confidence: MinimumConfidence;
}

export interface HCheckConfig {
  readonly version: 1;
  readonly project: {
    readonly root: string;
    readonly app_scope: string;
    readonly modules: readonly string[];
    readonly platform: "harmonyos";
    readonly minimum_api: number;
  };
  readonly build: {
    readonly profile: string;
    readonly clean: boolean;
    readonly command: string;
    readonly artifact: {
      readonly include: readonly string[];
      readonly exclude: readonly string[];
    };
  };
  readonly scan: ScanConfig;
  readonly policy: {
    readonly rulesets: readonly string[];
    readonly fail_on: FailOn;
    readonly minimum_confidence: MinimumConfidence;
  };
  readonly agc: {
    readonly enabled: boolean;
    readonly read_only: true;
    readonly app_id_env: string;
    readonly client_id_env: string;
    readonly client_secret_env: string;
    readonly cache_ttl_hours: number;
  };
  readonly privacy: {
    readonly consent_state_keys: readonly string[];
    readonly policy_files: readonly string[];
    readonly sdk_manifest: readonly string[];
  };
  readonly runtime: {
    readonly device: string;
    readonly reset_before_run: boolean;
    readonly record_video: "always" | "on_failure" | "never";
    readonly capture_screenshot: "each_assertion" | "on_failure" | "never";
    readonly redact_logs: boolean;
    readonly upload_source: false;
    readonly upload_package: "never" | "confirm" | "always";
  };
  readonly baseline: {
    readonly path: string;
    readonly fail_only_new: boolean;
    readonly suppressions: string;
  };
  readonly report: {
    readonly formats: readonly (
      "terminal" | "json" | "sarif" | "junit" | "html" | "agent-json"
    )[];
    readonly directory: string;
    readonly include_absolute_paths: false;
  };
}

export interface LoadConfigOptions {
  readonly projectRoot: string;
  readonly explicitConfig?: string;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly cli?: Readonly<Partial<ScanConfig>>;
  readonly textReader?: ConfigTextReader;
}

export interface ConfigTextReader {
  readText(path: string, maximumBytes: number): Promise<string>;
}

export const MAX_CONFIG_BYTES = 1024 * 1024;

export interface EffectiveConfigSummary {
  readonly version: 1;
  readonly project: {
    readonly root: string;
    readonly platform: "harmonyos";
    readonly modules: readonly string[];
  };
  readonly scan: {
    readonly fail_on: FailOn;
    readonly minimum_confidence: MinimumConfidence;
    readonly excludedPaths: readonly string[];
    readonly excludedRules: readonly string[];
  };
  readonly environmentReferences: readonly string[];
}

const DEFAULT_CONFIG_VALUE: HCheckConfig = {
  version: 1,
  project: {
    root: ".",
    app_scope: "AppScope",
    modules: [],
    platform: "harmonyos",
    minimum_api: 12,
  },
  build: {
    profile: "release",
    clean: true,
    command: "./hvigorw assembleApp",
    artifact: {
      include: ["**/*.app", "**/*.hap"],
      exclude: [],
    },
  },
  scan: {
    modes: {
      quick: { build: false, package: false, agc: false, runtime: false },
      release: { build: true, package: true, agc: false, runtime: false },
      submit: { build: true, package: true, agc: true, runtime: true },
    },
    exclude: {
      paths: ["node_modules/**", "oh_modules/**", "build/**"],
      rules: [],
    },
    fail_on: "blocker",
    minimum_confidence: "probable",
  },
  policy: {
    rulesets: ["harmonyos-release-readiness"],
    fail_on: "blocker",
    minimum_confidence: "probable",
  },
  agc: {
    enabled: false,
    read_only: true,
    app_id_env: "HCHECK_AGC_APP_ID",
    client_id_env: "HCHECK_AGC_CLIENT_ID",
    client_secret_env: "HCHECK_AGC_CLIENT_SECRET",
    cache_ttl_hours: 24,
  },
  privacy: {
    consent_state_keys: ["privacyAccepted", "userConsent"],
    policy_files: ["docs/privacy-policy.md"],
    sdk_manifest: ["docs/third-party-sdk.yml"],
  },
  runtime: {
    device: "local",
    reset_before_run: true,
    record_video: "on_failure",
    capture_screenshot: "each_assertion",
    redact_logs: true,
    upload_source: false,
    upload_package: "never",
  },
  baseline: {
    path: ".hcheck/baseline.json",
    fail_only_new: true,
    suppressions: ".hcheck/suppressions.json",
  },
  report: {
    formats: ["terminal", "json"],
    directory: ".hcheck/reports",
    include_absolute_paths: false,
  },
};

function deepFreeze<T>(value: T): Readonly<T> {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const nested of Object.values(value)) {
      deepFreeze(nested);
    }
  }
  return value;
}

export const DEFAULT_CONFIG: HCheckConfig = deepFreeze(DEFAULT_CONFIG_VALUE);

const schemaUrl = new URL(
  "../../../schemas/hcheck-config.schema.json",
  import.meta.url,
);
const UTF8 = new TextDecoder("utf-8", { fatal: true });

async function boundedNodeRead(
  path: string | URL,
  maximumBytes: number,
): Promise<string> {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > maximumBytes)
    throw new Error("unsafe config file");
  const handle = await open(
    path,
    constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
  );
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() ||
      opened.size !== before.size ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    )
      throw new Error("changed config file");
    const buffer = Buffer.allocUnsafe(maximumBytes + 1);
    let total = 0;
    while (total <= maximumBytes) {
      const { bytesRead } = await handle.read(
        buffer,
        total,
        maximumBytes + 1 - total,
        null,
      );
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    const after = await handle.stat();
    if (total > maximumBytes || after.size !== opened.size)
      throw new Error("oversized config file");
    return UTF8.decode(buffer.subarray(0, total));
  } finally {
    await handle.close();
  }
}

const defaultTextReader: ConfigTextReader = { readText: boundedNodeRead };
const schema = JSON.parse(
  await boundedNodeRead(schemaUrl, MAX_CONFIG_BYTES),
) as object;
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateConfig: ValidateFunction<HCheckConfig> =
  ajv.compile<HCheckConfig>(schema);

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function mergeConfig(lower: unknown, higher: unknown): unknown {
  if (higher === undefined) {
    return structuredClone(lower);
  }
  if (Array.isArray(higher)) {
    return structuredClone(higher);
  }
  if (isRecord(lower) && isRecord(higher)) {
    const merged: Record<string, unknown> = structuredClone(lower);
    for (const [key, value] of Object.entries(higher)) {
      if (value !== undefined) {
        merged[key] = mergeConfig(merged[key], value);
      }
    }
    return merged;
  }
  return structuredClone(higher);
}

function configurationError(message: string): HCheckError {
  return new HCheckError("CONFIGURATION_ERROR", message);
}

const dangerousObjectKeys: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

function assertSafeObjectKeys(
  value: unknown,
  ancestors: WeakSet<object> = new WeakSet(),
): void {
  if (typeof value !== "object" || value === null) {
    return;
  }
  if (ancestors.has(value)) {
    throw configurationError("HCheck 配置不能包含循环引用。");
  }

  ancestors.add(value);
  if (Array.isArray(value)) {
    for (const item of value) {
      assertSafeObjectKeys(item, ancestors);
    }
  } else {
    for (const [key, nested] of Object.entries(value)) {
      if (dangerousObjectKeys.has(key)) {
        throw configurationError("HCheck 配置包含不允许的对象键。");
      }
      assertSafeObjectKeys(nested, ancestors);
    }
  }
  ancestors.delete(value);
}

async function readYamlConfig(
  path: string,
  required: boolean,
  reader: ConfigTextReader,
): Promise<unknown> {
  let text: string;
  try {
    text = await reader.readText(path, MAX_CONFIG_BYTES);
  } catch (error: unknown) {
    if (
      !required &&
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return {};
    }
    throw configurationError("无法读取 HCheck 配置文件。");
  }

  let parsed: unknown;
  try {
    parsed = parse(text, { maxAliasCount: 0, uniqueKeys: true });
  } catch {
    throw configurationError("HCheck 配置文件不是有效的 YAML。");
  }
  assertSafeObjectKeys(parsed);
  return parsed ?? {};
}

function environmentOverrides(
  environment: Readonly<Record<string, string | undefined>>,
): unknown {
  const scan: Record<string, unknown> = {};
  if (environment.HCHECK_FAIL_ON !== undefined) {
    scan.fail_on = environment.HCHECK_FAIL_ON;
  }
  if (environment.HCHECK_MINIMUM_CONFIDENCE !== undefined) {
    scan.minimum_confidence = environment.HCHECK_MINIMUM_CONFIDENCE;
  }
  return Object.keys(scan).length === 0 ? {} : { scan };
}

function validationError(
  errors: readonly ErrorObject[] | null | undefined,
): HCheckError {
  const first = errors?.[0];
  const location = first?.instancePath === "" ? "/" : first?.instancePath;
  const suffix = location === undefined ? "" : `（位置：${location}）`;
  return configurationError(`HCheck 配置不符合 Schema${suffix}。`);
}

export async function loadConfig(
  options: LoadConfigOptions,
): Promise<HCheckConfig> {
  const repositoryConfig = await readYamlConfig(
    join(options.projectRoot, ".hcheck.yml"),
    false,
    options.textReader ?? defaultTextReader,
  );
  let merged: unknown = mergeConfig(DEFAULT_CONFIG, repositoryConfig);

  if (options.explicitConfig !== undefined) {
    const explicitPath = isAbsolute(options.explicitConfig)
      ? options.explicitConfig
      : join(options.projectRoot, options.explicitConfig);
    merged = mergeConfig(
      merged,
      await readYamlConfig(
        explicitPath,
        true,
        options.textReader ?? defaultTextReader,
      ),
    );
  }

  merged = mergeConfig(
    merged,
    environmentOverrides(options.environment ?? process.env),
  );
  if (options.cli !== undefined) {
    assertSafeObjectKeys(options.cli);
    merged = mergeConfig(merged, { scan: options.cli });
  }

  if (!validateConfig(merged)) {
    throw validationError(validateConfig.errors);
  }
  return structuredClone(merged);
}

export function summarizeConfig(config: HCheckConfig): EffectiveConfigSummary {
  const environmentReferences = [
    config.agc.app_id_env,
    config.agc.client_id_env,
    config.agc.client_secret_env,
  ].filter((value, index, values) => values.indexOf(value) === index);

  return {
    version: config.version,
    project: {
      root:
        posix.isAbsolute(config.project.root) ||
        win32.isAbsolute(config.project.root)
          ? "<PROJECT_ROOT>"
          : normalizeRelativeUri(config.project.root),
      platform: config.project.platform,
      modules: [...config.project.modules],
    },
    scan: {
      fail_on: config.scan.fail_on,
      minimum_confidence: config.scan.minimum_confidence,
      excludedPaths: [...config.scan.exclude.paths],
      excludedRules: [...config.scan.exclude.rules],
    },
    environmentReferences,
  };
}
