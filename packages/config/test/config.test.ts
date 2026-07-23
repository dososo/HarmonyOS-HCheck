import assert from "node:assert/strict";
import { mkdtemp, mkdir, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { HCheckError } from "@hcheck/core";
import {
  DEFAULT_CONFIG,
  MAX_CONFIG_BYTES,
  loadConfig,
  summarizeConfig,
  type HCheckConfig,
  type ScanConfig,
} from "../src/index.js";

async function withProject(
  run: (projectRoot: string) => Promise<void>,
): Promise<void> {
  const projectRoot = await mkdtemp(join(tmpdir(), "hcheck-config-"));
  try {
    await run(projectRoot);
  } finally {
    await removeIfPresent(join(projectRoot, ".hcheck.yml"), unlink);
    await removeIfPresent(join(projectRoot, "config", "release.yml"), unlink);
    await removeIfPresent(join(projectRoot, "config"), rmdir);
    await rmdir(projectRoot);
  }
}

async function removeIfPresent(
  path: string,
  remove: (path: string) => Promise<void>,
): Promise<void> {
  try {
    await remove(path);
  } catch (error: unknown) {
    if (
      typeof error !== "object" ||
      error === null ||
      !("code" in error) ||
      error.code !== "ENOENT"
    ) {
      throw error;
    }
  }
}

function assertConfigurationError(error: unknown): error is HCheckError {
  assert.ok(error instanceof HCheckError);
  assert.equal(error.code, "CONFIGURATION_ERROR");
  return true;
}

test("无配置文件时返回内置默认配置的独立副本", async () => {
  await withProject(async (projectRoot) => {
    const first = await loadConfig({ projectRoot, environment: {} });
    const second = await loadConfig({ projectRoot, environment: {} });

    assert.deepEqual(first, DEFAULT_CONFIG);
    assert.deepEqual(second, DEFAULT_CONFIG);
    assert.notEqual(first, DEFAULT_CONFIG);
    assert.notEqual(first.scan.exclude.paths, second.scan.exclude.paths);
  });
});

test("按仓库、显式文件、环境变量、CLI 的顺序覆盖配置", async () => {
  await withProject(async (projectRoot) => {
    await writeFile(
      join(projectRoot, ".hcheck.yml"),
      [
        "version: 1",
        "build:",
        "  profile: repository",
        "scan:",
        "  fail_on: high",
        "  minimum_confidence: possible",
        "",
      ].join("\n"),
    );
    await mkdir(join(projectRoot, "config"));
    await writeFile(
      join(projectRoot, "config", "release.yml"),
      [
        "version: 1",
        "build:",
        "  profile: explicit",
        "scan:",
        "  fail_on: medium",
        "",
      ].join("\n"),
    );

    const config = await loadConfig({
      projectRoot,
      explicitConfig: "config/release.yml",
      environment: {
        HCHECK_FAIL_ON: "low",
        HCHECK_MINIMUM_CONFIDENCE: "manual",
      },
      cli: { fail_on: "none" },
    });

    assert.equal(config.build.profile, "explicit");
    assert.equal(config.scan.fail_on, "none");
    assert.equal(config.scan.minimum_confidence, "manual");
  });
});

test("高优先级数组整体替换而不是与低优先级数组拼接", async () => {
  await withProject(async (projectRoot) => {
    await writeFile(
      join(projectRoot, ".hcheck.yml"),
      [
        "version: 1",
        "scan:",
        "  exclude:",
        "    paths:",
        "      - repository/**",
        "    rules:",
        "      - HOS-META-003",
        "",
      ].join("\n"),
    );

    const config = await loadConfig({
      projectRoot,
      environment: {},
      cli: {
        exclude: {
          paths: ["cli/**"],
          rules: [],
        },
      },
    });

    assert.deepEqual(config.scan.exclude.paths, ["cli/**"]);
    assert.deepEqual(config.scan.exclude.rules, []);
  });
});

test("未知配置字段由 JSON Schema 拒绝", async () => {
  await withProject(async (projectRoot) => {
    await writeFile(
      join(projectRoot, ".hcheck.yml"),
      "version: 1\nunknown_secret: should-not-appear\n",
    );

    await assert.rejects(
      loadConfig({ projectRoot, environment: {} }),
      assertConfigurationError,
    );
  });
});

test("损坏 YAML 统一映射为不泄露原文的配置错误", async () => {
  await withProject(async (projectRoot) => {
    const secret = "top-secret-yaml-value";
    await writeFile(
      join(projectRoot, ".hcheck.yml"),
      `version: 1\nagc: [${secret}\n`,
    );

    await assert.rejects(
      loadConfig({ projectRoot, environment: {} }),
      (error: unknown) => {
        assertConfigurationError(error);
        assert.ok(!error.message.includes(secret));
        assert.ok(!JSON.stringify(error.details).includes(secret));
        return true;
      },
    );
  });
});

test("默认与显式配置在 YAML 解析前拒绝超过 1MiB 的文件", async () => {
  await withProject(async (projectRoot) => {
    const oversized = Buffer.alloc(MAX_CONFIG_BYTES + 1, 97);
    await writeFile(join(projectRoot, ".hcheck.yml"), oversized);
    await assert.rejects(
      loadConfig({ projectRoot, environment: {} }),
      assertConfigurationError,
    );

    await unlink(join(projectRoot, ".hcheck.yml"));
    await mkdir(join(projectRoot, "config"));
    await writeFile(join(projectRoot, "config", "release.yml"), oversized);
    await assert.rejects(
      loadConfig({
        projectRoot,
        explicitConfig: "config/release.yml",
        environment: {},
      }),
      assertConfigurationError,
    );
  });
});

test("环境变量只接受白名单中的无秘密覆盖", async () => {
  await withProject(async (projectRoot) => {
    const secret = "environment-secret-value";
    const config = await loadConfig({
      projectRoot,
      environment: {
        HCHECK_FAIL_ON: "high",
        HCHECK_AGC_CLIENT_SECRET: secret,
        HCHECK_UNKNOWN: "low",
      },
    });

    assert.equal(config.scan.fail_on, "high");
    assert.equal(config.agc.client_secret_env, "HCHECK_AGC_CLIENT_SECRET");
    assert.ok(!JSON.stringify(config).includes(secret));
  });
});

test("非法环境变量值不出现在错误消息或详情中", async () => {
  await withProject(async (projectRoot) => {
    const secret = "invalid-secret-environment-value";

    await assert.rejects(
      loadConfig({
        projectRoot,
        environment: { HCHECK_FAIL_ON: secret },
      }),
      (error: unknown) => {
        assertConfigurationError(error);
        assert.ok(!error.message.includes(secret));
        assert.ok(!JSON.stringify(error.details).includes(secret));
        return true;
      },
    );
  });
});

test("配置摘要脱敏绝对工程根路径并规范化相对路径", () => {
  const absoluteRoot = "/Users/sensitive-user/private-project";
  const absoluteConfig: HCheckConfig = {
    ...structuredClone(DEFAULT_CONFIG),
    project: { ...DEFAULT_CONFIG.project, root: absoluteRoot },
  };
  const relativeConfig: HCheckConfig = {
    ...structuredClone(DEFAULT_CONFIG),
    project: { ...DEFAULT_CONFIG.project, root: "./apps\\demo" },
  };

  const absoluteSummary = summarizeConfig(absoluteConfig);
  const serialized = JSON.stringify(absoluteSummary);

  assert.equal(absoluteSummary.project.root, "<PROJECT_ROOT>");
  assert.ok(!serialized.includes(absoluteRoot));
  assert.ok(!serialized.includes("sensitive-user"));
  assert.equal(summarizeConfig(relativeConfig).project.root, "apps/demo");
});

test("配置加载在合并前拒绝危险对象键且不回显载荷", async () => {
  await withProject(async (projectRoot) => {
    for (const dangerousKey of ["__proto__", "constructor", "prototype"]) {
      const secret = `secret-${dangerousKey}-payload`;
      await writeFile(
        join(projectRoot, ".hcheck.yml"),
        `version: 1\n${dangerousKey}:\n  polluted: ${secret}\n`,
      );

      await assert.rejects(
        loadConfig({ projectRoot, environment: {} }),
        (error: unknown) => {
          assertConfigurationError(error);
          assert.equal(error.message, "HCheck 配置包含不允许的对象键。");
          assert.ok(!error.message.includes(secret));
          assert.ok(!JSON.stringify(error.details).includes(secret));
          return true;
        },
      );
    }
  });
});

test("循环 YAML alias 统一映射为不泄露内容的配置错误", async () => {
  await withProject(async (projectRoot) => {
    const secret = "cyclic-alias-secret-payload";
    await writeFile(
      join(projectRoot, ".hcheck.yml"),
      `version: 1\nloop: &loop\n  value: ${secret}\n  self: *loop\n`,
    );

    await assert.rejects(
      loadConfig({ projectRoot, environment: {} }),
      (error: unknown) => {
        assertConfigurationError(error);
        assert.ok(!error.message.includes(secret));
        assert.ok(!JSON.stringify(error.details).includes(secret));
        return true;
      },
    );
  });
});

test("循环 CLI 覆盖统一映射为不泄露内容的配置错误", async () => {
  await withProject(async (projectRoot) => {
    const secret = "cyclic-cli-secret-payload";
    const cyclicCli: Record<string, unknown> = { secret };
    cyclicCli.self = cyclicCli;

    await assert.rejects(
      loadConfig({
        projectRoot,
        environment: {},
        cli: cyclicCli as Partial<ScanConfig>,
      }),
      (error: unknown) => {
        assertConfigurationError(error);
        assert.ok(!error.message.includes(secret));
        assert.ok(!JSON.stringify(error.details).includes(secret));
        return true;
      },
    );
  });
});

test("有效配置摘要只显示秘密环境变量引用名而不读取值", () => {
  const config: HCheckConfig = {
    ...structuredClone(DEFAULT_CONFIG),
    agc: {
      ...DEFAULT_CONFIG.agc,
      app_id_env: "PRIVATE_APP_ID_REFERENCE",
      client_id_env: "PRIVATE_CLIENT_ID_REFERENCE",
      client_secret_env: "PRIVATE_SECRET_REFERENCE",
    },
  };
  process.env.PRIVATE_SECRET_REFERENCE = "must-not-leak";

  try {
    const summary = summarizeConfig(config);
    const serialized = JSON.stringify(summary);

    assert.deepEqual(summary.environmentReferences, [
      "PRIVATE_APP_ID_REFERENCE",
      "PRIVATE_CLIENT_ID_REFERENCE",
      "PRIVATE_SECRET_REFERENCE",
    ]);
    assert.ok(!serialized.includes("must-not-leak"));
    assert.ok(!serialized.includes("client_secret_env"));
  } finally {
    delete process.env.PRIVATE_SECRET_REFERENCE;
  }
});

test("仓库示例配置通过加载和 Schema 校验", async () => {
  const repositoryRoot = join(import.meta.dirname, "../../..");
  const config = await loadConfig({
    projectRoot: repositoryRoot,
    explicitConfig: "examples/hcheck.yml",
    environment: {},
  });

  assert.equal(config.version, 1);
  assert.equal(config.project.platform, "harmonyos");
  assert.deepEqual(config.report.formats, ["terminal", "json"]);
});
