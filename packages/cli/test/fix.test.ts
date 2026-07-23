import assert from "node:assert/strict";
import { mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildAgentJsonReport } from "@hcheck/agent-protocol";
import type { Finding } from "@hcheck/core";
import { runFix } from "../src/fix.js";
import { NodeFileSystem } from "../src/infrastructure/node-filesystem.js";

const A = "a".repeat(64);

const finding = (): Finding => ({
  schemaVersion: "1.0.0",
  id: `finding:${A}`,
  ruleId: "HOS-PERM-001",
  ruleVersion: "1.0.0",
  title: "缺少权限声明",
  severity: "HIGH",
  confidence: "PROBABLE",
  applicability: "APPLICABLE",
  fingerprint: `sha256:${A}`,
  message: "API 调用缺少对应权限声明。",
  locations: [{ uri: "entry/src/main/module.json5", line: 8 }],
  evidenceIds: [`evidence:${A}`],
  remediation: {
    summary: "补充 requestPermissions 声明",
    verification: "重新执行扫描",
  },
  autofix: "allowed",
  status: "new",
});

test("fix dry-run 从 Agent JSON 输出可审计安全修复计划", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "hcheck-fix-"));
  const file = path.join(directory, "agent.json");
  try {
    await writeFile(
      file,
      JSON.stringify(
        buildAgentJsonReport({
          run: {
            id: "run-fix",
            hcheckVersion: "0.6.0",
            completeness: "COMPLETE",
            gate: "FAIL",
          },
          findings: [finding()],
          allowedPaths: ["entry/src/main/module.json5"],
          forbiddenPaths: ["build", "oh_modules"],
          verificationCommands: ["pnpm check"],
        }),
      ),
    );

    let stdout = "",
      stderr = "";
    const code = await runFix(["fix", "--from-agent-json", file, "--dry-run"], {
      fs: new NodeFileSystem(),
      stdout: (value) => {
        stdout += value;
      },
      stderr: (value) => {
        stderr += value;
      },
    });
    const plan = JSON.parse(stdout) as {
      mode: string;
      actions: readonly {
        findingId: string;
        ruleId: string;
        targetPath: string;
        status: string;
      }[];
      blockedActions: readonly unknown[];
      audit: { rescanRequired: boolean; canMarkFixedWithoutRescan: boolean };
    };

    assert.equal(code, 0);
    assert.equal(stderr, "");
    assert.equal(plan.mode, "dry-run");
    assert.deepEqual(
      plan.actions.map(({ findingId, ruleId, targetPath, status }) => ({
        findingId,
        ruleId,
        targetPath,
        status,
      })),
      [
        {
          findingId: `finding:${A}`,
          ruleId: "HOS-PERM-001",
          targetPath: "entry/src/main/module.json5",
          status: "executable",
        },
      ],
    );
    assert.deepEqual(plan.blockedActions, []);
    assert.equal(plan.audit.rescanRequired, true);
    assert.equal(plan.audit.canMarkFixedWithoutRescan, false);
  } finally {
    await unlink(file);
    await rmdir(directory);
  }
});

test("fix 拒绝非 dry-run 执行，P2 不直接改写源码", async () => {
  let stdout = "",
    stderr = "";
  const code = await runFix(["fix", "--from-agent-json", "agent.json"], {
    fs: new NodeFileSystem(),
    stdout: (value) => {
      stdout += value;
    },
    stderr: (value) => {
      stderr += value;
    },
  });

  assert.equal(code, 3);
  assert.equal(stdout, "");
  assert.match(stderr, /P2 仅支持 --dry-run/u);
});
