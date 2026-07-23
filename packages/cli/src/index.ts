#!/usr/bin/env node

import path from "node:path";
import { fileURLToPath } from "node:url";
import { runBaseline } from "./baseline.js";
import { runDoctor } from "./doctor.js";
import { runExplain } from "./explain.js";
import { runFix } from "./fix.js";
import { NodeFileSystem } from "./infrastructure/node-filesystem.js";
import { NodeHash } from "./infrastructure/node-hash.js";
import { NodeProcessRunner } from "./infrastructure/node-process-runner.js";
import { runPackageInspect } from "./package-inspect.js";
import { RandomRunId } from "./infrastructure/random-run-id.js";
import { SystemClock } from "./infrastructure/system-clock.js";
import { runScan } from "./scan.js";
import { runVerify, type VerifyPorts } from "./verify.js";
import { HCHECK_VERSION } from "./version.js";

export { HCHECK_VERSION } from "./version.js";

export interface MainDependencies {
  /** 仅供本地 FakeRunner 测试注入；默认 CLI 不创建 verify run 的进程运行器。 */
  readonly verify?: VerifyPorts;
}

function printHelp(): void {
  console.log(`鸿鉴 HCheck ${HCHECK_VERSION}

用法：
  hcheck --help
  hcheck --version

可用命令：
  hcheck scan <目录> [--mode quick] [--format terminal|json|sarif|junit]
    [--config <文件>] [--fail-on <级别>] [--confidence <级别>]
    [--baseline <文件>] [--suppressions <文件>] [--rules <规则ID,规则ID>]
  hcheck baseline create <目录> [--format json] [--reference <名称>]
    [--config <文件>] [--rules <规则ID,规则ID>]
  hcheck package inspect <产物> [--format terminal|json]
  hcheck doctor [目录] [--format terminal|json]
  hcheck explain <规则ID> [--format terminal|json]
  hcheck fix --from-agent-json <文件> --dry-run [--allow-rule <规则ID>]
  hcheck verify replay <manifest.json> [--format terminal|json]
  hcheck verify run <参数> --dry-run|--preflight-only|--confirm-device-actions

后续目标命令（尚未实现）：
  hcheck init
  hcheck privacy compare
  hcheck agc compare

本仓库当前是开发基线，不应被用于正式发布裁决。`);
}

export async function main(
  args: readonly string[],
  dependencies: MainDependencies = {},
): Promise<number> {
  if (args.length === 1 && (args[0] === "--version" || args[0] === "-v")) {
    console.log(HCHECK_VERSION);
    return 0;
  }
  if (
    args.length === 0 ||
    (args.length === 1 && (args[0] === "--help" || args[0] === "-h"))
  ) {
    printHelp();
    return 0;
  }

  if (args[0] === "scan") {
    return runScan(args, {
      fs: new NodeFileSystem(),
      hash: new NodeHash(),
      clock: new SystemClock(),
      runId: new RandomRunId(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
    });
  }
  if (args[0] === "baseline") {
    return runBaseline(args, {
      fs: new NodeFileSystem(),
      hash: new NodeHash(),
      clock: new SystemClock(),
      runId: new RandomRunId(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
    });
  }
  if (args[0] === "doctor") {
    return runDoctor(args, {
      fs: new NodeFileSystem(),
      runner: new NodeProcessRunner(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
      environment: process.env,
    });
  }
  if (args[0] === "explain") {
    return runExplain(args, {
      fs: new NodeFileSystem(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
    });
  }
  if (args[0] === "package") {
    return runPackageInspect(args, {
      fs: new NodeFileSystem(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
    });
  }
  if (args[0] === "fix") {
    return runFix(args, {
      fs: new NodeFileSystem(),
      stdout: (text) => process.stdout.write(text),
      stderr: (text) => process.stderr.write(text),
    });
  }
  if (args[0] === "verify") {
    return runVerify(
      args,
      dependencies.verify ?? {
        fs: new NodeFileSystem(),
        stdout: (text) => process.stdout.write(text),
        stderr: (text) => process.stderr.write(text),
      },
    );
  }

  console.error(
    "当前命令尚未实现。请运行 --help 查看可用命令，并参阅 README.md。",
  );
  return 8;
}

if (
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  process.exitCode = await main(process.argv.slice(2));
}
