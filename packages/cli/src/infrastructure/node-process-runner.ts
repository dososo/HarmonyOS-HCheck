import { spawn } from "node:child_process";
import path from "node:path";
import type {
  ProcessRunRequest,
  ProcessRunResult,
  ProcessRunnerPort,
} from "@hcheck/core";

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_TERMINATION_GRACE_MS = 1_000;
const MAX_TERMINATION_GRACE_MS = 10_000;
const POST_KILL_CLOSE_TIMEOUT_MS = 1_000;
const DEFAULT_MAX_STDOUT_BYTES = 64 * 1024;
const DEFAULT_MAX_STDERR_BYTES = 64 * 1024;
const EXTRA_REDACTION_BYTES = 4 * 1024;
const DEFAULT_ENVIRONMENT_ALLOW_LIST = Object.freeze([
  "PATH",
  "HOME",
  "USER",
  "TMPDIR",
  "TMP",
  "TEMP",
  "SystemRoot",
  "WINDIR",
  "ComSpec",
  "PATHEXT",
] as const);
const SENSITIVE_ENVIRONMENT_KEY =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY)/iu;
const CREDENTIAL_ASSIGNMENT =
  /\b(?:api[_-]?key|api[_-]?token|access[_-]?token|password|passwd|secret|credential|private[_-]?key)\b\s*[:=：]\s*([^\s，。；、）)]+)/giu;

export interface NodeProcessRunnerOptions {
  readonly baseEnvironment?: Readonly<Record<string, string | undefined>>;
  readonly environmentAllowList?: readonly string[];
  readonly defaultTimeoutMs?: number;
  readonly terminationGraceMs?: number;
  readonly defaultMaxStdoutBytes?: number;
  readonly defaultMaxStderrBytes?: number;
}

export class NodeProcessRunner implements ProcessRunnerPort {
  private readonly baseEnvironment: Readonly<
    Record<string, string | undefined>
  >;
  private readonly environmentAllowList: readonly string[];
  private readonly defaultTimeoutMs: number;
  private readonly terminationGraceMs: number;
  private readonly defaultMaxStdoutBytes: number;
  private readonly defaultMaxStderrBytes: number;

  public constructor(options: NodeProcessRunnerOptions = {}) {
    const terminationGraceMs =
      options.terminationGraceMs ?? DEFAULT_TERMINATION_GRACE_MS;
    if (
      !Number.isSafeInteger(terminationGraceMs) ||
      terminationGraceMs < 0 ||
      terminationGraceMs > MAX_TERMINATION_GRACE_MS
    ) {
      throw new RangeError("终止宽限期必须是 0 到 10000 毫秒之间的整数。");
    }
    this.baseEnvironment = options.baseEnvironment ?? process.env;
    this.environmentAllowList =
      options.environmentAllowList ?? DEFAULT_ENVIRONMENT_ALLOW_LIST;
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.terminationGraceMs = terminationGraceMs;
    this.defaultMaxStdoutBytes =
      options.defaultMaxStdoutBytes ?? DEFAULT_MAX_STDOUT_BYTES;
    this.defaultMaxStderrBytes =
      options.defaultMaxStderrBytes ?? DEFAULT_MAX_STDERR_BYTES;
  }

  public async run(request: ProcessRunRequest): Promise<ProcessRunResult> {
    const timeoutMs = request.timeoutMs ?? this.defaultTimeoutMs;
    const maxStdoutBytes = request.maxStdoutBytes ?? this.defaultMaxStdoutBytes;
    const maxStderrBytes = request.maxStderrBytes ?? this.defaultMaxStderrBytes;
    const environment = this.buildEnvironment(request.env);
    const redaction = buildRedactionContext(request, environment);
    const stdout = new BoundedOutput(maxStdoutBytes);
    const stderr = new BoundedOutput(maxStderrBytes);

    return new Promise<ProcessRunResult>((resolve) => {
      let settled = false;
      let timedOut = false;
      let timeout: NodeJS.Timeout | undefined;
      let terminationGrace: NodeJS.Timeout | undefined;
      let postKillCloseTimeout: NodeJS.Timeout | undefined;

      const finish = (result: ProcessRunResult): void => {
        if (settled) return;
        settled = true;
        if (timeout !== undefined) clearTimeout(timeout);
        if (terminationGrace !== undefined) clearTimeout(terminationGrace);
        if (postKillCloseTimeout !== undefined) {
          clearTimeout(postKillCloseTimeout);
        }
        resolve(result);
      };

      const child = spawn(request.executable, [...request.args], {
        cwd: request.cwd,
        env: environment,
        shell: false,
        windowsHide: true,
      });

      child.stdout?.on("data", (chunk: Buffer) => stdout.append(chunk));
      child.stderr?.on("data", (chunk: Buffer) => stderr.append(chunk));

      child.on("error", (error) => {
        if (timedOut) return;
        const errorCode = (error as { readonly code?: unknown }).code;
        const code = typeof errorCode === "string" ? errorCode : error.name;
        finish({
          status: "start_failed",
          timedOut: false,
          stdout: stdout.text(redaction),
          stderr: stderr.text(redaction),
          stdoutTruncated: stdout.truncated,
          stderrTruncated: stderr.truncated,
          errorMessage: redactText(`启动外部进程失败：${code}`, redaction),
        });
      });

      child.once("close", (exitCode, signal) => {
        finish({
          status: timedOut ? "timed_out" : "completed",
          ...(typeof exitCode === "number" ? { exitCode } : {}),
          ...(signal === null ? {} : { signal }),
          timedOut,
          stdout: stdout.text(redaction),
          stderr: stderr.text(redaction),
          stdoutTruncated: stdout.truncated,
          stderrTruncated: stderr.truncated,
        });
      });

      if (timeoutMs > 0) {
        timeout = setTimeout(() => {
          timedOut = true;
          child.kill("SIGTERM");
          terminationGrace = setTimeout(() => {
            child.kill("SIGKILL");
            postKillCloseTimeout = setTimeout(() => {
              finish({
                status: "timed_out",
                timedOut: true,
                stdout: stdout.text(redaction),
                stderr: stderr.text(redaction),
                stdoutTruncated: stdout.truncated,
                stderrTruncated: stderr.truncated,
              });
            }, POST_KILL_CLOSE_TIMEOUT_MS);
          }, this.terminationGraceMs);
        }, timeoutMs);
      }
    });
  }

  private buildEnvironment(
    overrides: Readonly<Record<string, string | undefined>> | undefined,
  ): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = {};
    for (const key of this.environmentAllowList) {
      const value = this.baseEnvironment[key];
      if (typeof value === "string") environment[key] = value;
    }
    if (overrides !== undefined) {
      for (const [key, value] of Object.entries(overrides)) {
        if (value === undefined) delete environment[key];
        else environment[key] = value;
      }
    }
    return environment;
  }
}

interface RedactionContext {
  readonly paths: readonly string[];
  readonly secretValues: readonly string[];
}

class BoundedOutput {
  private readonly chunks: Buffer[] = [];
  private readonly storedBytesLimit: number;
  private observedBytes = 0;

  public constructor(private readonly maxBytes: number) {
    this.storedBytesLimit = maxBytes + EXTRA_REDACTION_BYTES;
  }

  public get truncated(): boolean {
    return this.observedBytes > this.maxBytes;
  }

  public append(chunk: Buffer): void {
    this.observedBytes += chunk.length;
    const storedBytes = this.chunks.reduce(
      (total, item) => total + item.length,
      0,
    );
    const remaining = this.storedBytesLimit - storedBytes;
    if (remaining <= 0) return;
    this.chunks.push(chunk.subarray(0, remaining));
  }

  public text(redaction: RedactionContext): string {
    const redacted = redactText(
      Buffer.concat(this.chunks).toString(),
      redaction,
    );
    if (Buffer.byteLength(redacted) <= this.maxBytes) return redacted;
    return Buffer.from(redacted).subarray(0, this.maxBytes).toString();
  }
}

function buildRedactionContext(
  request: ProcessRunRequest,
  environment: Readonly<Record<string, string | undefined>>,
): RedactionContext {
  return {
    paths: [request.cwd, request.executable]
      .filter((value): value is string => value !== undefined)
      .filter((value) => path.isAbsolute(value)),
    secretValues: Object.entries(environment)
      .filter(([key, value]) => SENSITIVE_ENVIRONMENT_KEY.test(key) && value)
      .map(([, value]) => value as string),
  };
}

function redactText(text: string, context: RedactionContext): string {
  let redacted = text;
  for (const secret of context.secretValues) {
    redacted = redacted.replaceAll(secret, "[REDACTED_SECRET]");
  }
  for (const unsafePath of context.paths) {
    redacted = redacted.replaceAll(unsafePath, "[REDACTED_PATH]");
  }
  return redacted.replace(CREDENTIAL_ASSIGNMENT, (match) =>
    match.replace(/([:=：]\s*)([^\s，。；、）)]+)/u, "$1[REDACTED_SECRET]"),
  );
}
