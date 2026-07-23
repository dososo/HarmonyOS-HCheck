import { HCheckError, type HCheckErrorCode } from "@hcheck/core";

export type HCheckErrorExitCode = 3 | 4 | 5 | 6 | 7 | 8 | 10;
/** 0=未触发门禁；1=存在满足当前门禁策略的问题；2=保留给基线新增问题。 */
export type GateExitCode = 0 | 1 | 2;

const ERROR_EXIT_CODES = {
  CONFIGURATION_ERROR: 3,
  UNSUPPORTED_PROJECT: 8,
  TOOL_UNAVAILABLE: 3,
  TOOL_EXECUTION_ERROR: 3,
  BUILD_FAILED: 3,
  ARTIFACT_PARSE_ERROR: 8,
  EXTERNAL_SERVICE_UNAVAILABLE: 5,
  CREDENTIAL_ERROR: 7,
  DEVICE_UNAVAILABLE: 4,
  RULE_DEFINITION_ERROR: 6,
  EVIDENCE_INCOMPLETE: 4,
  INTERNAL_ERROR: 10,
} as const satisfies Readonly<Record<HCheckErrorCode, HCheckErrorExitCode>>;

export function exitCodeForError(error: unknown): HCheckErrorExitCode {
  if (!(error instanceof HCheckError)) {
    return 10;
  }

  return (
    (
      ERROR_EXIT_CODES as Readonly<Partial<Record<string, HCheckErrorExitCode>>>
    )[error.code] ?? 10
  );
}
