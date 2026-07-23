import { HCheckError } from "@hcheck/core";
import JSON5 from "json5";

interface Json5SyntaxError extends Error {
  readonly lineNumber?: number;
  readonly columnNumber?: number;
}

export function parseJson5(text: string, sourcePath: string): unknown {
  try {
    return JSON5.parse(text.replace(/^\uFEFF/u, ""));
  } catch (error) {
    const syntaxError = error as Json5SyntaxError;
    const details: Record<string, unknown> = { path: sourcePath };
    if (typeof syntaxError.lineNumber === "number") {
      details.line = syntaxError.lineNumber;
    }
    if (typeof syntaxError.columnNumber === "number") {
      details.column = syntaxError.columnNumber;
    }
    throw new HCheckError(
      "ARTIFACT_PARSE_ERROR",
      `无法解析 JSON5 配置：${sourcePath}${formatLocation(syntaxError)}`,
      details,
    );
  }
}

function formatLocation(error: Json5SyntaxError): string {
  if (typeof error.lineNumber !== "number") return "";
  if (typeof error.columnNumber !== "number")
    return `（第 ${error.lineNumber} 行）`;
  return `（第 ${error.lineNumber} 行，第 ${error.columnNumber} 列）`;
}
