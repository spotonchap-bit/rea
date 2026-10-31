import { isSafeNumber, parse } from "lossless-json";
import { err, ok, type Result } from "../../result.js";

/**
 * Apple diagnostic report (`.ips`) container: a one-line JSON header followed
 * by a JSON payload whose schema is selected by `header.bug_type`.
 *
 * Integers outside the IEEE-754 safe range are kept as their decimal source
 * text so addresses and counters never round. Every other number is a JS
 * number.
 */
export type IpsJsonValue =
  | null
  | boolean
  | number
  | string
  | IpsUnsafeInteger
  | readonly IpsJsonValue[]
  | { readonly [key: string]: IpsJsonValue };

/** An integer literal that does not fit a JS number, kept as decimal text. */
export class IpsUnsafeInteger {
  constructor(readonly decimal: string) {}
  toJSON(): string {
    return this.decimal;
  }
}

/** Input bound: real iOS 15 stackshots stay well below this. */
export const IPS_MAX_INPUT_BYTES = 16 * 1024 * 1024;

export type IpsFormatErrorCode =
  | "input_limit"
  | "header_missing"
  | "header_invalid"
  | "bug_type_missing"
  | "payload_invalid";

export interface IpsFormatError {
  readonly kind: "ips_format";
  readonly code: IpsFormatErrorCode;
  readonly message: string;
}

const formatError = (
  code: IpsFormatErrorCode,
  message: string,
): IpsFormatError => ({ kind: "ips_format", code, message });

export interface IpsHeader {
  /** The header exactly as decoded, including fields REA does not interpret. */
  readonly raw: { readonly [key: string]: IpsJsonValue };
  /** `bug_type` as written: Apple writes a string, older tools a number. */
  readonly bugType: string;
  readonly name: string | null;
  readonly timestamp: string | null;
  readonly osVersion: string | null;
  readonly incidentId: string | null;
}

export interface IpsDocument {
  readonly header: IpsHeader;
  /** `null` when the file carries a header only. */
  readonly payload: IpsJsonValue | null;
  readonly byteLength: number;
}

const parseNumber = (literal: string): number | IpsUnsafeInteger =>
  isSafeNumber(literal, { approx: false }) || !/^-?\d+$/u.test(literal)
    ? Number(literal)
    : new IpsUnsafeInteger(literal);

const parseJson = (text: string): IpsJsonValue =>
  parse(text, null, parseNumber) as IpsJsonValue;

const isRecord = (
  value: IpsJsonValue | null,
): value is { readonly [key: string]: IpsJsonValue } =>
  typeof value === "object" &&
  value !== null &&
  !Array.isArray(value) &&
  !(value instanceof IpsUnsafeInteger);

const optionalString = (value: IpsJsonValue | undefined): string | null =>
  typeof value === "string" ? value : null;

/** Split and decode an `.ips` document without interpreting its payload. */
export const parseIpsDocument = (
  bytes: Uint8Array,
): Result<IpsDocument, IpsFormatError> => {
  if (bytes.byteLength > IPS_MAX_INPUT_BYTES)
    return err(
      formatError(
        "input_limit",
        `.ips input is ${String(bytes.byteLength)} bytes; the limit is ${String(IPS_MAX_INPUT_BYTES)}.`,
      ),
    );
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return err(formatError("header_invalid", ".ips input is not UTF-8."));
  }
  if (text.startsWith("﻿")) text = text.slice(1);
  const newline = text.indexOf("\n");
  const headerText = (newline === -1 ? text : text.slice(0, newline)).trim();
  const payloadText = newline === -1 ? "" : text.slice(newline + 1).trim();
  if (headerText === "")
    return err(formatError("header_missing", ".ips header line is empty."));

  let header: IpsJsonValue;
  try {
    header = parseJson(headerText);
  } catch (cause) {
    return err(
      formatError(
        "header_invalid",
        `.ips header line is not JSON: ${(cause as Error).message}`,
      ),
    );
  }
  if (!isRecord(header))
    return err(
      formatError("header_invalid", ".ips header line is not a JSON object."),
    );
  const bugTypeValue = header.bug_type;
  const bugType =
    typeof bugTypeValue === "string"
      ? bugTypeValue.trim()
      : typeof bugTypeValue === "number" && Number.isInteger(bugTypeValue)
        ? String(bugTypeValue)
        : null;
  if (bugType === null || bugType === "")
    return err(
      formatError("bug_type_missing", ".ips header has no bug_type value."),
    );

  let payload: IpsJsonValue | null = null;
  if (payloadText !== "") {
    try {
      payload = parseJson(payloadText);
    } catch (cause) {
      return err(
        formatError(
          "payload_invalid",
          `.ips payload is not JSON: ${(cause as Error).message}`,
        ),
      );
    }
  }

  return ok({
    header: {
      raw: header,
      bugType,
      name: optionalString(header.name ?? header.app_name),
      timestamp: optionalString(header.timestamp),
      osVersion: optionalString(header.os_version),
      incidentId: optionalString(header.incident_id),
    },
    payload,
    byteLength: bytes.byteLength,
  });
};

export { isRecord as isIpsRecord };
