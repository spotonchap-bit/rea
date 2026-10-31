import type { IpsDocument } from "./appleIpsDocument.js";
import {
  interpretJetsam,
  type JetsamInterpretation,
} from "./appleIpsJetsam.js";
import {
  interpretStackshot,
  type StackshotInterpretation,
} from "./appleIpsStackshot.js";

/** bug_type values with a known meaning on iOS/iPadOS 15. */
export const IPS_BUG_TYPES = {
  crash: "309",
  jetsam: "298",
  stackshot: "288",
} as const;

/**
 * The single owner of `bug_type` dispatch. Crash reports (309) are owned by
 * the existing crash interpreter and are reported here as `delegated`;
 * unrecognised types and payloads that do not match their declared type stay
 * `unknown` rather than being guessed.
 */
export type IpsInterpretation =
  | JetsamInterpretation
  | StackshotInterpretation
  | {
      readonly kind: "delegated";
      readonly bugType: string;
      readonly owner: "crash";
    }
  | {
      readonly kind: "unknown";
      readonly bugType: string;
      readonly reason: string;
    };

export interface IpsInterpretationOptions {
  readonly offset?: number;
  readonly limit?: number;
}

export const interpretIpsDocument = (
  document: IpsDocument,
  options: IpsInterpretationOptions = {},
): IpsInterpretation => {
  const { bugType } = document.header;
  switch (bugType) {
    case IPS_BUG_TYPES.crash:
      return { kind: "delegated", bugType, owner: "crash" };
    case IPS_BUG_TYPES.jetsam:
      return (
        interpretJetsam(document.payload, options) ?? {
          kind: "unknown",
          bugType,
          reason: "JetsamEvent payload is not a JSON object.",
        }
      );
    case IPS_BUG_TYPES.stackshot:
      return (
        interpretStackshot(document.payload, options) ?? {
          kind: "unknown",
          bugType,
          reason: "Stackshot payload is not a JSON object.",
        }
      );
    default:
      return {
        kind: "unknown",
        bugType,
        reason: `bug_type ${bugType} has no interpreter; the header and raw payload are preserved.`,
      };
  }
};
