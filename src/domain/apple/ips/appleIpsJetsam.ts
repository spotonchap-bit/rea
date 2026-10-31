import {
  isIpsRecord,
  IpsUnsafeInteger,
  type IpsJsonValue,
} from "./appleIpsDocument.js";

/**
 * Interpretation of a JetsamEvent report (`bug_type` 298) as written by
 * iOS/iPadOS 15. Only fields REA reads are typed; the payload stays available
 * to callers through the document. Missing or mistyped fields become `null`
 * (unknown), never zero.
 */
export interface JetsamProcess {
  readonly name: string | null;
  readonly pid: number | null;
  readonly uuid: string | null;
  /** Kill reason, e.g. `per-process-limit` or `vm-pageshortage`; present only on the killed process(es). */
  readonly reason: string | null;
  readonly states: readonly string[];
  /** Resident pages as recorded. */
  readonly residentPages: number | null;
  /** `residentPages * pageSize`; `null` when either is unknown. */
  readonly residentBytes: number | null;
  readonly lifetimeMaxPages: number | null;
  readonly priority: number | null;
  readonly coalition: number | null;
}

export interface JetsamInterpretation {
  readonly kind: "jetsam";
  readonly product: string | null;
  readonly build: string | null;
  readonly incident: string | null;
  readonly date: string | null;
  readonly largestProcess: string | null;
  /** Page size in bytes from `memoryStatus.pageSize`, else top-level `pageSize`. */
  readonly pageSize: number | null;
  readonly memoryPages: Readonly<Record<string, number>>;
  readonly compressorSizePages: number | null;
  /** Processes carrying a `reason`, i.e. the ones jetsam killed. */
  readonly killed: readonly JetsamProcess[];
  /** Largest processes by resident pages, at most `limit`. */
  readonly topByResidentPages: readonly JetsamProcess[];
  readonly processCount: number;
  /** Process entries that were not JSON objects. */
  readonly malformedProcessEntries: number;
  readonly limitations: readonly string[];
}

const finite = (value: IpsJsonValue | undefined): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (value: IpsJsonValue | undefined): string | null =>
  typeof value === "string" ? value : null;

const toProcess = (
  entry: { readonly [key: string]: IpsJsonValue },
  pageSize: number | null,
): JetsamProcess => {
  const residentPages = finite(entry.rpages);
  const residentBytes =
    residentPages !== null && pageSize !== null
      ? residentPages * pageSize
      : null;
  return {
    name: text(entry.name),
    pid: finite(entry.pid),
    uuid: text(entry.uuid),
    reason: text(entry.reason),
    states: Array.isArray(entry.states)
      ? entry.states.filter(
          (state): state is string => typeof state === "string",
        )
      : [],
    residentPages,
    residentBytes:
      residentBytes !== null && Number.isSafeInteger(residentBytes)
        ? residentBytes
        : null,
    lifetimeMaxPages: finite(entry.lifetimeMax),
    priority: finite(entry.priority),
    coalition: finite(entry.coalition),
  };
};

export const JETSAM_DEFAULT_TOP_LIMIT = 20;

export const interpretJetsam = (
  payload: IpsJsonValue | null,
  options: { readonly limit?: number } = {},
): JetsamInterpretation | null => {
  if (!isIpsRecord(payload)) return null;
  const limit = options.limit ?? JETSAM_DEFAULT_TOP_LIMIT;
  const limitations: string[] = [];
  const memoryStatus = isIpsRecord(payload.memoryStatus ?? null)
    ? (payload.memoryStatus as { readonly [key: string]: IpsJsonValue })
    : null;
  const pageSize = finite(memoryStatus?.pageSize) ?? finite(payload.pageSize);
  if (pageSize === null)
    limitations.push(
      "Page size is not recorded; resident sizes are reported in pages only.",
    );

  const memoryPages: Record<string, number> = {};
  const pagesValue = memoryStatus?.memoryPages;
  if (pagesValue !== undefined && isIpsRecord(pagesValue))
    for (const [key, value] of Object.entries(pagesValue)) {
      const pages = finite(value);
      if (pages !== null) memoryPages[key] = pages;
    }

  const processes: JetsamProcess[] = [];
  let malformedProcessEntries = 0;
  const rawProcesses = payload.processes;
  if (Array.isArray(rawProcesses)) {
    for (const entry of rawProcesses as readonly IpsJsonValue[]) {
      if (isIpsRecord(entry)) processes.push(toProcess(entry, pageSize));
      else malformedProcessEntries += 1;
    }
  } else {
    limitations.push("The report has no processes array.");
  }

  const unsafe = Object.values(payload).some(
    (value) => value instanceof IpsUnsafeInteger,
  );
  if (unsafe)
    limitations.push(
      "Some top-level integers exceed the safe range and are kept as decimal text in the raw payload.",
    );

  return {
    kind: "jetsam",
    product: text(payload.product),
    build: text(payload.build),
    incident: text(payload.incident),
    date: text(payload.date),
    largestProcess: text(payload.largestProcess),
    pageSize,
    memoryPages,
    compressorSizePages: finite(memoryStatus?.compressorSize),
    killed: processes.filter((process) => process.reason !== null),
    topByResidentPages: [...processes]
      .filter((process) => process.residentPages !== null)
      .sort((a, b) => (b.residentPages ?? 0) - (a.residentPages ?? 0))
      .slice(0, limit),
    processCount: processes.length,
    malformedProcessEntries,
    limitations,
  };
};
