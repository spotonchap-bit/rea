import {
  isIpsRecord,
  IpsUnsafeInteger,
  type IpsJsonValue,
} from "./appleIpsDocument.js";

/**
 * Interpretation of a stackshot report (`bug_type` 288). Frames resolve to a
 * binary image identity plus offset; symbolication is a separate step.
 *
 * Two frame spellings are accepted because both appear in Apple JSON reports:
 * `[imageIndex, offset]` arrays and `{imageIndex, imageOffset}` objects.
 * Binary images are accepted as `[uuid, loadAddress, kind?]` arrays or
 * `{uuid, base, name}` objects. Anything else is counted, not guessed.
 */
export interface StackshotImage {
  readonly index: number;
  readonly uuid: string | null;
  /** Decimal text when the address exceeds the safe integer range. */
  readonly loadAddress: number | string | null;
  readonly kind: string | null;
  readonly name: string | null;
}

export interface StackshotFrame {
  readonly imageIndex: number;
  readonly imageUuid: string | null;
  readonly offset: number | string;
}

export interface StackshotThread {
  readonly pid: number;
  readonly processName: string | null;
  readonly threadId: string;
  readonly name: string | null;
  readonly state: readonly string[];
  readonly waitEvent: string | null;
  readonly userFrames: readonly StackshotFrame[];
  readonly kernelFrames: readonly StackshotFrame[];
  readonly framesTruncated: boolean;
}

export interface StackshotInterpretation {
  readonly kind: "stackshot";
  readonly reason: string | null;
  readonly processCount: number;
  readonly threadCount: number;
  readonly images: readonly StackshotImage[];
  /** One page of threads in pid, then thread-id order. */
  readonly threads: readonly StackshotThread[];
  readonly page: {
    readonly offset: number;
    readonly limit: number;
    readonly total: number;
  };
  readonly unrecognizedFrames: number;
  readonly limitations: readonly string[];
}

export const STACKSHOT_DEFAULT_THREAD_LIMIT = 50;
export const STACKSHOT_MAX_FRAMES_PER_THREAD = 128;

type JsonRecord = { readonly [key: string]: IpsJsonValue };

const finite = (value: IpsJsonValue | undefined): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;
const text = (value: IpsJsonValue | undefined): string | null =>
  typeof value === "string" ? value : null;
const integerText = (
  value: IpsJsonValue | undefined,
): number | string | null =>
  value instanceof IpsUnsafeInteger ? value.decimal : finite(value);

const readImage = (
  entry: IpsJsonValue,
  index: number,
): StackshotImage | null => {
  if (Array.isArray(entry)) {
    const [uuid, base, kind] = entry as readonly IpsJsonValue[];
    return {
      index,
      uuid: text(uuid),
      loadAddress: integerText(base),
      kind: text(kind),
      name: null,
    };
  }
  if (isIpsRecord(entry))
    return {
      index,
      uuid: text(entry.uuid),
      loadAddress: integerText(entry.base ?? entry.loadAddress),
      kind: text(entry.source ?? entry.kind),
      name: text(entry.name),
    };
  return null;
};

const readImages = (
  rawImages: IpsJsonValue | undefined,
  limitations: string[],
): StackshotImage[] => {
  const images: StackshotImage[] = [];
  let malformedImages = 0;
  if (!Array.isArray(rawImages)) {
    limitations.push(
      "The report has no binaryImages array; frames carry image indexes only.",
    );
    return images;
  }
  (rawImages as readonly IpsJsonValue[]).forEach((entry, index) => {
    const image = readImage(entry, index);
    if (image === null) malformedImages += 1;
    else images.push(image);
  });
  if (malformedImages > 0)
    limitations.push(
      `${String(malformedImages)} binary image entries were not recognised.`,
    );
  return images;
};

export const interpretStackshot = (
  payload: IpsJsonValue | null,
  options: { readonly offset?: number; readonly limit?: number } = {},
): StackshotInterpretation | null => {
  if (!isIpsRecord(payload)) return null;
  const offset = Math.max(0, options.offset ?? 0);
  const limit = Math.max(1, options.limit ?? STACKSHOT_DEFAULT_THREAD_LIMIT);
  const limitations: string[] = [];

  const images = readImages(payload.binaryImages, limitations);
  const imageUuid = (index: number): string | null =>
    images.find((image) => image.index === index)?.uuid ?? null;

  let unrecognizedFrames = 0;
  const readFrames = (
    value: IpsJsonValue | undefined,
  ): { frames: StackshotFrame[]; truncated: boolean } => {
    const frames: StackshotFrame[] = [];
    if (!Array.isArray(value)) return { frames, truncated: false };
    const entries = value as readonly IpsJsonValue[];
    for (const entry of entries.slice(0, STACKSHOT_MAX_FRAMES_PER_THREAD)) {
      let imageIndex: number | null = null;
      let frameOffset: number | string | null = null;
      if (Array.isArray(entry)) {
        imageIndex = finite((entry as readonly IpsJsonValue[])[0]);
        frameOffset = integerText((entry as readonly IpsJsonValue[])[1]);
      } else if (isIpsRecord(entry)) {
        imageIndex = finite(entry.imageIndex);
        frameOffset = integerText(entry.imageOffset);
      }
      if (imageIndex === null || frameOffset === null) {
        unrecognizedFrames += 1;
        continue;
      }
      frames.push({
        imageIndex,
        imageUuid: imageUuid(imageIndex),
        offset: frameOffset,
      });
    }
    return {
      frames,
      truncated: entries.length > STACKSHOT_MAX_FRAMES_PER_THREAD,
    };
  };

  const threads: StackshotThread[] = [];
  let processCount = 0;
  const byPid = payload.processByPid;
  if (isIpsRecord(byPid ?? null)) {
    const pids = Object.entries(byPid as JsonRecord)
      .map(([key, value]) => ({ pid: Number(key), value }))
      .filter((entry) => Number.isSafeInteger(entry.pid))
      .sort((a, b) => a.pid - b.pid);
    for (const { pid, value } of pids) {
      if (!isIpsRecord(value)) continue;
      processCount += 1;
      const processName = text(value.procname ?? value.name);
      const threadsValue = value.threadById;
      if (!isIpsRecord(threadsValue ?? null)) continue;
      const threadEntries = Object.entries(threadsValue as JsonRecord).sort(
        ([a], [b]) => Number(a) - Number(b) || a.localeCompare(b),
      );
      for (const [threadId, thread] of threadEntries) {
        if (!isIpsRecord(thread)) continue;
        const user = readFrames(thread.userFrames);
        const kernel = readFrames(thread.kernelFrames);
        threads.push({
          pid,
          processName,
          threadId,
          name: text(thread.name),
          state: Array.isArray(thread.state)
            ? (thread.state as readonly IpsJsonValue[]).filter(
                (item): item is string => typeof item === "string",
              )
            : [],
          waitEvent: text(thread.waitEvent),
          userFrames: user.frames,
          kernelFrames: kernel.frames,
          framesTruncated: user.truncated || kernel.truncated,
        });
      }
    }
  } else {
    limitations.push("The report has no processByPid object.");
  }
  if (unrecognizedFrames > 0)
    limitations.push(
      `${String(unrecognizedFrames)} frames were not recognised and were skipped.`,
    );

  return {
    kind: "stackshot",
    reason: text(payload.reason),
    processCount,
    threadCount: threads.length,
    images,
    threads: threads.slice(offset, offset + limit),
    page: { offset, limit, total: threads.length },
    unrecognizedFrames,
    limitations,
  };
};
