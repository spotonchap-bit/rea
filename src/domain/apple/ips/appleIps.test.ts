import { describe, expect, it } from "vitest";
import {
  IPS_MAX_INPUT_BYTES,
  IpsUnsafeInteger,
  parseIpsDocument,
  type IpsDocument,
} from "./appleIpsDocument.js";
import { interpretIpsDocument } from "./appleIpsInterpretation.js";
import { STACKSHOT_MAX_FRAMES_PER_THREAD } from "./appleIpsStackshot.js";

// Synthetic fixtures shaped after iPadOS 15 reports. They are not real device
// output; replace with sanitised iPad mini 4 samples once available.
const encode = (header: unknown, payload?: unknown): Uint8Array =>
  new TextEncoder().encode(
    payload === undefined
      ? JSON.stringify(header)
      : `${JSON.stringify(header)}\n${JSON.stringify(payload, null, 2)}`,
  );

const parsed = (bytes: Uint8Array): IpsDocument => {
  const result = parseIpsDocument(bytes);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
};

const jetsamPayload = {
  product: "iPad5,1",
  build: "iPhone OS 15.8 (19H000)",
  incident: "00000000-0000-0000-0000-000000000001",
  date: "2026-10-30 10:00:00.00 +0000",
  largestProcess: "BigApp",
  memoryStatus: {
    pageSize: 4096,
    compressorSize: 1200,
    memoryPages: { free: 900, active: 30000, wired: 20000 },
  },
  processes: [
    { name: "SmallApp", pid: 10, rpages: 100, states: ["daemon"] },
    {
      name: "BigApp",
      pid: 11,
      rpages: 50000,
      reason: "per-process-limit",
      states: ["frontmost"],
      lifetimeMax: 52000,
    },
    { name: "MidApp", pid: 12, rpages: 3000 },
    "garbage",
  ],
};

describe("parseIpsDocument", () => {
  it("splits the header line from the payload and keeps bug_type as text", () => {
    const document = parsed(
      encode(
        { bug_type: "298", os_version: "iPhone OS 15.8 (19H000)", name: "x" },
        {},
      ),
    );
    expect(document.header.bugType).toBe("298");
    expect(document.header.osVersion).toBe("iPhone OS 15.8 (19H000)");
    expect(document.payload).toEqual({});
  });

  it("accepts a numeric bug_type and a header-only file", () => {
    const document = parsed(encode({ bug_type: 288 }));
    expect(document.header.bugType).toBe("288");
    expect(document.payload).toBeNull();
  });

  it("keeps integers beyond the safe range as decimal text", () => {
    const bytes = new TextEncoder().encode(
      '{"bug_type":"288"}\n{"binaryImages":[["U",18446744073709551615,"K"]]}',
    );
    const document = parsed(bytes);
    const image = (document.payload as { binaryImages: unknown[][] })
      .binaryImages[0];
    expect(image?.[1]).toBeInstanceOf(IpsUnsafeInteger);
    expect(JSON.stringify(image)).toContain("18446744073709551615");
  });

  it.each([
    ["header_missing", "\n{}"],
    ["header_invalid", "not json\n{}"],
    ["header_invalid", "[1]\n{}"],
    ["bug_type_missing", '{"name":"x"}\n{}'],
    ["payload_invalid", '{"bug_type":"298"}\n{"processes": ['],
  ])("reports %s", (code, source) => {
    const result = parseIpsDocument(new TextEncoder().encode(source));
    expect(result.ok ? null : result.error.code).toBe(code);
  });

  it("refuses input over the size bound before decoding", () => {
    const result = parseIpsDocument(new Uint8Array(IPS_MAX_INPUT_BYTES + 1));
    expect(result.ok ? null : result.error.code).toBe("input_limit");
  });
});

describe("jetsam (298)", () => {
  it("reports the killed process, sizes in bytes and the largest processes", () => {
    const result = interpretIpsDocument(
      parsed(encode({ bug_type: "298" }, jetsamPayload)),
      { limit: 2 },
    );
    if (result.kind !== "jetsam") throw new Error(result.kind);
    expect(result.pageSize).toBe(4096);
    expect(result.largestProcess).toBe("BigApp");
    expect(
      result.killed.map((p) => [p.name, p.reason, p.residentBytes]),
    ).toEqual([["BigApp", "per-process-limit", 50000 * 4096]]);
    expect(result.topByResidentPages.map((p) => p.name)).toEqual([
      "BigApp",
      "MidApp",
    ]);
    expect(result.processCount).toBe(3);
    expect(result.malformedProcessEntries).toBe(1);
    expect(result.memoryPages).toEqual({
      free: 900,
      active: 30000,
      wired: 20000,
    });
  });

  it("leaves sizes unknown when the page size is missing", () => {
    const { memoryStatus: _omit, ...withoutStatus } = jetsamPayload;
    const result = interpretIpsDocument(
      parsed(encode({ bug_type: "298" }, withoutStatus)),
    );
    if (result.kind !== "jetsam") throw new Error(result.kind);
    expect(result.pageSize).toBeNull();
    expect(result.killed[0]?.residentBytes).toBeNull();
    expect(result.limitations.join(" ")).toContain("Page size");
  });
});

describe("stackshot (288)", () => {
  const payload = {
    reason: "hang",
    binaryImages: [
      ["11111111-1111-1111-1111-111111111111", 4294967296, "U"],
      { uuid: "22222222-2222-2222-2222-222222222222", base: 0, name: "kernel" },
      42,
    ],
    processByPid: {
      "20": {
        procname: "Second",
        threadById: {
          "7": { name: "worker", state: ["TH_WAIT"], userFrames: [[0, 16]] },
        },
      },
      "3": {
        procname: "First",
        threadById: {
          "9": {
            userFrames: [
              [0, 100],
              { imageIndex: 0, imageOffset: 200 },
              ["bad"],
            ],
            kernelFrames: [[1, 300]],
            waitEvent: "semaphore",
          },
        },
      },
    },
  };

  it("resolves frames to image UUID plus offset in pid order", () => {
    const result = interpretIpsDocument(
      parsed(encode({ bug_type: "288" }, payload)),
    );
    if (result.kind !== "stackshot") throw new Error(result.kind);
    expect(result.processCount).toBe(2);
    expect(result.threads.map((t) => [t.pid, t.processName])).toEqual([
      [3, "First"],
      [20, "Second"],
    ]);
    const first = result.threads[0];
    expect(first?.userFrames).toEqual([
      {
        imageIndex: 0,
        imageUuid: "11111111-1111-1111-1111-111111111111",
        offset: 100,
      },
      {
        imageIndex: 0,
        imageUuid: "11111111-1111-1111-1111-111111111111",
        offset: 200,
      },
    ]);
    expect(first?.kernelFrames[0]?.imageUuid).toBe(
      "22222222-2222-2222-2222-222222222222",
    );
    expect(result.unrecognizedFrames).toBe(1);
    expect(result.images).toHaveLength(2);
    expect(result.limitations.join(" ")).toContain("1 binary image");
  });

  it("pages threads and caps frames per thread", () => {
    const many = {
      processByPid: {
        "1": {
          threadById: Object.fromEntries(
            Array.from({ length: 5 }, (_, i) => [
              String(i),
              {
                userFrames: Array.from(
                  { length: STACKSHOT_MAX_FRAMES_PER_THREAD + 1 },
                  () => [0, 1],
                ),
              },
            ]),
          ),
        },
      },
    };
    const result = interpretIpsDocument(
      parsed(encode({ bug_type: "288" }, many)),
      {
        offset: 2,
        limit: 2,
      },
    );
    if (result.kind !== "stackshot") throw new Error(result.kind);
    expect(result.page).toEqual({ offset: 2, limit: 2, total: 5 });
    expect(result.threads.map((t) => t.threadId)).toEqual(["2", "3"]);
    expect(result.threads[0]?.userFrames).toHaveLength(
      STACKSHOT_MAX_FRAMES_PER_THREAD,
    );
    expect(result.threads[0]?.framesTruncated).toBe(true);
  });
});

describe("dispatch", () => {
  it("delegates crash reports and keeps other bug types unknown", () => {
    expect(
      interpretIpsDocument(parsed(encode({ bug_type: "309" }, {}))).kind,
    ).toBe("delegated");
    const unknown = interpretIpsDocument(
      parsed(encode({ bug_type: "210" }, {})),
    );
    expect(unknown).toMatchObject({ kind: "unknown", bugType: "210" });
    expect(
      interpretIpsDocument(parsed(encode({ bug_type: "298" }, [1]))).kind,
    ).toBe("unknown");
  });
});
