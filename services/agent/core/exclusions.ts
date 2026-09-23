// Entity Keys an analyst excluded in Vigil, snapshotted onto the spec at enqueue.
// Known and handled already, so a run treats them as context and never as a lead.

export function excludedEntities(spec: { sections?: Record<string, unknown> }): ReadonlySet<string> {
  const held = spec.sections?.["excluded_entities"];
  if (!Array.isArray(held)) return new Set();
  return new Set(held.filter((one): one is string => typeof one === "string" && one !== "").map((one) => one.toLowerCase()));
}

// What every backend tool call of this run says about exclusions; undefined sends none.
export function toolContext(spec: { sections?: Record<string, unknown> }): Record<string, unknown> | undefined {
  return spec.sections?.["include_excluded"] === true ? { include_excluded: true } : undefined;
}

// Said once, in the words the lead reads: excluded is not benign, it is already known.
export function exclusionNote(excluded: ReadonlySet<string>): string {
  return (
    `An analyst has excluded ${[...excluded].sort().join(", ")} in Vigil: already known and handled. ` +
    "Records naming them stay in the record, but they are not leads -- do not open new work on them, " +
    "do not build a claim on them, and do not read the exclusion as a judgement on anything else."
  );
}
