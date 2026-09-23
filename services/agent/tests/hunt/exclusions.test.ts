import { copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { excludedEntities, toolContext } from "../../core/exclusions.js";
import { recallKeysOf } from "../../workflows/hunt/config.js";
import { validateDecision } from "../../workflows/hunt/controller.js";
import { buildDigest, suppressedEntities } from "../../workflows/hunt/digest.js";
import type { Enricher } from "../../workflows/hunt/ports.js";
import { ScriptedWorkerDispatcher } from "../../workflows/hunt/scripted.js";
import type { Entity } from "../../workflows/hunt/types.js";
import { resolveSpec } from "../../worker.js";
import { controllerFor, evidenceOn, huntSpecFor, INVESTIGATE, newLedger, SEED_IP } from "../support/hunt.js";

const SEED_KEY = `${SEED_IP.type}:${SEED_IP.value}`;
const EXCLUDED = { sections: { excluded_entities: [SEED_KEY] } };

describe("analyst IP exclusions in a hunt", () => {
  it("refuses new work on an excluded address, and says why in the analyst's terms", async () => {
    const started = await newLedger(EXCLUDED);
    evidenceOn(started.ledger, started.hypothesisIds[0]!, { source: "duckdb", entities: [SEED_IP] });
    const citations = [...started.ledger.projection.evidence.keys()];

    for (const action of ["INVESTIGATE", "DEEPEN", "PIVOT"] as const) {
      expect(() =>
        validateDecision(
          { action, rationale: "chase it", target_entity: SEED_KEY, evidence_citations: citations },
          started.ledger.projection,
        ),
      ).toThrow(/excluded .* in Vigil as already known/);
    }
    expect(() =>
      validateDecision(
        { action: "ABANDON", rationale: "excluded", target_entity: SEED_KEY, evidence_citations: citations },
        started.ledger.projection,
      ),
    ).not.toThrow();
  });

  it("keeps the evidence, marks the entity excluded rather than benign, and tells the lead", async () => {
    const started = await newLedger(EXCLUDED);
    const evidenceId = evidenceOn(started.ledger, started.hypothesisIds[0]!, { source: "duckdb", entities: [SEED_IP] });

    const digest = buildDigest(started.ledger.projection, 1);
    const view = digest.entities.find((entity) => entity.value === SEED_IP.value)!;
    expect(view.excluded).toBe(true);
    expect(view.suppressed).toBeUndefined();
    expect(digest.notes.join(" ")).toMatch(/excluded .* already known and handled/);
    expect(digest.notes.join(" ")).not.toMatch(/known-benign/);
    expect(suppressedEntities(started.ledger.projection).size).toBe(0);
    expect(started.ledger.projection.evidence.has(evidenceId)).toBe(true);
  });

  it("keeps an excluded address out of enrichment and out of the pivot candidates", async () => {
    const started = await newLedger(EXCLUDED);
    const enriched: string[] = [];
    const enricher: Enricher = async (entity: Entity) => {
      enriched.push(`${entity.type}:${entity.value}`);
      return [];
    };
    await controllerFor(started.ledger, [INVESTIGATE], {
      enricher,
      dispatcher: new ScriptedWorkerDispatcher([
        {
          source_system: "duckdb",
          summary: `10.0.0.5 talked to ${SEED_IP.value}`,
          payload: { src_ip: "10.0.0.5", dest_ip: SEED_IP.value },
          salience: "routine",
          why_notable: "",
          provenance: "worker",
          attacker_influenceable: false,
          instruction_like: false,
        },
      ]),
    }).advanceIteration();

    expect(enriched).toContain("ip:10.0.0.5");
    expect(enriched).not.toContain(SEED_KEY);
    const digest = buildDigest(started.ledger.projection, 2);
    expect(digest.pivot_candidates.map((entity) => entity.value)).not.toContain(SEED_IP.value);
  });

  it("does not recall memory on an excluded address", () => {
    const statement = `beaconing to ${SEED_IP.value} from 10.0.0.5`;
    const plain = huntSpecFor({ hypotheses: [statement] });
    const excluded = huntSpecFor({ hypotheses: [statement], ...EXCLUDED });
    expect(recallKeysOf(plain)).toContain(SEED_KEY);
    expect(recallKeysOf(excluded)).toEqual(["ip:10.0.0.5"]);
  });

  it("reads the set case-insensitively and ignores junk", () => {
    expect([...excludedEntities({ sections: { excluded_entities: ["IP:2001:DB8::1", "", 7] } })]).toEqual(["ip:2001:db8::1"]);
    expect(excludedEntities({ sections: {} }).size).toBe(0);
  });
});

describe("the job carries the set onto the spec", () => {
  it("journals excluded_entities with the spec, so a resume reads the set the run began with", async () => {
    const fixtures = join(import.meta.dirname, "..", "fixtures");
    const config = join(mkdtempSync(join(tmpdir(), "vigil-exclusions-")), "vigil.config.yaml");
    copyFileSync(join(fixtures, "hunt.config.yaml"), config);
    const job = {
      schema_version: 1,
      run_id: "7d3c2d3e-0000-4000-8000-000000000777",
      run_kind: "hunt" as const,
      tenant_id: null,
      enqueued_at: new Date().toISOString(),
      enqueued_by: "test",
      reason: "start" as const,
      request: {
        arch: "",
        playbook: join(fixtures, "hunt.playbook.yaml"),
        config,
        prompt: "go",
        excluded_entities: [SEED_KEY],
      },
    };
    expect((await resolveSpec(job)).sections["excluded_entities"]).toEqual([SEED_KEY]);

    const { excluded_entities: _dropped, ...without } = job.request;
    expect((await resolveSpec({ ...job, request: without })).sections["excluded_entities"]).toBeUndefined();

    // A run started to include them carries no set and tells every tool call so.
    const included = await resolveSpec({ ...job, request: { ...without, excluded_entities: [], include_excluded: true } });
    expect(included.sections["excluded_entities"]).toBeUndefined();
    expect(included.sections["include_excluded"]).toBe(true);
    expect(toolContext(included)).toEqual({ include_excluded: true });
    expect(toolContext(await resolveSpec(job))).toBeUndefined();
  });
});
