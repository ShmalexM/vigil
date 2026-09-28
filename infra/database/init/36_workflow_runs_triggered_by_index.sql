-- The index the WorkflowRun model declares on (triggered_by, started_at). A hunt
-- handing off looks it up to decide whether a root-cause run was already teed
-- up, and without it that lookup is a sequential scan that grows with run
-- history. 12_workflow_runs.sql creates the table without it, and create_all
-- never adds an index to a table it finds, so compose and Helm installs had it
-- only once scripts/migrate_schema.py ran as the table's owner. Here the user
-- that created the table adds it.

CREATE INDEX IF NOT EXISTS idx_workflow_runs_triggered_by
    ON workflow_runs (triggered_by, started_at);
