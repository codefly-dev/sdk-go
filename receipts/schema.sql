-- The effect receipts of one module's Runnable operations.
--
-- A receipt is written inside the transaction that commits its effect, so this
-- table lives in the module's own database beside the effect it describes. It
-- is never a shared store: a receipt in another database could not be written
-- in that transaction, which is the whole property it exists to have.
CREATE TABLE IF NOT EXISTS codefly_effect_receipts (
    tenant         text        NOT NULL,
    effect_id      text        NOT NULL,
    method         text        NOT NULL,
    request_digest bytea       NOT NULL,
    response       bytea       NOT NULL,
    committed_at   timestamptz NOT NULL,
    PRIMARY KEY (tenant, effect_id, method)
);

-- Sweeping is the only access that is not by primary key. The tenant column
-- leads here as it leads the primary key, so a row-level security policy
-- restricting a session to its own tenant is answered from an index rather than
-- by filtering a scan of every tenant's receipts.
CREATE INDEX IF NOT EXISTS codefly_effect_receipts_committed_at
    ON codefly_effect_receipts (tenant, committed_at);
