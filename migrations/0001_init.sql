-- Substation remote switching: initial schema.
-- All timing decisions use database clock (now()/clock_timestamp());
-- all state arbitration happens through conditional UPDATE / row locks.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Registered Ed25519 public keys. A key belongs to one subject and one role.
CREATE TABLE IF NOT EXISTS signing_keys (
    key_id         BIGSERIAL PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    subject        TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('OPERATOR', 'SAFETY')),
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at    TIMESTAMPTZ,
    CONSTRAINT signing_keys_pem_uniq UNIQUE (public_key_pem)
);

-- Versioned authorization policy. Only one active version; commands keep an
-- immutable snapshot of the policy that was active at submission time.
CREATE TABLE IF NOT EXISTS policies (
    version     BIGSERIAL PRIMARY KEY,
    active      BOOLEAN NOT NULL DEFAULT FALSE,
    body        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS commands (
    command_id        TEXT PRIMARY KEY,
    submitter         TEXT NOT NULL,
    station           TEXT NOT NULL,
    device            TEXT NOT NULL,
    action            TEXT NOT NULL,
    params            JSONB NOT NULL,
    not_before        TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    payload_version   INTEGER NOT NULL CHECK (payload_version > 0),
    -- Exact deterministic byte encoding of the immutable business payload;
    -- duplicate submissions are compared against this.
    content_canonical BYTEA NOT NULL,
    policy_version    BIGINT NOT NULL,
    policy_snapshot   JSONB NOT NULL,

    state             TEXT NOT NULL CHECK (state IN (
                          'PENDING',        -- awaiting signatures
                          'AUTHORIZED',     -- two valid signatures, deliverable window permitting
                          'CLAIMED',        -- delivery claim transaction committed
                          'EXECUTING',      -- at least one delivery attempt in flight/made
                          'SUCCEEDED',      -- terminal: single physical effect confirmed
                          'FAILED',         -- terminal: explicit downstream rejection
                          'CANCELLED',      -- terminal: revoked before the claim boundary
                          'EXPIRED'         -- terminal: expires_at reached before claim
                      )),
    execution_key     TEXT,
    lease_owner       TEXT,
    lease_expires_at  TIMESTAMPTZ,
    lease_epoch       INTEGER NOT NULL DEFAULT 0,
    delivery_attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at     TIMESTAMPTZ,
    final_result      JSONB,
    final_at          TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CHECK (not_before < expires_at),
    CHECK (expires_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS commands_state_idx ON commands (state, next_retry_at);

CREATE TABLE IF NOT EXISTS signatures (
    command_id           TEXT NOT NULL REFERENCES commands(command_id),
    role                 TEXT NOT NULL CHECK (role IN ('OPERATOR', 'SAFETY')),
    subject              TEXT NOT NULL,
    key_id               BIGINT NOT NULL REFERENCES signing_keys(key_id),
    signature            BYTEA NOT NULL,
    signed_policy_version BIGINT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (command_id, role),
    -- A single subject may never occupy both roles on one command.
    CONSTRAINT signatures_subject_once UNIQUE (command_id, subject)
);

-- Append-only audit timeline. event_key makes replay idempotent: the same
-- logical event (claim, attempt N, terminal...) is stored at most once.
CREATE TABLE IF NOT EXISTS audit_events (
    id         BIGSERIAL PRIMARY KEY,
    command_id TEXT NOT NULL REFERENCES commands(command_id),
    event_key  TEXT NOT NULL,
    type       TEXT NOT NULL,
    data       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT audit_event_dedupe UNIQUE (command_id, event_key)
);

CREATE INDEX IF NOT EXISTS audit_events_cmd_idx ON audit_events (command_id, id);

INSERT INTO policies (version, active, body)
VALUES (1, TRUE, jsonb_build_object(
    'policyVersion', 1,
    'requireRoles', jsonb_build_array('OPERATOR', 'SAFETY'),
    'distinctSubjects', TRUE,
    'submitterCannotSign', TRUE,
    'description',
    'One OPERATOR and one SAFETY signature from distinct subjects; submitter cannot sign.'
))
ON CONFLICT (version) DO NOTHING;

INSERT INTO schema_migrations (version) VALUES ('0001_init')
ON CONFLICT (version) DO NOTHING;
