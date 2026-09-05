-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE authorization_traces (
    sequence_id BIGSERIAL PRIMARY KEY,
    schema_version SMALLINT NOT NULL CHECK (schema_version = 1),
    recorded_at TIMESTAMPTZ NOT NULL,
    recorded_at_exact NUMERIC(29,9) NOT NULL,
    request_id VARCHAR(256) NOT NULL,
    protocol VARCHAR(8) NOT NULL CHECK (protocol IN ('HTTP', 'MCP')),
    operation VARCHAR(64) NOT NULL,
    resource VARCHAR(2048) NOT NULL,
    request_digest CHAR(71) NOT NULL CHECK (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    requested_at TIMESTAMPTZ NOT NULL,
    requested_at_exact NUMERIC(29,9) NOT NULL,
    decision_id VARCHAR(256) NOT NULL,
    outcome VARCHAR(8) NOT NULL CHECK (outcome IN ('ALLOW', 'DENY')),
    reason VARCHAR(64) NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    decided_at_exact NUMERIC(29,9) NOT NULL,
    policy_ids VARCHAR(256)[] NOT NULL CHECK (cardinality(policy_ids) <= 32)
);
CREATE INDEX authorization_traces_recorded_at_idx ON authorization_traces (recorded_at_exact);
CREATE INDEX authorization_traces_decided_sequence_idx ON authorization_traces (decided_at_exact DESC, sequence_id DESC);
CREATE INDEX authorization_traces_request_idx ON authorization_traces (request_id, sequence_id DESC);
