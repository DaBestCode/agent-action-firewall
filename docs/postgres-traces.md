# PostgreSQL trace repository — Day 13

## Schema and migration

`firewall-trace-postgres` implements the core `AuthorizationTraceRepository` using prepared JDBC
statements and one explicit migration: `db/migration/V001__authorization_traces.sql`. The relational
table contains only the existing sanitized event fields—no tokens, payloads, query parameters,
request attributes, free-form messages or generic JSON blobs. Policy IDs use a bounded varchar array.
Database checks reinforce schema version, enum-like protocol/outcome values, digest form and policy count.

Call `PostgresTraceMigrations.apply(dataSource)` explicitly before constructing the repository.
It acquires a transaction-scoped PostgreSQL advisory lock, bootstraps a migration ledger, verifies
the SHA-256 of an already-applied resource, rejects unknown future versions, and applies transactional
DDL exactly once. This small runner is purpose-built for the current single migration; it is not a
general Flyway replacement and cannot downgrade or repair a database.

PostgreSQL `TIMESTAMPTZ` is retained for operational inspection, while parallel `NUMERIC(29,9)`
columns preserve exact Java `Instant` nanoseconds. Filters and retention use exact numeric values,
so the core half-open interval and inclusive expiry behavior are not silently weakened to PostgreSQL's
microsecond timestamp precision.

## Behavior and deployment boundary

- Writes, reads and explicit purge lazily remove rows whose receipt age has reached configured retention.
- Receipt time comes from the repository clock; caller-controlled event timestamps never extend retention.
- Queries use prepared exact-match predicates and half-open exact decision-time bounds, order by insertion
  sequence descending, apply the validated core limit, and return immutable snapshots.
- Duplicate decision IDs remain separate records. Concurrent JDBC writes are supported by PostgreSQL.
- JDBC/parser/corrupt-row failures become fixed-message `TraceStorageException` instances without causes,
  connection URLs, SQL, labels or driver diagnostics. The core firewall still suppresses sink failures.
- The constructor does not run DDL. This avoids hidden database mutation and requires explicit startup migration.

There is no row-capacity limit, tenant column, row-level security, encryption policy, pooling,
availability metric, partitioning, backup/WORM guarantee or scheduled purge. The caller owns a hardened
`DataSource`, TLS/channel-binding settings, least-privilege database role, pool timeouts, migration role,
tenant routing and retention scheduling. The migration currently grants no privileges; do not run the
application routinely as the test superuser.

## Verification and evidence

The explicit `postgres,containers` profiles start the digest-pinned official image on a random
127.0.0.1 port, with no host data mount:

```text
postgres:17.11-alpine3.23@sha256:9ae4e8f8d0284836a505f0b2e825144e32e20499856e7dc5f7b99e19d10eedd6
```

Tests cover round trips, all filter types, insertion ordering, SQL-like labels through prepared
statements, exact nanosecond intervals, persistence across repository instances, receipt retention,
30 concurrent writes, immutable results, migration concurrency/idempotence/checksum/future-version
rejection, and sanitized connection failures. Docker absence with `--containers` is a failure, not a skip.

Run `bash scripts/verify-open-agent-auth.sh --offline --containers` after Maven dependencies and
images are cached. Maven offline mode does not prevent Docker from pulling a missing image.

Primary evidence:

- The [official PostgreSQL image](https://hub.docker.com/_/postgres) documents initialization and warns
  against trust authentication. Tests set a password; production authentication/TLS remain caller-owned.
- [pgJDBC 42.7.13](https://jdbc.postgresql.org/changelogs/2026-07-06-42.7.13-release/) is the current
  maintenance release inspected on 2026-09-05.
- [pgJDBC 42.7.12](https://jdbc.postgresql.org/changelogs/2026-06-29-42.7.12-release/) documents a
  channel-binding downgrade fix. Selecting 42.7.13 is confirmed; secure connection configuration is not.

No upstream Open Agent Auth issue/PR proposes this independent trace backend. The issue/PR history was
refreshed on 2026-09-04 for the preceding work; repository activity and maintainer intent remain unclear.
