/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.trace.postgres;

import dev.agentfirewall.core.*;
import java.sql.*;
import java.math.BigDecimal;
import java.time.*;
import java.util.*;
import javax.sql.DataSource;

/** Prepared-statement PostgreSQL repository; connection pooling and tenant routing belong to callers. */
public final class PostgresAuthorizationTraceRepository implements AuthorizationTraceRepository {
    private final DataSource dataSource;
    private final Duration retention;
    private final Clock clock;

    public PostgresAuthorizationTraceRepository(DataSource dataSource, Duration retention, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource); this.clock = Objects.requireNonNull(clock);
        this.retention = Objects.requireNonNull(retention);
        if (retention.isZero() || retention.isNegative()) throw new IllegalArgumentException("retention must be positive");
    }

    @Override public void record(AuthorizationTraceEvent event) {
        Objects.requireNonNull(event, "event must not be null");
        purgeExpired();
        String sql = "INSERT INTO authorization_traces(schema_version,recorded_at,recorded_at_exact,request_id,protocol,operation,resource,"
                + "request_digest,requested_at,requested_at_exact,decision_id,outcome,reason,decided_at,decided_at_exact,policy_ids) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(sql)) {
            int i = 1;
            Instant recordedAt = clock.instant();
            statement.setInt(i++, TraceRecord.CURRENT_VERSION); statement.setObject(i++, utc(recordedAt)); statement.setBigDecimal(i++, exact(recordedAt));
            statement.setString(i++, event.requestId()); statement.setString(i++, event.protocol().name());
            statement.setString(i++, event.operation()); statement.setString(i++, event.resource());
            statement.setString(i++, event.requestDigest()); statement.setObject(i++, utc(event.requestedAt())); statement.setBigDecimal(i++, exact(event.requestedAt()));
            statement.setString(i++, event.decisionId()); statement.setString(i++, event.outcome().name());
            statement.setString(i++, event.reason().name()); statement.setObject(i++, utc(event.decidedAt())); statement.setBigDecimal(i++, exact(event.decidedAt()));
            var policyArray = connection.createArrayOf("varchar", event.policyIds().toArray());
            try { statement.setArray(i, policyArray); statement.executeUpdate(); } finally { policyArray.free(); }
        } catch (SQLException failure) { throw new TraceStorageException(); }
    }

    @Override public List<TraceRecord> find(TraceQuery query) {
        Objects.requireNonNull(query, "query must not be null"); purgeExpired();
        var clauses = new ArrayList<String>(); var values = new ArrayList<Object>();
        add(clauses, values, "request_id = ?", query.requestId());
        add(clauses, values, "protocol = ?", query.protocol() == null ? null : query.protocol().name());
        add(clauses, values, "outcome = ?", query.outcome() == null ? null : query.outcome().name());
        add(clauses, values, "reason = ?", query.reason() == null ? null : query.reason().name());
        add(clauses, values, "decided_at_exact >= ?", query.fromInclusive() == null ? null : exact(query.fromInclusive()));
        add(clauses, values, "decided_at_exact < ?", query.untilExclusive() == null ? null : exact(query.untilExclusive()));
        String sql = "SELECT schema_version,recorded_at_exact,request_id,protocol,operation,resource,request_digest,requested_at_exact,"
                + "decision_id,outcome,reason,decided_at_exact,policy_ids FROM authorization_traces"
                + (clauses.isEmpty() ? "" : " WHERE " + String.join(" AND ", clauses))
                + " ORDER BY sequence_id DESC LIMIT ?";
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement(sql)) {
            int i = 1;
            for (Object value : values) statement.setObject(i++, value);
            statement.setInt(i, query.limit());
            try (var rows = statement.executeQuery()) {
                var records = new ArrayList<TraceRecord>();
                while (rows.next()) records.add(read(rows));
                return List.copyOf(records);
            }
        } catch (SQLException | RuntimeException failure) { throw new TraceStorageException(); }
    }

    @Override public int purgeExpired() {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("DELETE FROM authorization_traces WHERE recorded_at_exact <= ?")) {
            statement.setBigDecimal(1, exact(clock.instant().minus(retention))); return statement.executeUpdate();
        } catch (SQLException | ArithmeticException failure) { throw new TraceStorageException(); }
    }

    private static void add(List<String> clauses, List<Object> values, String clause, Object value) {
        if (value != null) { clauses.add(clause); values.add(value); }
    }
    private static TraceRecord read(ResultSet row) throws SQLException {
        var array = row.getArray(13);
        try {
            var policies = Arrays.asList((String[]) array.getArray());
            var event = new AuthorizationTraceEvent(row.getString(3), ActionProtocol.valueOf(row.getString(4)), row.getString(5),
                    row.getString(6), row.getString(7), instant(row.getBigDecimal(8)), row.getString(9),
                    AuthorizationOutcome.valueOf(row.getString(10)), AuthorizationReason.valueOf(row.getString(11)),
                    instant(row.getBigDecimal(12)), policies);
            return new TraceRecord(row.getInt(1), instant(row.getBigDecimal(2)), event);
        } finally { array.free(); }
    }
    private static OffsetDateTime utc(Instant instant) { return instant.atOffset(ZoneOffset.UTC); }
    private static BigDecimal exact(Instant instant) {
        return BigDecimal.valueOf(instant.getEpochSecond()).add(BigDecimal.valueOf(instant.getNano(), 9));
    }
    private static Instant instant(BigDecimal value) {
        BigDecimal[] parts = value.divideAndRemainder(BigDecimal.ONE);
        return Instant.ofEpochSecond(parts[0].longValueExact(), parts[1].movePointRight(9).longValueExact());
    }
}
