/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.trace.postgres;

import com.github.dockerjava.api.model.*;
import dev.agentfirewall.core.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import static org.junit.jupiter.api.Assertions.*;

class PostgresAuthorizationTraceRepositoryIT {
    private static final String IMAGE = "postgres:17.11-alpine3.23@sha256:9ae4e8f8d0284836a505f0b2e825144e32e20499856e7dc5f7b99e19d10eedd6";
    private PostgreSQLContainer postgres;
    private PGSimpleDataSource dataSource;
    private MutableClock clock;

    @BeforeEach void start() {
        postgres = new PostgreSQLContainer(DockerImageName.parse(IMAGE).asCompatibleSubstituteFor("postgres")).withDatabaseName("firewall")
                .withUsername("firewall").withPassword("test-only-password")
                .withCreateContainerCmdModifier(command -> command.getHostConfig().withPortBindings(
                        new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(5432))));
        postgres.start();
        assertEquals("127.0.0.1", postgres.getContainerInfo().getNetworkSettings().getPorts()
                .getBindings().get(new ExposedPort(5432))[0].getHostIp());
        dataSource = new PGSimpleDataSource(); dataSource.setURL(postgres.getJdbcUrl());
        dataSource.setUser(postgres.getUsername()); dataSource.setPassword(postgres.getPassword());
        clock = new MutableClock(Instant.parse("2026-09-05T12:00:00.123456Z"));
        PostgresTraceMigrations.apply(dataSource);
    }
    @AfterEach void stop() { if (postgres != null && postgres.isRunning()) postgres.stop(); }

    @Test void persistsRoundTripsFiltersOrdersAndUsesPreparedStatements() throws Exception {
        var repository = new PostgresAuthorizationTraceRepository(dataSource, Duration.ofHours(1), clock);
        var first = event("request'; DROP TABLE authorization_traces;--", ActionProtocol.HTTP,
                AuthorizationOutcome.ALLOW, AuthorizationReason.POLICY_MATCHED, clock.instant(), List.of("policy-a"));
        repository.record(first); clock.advance(Duration.ofSeconds(1));
        var second = event("request-2", ActionProtocol.MCP, AuthorizationOutcome.DENY,
                AuthorizationReason.POLICY_DENIED, clock.instant(), List.of());
        repository.record(second);
        assertEquals(List.of(second, first), repository.find(TraceQuery.latest(10)).stream().map(TraceRecord::event).toList());
        assertEquals(first, new PostgresAuthorizationTraceRepository(dataSource, Duration.ofHours(1), clock)
                .find(new TraceQuery(first.requestId(), ActionProtocol.HTTP, AuthorizationOutcome.ALLOW,
                        AuthorizationReason.POLICY_MATCHED, first.decidedAt(), first.decidedAt().plusNanos(1), 2)).get(0).event());
        try (var connection = dataSource.getConnection(); var result = connection.createStatement()
                .executeQuery("SELECT COUNT(*) FROM authorization_traces")) {
            assertTrue(result.next()); assertEquals(2, result.getInt(1));
        }
    }

    @Test void expiresByReceiptTimeAndNeverByAttackerControlledEventTimes() {
        var repository = new PostgresAuthorizationTraceRepository(dataSource, Duration.ofMinutes(5), clock);
        repository.record(event("future", ActionProtocol.HTTP, AuthorizationOutcome.DENY,
                AuthorizationReason.POLICY_DENIED, clock.instant().plus(Duration.ofDays(99)), List.of()));
        clock.advance(Duration.ofMinutes(5));
        assertTrue(repository.find(TraceQuery.latest(10)).isEmpty());
        assertEquals(0, repository.purgeExpired());
    }

    @Test void concurrentWritesRetainDuplicateDecisionIdsAndReturnImmutableSnapshots() throws Exception {
        var repository = new PostgresAuthorizationTraceRepository(dataSource, Duration.ofHours(1), clock);
        var executor = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Void>> writes = new ArrayList<>();
            for (int i = 0; i < 30; i++) { int id = i; writes.add(() -> {
                repository.record(event("request-" + id, ActionProtocol.MCP, AuthorizationOutcome.ALLOW,
                        AuthorizationReason.POLICY_MATCHED, clock.instant(), List.of("policy"))); return null; }); }
            for (var result : executor.invokeAll(writes)) result.get();
        } finally { executor.shutdownNow(); }
        var records = repository.find(TraceQuery.latest(100));
        assertEquals(30, records.size()); assertThrows(UnsupportedOperationException.class, records::clear);
        assertEquals(30, records.stream().map(record -> record.event().decisionId()).filter("shared-decision"::equals).count());
    }

    @Test void migrationsAreIdempotentSerializedAndDetectTamperingOrFutureSchemas() throws Exception {
        var executor = Executors.newFixedThreadPool(4);
        try {
            var calls = List.of((Callable<Void>) () -> { PostgresTraceMigrations.apply(dataSource); return null; },
                    () -> { PostgresTraceMigrations.apply(dataSource); return null; },
                    () -> { PostgresTraceMigrations.apply(dataSource); return null; });
            for (var result : executor.invokeAll(calls)) result.get();
        } finally { executor.shutdownNow(); }
        String checksum;
        try (var connection = dataSource.getConnection(); var result = connection.createStatement()
                .executeQuery("SELECT checksum FROM firewall_schema_migrations WHERE version = 1")) {
            assertTrue(result.next()); checksum = result.getString(1);
        }
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE firewall_schema_migrations SET checksum = repeat('0', 64) WHERE version = 1");
        }
        var exception = assertThrows(TraceStorageException.class, () -> PostgresTraceMigrations.apply(dataSource));
        assertNull(exception.getCause()); assertFalse(exception.toString().contains(postgres.getPassword()));
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.executeUpdate("UPDATE firewall_schema_migrations SET checksum = '" + checksum + "' WHERE version = 1");
            statement.executeUpdate("INSERT INTO firewall_schema_migrations(version, checksum) VALUES (2, repeat('2', 64))");
        }
        assertThrows(TraceStorageException.class, () -> PostgresTraceMigrations.apply(dataSource));
    }

    @Test void jdbcFailuresAreSanitized() {
        postgres.stop();
        var repository = new PostgresAuthorizationTraceRepository(dataSource, Duration.ofMinutes(1), clock);
        for (Runnable operation : new Runnable[] {() -> repository.record(event("request", ActionProtocol.HTTP,
                AuthorizationOutcome.DENY, AuthorizationReason.POLICY_DENIED, clock.instant(), List.of())),
                () -> repository.find(TraceQuery.latest(1)), repository::purgeExpired}) {
            var failure = assertThrows(TraceStorageException.class, operation::run);
            assertNull(failure.getCause()); assertEquals("PostgreSQL trace operation failed", failure.getMessage());
        }
    }

    private static AuthorizationTraceEvent event(String requestId, ActionProtocol protocol, AuthorizationOutcome outcome,
            AuthorizationReason reason, Instant time, List<String> policies) {
        return new AuthorizationTraceEvent(requestId, protocol, protocol == ActionProtocol.HTTP ? "POST" : "tools/call",
                protocol == ActionProtocol.HTTP ? "https://service.example/path" : "inventory/buy",
                "sha256:" + "a".repeat(64), time, "shared-decision", outcome, reason, time, policies);
    }
    private static final class MutableClock extends Clock {
        private Instant instant;
        MutableClock(Instant instant) { this.instant = instant; }
        void advance(Duration duration) { instant = instant.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
