/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.trace.postgres;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.HexFormat;
import javax.sql.DataSource;

/** Minimal append-only migration runner for this module's one reviewed schema. */
public final class PostgresTraceMigrations {
    private static final int VERSION = 1;
    private static final String RESOURCE = "/db/migration/V001__authorization_traces.sql";
    private PostgresTraceMigrations() { }

    public static void apply(DataSource dataSource) {
        try (var connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                try (var statement = connection.createStatement()) {
                    statement.execute("SELECT pg_advisory_xact_lock(2140815521)");
                    statement.execute("CREATE TABLE IF NOT EXISTS firewall_schema_migrations "
                            + "(version INTEGER PRIMARY KEY, checksum CHAR(64) NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)");
                }
                byte[] sql = resource();
                String checksum = sha256(sql);
                try (var versions = connection.createStatement().executeQuery("SELECT COALESCE(MAX(version), 0) FROM firewall_schema_migrations")) {
                    if (!versions.next() || versions.getInt(1) > VERSION) throw new TraceStorageException();
                }
                try (var query = connection.prepareStatement("SELECT checksum FROM firewall_schema_migrations WHERE version = ?")) {
                    query.setInt(1, VERSION);
                    try (var result = query.executeQuery()) {
                        if (result.next()) {
                            if (!checksum.equals(result.getString(1))) throw new TraceStorageException();
                            connection.commit(); return;
                        }
                    }
                }
                try (var statement = connection.createStatement()) {
                    statement.execute(new String(sql, StandardCharsets.UTF_8));
                }
                try (var insert = connection.prepareStatement("INSERT INTO firewall_schema_migrations(version, checksum) VALUES (?, ?)")) {
                    insert.setInt(1, VERSION); insert.setString(2, checksum); insert.executeUpdate();
                }
                connection.commit();
            } catch (Exception failure) {
                try { connection.rollback(); } catch (SQLException ignored) { }
                if (failure instanceof TraceStorageException known) throw known;
                throw new TraceStorageException();
            }
        } catch (SQLException failure) { throw new TraceStorageException(); }
    }

    private static byte[] resource() throws Exception {
        try (InputStream input = PostgresTraceMigrations.class.getResourceAsStream(RESOURCE)) {
            if (input == null) throw new IllegalStateException();
            return input.readAllBytes();
        }
    }
    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
