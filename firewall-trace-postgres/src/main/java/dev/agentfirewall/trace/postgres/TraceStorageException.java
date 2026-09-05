/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.trace.postgres;

/** Fixed-message boundary that deliberately does not retain JDBC exceptions or connection details. */
public final class TraceStorageException extends RuntimeException {
    TraceStorageException() { super("PostgreSQL trace operation failed"); }
}
