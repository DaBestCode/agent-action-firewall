/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.protocol.mcp;

/** Redacted transport result. Response bytes are never included in toString. */
public final class McpProxyResult {
    public enum Status { FORWARDED, REJECTED, MALFORMED, DOWNSTREAM_FAILURE }
    private final Status status;
    private final byte[] response;
    private final String decisionId;

    McpProxyResult(Status status, byte[] response, String decisionId) {
        this.status = status; this.response = response.clone(); this.decisionId = decisionId;
    }
    public Status status() { return status; }
    public byte[] response() { return response.clone(); }
    public String decisionId() { return decisionId; }
    @Override public String toString() { return "McpProxyResult[status=" + status + ", response=redacted]"; }
}
