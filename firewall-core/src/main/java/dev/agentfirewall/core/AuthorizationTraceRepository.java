/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import java.util.List;

/** Trace write/query boundary; consumers never receive a request or raw credentials. */
public interface AuthorizationTraceRepository extends AuthorizationTraceSink {
    /** Immutable snapshot in newest-insertion-first order; equal event times remain deterministic. */
    List<TraceRecord> find(TraceQuery query);

    /** Removes records whose receipt age is at least the configured retention duration. */
    int purgeExpired();
}
