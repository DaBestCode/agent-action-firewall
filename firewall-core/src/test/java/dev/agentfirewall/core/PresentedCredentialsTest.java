/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PresentedCredentialsTest {
    @Test
    void stringRepresentationNeverContainsRawTokens() {
        PresentedCredentials credentials = new PresentedCredentials(
                "secret-aoat", "secret-wit", "secret-wpt");

        String rendered = credentials.toString();

        assertFalse(rendered.contains("secret-aoat"));
        assertFalse(rendered.contains("secret-wit"));
        assertFalse(rendered.contains("secret-wpt"));
        assertTrue(rendered.contains("[REDACTED]"));
    }
}

