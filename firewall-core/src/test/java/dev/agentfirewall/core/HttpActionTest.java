/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class HttpActionTest {
    @Test
    void normalizesSecurityRelevantHttpMetadata() {
        HttpAction action = new HttpAction(
                "post",
                URI.create("HTTPS://Example.COM:443/a/../purchases?currency=USD"),
                " application/json ",
                "{}".getBytes(StandardCharsets.UTF_8));

        assertEquals(ActionProtocol.HTTP, action.protocol());
        assertEquals("POST", action.operation());
        assertEquals("https://example.com/purchases", action.resource());
        assertEquals("https://example.com/purchases?currency=USD", action.target());
        assertEquals("application/json", action.mediaType());
    }

    @Test
    void protectsBodyFromMutation() {
        byte[] body = {1, 2, 3};
        HttpAction action = new HttpAction("POST", URI.create("https://example.com/actions"), null, body);
        body[0] = 9;
        byte[] returned = action.body();
        returned[1] = 9;

        assertArrayEquals(new byte[] {1, 2, 3}, action.body());
    }

    @Test
    void rejectsAmbiguousOrNonHttpTargets() {
        assertThrows(IllegalArgumentException.class,
                () -> new HttpAction("GET", URI.create("/relative"), null, new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new HttpAction("GET", URI.create("https://user@example.com/action"), null, new byte[0]));
        assertThrows(IllegalArgumentException.class,
                () -> new HttpAction("GET", URI.create("https://example.com/action#fragment"), null, new byte[0]));
    }
}
