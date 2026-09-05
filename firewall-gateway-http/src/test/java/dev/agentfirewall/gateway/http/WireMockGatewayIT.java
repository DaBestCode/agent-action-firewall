/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.gateway.http;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit opt-in: never skips a requested container run when Docker is unavailable. */
class WireMockGatewayIT {
    private static final String IMAGE = "wiremock/wiremock:3.13.1@sha256:d61e7720f89483fdef5366843b58d1dfd06bcce5828179c9f2f54de5c28354b0";

    @Test void signedRequestsReachIsolatedDownstreamOnlyAfterAllowance() throws Exception {
        try (var wiremock = new GenericContainer<>(DockerImageName.parse(IMAGE))
                .withExposedPorts(8080)
                .withCreateContainerCmdModifier(command -> command.getHostConfig().withPortBindings(
                        new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(8080))))
                .waitingFor(Wait.forHttp("/__admin/mappings").forStatusCode(200))
                .withStartupTimeout(Duration.ofSeconds(60))) {
            wiremock.start();
            assertEquals("127.0.0.1", wiremock.getContainerInfo().getNetworkSettings().getPorts()
                    .getBindings().get(new ExposedPort(8080))[0].getHostIp());
            String origin = "http://" + wiremock.getHost() + ":" + wiremock.getMappedPort(8080);
            var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            String mapping = """
                    {"request":{"method":"POST","url":"/purchase"},
                     "response":{"status":200,"headers":{"Content-Type":"application/json"},"body":"{\\"amount\\":5}"}}
                    """;
            assertEquals(201, post(client, origin + "/__admin/mappings", mapping).statusCode());
            ProtectedServiceTest.verifyFlow(URI.create(origin + "/purchase"));
            var received = client.send(HttpRequest.newBuilder(URI.create(origin + "/__admin/requests"))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, received.statusCode());
            var requests = new ObjectMapper().readTree(received.body()).get("requests");
            assertEquals(1, requests.size(), "Denied and replayed requests must never reach WireMock");
            var request = requests.get(0).get("request");
            assertEquals("/purchase", request.get("url").asText());
            assertEquals("{\"amount\":5}", request.get("body").asText());
            request.get("headers").fieldNames().forEachRemaining(name -> {
                assertFalse(name.toLowerCase(java.util.Locale.ROOT).startsWith("x-agent-"));
                assertFalse(name.equalsIgnoreCase("Authorization"));
                assertFalse(name.equalsIgnoreCase("Cookie"));
            });
        }
    }

    private static HttpResponse<String> post(HttpClient client, String url, String json) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(json)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
