/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.gateway.http;

import jakarta.servlet.DispatcherType;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;

/** Explicit Boot registration: no auto-created allow-all engine or unprotected health route. */
public final class FirewallRegistration {
    private FirewallRegistration() { }

    /** Register the returned object as a bean in a dedicated, stateless resource-server application. */
    public static FilterRegistrationBean<ActionFirewallFilter> allRoutes(ActionFirewallFilter filter) {
        var registration = new FilterRegistrationBean<>(filter);
        registration.setName("agentActionFirewall");
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setDispatcherTypes(java.util.EnumSet.allOf(DispatcherType.class));
        registration.setAsyncSupported(false);
        return registration;
    }
}
