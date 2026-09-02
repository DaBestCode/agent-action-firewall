# Authorization engine contract kit

`firewall-testkit` is a separate module intended only as a test-scoped dependency. It depends on
`firewall-core` and JUnit's API; core does not depend on it. The deterministic engine does no
cryptographic verification and is not eligible for production use.

A future adapter test adds this dependency:

```xml
<dependency>
    <groupId>dev.agentfirewall</groupId>
    <artifactId>firewall-testkit</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

Implement `AuthorizationEngineContract` in a JUnit test and return a fresh
`AuthorizationEngineScenario` for every invocation:

```java
class ExampleEngineTest implements AuthorizationEngineContract {
    @Override
    public AuthorizationEngineScenario scenario() {
        return DeterministicTestEngine.scenario();
    }
}
```

The example proves the test harness works; it is not an adapter implementation. Real adapters must
replace it with their engine and signed fixtures. Each scenario supplies an authorized action,
invalid credentials, a policy-denied action and an altered-payload binding. Invalid cases must vary
the property under test rather than all reusing an unrelated invalid token.

The six inherited tests check allow, three denial paths, and allow/deny recording through the
firewall. Fresh scenarios avoid accidental reuse of single-use authorization evidence. Sensitivity
tests demonstrate that always-allow and always-deny engines fail the suite.

Passing this contract is necessary but not sufficient. Issuer/audience validation, algorithm
selection, time claims, replay, delegation and signature verification still require adapter-specific
tests and the attack corpus. Core tests separately cover engine exceptions and null returns.
