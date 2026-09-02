/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.testkit;

class DeterministicTestEngineContractTest implements AuthorizationEngineContract {
    @Override
    public AuthorizationEngineScenario scenario() {
        return DeterministicTestEngine.scenario();
    }
}
