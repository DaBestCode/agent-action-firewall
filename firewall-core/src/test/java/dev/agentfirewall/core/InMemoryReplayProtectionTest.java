/* SPDX-License-Identifier: Apache-2.0 */
package dev.agentfirewall.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

class InMemoryReplayProtectionTest {
    private static final Instant NOW = Instant.parse("2026-09-01T12:00:00Z");
    private static final ReplayKey KEY = new ReplayKey("https://issuer.example", "token-1");

    @Test
    void acceptsOnceThenDetectsReplay() {
        InMemoryReplayProtection protection = new InMemoryReplayProtection(
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(ReplayCheckResult.ACCEPTED,
                protection.checkAndStore(KEY, NOW.plusSeconds(60)));
        assertEquals(ReplayCheckResult.REPLAYED,
                protection.checkAndStore(KEY, NOW.plusSeconds(120)));
        assertEquals(1, protection.size());
    }

    @Test
    void rejectsAlreadyExpiredEvidenceWithoutStoringIt() {
        InMemoryReplayProtection protection = new InMemoryReplayProtection(
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(ReplayCheckResult.EXPIRED, protection.checkAndStore(KEY, NOW));
        assertEquals(0, protection.size());
    }

    @Test
    void permitsReuseOnlyAfterClaimExpiresAndSupportsCleanup() {
        MutableClock clock = new MutableClock(NOW);
        InMemoryReplayProtection protection = new InMemoryReplayProtection(clock);
        assertEquals(ReplayCheckResult.ACCEPTED,
                protection.checkAndStore(KEY, NOW.plusSeconds(30)));
        assertEquals(ReplayCheckResult.REPLAYED,
                protection.checkAndStore(KEY, NOW.plusSeconds(120)));

        clock.advance(Duration.ofSeconds(30));

        assertEquals(1, protection.purgeExpired());
        assertEquals(ReplayCheckResult.ACCEPTED,
                protection.checkAndStore(KEY, NOW.plusSeconds(60)));
    }

    @RepeatedTest(20)
    void atomicallyAcceptsExactlyOneConcurrentClaim() throws Exception {
        int contenders = 32;
        InMemoryReplayProtection protection = new InMemoryReplayProtection(
                Clock.fixed(NOW, ZoneOffset.UTC));
        ExecutorService executor = Executors.newFixedThreadPool(contenders);
        CountDownLatch ready = new CountDownLatch(contenders);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<ReplayCheckResult>> results = new ArrayList<>();
        try {
            for (int index = 0; index < contenders; index++) {
                results.add(executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    return protection.checkAndStore(KEY, NOW.plusSeconds(60));
                }));
            }
            ready.await();
            start.countDown();

            long accepted = 0;
            long replayed = 0;
            for (Future<ReplayCheckResult> result : results) {
                if (result.get() == ReplayCheckResult.ACCEPTED) {
                    accepted++;
                } else {
                    replayed++;
                }
            }
            assertEquals(1, accepted);
            assertEquals(contenders - 1, replayed);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void scopesTokenIdentifiersByIssuer() {
        InMemoryReplayProtection protection = new InMemoryReplayProtection(
                Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(ReplayCheckResult.ACCEPTED,
                protection.checkAndStore(KEY, NOW.plusSeconds(60)));
        assertEquals(ReplayCheckResult.ACCEPTED,
                protection.checkAndStore(
                        new ReplayKey("https://other-issuer.example", KEY.tokenId()),
                        NOW.plusSeconds(60)));
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> now;

        private MutableClock(Instant now) {
            this.now = new AtomicReference<>(now);
        }

        private void advance(Duration duration) {
            now.updateAndGet(current -> current.plus(duration));
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }
}
