package io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing;

import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertEquals;

public class SeverityCountsTest {
    @Test
    public void testIncrementAll_Normal() {
        SeverityCounts severityCounts = new SeverityCounts();

        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.CRITICAL)), Optional.of(0));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.HIGH)), Optional.of(0));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.MEDIUM)), Optional.of(0));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.LOW)), Optional.of(0));

        severityCounts.increment(Severity.CRITICAL);
        severityCounts.increment(Severity.HIGH);
        severityCounts.increment(Severity.MEDIUM);
        severityCounts.increment(Severity.LOW);

        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.CRITICAL)), Optional.of(1));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.HIGH)), Optional.of(1));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.MEDIUM)), Optional.of(1));
        assertEquals(Optional.ofNullable(severityCounts.getCounts().get(Severity.LOW)), Optional.of(1));
    }
}
