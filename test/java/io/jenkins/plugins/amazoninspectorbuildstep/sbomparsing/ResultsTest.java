package io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing;

import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.assertEquals;

public class ResultsTest {
    @Test
    public void testIncrementAll_Normal() {
        Results results = new Results();

        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.CRITICAL)), Optional.of(0));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.HIGH)), Optional.of(0));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.MEDIUM)), Optional.of(0));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.LOW)), Optional.of(0));

        results.increment(Severity.CRITICAL);
        results.increment(Severity.HIGH);
        results.increment(Severity.MEDIUM);
        results.increment(Severity.LOW);

        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.CRITICAL)), Optional.of(1));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.HIGH)), Optional.of(1));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.MEDIUM)), Optional.of(1));
        assertEquals(Optional.ofNullable(results.getCounts().get(Severity.LOW)), Optional.of(1));
    }
}
