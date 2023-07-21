package io.jenkins.plugins.awsinspectorbuildstep.sbomparsing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class SeverityTest {
    @Test
    public void testGetHigherSeverity_Normal() {
        assertEquals(Severity.getHigherSeverity(Severity.CRITICAL, Severity.HIGH), Severity.CRITICAL);
        assertEquals(Severity.getHigherSeverity(Severity.HIGH, Severity.MEDIUM), Severity.HIGH);
        assertEquals(Severity.getHigherSeverity(Severity.MEDIUM, Severity.LOW), Severity.MEDIUM);
        assertEquals(Severity.getHigherSeverity(Severity.LOW, Severity.NONE), Severity.LOW);
        assertEquals(Severity.getHigherSeverity(Severity.NONE, Severity.LOW), Severity.LOW);
        assertEquals(Severity.getHigherSeverity(Severity.HIGH, Severity.CRITICAL), Severity.CRITICAL);
        assertEquals(Severity.getHigherSeverity(Severity.MEDIUM, Severity.HIGH), Severity.HIGH);
        assertEquals(Severity.getHigherSeverity(Severity.LOW, Severity.MEDIUM), Severity.MEDIUM);
        assertEquals(Severity.getHigherSeverity(Severity.NONE, Severity.LOW), Severity.LOW);
    }

    @Test
    public void testGetSeverityFromString_Normal() {
        assertEquals(Severity.getSeverityFromString("critical"), Severity.CRITICAL);
        assertEquals(Severity.getSeverityFromString("high"), Severity.HIGH);
        assertEquals(Severity.getSeverityFromString("medium"), Severity.MEDIUM);
        assertEquals(Severity.getSeverityFromString("low"), Severity.LOW);

        assertThrows(RuntimeException.class, () -> Severity.getSeverityFromString("invalid"));
    }
}
