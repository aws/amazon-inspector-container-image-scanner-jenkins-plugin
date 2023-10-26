package io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.CRITICAL;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.HIGH;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.INFO;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.LOW;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.MEDIUM;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity.NONE;

public class SeverityCounts {

    @Getter
    private Map<Severity, Integer> counts = new HashMap<>();

    public SeverityCounts() {
        counts.put(CRITICAL, 0);
        counts.put(HIGH, 0);
        counts.put(MEDIUM, 0);
        counts.put(INFO, 0);
        counts.put(LOW, 0);
        counts.put(NONE, 0);
    }

    public void increment(Severity severityToIncrement) {
        counts.put(severityToIncrement, counts.get(severityToIncrement) + 1);
    }

    public String toString() {
        return String.format("Critical: %s, High: %s, Medium: %s, Low: %s",
                counts.get(CRITICAL), counts.get(HIGH), counts.get(MEDIUM), counts.get(LOW));
    }
}
