package io.jenkins.plugins.awsinspectorbuildstep;

import lombok.Getter;

import java.util.Map;

import static io.jenkins.plugins.awsinspectorbuildstep.Severity.CRITICAL;
import static io.jenkins.plugins.awsinspectorbuildstep.Severity.HIGH;
import static io.jenkins.plugins.awsinspectorbuildstep.Severity.LOW;
import static io.jenkins.plugins.awsinspectorbuildstep.Severity.MEDIUM;

public class Results {

    @Getter
    private Map<Severity, Integer> counts = Map.of(
            CRITICAL, 0,
            HIGH, 0,
            MEDIUM, 0,
            LOW, 0
    );

    public Results() {}

    public void increment(Severity severityToIncrement) {
        counts.get(severityToIncrement);
    }
}
