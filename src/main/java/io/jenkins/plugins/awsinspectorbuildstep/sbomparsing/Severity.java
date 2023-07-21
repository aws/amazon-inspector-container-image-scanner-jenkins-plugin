package io.jenkins.plugins.awsinspectorbuildstep;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public enum Severity {
    CRITICAL("critical", 4),
    HIGH("high", 3),
    MEDIUM("medium", 2),
    LOW("low", 1),
    NONE("none", 0);

    private String severityName;
    private int rating;

    public static Severity getHigherSeverity(Severity sevLeft, Severity sevRight) {
        if (sevLeft.rating > sevRight.rating) {
            return sevLeft;
        }
        return sevRight;
    }

    public static Severity getSeverityFromString(String severityName) {
        switch (severityName) {
            case "critical":
                return CRITICAL;
            case "high":
                return HIGH;
            case "medium":
                return MEDIUM;
            case "low":
                return LOW;
            default:
                throw new RuntimeException("Severity value doesn't exist!");
        }
    }
}
