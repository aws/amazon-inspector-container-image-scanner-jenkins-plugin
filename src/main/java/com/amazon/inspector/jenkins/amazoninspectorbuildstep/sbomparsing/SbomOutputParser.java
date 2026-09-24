package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing;

import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import lombok.Getter;

import java.util.List;

@Getter
public class SbomOutputParser {
    private static final String MALICIOUS_PACKAGES_PROPERTY = "amazon:inspector:sbom_scanner:malicious_packages";

    private final SbomData sbom;
    private final SeverityCounts vulnCounts = new SeverityCounts();
    private final SeverityCounts dockerCounts = new SeverityCounts();
    private final SeverityCounts aggregateCounts = new SeverityCounts();

    public SbomOutputParser(SbomData sbomData) {
        this.sbom = sbomData;
    }

    public void parseVulnCounts() {
        List<Vulnerability> vulnerabilities = sbom.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            List<Rating> ratings = vulnerability.getRatings();

            Severity severity = getHighestRatingFromList(ratings);

            if (vulnerability.getId().contains("IN-DOCKER")) {
                dockerCounts.increment(severity);
            } else {
                vulnCounts.increment(severity);
            }
            aggregateCounts.increment(severity);
        }
    }

    public Integer getMaliciousPackageCount() {
        Sbom scanResult = sbom.getSbom();
        if (scanResult == null || scanResult.getMetadata() == null
                || scanResult.getMetadata().getProperties() == null) {
            return null;
        }

        for (Property property : scanResult.getMetadata().getProperties()) {
            if (property != null && MALICIOUS_PACKAGES_PROPERTY.equals(property.getName())) {
                return parseCount(property.getValue());
            }
        }
        return null;
    }

    private static Integer parseCount(String value) {
        if (value == null) {
            return null;
        }
        try {
            int count = Integer.parseInt(value.trim());
            if (count < 0) {
                return null;
            }
            return count;
        } catch (NumberFormatException e) {
            return null;
        }
    }


    @VisibleForTesting
    protected Severity getHighestRatingFromList(List<Rating> ratings) {
        Severity highestSeverity = null;

        if (ratings == null || ratings.size() == 0) {
            return Severity.OTHER;
        }

        for (Rating rating : ratings) {
            Severity severity = Severity.getSeverityFromString(rating.getSeverity());

            if (highestSeverity == null) {
                highestSeverity = severity;
            }

            highestSeverity = Severity.getHigherSeverity(highestSeverity, severity);
        }

        return highestSeverity;
    }
}
