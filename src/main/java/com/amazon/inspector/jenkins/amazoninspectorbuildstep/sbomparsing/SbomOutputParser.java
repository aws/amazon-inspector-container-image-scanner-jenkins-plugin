package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing;

import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Getter;

import java.util.List;

@SuppressFBWarnings
@Getter
public class SbomOutputParser {
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
