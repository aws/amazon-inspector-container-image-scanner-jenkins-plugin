package com.amazon.inspector.jenkins.sbomparsing;

import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.models.sbom.SbomData;
import lombok.Getter;

import java.util.List;

public class SbomOutputParser {
    @Getter
    private SbomData sbom;

    public SbomOutputParser(SbomData sbomData) {
        this.sbom = sbomData;
    }

    public SeverityCounts parseSbom() {
        SeverityCounts severityCounts = new SeverityCounts();
        List<Vulnerability> vulnerabilities = sbom.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return severityCounts;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            List<Rating> ratings = vulnerability.getRatings();

            Severity severity = getHighestRatingFromList(ratings);
            severityCounts.increment(severity);
        }

        return severityCounts;
    }

    @VisibleForTesting
    protected Severity getHighestRatingFromList(List<Rating> ratings) {
        Severity highestSeverity = null;

        if (ratings == null || ratings.size() == 0) {
            return Severity.NONE;
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
