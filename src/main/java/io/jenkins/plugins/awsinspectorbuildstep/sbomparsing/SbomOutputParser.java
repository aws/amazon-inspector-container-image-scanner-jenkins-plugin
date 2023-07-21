package io.jenkins.plugins.awsinspectorbuildstep.sbomparsing;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.Gson;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.SbomData;

import java.util.List;

public class SbomOutputParser {
    private SbomData sbom;

    public SbomOutputParser(String sbomJson) {
        this.sbom = new Gson().fromJson(sbomJson, SbomData.class);
    }

    public Results parseSbom() {
        Results results = new Results();
        List<Vulnerability> vulnerabilities = sbom.getSbom().getVulnerabilities();

        for (Vulnerability vulnerability : vulnerabilities) {
            List<Rating> ratings = vulnerability.getRatings();

            Severity severity = getHighestRatingFromList(ratings);
            results.increment(severity);
        }

        return results;
    }

    @VisibleForTesting
    protected Severity getHighestRatingFromList(List<Rating> ratings) {
        Severity highestSeverity = null;

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
