package io.jenkins.plugins.awsinspectorbuildstep;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.Gson;
import io.jenkins.plugins.awsinspectorbuildstep.Sbom.SbomData;

import java.util.List;

public class SbomOutputParser {
    private SbomData sbom;

    public SbomOutputParser(String sbomJson) {
        this.sbom = new Gson().fromJson(sbomJson, SbomData.class);
    }

    public Results parseSbom() {
        Results results = new Results();
        List<SbomData.Vulnerability> vulnerabilities = sbom.getSbom().getVulnerabilities();

        for (SbomData.Vulnerability vulnerability : vulnerabilities) {
            List<SbomData.Rating> ratings = vulnerability.getRatings();

            Severity severity = getHighestSeverityFromList(ratings);
            results.increment(severity);
        }

        return results;
    }

    @VisibleForTesting
    protected Severity getHighestSeverityFromList(List<SbomData.Rating> ratings) {
        Severity highestSeverity = null;

        for (SbomData.Rating rating : ratings) {
            Severity severity = Severity.getSeverityFromString(rating.getSeverity());

            if (highestSeverity == null) {
                highestSeverity = severity;
            }

            highestSeverity = Severity.getHigherSeverity(highestSeverity, severity);
        }

        return highestSeverity;
    }
}
