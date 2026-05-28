package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class SbomOutputParserTest {

    @Test
    void testGetHighestRatingFromList_Successful() {
        List<Rating> ratings = List.of(
                Rating.builder().severity(Severity.HIGH.name()).build(),
                Rating.builder().severity(Severity.LOW.name()).build());

        assertEquals(Severity.HIGH, new SbomOutputParser(null).getHighestRatingFromList(ratings));
    }

    @Test
    void testGetHighestRatingFromList_EmptyRatings() {
        assertEquals(Severity.OTHER, new SbomOutputParser(null).getHighestRatingFromList(null));
        assertEquals(Severity.OTHER, new SbomOutputParser(null).getHighestRatingFromList(List.of()));
    }

    @Test
    void testParseSbom_Successful() {
        SbomData sbomData = SbomData.builder().sbom(Sbom.builder().vulnerabilities(
                List.of(Vulnerability.builder().id("CVE").ratings(
                        List.of(
                                Rating.builder().severity(Severity.CRITICAL.name()).build(),
                                Rating.builder().severity(Severity.LOW.name()).build()
                        )).build()
                )
        ).build()).build();
        SeverityCounts severityCounts = new SeverityCounts();
        severityCounts.increment(Severity.CRITICAL);
        SbomOutputParser parser = new SbomOutputParser(sbomData);
        parser.parseVulnCounts();
        assertEquals(SbomOutputParser.aggregateCounts.getCounts(), severityCounts.getCounts());
    }
}
