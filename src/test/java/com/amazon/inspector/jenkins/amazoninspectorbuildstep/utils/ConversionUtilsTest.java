package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.TestUtils;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.Map;

class ConversionUtilsTest {

    private SbomData sbomData;

    @BeforeEach
    void beforeEach() throws IOException {
        String str = TestUtils.readStringFromFile("src/test/resources/data/SbomOutputExampleUbuntu.json");
        sbomData = TestUtils.getSbomDataFromString(str);
    }

    @Test
    void testGetSeverities() {
        SeverityCounts severityCounts = new SeverityCounts();

        for (Vulnerability vulnerability : sbomData.getSbom().getVulnerabilities()) {
            Severity severity = ConversionUtils.getSeverity(vulnerability);
            severityCounts.increment(severity);
        }

        Map<Severity, Integer> severityMap = severityCounts.getCounts();
        assertEquals(Integer.valueOf(47), severityMap.get(Severity.CRITICAL));
        assertEquals(Integer.valueOf(214), severityMap.get(Severity.HIGH));
        assertEquals(Integer.valueOf(110), severityMap.get(Severity.MEDIUM));
        assertEquals(Integer.valueOf(9), severityMap.get(Severity.LOW));
        assertEquals(Integer.valueOf(0), severityMap.get(Severity.OTHER));
    }
}
