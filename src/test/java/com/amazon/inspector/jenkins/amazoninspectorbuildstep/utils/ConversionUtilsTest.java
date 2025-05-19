package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.TestUtils;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.Map;

public class ConversionUtilsTest {
    SbomData sbomData;

    @Before
    public void setUp() throws IOException {
        String str = TestUtils.readStringFromFile("src/test/resources/data/SbomOutputExampleUbuntu.json");
        sbomData = TestUtils.getSbomDataFromString(str);
    }

    @Test
    public void testGetSeverities() {
        SeverityCounts severityCounts = new SeverityCounts();

        for (Vulnerability vulnerability : sbomData.getSbom().getVulnerabilities()) {
            Severity severity = ConversionUtils.getSeverity(vulnerability);
            severityCounts.increment(severity);
        }

        Map<Severity, Integer> severityMap = severityCounts.getCounts();
        Assert.assertEquals(Integer.valueOf(47), severityMap.get(Severity.CRITICAL));
        Assert.assertEquals(Integer.valueOf(214), severityMap.get(Severity.HIGH));
        Assert.assertEquals(Integer.valueOf(110), severityMap.get(Severity.MEDIUM));
        Assert.assertEquals(Integer.valueOf(9), severityMap.get(Severity.LOW));
        Assert.assertEquals(Integer.valueOf(0), severityMap.get(Severity.OTHER));
    }
}
