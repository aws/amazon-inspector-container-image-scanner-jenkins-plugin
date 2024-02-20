package com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Source;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.google.gson.Gson;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.TestUtils.readStringFromFile;
import static org.junit.Assert.assertEquals;

public class CsvConverterTest {
    SbomData sbomData;
    Vulnerability vulnerability;
    Component component;
    CsvConverter csvConverter;
    private SbomData sbomDataNullVulns = SbomData.builder()
            .sbom(Sbom.builder().vulnerabilities(List.of(Vulnerability.builder().build())).build())
            .build();

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        String testFilePath = "src/test/resources/data/SbomOutputExample.json";
        String sbom = readStringFromFile(testFilePath);
        sbomData = new Gson().fromJson(sbom, SbomData.class);
        vulnerability = sbomData.getSbom().getVulnerabilities().get(0);
        component = sbomData.getSbom().getComponents().get(0);
        csvConverter = new CsvConverter(sbomData);
    }

    @Test
    public void testBuildCsvData_Success() {
        CsvData csvData = csvConverter.buildCsvData(vulnerability, component);

        assertEquals(csvData.getVulnerabilityId(), "CVE-2021-44228");
        assertEquals(csvData.getSeverity(), "critical");
        assertEquals(csvData.getPublished(), "2021-12-10T10:15:00Z");
        assertEquals(csvData.getModified(), "2023-04-03T20:15:00Z");
        assertEquals(csvData.getEpssScore(), "0.97565");
        assertEquals(csvData.getDescription(), "description");
        assertEquals(csvData.getPackageInstalledVersion(), "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1");
        assertEquals(csvData.getPackageFixedVersion(), "2.15.0");
        assertEquals(csvData.getPackagePath(), "N/A");
        assertEquals(csvData.getCwes(), "CWE-400, CWE-20, CWE-502");
        assertEquals(csvData.getExploitAvailable(), "true");
        assertEquals(csvData.getExploitLastSeen(), "2023-03-06T00:00:00Z");
    }

    @Test
    public void testGetSeverity_Success() {
        assertEquals(csvConverter.getSeverity(vulnerability), "critical");
    }

    @Test
    public void testBuildCsvDataLines_Success() {
       List<String[]> lines = csvConverter.buildCsvDataLines();
       assertEquals(Arrays.toString(lines.get(0)), Arrays.toString(new String[] {"Vulnerability ID", "Severity",
               "Published", "Modified", "Description", "Package Installed Version", "Package Fixed Version",
               "Package Path", "EPSS Score", "Exploit Available", "Exploit Last Seen", "CWEs"}));
       assertEquals(Arrays.toString(lines.get(1)), Arrays.toString(new String[] {"CVE-2021-44228", "Critical",
               "2021-12-10T10:15:00Z", "2023-04-03T20:15:00Z", "description",
               "pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1", "2.15.0", "N/A", "0.97565", "true",
               "2023-03-06T00:00:00Z", "CWE-400", "CWE-20", "CWE-502"}));
    }

    @Test
    public void testBuildCsvDataLines_NullVulnerabilities() {
        SbomData sbomData = SbomData.builder()
                .sbom(Sbom.builder().build())
                .build();
        CsvConverter csvConverter = new CsvConverter(sbomData);
        List<String[]> dataLines = csvConverter.buildCsvDataLines();

        assertEquals(dataLines.size(), 1);
    }

    @Test
    public void testGetUpdated_NullVulnerabilities() {
        csvConverter.getUpdated(null);
        String updated = csvConverter.getUpdated(sbomDataNullVulns.getSbom().getVulnerabilities().get(0));

        assertEquals(updated, "N/A");
    }

    @Test
    public void testGetCwes_NullVulnerabilities() {
        csvConverter.getCwesAsString(null);
        String cwes = csvConverter.getCwesAsString(sbomDataNullVulns.getSbom().getVulnerabilities().get(0));

        assertEquals(cwes, "");
    }

    @Test
    public void testGetEpssScore_NullVulnerabilities() {
        csvConverter.getEpssScore(null);
        String epss = csvConverter.getEpssScore(sbomDataNullVulns.getSbom().getVulnerabilities().get(0));

        assertEquals(epss, "N/A");
    }

    @Test
    public void testGetEpssScore_ScoreNotFound() {
        SbomData sbomData = SbomData.builder()
                .sbom(Sbom.builder().vulnerabilities(List.of(Vulnerability.builder().ratings(List.of()).build()))
                        .build())
                .build();

        csvConverter.getEpssScore(null);
        String epss = csvConverter.getEpssScore(sbomData.getSbom().getVulnerabilities().get(0));

        assertEquals(epss, "N/A");
    }

    @Test
    public void testGetPropertyValueFromKey_NullVulnerabilities() {
        assertEquals(csvConverter.getPropertyValueFromKey((Vulnerability) null, null), "N/A");
    }

    @Test
    public void testGetPropertyValueFromKey_ScoreNotFound() {
        SbomData sbomData = SbomData.builder()
                .sbom(Sbom.builder().vulnerabilities(List.of(Vulnerability.builder().properties(List.of()).build()))
                        .build())
                .build();

        String property = csvConverter.getPropertyValueFromKey(sbomData.getSbom().getVulnerabilities().get(0), "");

        assertEquals(property, "N/A");
    }

    @Test
    public void testGetPropertyValueFromKey_Success() {
        Component component = Component.builder().properties(List.of(Property.builder()
                .value("comp")
                .name("comp")
                        .build()))
                .build();
        assertEquals(csvConverter.getPropertyValueFromKey(component, "comp"), "comp");
    }

    @Test
    public void testGetPropertyValueFromKey_ComponentNotFound() {
        Component component = Component.builder().properties(List.of()).build();
        assertEquals(csvConverter.getPropertyValueFromKey(component, "comp"), "N/A");
    }

    @Test
    public void testGetPropertyValueFromKey_NullComponent() {
        assertEquals(csvConverter.getPropertyValueFromKey((Component) null, null), "N/A");
    }


    @Test
    public void testGetSeverity_NullVulnerability() {
        assertEquals(csvConverter.getSeverity((Vulnerability) null), "UNTRIAGED");
        assertEquals(csvConverter.getSeverity(Vulnerability.builder().build()), "UNTRIAGED");
    }

    @Test
    public void testGetSeverity_NoNVD() {
        assertEquals(csvConverter.getSeverity(Vulnerability.builder()
                .ratings(
                        List.of(Rating.builder()
                                        .source(Source.builder().name("").url("").build())
                                        .method("")
                                .severity(Severity.CRITICAL.name()
                        ).build())
                ).build()),
                Severity.CRITICAL.name()
        );
    }
}
