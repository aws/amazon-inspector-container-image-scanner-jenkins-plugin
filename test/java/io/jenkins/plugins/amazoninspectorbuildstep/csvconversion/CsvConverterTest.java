package io.jenkins.plugins.amazoninspectorbuildstep.csvconversion;

import com.google.gson.Gson;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.util.List;

import static io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.SbomOutputParserTest.readStringFromFile;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CsvConverterTest {
    SbomData sbomData;
    Vulnerability vulnerability;
    Component component;
    CsvConverter csvConverter;

    @Before
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        String testFilePath = "test/data/SbomOutputExample.json";
        String sbom = readStringFromFile(testFilePath);
        sbomData = new Gson().fromJson(sbom, SbomData.class);
        vulnerability = sbomData.getSbom().getVulnerabilities().get(0);
        component = sbomData.getSbom().getComponents().get(0);
        csvConverter = new CsvConverter(System.out, sbomData);
    }

    @Test
    public void testBuildCsvData_Success() {
        CsvData csvData = csvConverter.buildCsvData(vulnerability, component);

        assertEquals(csvData.getCve(), "CVE-2021-44228");
        assertEquals(csvData.getDescription(), "\"description\"");
        assertEquals(csvData.getSeverity(), "critical");
        assertEquals(csvData.getExploitAvailable(), "\"true\"");
        assertEquals(csvData.getPackageFixedVersion(), "2.15.0");
        assertEquals(csvData.getPackageInstalledVersion(), "2.12.1");
        assertEquals(csvData.getPackageName(), "log4j-core");
    }

    @Test
    public void testGetExploitAvailable_Success() {
        assertTrue(Boolean.parseBoolean(csvConverter.getExploitAvailable(vulnerability)));
    }

    @Test
    public void testGetFixedVersion_Success() {
        assertEquals(csvConverter.getFixedVersion(vulnerability, "comp-1"), "2.15.0");
    }

    @Test
    public void testGetFixedVersion_ThrowsRuntimeException() {
        assertThrows(RuntimeException.class, () -> csvConverter.getFixedVersion(vulnerability, "key"));
    }


    @Test
    public void testGetInstalledVersion_Success() {
        assertEquals(csvConverter.getInstalledVersion(component), "2.12.1");
    }

    @Test
    public void testGetInstalledVersion_ThrowsRuntimeException() {
        Component invalidComponent = Component.builder().purl("").build();
        assertThrows(RuntimeException.class, () ->  csvConverter.getInstalledVersion(invalidComponent));
    }

    @Test
    public void testGetSeverity_Success() {
        assertEquals(csvConverter.getSeverity(vulnerability), "critical");
    }

    @Test
    public void testBuildCsvDataLines() {
       List<List<String>> lines = csvConverter.buildCsvDataLines();
       assertEquals(lines.get(0), List.of("CVE", "Severity", "Description", "Package Name",
               "Package Installed Version", "Package Fixed Version", "Exploit Available"));
       assertEquals(lines.get(1), List.of("CVE-2021-44228", "critical", "\"description\"",
                "log4j-core", "2.12.1", "2.15.0", "\"true\""));

    }
}
