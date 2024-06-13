package com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.TestUtils;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import com.google.gson.Gson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity.OTHER;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class CsvConverterTest {

    private CsvConverter csvConverter;
    private SbomData sbomData;

    @BeforeEach
    public void setUp() throws IOException {
        sbomData = new Gson().fromJson(TestUtils.readStringFromFile("src/test/resources/data/SbomOutputExample.json"), SbomData.class);
    }

    @Test
    public void convertVulnerabilities_shouldReturnNull_whenNoVulnData() throws IOException {
        csvConverter = new CsvConverter(sbomData);
        SeverityCounts counts = new SeverityCounts();
        assertEquals(null, csvConverter.convertVulnerabilities("imageName", "imageSha", "buildId", counts));
    }

    @Test
    public void convertVulnerabilities_normalBehavior() throws IOException {
        csvConverter = new CsvConverter(sbomData);
        csvConverter.routeVulnerabilities();
        SeverityCounts counts = new SeverityCounts();
        assertEquals(123007, csvConverter.convertVulnerabilities("imageName", "imageSha", "buildId", counts).length());
    }

    @Test
    public void convertDocker_shouldReturnNull_whenNoDockerData() throws IOException {
        csvConverter = new CsvConverter(sbomData);
        SeverityCounts counts = new SeverityCounts();
        assertEquals(null, csvConverter.convertDocker("imageName", "imageSha", "buildId", counts));
    }

    @Test
    public void convertDocker_normalBehavior() throws IOException {
        csvConverter = new CsvConverter(sbomData);
        csvConverter.routeVulnerabilities();
        SeverityCounts counts = new SeverityCounts();
        assertEquals(1320, csvConverter.convertDocker("imageName", "imageSha", "buildId", counts).length());
    }

    @Test
    public void populateComponentMap_shouldReturnEmptyMap_whenSbomDataIsNull() {
        SbomData sbomData = null;
        csvConverter = new CsvConverter(sbomData);
        assertEquals(new HashMap<>(), csvConverter.populateComponentMap(sbomData));
    }

    @Test
    public void populateComponentMap_shouldReturnEmptyMap_whenSbomDataHasNoComponents() {
        sbomData.setSbom(null);
        csvConverter = new CsvConverter(sbomData);
        assertEquals(new HashMap<>(), csvConverter.populateComponentMap(sbomData));
    }

    @Test
    public void routeVulnerabilities_shouldNotThrowException_whenVulnerabilitiesAreNull() {
        csvConverter = new CsvConverter(sbomData);
        csvConverter.routeVulnerabilities(); // No exception expected
    }


    @Test
    public void routeVulnCsvData_vulnListSizes_nonINDOCKERVulnId() {
        csvConverter = new CsvConverter(sbomData);
        Vulnerability vulnerability = Vulnerability.builder().id("123").build();
        Component component = Component.builder().build();
        component.setPurl("InstalledVersion");
        csvConverter.routeVulnCsvData(vulnerability, component);
        assertEquals(1, CsvConverter.vulnData.size());
        assertEquals(0, CsvConverter.dockerData.size());
    }

    @Test
    public void getSeverity_emptyRatingsReturnsOTHER() {
        csvConverter = new CsvConverter(sbomData);
        Vulnerability vulnerability = Vulnerability.builder().ratings(new ArrayList<>()).build();
        assertTrue(csvConverter.getSeverity(vulnerability).equals(OTHER.name()));
    }

    @Test
    public void getProprtyValueFromKey_returnsProperty() {
        csvConverter = new CsvConverter(sbomData);
        String key = "value";
        List<Property> properties = List.of(Property.builder().name(key).value(key).build());
        Component component = Component.builder().properties(properties).build();

        assertEquals(key, csvConverter.getPropertyValueFromKey(component, key));
    }
}
