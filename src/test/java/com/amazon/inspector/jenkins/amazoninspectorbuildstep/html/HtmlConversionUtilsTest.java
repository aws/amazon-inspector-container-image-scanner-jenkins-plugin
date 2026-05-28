package com.amazon.inspector.jenkins.amazoninspectorbuildstep.html;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.TestUtils;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.DockerVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Source;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.util.List;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlConversionUtils.sortVulnerabilitiesBySeverity;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.ConversionUtils.getSeverity;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlConversionUtilsTest {

    private SbomData sbomData;

    @BeforeEach
    void beforeEach() throws IOException {
        String str = TestUtils.readStringFromFile("src/test/resources/data/SbomOutputExampleUbuntu.json");
        sbomData = TestUtils.getSbomDataFromString(str);
    }

    @Test
    void testConvertVulnerabilities() {
        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();
        List<Component> components = sbomData.getSbom().getComponents();

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities,
                components);

        assertEquals(396, htmlVulnerabilities.size());
    }

    @Test
    void testConvertVulnerabilities_emptyComponents() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .method("CVSSv4")
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<Component> components = List.of();

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, components);

        assertEquals(1, htmlVulnerabilities.size());
    }

    @Test
    void testConvertVulnerabilities_nullSeverity() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .ratings(List.of())
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        Component component = Component.builder()
                .bomRef("bom")
                .purl("purl")
                .build();
        List<Component> components = List.of(component);

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, components);

        assertEquals("UNTRIAGED", htmlVulnerabilities.get(0).severity);
    }

    @Test
    void testConvertVulnerabilities_skipsDocker() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, null);

        assertEquals(0, htmlVulnerabilities.size());
    }

    @Test
    void testConvertVulnerabilities_nullVulnerabilities() {
        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(null, null);

        assertEquals(0, htmlVulnerabilities.size());
    }

    @Test
    void testConvertDocker() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .method("CVSSv4")
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        Component component = Component.builder()
                .bomRef("bom")
                .name("dockerfile")
                .purl("purl")
                .build();
        List<Component> components = List.of(component);

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, components);

        assertEquals(1, htmlVulnerabilities.size());
    }

    @Test
    void testConvertDocker_emptyComponents() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .method("CVSSv4")
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<Component> components = List.of();

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, components);

        assertEquals(1, htmlVulnerabilities.size());
    }

    @Test
    void testConvertDocker_nullSeverity() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of())
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        Component component = Component.builder()
                .bomRef("bom")
                .name("dockerfile")
                .purl("purl")
                .build();
        List<Component> components = List.of(component);

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, components);

        assertEquals("UNTRIAGED", htmlVulnerabilities.get(0).severity);
    }

    @Test
    void testConvertDocker_skipsVuln() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, null);

        assertEquals(0, htmlVulnerabilities.size());
    }

    @Test
    void testConvertDocker_nullVulnerabilities() {
        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(null, null);

        assertEquals(0, htmlVulnerabilities.size());
    }

    @Test
    void testConvertDocker_derivedDockerfile() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .method("CVSSv4")
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        Component component = Component.builder()
                .bomRef("bom")
                .name("dockerfile:comp-1.Dockerfile")
                .purl("purl")
                .build();
        List<Component> components = List.of(component);

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, components);

        assertTrue(htmlVulnerabilities.get(0).lines.contains(" - Derived"));
    }

    @Test
    void testGetLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                        .value("affected_lines:6-6")
                        .name(id)
                .build());
        assertEquals("6", HtmlConversionUtils.getLines(id, properties));
    }

    @Test
    void testGetLines_multipleLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                .value("affected_lines:6-7")
                .name(id)
                .build());
        assertEquals("6-7", HtmlConversionUtils.getLines(id, properties));
    }

    @Test
    void testGetLines_nullProperties() {
        assertEquals("N/A", HtmlConversionUtils.getLines(null, null));
    }

    @Test
    void testGetLines_noApplicableLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                .value("affected_lines:6-6")
                .name(id)
                .build());
        assertEquals("N/A", HtmlConversionUtils.getLines("invalid", properties));
    }

    @Test
    void testSortVulnerabilitiesBySeverity() {
        assertEquals(-2, sortVulnerabilitiesBySeverity("high", "low"));
        assertEquals(2, sortVulnerabilitiesBySeverity("low", "high"));
        assertEquals(0, sortVulnerabilitiesBySeverity("high", "high"));
    }

    @Test
    void testGetSeverity_noNVD() {
        Vulnerability vuln = Vulnerability.builder().ratings(List.of(
                Rating.builder()
                        .severity("low")
                        .method("CVSSv4")
                        .source(Source.builder()
                                .name("NonNVD").build()
                        ).build())).build();
        assertEquals(Severity.UNTRIAGED, getSeverity(vuln)
        );
    }
}
