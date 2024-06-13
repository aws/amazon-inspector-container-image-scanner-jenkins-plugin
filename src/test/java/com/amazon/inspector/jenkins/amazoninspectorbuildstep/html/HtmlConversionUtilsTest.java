package com.amazon.inspector.jenkins.amazoninspectorbuildstep.html;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.DockerVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Source;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;

import org.junit.Test;

import java.util.List;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlConversionUtils.getSeverity;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlConversionUtils.sortVulnerabilitiesBySeverity;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class HtmlConversionUtilsTest {

    @Test
    public void testConvertVulnerabilities() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .ratings(List.of(Rating.builder().source(
                        Source.builder().name("NVD").build()
                )
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        Component component = Component.builder()
                .bomRef("bom")
                .purl("purl")
                .build();
        List<Component> components = List.of(component);

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, components);

        assertEquals(htmlVulnerabilities.size(), 1);
    }

    @Test
    public void testConvertVulnerabilities_emptyComponents() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<Component> components = List.of();

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, components);

        assertEquals(htmlVulnerabilities.size(), 0);
    }

    @Test
    public void testConvertVulnerabilities_nullSeverity() {
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

        assertEquals(htmlVulnerabilities.get(0).severity, "Untriaged");
    }

    @Test
    public void testConvertVulnerabilities_skipsDocker() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(vulnerabilities, null);

        assertEquals(htmlVulnerabilities.size(), 0);
    }

    @Test
    public void testConvertVulnerabilities_nullVulnerabilities() {
        List<HtmlVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertVulnerabilities(null, null);

        assertEquals(htmlVulnerabilities.size(), 0);
    }

    @Test
    public void testConvertDocker() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
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

        assertEquals(htmlVulnerabilities.size(), 1);
    }

    @Test
    public void testConvertDocker_emptyComponents() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
                        .severity("HIGH").build()))
                .affects(List.of(Affect.builder().ref("bom").build()))
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<Component> components = List.of();

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, components);

        assertEquals(htmlVulnerabilities.size(), 1);
    }

    @Test
    public void testConvertDocker_nullSeverity() {
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

        assertEquals(htmlVulnerabilities.get(0).severity, "Untriaged");
    }

    @Test
    public void testConvertDocker_skipsVuln() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("ID")
                .build();
        List<Vulnerability> vulnerabilities = List.of(vulnerability);

        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(vulnerabilities, null);

        assertEquals(htmlVulnerabilities.size(), 0);
    }

    @Test
    public void testConvertDocker_nullVulnerabilities() {
        List<DockerVulnerability> htmlVulnerabilities = HtmlConversionUtils.convertDocker(null, null);

        assertEquals(htmlVulnerabilities.size(), 0);
    }

    @Test
    public void testConvertDocker_derivedDockerfile() {
        Vulnerability vulnerability = Vulnerability.builder()
                .id("IN-DOCKER")
                .ratings(List.of(Rating.builder().source(
                                Source.builder().name("NVD").build()
                        )
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
    public void testGetLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                        .value("affected_lines:6-6")
                        .name(id)
                .build());
        assertEquals(HtmlConversionUtils.getLines(id, properties), "6");
    }

    @Test
    public void testGetLines_multipleLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                .value("affected_lines:6-7")
                .name(id)
                .build());
        assertEquals(HtmlConversionUtils.getLines(id, properties), "6-7");
    }

    @Test
    public void testGetLines_nullProperties() {
        assertEquals(HtmlConversionUtils.getLines(null, null), "N/A");
    }

    @Test
    public void testGetLines_noApplicableLines() {
        String id = "testId";
        List<Property> properties = List.of(Property.builder()
                .value("affected_lines:6-6")
                .name(id)
                .build());
        assertEquals(HtmlConversionUtils.getLines("invalid", properties), "N/A");
    }

    @Test
    public void testSortVulnerabilitiesBySeverity() {
        assertEquals(sortVulnerabilitiesBySeverity("high", "low"), -2);
        assertEquals(sortVulnerabilitiesBySeverity("low", "high"), 2);
        assertEquals(sortVulnerabilitiesBySeverity("high", "high"), 0);
    }

    @Test
    public void testGetSeverity_noNVD() {
        assertEquals(getSeverity(
                List.of(
                        Rating.builder()
                                .severity("low")
                                .source(Source.builder()
                                        .name("NonNVD").build()
                                ).build())
        ), "low");
    }
}
