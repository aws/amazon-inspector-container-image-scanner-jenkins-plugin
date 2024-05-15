package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.DockerVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Metadata;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;


public class HtmlConversionUtils {

    public static List<HtmlVulnerability> convertVulnerabilities(List<Vulnerability> vulnerabilities,
                                                                 List<Component> components) {
        List<HtmlVulnerability> htmlVulnerabilities = new ArrayList<>();
        if (vulnerabilities == null) {
            return htmlVulnerabilities;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getId().contains("IN-DOCKER")) {
                continue;
            }

            String severity = getSeverity(vulnerability.getRatings());
            if (severity == null) {
                severity = "Untriaged";
            }

            for (Affect affect : vulnerability.getAffects()) {
                String component = StringEscapeUtils.unescapeJava(getComponent(components, affect.getRef()));
                HtmlVulnerability htmlVulnerability = HtmlVulnerability.builder()
                        .title(vulnerability.getId())
                        .severity(StringUtils.capitalize(severity))
                        .component(component)
                        .build();
                htmlVulnerabilities.add(htmlVulnerability);
            }
        }

        Collections.sort(htmlVulnerabilities, (v1, v2) -> sortVulnerabilitiesBySeverity(v1.severity, v2.severity));
        return htmlVulnerabilities;
    }

    public static String getLines(String id, List<Property> properties) {
        for (Property property : properties) {
            if (property.getName().contains(id)) {
                String lines = property.getValue().split(":")[1];
                String[] splitLines = lines.split("-");
                if (splitLines[0].equals(splitLines[1])) {
                    return splitLines[0];
                } else {
                    return lines;
                }
            }
        }

        return "N/A";
    }

    public static Component getLineComponent(String bomRef, List<Component> components) {
        for (Component component : components) {
            if (component.getName().contains(bomRef)) {
                return component;
            }
        }

        return null;
    }

    public static List<DockerVulnerability> convertDocker(Metadata metadata, List<Vulnerability> vulnerabilities,
                                                                   List<Component> components) {
        List<DockerVulnerability> dockerVulnerabilities = new ArrayList<>();

        for (Vulnerability vulnerability : vulnerabilities) {

            if (!vulnerability.getId().contains("IN-DOCKER")) {
                continue;
            }

            String severity = getSeverity(vulnerability.getRatings());
            if (severity == null) {
                severity = "Untriaged";
            }

            String description = vulnerability.getDescription();
//            int descriptionLen = 30;
//            if (vulnerability.getDescription().length() > descriptionLen) {
//                description = vulnerability.getDescription().substring(0, descriptionLen) + "...";
//            } else {
//                description = vulnerability.getDescription();
//            }

            Component lineComponent = getLineComponent("comp-1", components);
            String lines = "N/A";
            if (lineComponent != null) {
                lines = getLines(vulnerability.getId(), lineComponent.getProperties());
                if (lineComponent.getName().equals("dockerfile:comp-1.Dockerfile")) {
                    lines += " (D - N/A)";
                }
            }

            for (Affect affect : vulnerability.getAffects()) {
                DockerVulnerability dockerVulnerability = DockerVulnerability.builder()
                        .id(vulnerability.getId())
                        .severity(severity)
                        .description(description)
                        .file("will-test-tarball.tar")
                        .lines(lines)
                        .build();
                dockerVulnerabilities.add(dockerVulnerability);
            }
        }

        return dockerVulnerabilities;
    }

    private static int sortVulnerabilitiesBySeverity(String s1, String s2) {
        Severity sev1 = Severity.getSeverityFromString(s1);
        Severity sev2 = Severity.getSeverityFromString(s2);

        return sev1.compareTo(sev2);
    }

    private static String getComponent(List<Component> components, String componentId) {
        for (Component component : components) {
            if (component.getBomRef().equals(componentId)) {
                return component.getPurl();
            }
        }

        return "None Found";
    }

    private static String getSeverity(List<Rating> ratings) {
        if (ratings == null || ratings.size() == 0) {
            return null;
        }

        for (Rating rating : ratings) {
            if (rating.getSource().getName().equals("NVD")) {
                return rating.getSeverity();
            }
        }

        return ratings.get(0).getSeverity();
    }
}
