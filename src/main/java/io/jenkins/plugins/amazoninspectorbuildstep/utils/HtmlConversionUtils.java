package io.jenkins.plugins.amazoninspectorbuildstep.utils;

import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class HtmlConversionUtils {

    public static List<HtmlVulnerability> convertVulnerabilities(List<Vulnerability> vulnerabilities,
                                                                 List<Component> components) {
        List<HtmlVulnerability> htmlVulnerabilities = new ArrayList<>();

        if (vulnerabilities == null) {
            return htmlVulnerabilities;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            String severity = getSeverity(vulnerability.getRatings());
            if (severity == null) {
                continue;
            }

            for (Affect affect : vulnerability.getAffects()) {
                HtmlVulnerability htmlVulnerability = HtmlVulnerability.builder()
                        .title(vulnerability.getId())
                        .severity(severity)
                        .component(getComponent(components, affect.getRef()))
                        .build();
                htmlVulnerabilities.add(htmlVulnerability);
            }
        }

        Collections.sort(htmlVulnerabilities, (v1, v2) -> sortVulnerabilitiesBySeverity(v1.severity, v2.severity));
        return htmlVulnerabilities;
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
