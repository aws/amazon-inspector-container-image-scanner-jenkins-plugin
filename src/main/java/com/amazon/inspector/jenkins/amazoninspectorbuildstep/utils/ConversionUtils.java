package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ConversionUtils {
    static final String NVD = "NVD";
    static final String CVSS4 = "CVSSv4";
    static final String CVSS31 = "CVSSv31";
    static final String CVSS3 = "CVSSv3";
    static final String CVSS2 = "CVSSv2";


    public static Severity getSeverity(Vulnerability vulnerability) {
        if (vulnerability == null || vulnerability.getRatings() == null) {
            return Severity.UNTRIAGED;
        }

        List<Rating> ratings = vulnerability.getRatings();

        if (ratings.isEmpty()) {
            return Severity.UNTRIAGED;
        }

        Map<String, Severity> severityMap = new HashMap<>();
        for (Rating rating : ratings) {
            if (rating == null) {
                continue;
            }

            String sourceName = rating.getSource().getName();
            String method = rating.getMethod();

            if (sourceName.equals(NVD)) {
                severityMap.put(getCvssMethod(method), Severity.getSeverityFromString(rating.getSeverity()));
            }
        }

        return getHighestCvssMethodSeverity(severityMap);
    }

    private static String getCvssMethod(String method) {
        if (method.startsWith(CVSS4)) {
            return CVSS4;
        } else if (method.startsWith(CVSS31)) {
            return CVSS31;
        } else if (method.startsWith(CVSS3)) {
            return CVSS3;
        } else if (method.startsWith(CVSS2)) {
            return CVSS2;
        }

        throw new RuntimeException("Unsupported CVSS method: " + method);
    }

    private static Severity getHighestCvssMethodSeverity(Map<String, Severity> severityMap) {
        if (severityMap.containsKey(CVSS4)) {
            return severityMap.get(CVSS4);
        } else if (severityMap.containsKey(CVSS31)) {
            return severityMap.get(CVSS31);
        } else if (severityMap.containsKey(CVSS3)) {
            return severityMap.get(CVSS3);
        } else if (severityMap.containsKey(CVSS2)) {
            return severityMap.get(CVSS2);
        }

        return Severity.UNTRIAGED;
    }
}