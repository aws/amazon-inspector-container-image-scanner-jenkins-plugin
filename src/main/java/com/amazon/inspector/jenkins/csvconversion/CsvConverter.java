package com.amazon.inspector.jenkins.csvconversion;

import com.google.common.annotations.VisibleForTesting;
import com.opencsv.CSVWriter;
import freemarker.template.utility.StringUtil;
import com.amazon.inspector.jenkins.models.sbom.Components.Affect;
import com.amazon.inspector.jenkins.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.models.sbom.SbomData;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CsvConverter {
    private SbomData sbomData;
    private Map<String, Component> componentMap;

    public CsvConverter(SbomData sbomData) {
        this.sbomData = sbomData;
        this.componentMap = populateComponentMap(sbomData);
    }

    public void convert(String filePath) {
        List<String[]> dataLineArray = buildCsvDataLines();
        File file = new File(filePath);

        try {
            FileWriter outputfile = new FileWriter(file);
            CSVWriter writer = new CSVWriter(outputfile);

            writer.writeAll(dataLineArray);
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Map<String, Component> populateComponentMap(SbomData sbomData) {
        Map<String, Component> componentMap = new HashMap<>();

        if (sbomData.getSbom().getComponents() == null) {
            return componentMap;
        }

        for (Component component : sbomData.getSbom().getComponents()) {
            componentMap.put(component.getBomRef(), component);
        }

        return componentMap;
    }

    protected List<String[]> buildCsvDataLines() {
        List<String[]> dataLines = new ArrayList<>();
        String[] headers = new String[] {"Vulnerability ID", "Severity", "Published", "Modified", "Description",
                "Package Installed Version", "Package Fixed Version", "Package Path", "EPSS Score", "Exploit Available",
                "Exploit Last Seen", "CWEs"};
        dataLines.add(headers);

        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return dataLines;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            for (Affect componentRef : vulnerability.getAffects()) {
                CsvData csvData = buildCsvData(vulnerability, componentMap.get(componentRef.getRef()));

                String[] dataLine = new String[] {csvData.getVulnerabilityId(),
                        StringUtil.capitalize(csvData.getSeverity()), csvData.getPublished(), csvData.getModified(),
                        csvData.getDescription(), csvData.getPackageInstalledVersion(),
                        csvData.getPackageFixedVersion(), csvData.getPackagePath(), csvData.getEpssScore(),
                        csvData.getExploitAvailable(), csvData.getExploitLastSeen(), csvData.getCwes()};

                dataLines.add(dataLine);
            }
        }

        return dataLines;
    }

    public CsvData buildCsvData(Vulnerability vulnerability, Component component) {
        String fixedVersion = getPropertyValueFromKey(vulnerability,
                String.format("amazon:inspector:sbom_scanner:fixed_version:%s",  component.getBomRef()));
        String exploitAvailable = getPropertyValueFromKey(vulnerability,
                "amazon:inspector:sbom_scanner:exploit_available");
        String exploitLastSeen = getPropertyValueFromKey(vulnerability,
                "amazon:inspector:sbom_scanner:exploit_last_seen_in_public");
        String path = getPropertyValueFromKey(component,
                "amazon:inspector:sbom_scanner:path");

        return CsvData.builder()
                .vulnerabilityId(vulnerability.getId())
                .severity(getSeverity(vulnerability))
                .published(vulnerability.getCreated())
                .modified(getUpdated(vulnerability))
                .epssScore(getEpssScore(vulnerability))
                .description(vulnerability.getDescription())
                .packageInstalledVersion(component.getPurl())
                .packageFixedVersion(fixedVersion)
                .packagePath(path)
                .cwes(getCwesAsString(vulnerability))
                .exploitAvailable(exploitAvailable)
                .exploitLastSeen(exploitLastSeen)
                .build();
    }

    @VisibleForTesting
    protected String getUpdated(Vulnerability vulnerability) {
        if (vulnerability == null || vulnerability.getUpdated() == null) {
            return "N/A";
        }

        return vulnerability.getUpdated();
    }

    @VisibleForTesting
    protected String getCwesAsString(Vulnerability vulnerability) {
        List<String> cwes = new ArrayList<>();

        if (vulnerability == null || vulnerability.getCwes() == null) {
            return "";
        }

        for (Integer cwe : vulnerability.getCwes()) {
            cwes.add(String.format("CWE-%s", cwe.toString()));
        }

        return String.join(", ", cwes);
    }

    @VisibleForTesting
    protected String getEpssScore(Vulnerability vulnerability) {
        if (vulnerability == null || vulnerability.getRatings() == null) {
            return "N/A";
        }

        for (Rating rating : vulnerability.getRatings()) {
            if (rating.getSource().getName().equals("EPSS")) {
                return Double.toString(rating.getScore());
            }
        }

        return "N/A";
    }

    @VisibleForTesting
    protected String getPropertyValueFromKey(Vulnerability vulnerability, String key) {
        if (vulnerability == null) {
            return "N/A";
        }

        for (Property property : vulnerability.getProperties()) {
            if (property.getName().equals(key)) {
                return property.getValue();
            }
        }

        return "N/A";
    }

    protected String getPropertyValueFromKey(Component component, String key) {
        if (component == null || component.getProperties() == null) {
            return "N/A";
        }

        for (Property property : component.getProperties()) {
            if (property.getName().equals(key)) {
                return property.getValue();
            }
        }

        return "N/A";
    }

    protected String getSeverity(Vulnerability vulnerability) {
        if (vulnerability == null || vulnerability.getRatings() == null) {
            return "";
        }

        List<Rating> ratings = vulnerability.getRatings();
        final String nvd = "NVD";
        final String cvss = "CVSSv3";

        for (Rating rating : ratings) {
            String sourceName = rating.getSource().getName();
            String method = rating.getMethod();

            if (sourceName.equals(nvd) && method.startsWith(cvss)) {
                return rating.getSeverity();
            }
        }

        return ratings.get(0).getSeverity();
    }
}
