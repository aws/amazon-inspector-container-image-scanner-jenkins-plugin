package com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.HtmlConversionUtils;
import com.google.common.annotations.VisibleForTesting;
import com.opencsv.CSVWriter;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Component;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.HtmlConversionUtils.getLineComponents;

public class CsvConverter {
    private SbomData sbomData;
    private Map<String, Component> componentMap;
    private static List<CsvData> dockerData;
    private static List<CsvData> vulnData;

    public CsvConverter(SbomData sbomData) {
        this.sbomData = sbomData;
        this.componentMap = populateComponentMap(sbomData);
        dockerData = new ArrayList<>();
        vulnData = new ArrayList<>();
    }

    private Map<String, Component> populateComponentMap(SbomData sbomData) {
        Map<String, Component> componentMap = new HashMap<>();

        if (sbomData == null || sbomData.getSbom() == null || sbomData.getSbom().getComponents() == null) {
            return componentMap;
        }

        for (Component component : sbomData.getSbom().getComponents()) {
            componentMap.put(component.getBomRef(), component);
        }

        return componentMap;
    }

    public String convertVulnerabilities(String imageName, String imageSha, String buildId, SeverityCounts counts) throws IOException {
        Map<Severity, Integer> countMap = counts.getCounts();
        String tmpdir = System.getProperty("java.io.tmpdir");
        List<String[]> dataLineArray = new ArrayList<>();

        dataLineArray.add(new String[]{String.format("#image_name: %s; image_sha: %s; build_id: %s", imageName, imageSha, buildId)});
        dataLineArray.add(new String[]{String.format("#low_vulnerabilities: %s; medium_vulnerabilities: %s; high_vulnerabilities: %s; " +
                        "critical_vulnerabilities: %s; other_vulnerabilities: %s", countMap.get(Severity.LOW),
                countMap.get(Severity.MEDIUM), countMap.get(Severity.HIGH), countMap.get(Severity.CRITICAL),
                countMap.get(Severity.OTHER))});
        dataLineArray.addAll(buildVulnerabilityDataLines());

        File file = new File(tmpdir + "/temp.csv");

        try {
            FileWriter outputfile = new FileWriter(file, Charset.forName("UTF-8"));
            CSVWriter writer = new CSVWriter(outputfile);

            writer.writeAll(dataLineArray);
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        return new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())), StandardCharsets.UTF_8);
    }

    public String convertDocker(String imageName, String imageSha, String buildId, SeverityCounts counts) throws IOException {
        Map<Severity, Integer> countMap = counts.getCounts();
        String tmpdir = System.getProperty("java.io.tmpdir");
        List<String[]> dataLineArray = new ArrayList<>();

        dataLineArray.add(new String[]{String.format("#image_name: %s; image_sha: %s; build_id: %s", imageName, imageSha, buildId)});
        dataLineArray.add(new String[]{String.format("#low_vulnerabilities: %s; medium_vulnerabilities: %s; high_vulnerabilities: %s; " +
                        "critical_vulnerabilities: %s; other_vulnerabilities: %s", countMap.get(Severity.LOW),
                countMap.get(Severity.MEDIUM), countMap.get(Severity.HIGH), countMap.get(Severity.CRITICAL),
                countMap.get(Severity.OTHER))});
        dataLineArray.addAll(buildDockerDataLines());

        File file = new File(tmpdir + "/temp.csv");

        try {
            FileWriter outputfile = new FileWriter(file, Charset.forName("UTF-8"));
            CSVWriter writer = new CSVWriter(outputfile);

            writer.writeAll(dataLineArray);
            writer.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }

        return new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())), StandardCharsets.UTF_8);
    }


    protected List<String[]> buildVulnerabilityDataLines() {
        List<String[]> dataLines = new ArrayList<>();
        String[] headers = new String[] {"Vulnerability ID", "Severity", "Published", "Modified", "Description",
                "Package Installed Version", "Package Fixed Version", "Package Path", "EPSS Score", "Exploit Available",
                "Exploit Last Seen", "CWEs"};
        dataLines.add(headers);

        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return dataLines;
        }

        for (CsvData csvData : vulnData) {
                String[] dataLine = new String[] {csvData.getVulnerabilityId(),
                        StringUtils.capitalize(csvData.getSeverity()), csvData.getPublished(), csvData.getModified(),
                        csvData.getDescription(), csvData.getPackageInstalledVersion(),
                        csvData.getPackageFixedVersion(), csvData.getPackagePath(), csvData.getEpssScore(),
                        csvData.getExploitAvailable(), csvData.getExploitLastSeen(), csvData.getCwes()};

                dataLines.add(dataLine);
        }

        return dataLines;
    }

    protected List<String[]> buildDockerDataLines() {
        List<String[]> dataLines = new ArrayList<>();
        String[] headers = new String[] {"Vulnerability ID", "Severity", "Description", "File", "Line(s)"};
        dataLines.add(headers);

        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return dataLines;
        }

        for (CsvData csvData: dockerData) {
                String[] dataLine = new String[] {csvData.getVulnerabilityId(), StringUtils.capitalize(csvData.getSeverity()),
                        csvData.getDescription(), csvData.getFile(), csvData.getLines()};

                dataLines.add(dataLine);
        }

        return dataLines;
    }

    public void routeVulnerabilities() {
        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        for (Vulnerability vulnerability : vulnerabilities) {
            for (Affect componentRef : vulnerability.getAffects()) {
                routeCsvData(vulnerability, componentMap.get(componentRef.getRef()));
            }
        }
    }

    public void routeCsvData(Vulnerability vulnerability, Component component) {
        String fixedVersion = getPropertyValueFromKey(vulnerability,
                String.format("amazon:inspector:sbom_scanner:fixed_version:%s",  component.getBomRef()));
        String exploitAvailable = getPropertyValueFromKey(vulnerability,
                "amazon:inspector:sbom_scanner:exploit_available");
        String exploitLastSeen = getPropertyValueFromKey(vulnerability,
                "amazon:inspector:sbom_scanner:exploit_last_seen_in_public");
        String path = getPropertyValueFromKey(component,
                "amazon:inspector:sbom_scanner:path");

        List<Component> lineComponents = getLineComponents(sbomData.getSbom().getComponents());
        String lines = "N/A";
        String file = "N/A";
        for (Component lineComponent : lineComponents) {
            if (lineComponent != null && !lineComponent.getName().startsWith("dockerfile:")) {
                lines = HtmlConversionUtils.getLines(vulnerability.getId(), lineComponent.getProperties());
                file = lineComponent.getName();
            }

            CsvData csvData = CsvData.builder()
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
                    .file(file)
                    .lines(lines)
                    .build();

            if (vulnerability.getId().contains("IN-DOCKER")) {
                dockerData.add(csvData);
            } else {
                vulnData.add(csvData);
            }
        }
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
    protected static String getPropertyValueFromKey(Vulnerability vulnerability, String key) {
        if (vulnerability == null || vulnerability.getProperties() == null) {
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
        final String OTHER = "OTHER";

        if (vulnerability == null || vulnerability.getRatings() == null) {
            return OTHER;
        }

        List<Rating> ratings = vulnerability.getRatings();

        if (ratings.isEmpty()) {
            return OTHER;
        }

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
