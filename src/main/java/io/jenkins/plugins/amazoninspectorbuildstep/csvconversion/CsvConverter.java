package io.jenkins.plugins.amazoninspectorbuildstep.csvconversion;

import com.opencsv.CSVWriter;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Property;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

        for (Component component : sbomData.getSbom().getComponents()) {
            componentMap.put(component.getBomRef(), component);
        }

        return componentMap;
    }

    protected List<String []> buildCsvDataLines() {
        List<String[]> dataLines = new ArrayList<>();
        String[] headers = new String[] {"CVE", "Severity", "Published", "Modified", "Description",
                "Package Installed Version",
//                "Package Path",
                "Package Fixed Version", "EPSS Score", "Exploit Available", "CWEs"};
        dataLines.add(headers);

        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return dataLines;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            for (Affect componentRef : vulnerability.getAffects()) {
                CsvData csvData = buildCsvData(vulnerability, componentMap.get(componentRef.getRef()));

                String[] dataLine = new String[] {csvData.getVulnerabilityId(), csvData.getSeverity(),
                        csvData.getPublished(), csvData.getModified(),
                        csvData.getDescription(),
                        csvData.getPackageInstalledVersion(),
//                        csvData.getPackagePath(),
                        csvData.getPackageFixedVersion(), csvData.getEpssScore(),
                        csvData.getExploitAvailable(), csvData.getCwes()};

                dataLines.add(dataLine);
            }
        }

        return dataLines;
    }

    public CsvData buildCsvData(Vulnerability vulnerability, Component component) {
        String installedVersion = getInstalledVersion(component);
        String fixedVersion = getFixedVersion(vulnerability, component.getBomRef());
        String exploitAvailable = getExploitAvailable(vulnerability);

        return CsvData.builder()
                .vulnerabilityId(vulnerability.getId())
                .severity(getSeverity(vulnerability))
                .published(vulnerability.getCreated())
                .modified(getModified(vulnerability))
                .epssScore(getEpssScore(vulnerability))
                .description(vulnerability.getDescription())
                .packageInstalledVersion(installedVersion)
                .packageFixedVersion(fixedVersion)
                .packagePath("N/A")
                .cwes(getCwesAsString(vulnerability))
                .exploitAvailable(exploitAvailable)
                .build();
    }

    private String getModified(Vulnerability vulnerability) {
        if (vulnerability.getModified() == null) {
            return "N/A";
        }

        return vulnerability.getModified();
    }

    protected String getCwesAsString(Vulnerability vulnerability) {
        List<String> cwes = new ArrayList<>();

        for (Integer cwe : vulnerability.getCwes()) {
            cwes.add(String.format("CWE-%s", cwe.toString()));
        }

        return String.join(", ", cwes);
    }

    protected String getEpssScore(Vulnerability vulnerability) {
        for (Rating rating : vulnerability.getRatings()) {
            if (rating.getSource().getName().equals("EPSS")) {
                return Double.toString(rating.getScore());
            }
        }

        return "N/A";
    }

    protected String getExploitAvailable(Vulnerability vulnerability) {
        final String exploitAvailableName = "amazon:inspector:sbom_scanner:exploit_available";

        for (Property property : vulnerability.getProperties()) {
            if (property.getName().equals(exploitAvailableName)) {
                return property.getValue();
            }
        }
        return "N/A";
    }

    protected String getFixedVersion(Vulnerability vulnerability, String componentKey) {
        final String fixedVersionName =
                String.format("amazon:inspector:sbom_scanner:fixed_version:%s", componentKey);

        for (Property property : vulnerability.getProperties()) {
            if (property.getName().equals(fixedVersionName)) {
                return property.getValue();
            }
        }

        throw new RuntimeException(String.format("No fixed version for name %s in %s", fixedVersionName,
                vulnerability.getBomRef()));
    }

    protected String getInstalledVersion(Component component) {
        // Matches strings like 3.11.321.2...
        final String versionPattern = "@(?<version>[^?#]+)";

        Pattern pattern = Pattern.compile(versionPattern);
        Matcher matcher = pattern.matcher(component.getPurl());

        if (matcher.find()) {
            return matcher.group(0).replace("@", "");
        }

        throw new RuntimeException(String.format("No version found from component %s", component));
    }

    protected String getSeverity(Vulnerability vulnerability) {
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
