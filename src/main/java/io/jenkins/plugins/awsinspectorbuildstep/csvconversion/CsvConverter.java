package io.jenkins.plugins.awsinspectorbuildstep.csvconversion;

import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Affect;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.SbomData;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CsvConverter {
//    CVE, Severity, Description, Package Name, Package Installed Version, Package Fixed Version, Exploit Available
    private SbomData sbomData;
    private Map<String, Component> componentMap;
    private String outputFileDestination;

    public CsvConverter(SbomData sbomData, String outputFileDestination) {
        this.sbomData = sbomData;
        this.outputFileDestination = outputFileDestination;
        this.componentMap = populateComponentMap(sbomData);
    }

    public void convert() throws FileNotFoundException {
        List<String[]> dataLines = buildCsvData();
        File csvOutputFile = new File(outputFileDestination);
        try (PrintWriter pw = new PrintWriter(csvOutputFile)) {
            dataLines.stream()
                    .map(d -> String.join(",", d))
                    .forEach(pw::println);
        }
    }

    private Map<String, Component> populateComponentMap(SbomData sbomData) {
        Map<String, Component> componentMap = new HashMap<>();
        sbomData.getSbom().getComponents().forEach(c -> componentMap.put(c.getBomRef(), c));
        return componentMap;
    }

    private List<String[]> buildCsvData() {
        List<String[]> dataLines = new ArrayList<>();
        dataLines.add(new String[]
                {"CVE", "Severity", "Description", "Package Name", "Package Installed Version",
                        "Package Fixed Version", "Exploit Available"});

        for (Vulnerability vulnerability : sbomData.getSbom().getVulnerabilities()) {
            for (Affect componentRef : vulnerability.getAffects()) {
                CsvData csvData = buildCsvData(vulnerability, componentMap.get(componentRef.getRef()));
                String[] dataLine = new String[]{csvData.getCve(), csvData.getSeverity(),
                        csvData.getDescription(), csvData.getPackageName(),
                        csvData.getPackageInstalledVersion(), csvData.getPackageFixedVersion(),
                        csvData.getExploitAvailable()};
                dataLines.add(dataLine);
            }
        }

        return dataLines;
    }

    public CsvData buildCsvData(Vulnerability vulnerability, Component component) {
        String version = getVersion(component);
        String exploitAvailable = getExploitAvailable(vulnerability);

        return CsvData.builder()
                .cve(vulnerability.getId())
                .severity(getSeverity(vulnerability))
                .description(vulnerability.getDescription())
                .packageName(component.getName())
                .packageFixedVersion(version)
                .packageInstalledVersion(version)
                .exploitAvailable(exploitAvailable)
                .build();
    }

    private String getExploitAvailable(Vulnerability vulnerability) {
        final String exploitAvailableName = "amazon:inspector:sbom_scanner:exploit_available";

        return vulnerability.getProperties().stream()
                .filter(v -> v.getName().equals(exploitAvailableName))
                .findFirst().get().getValue();
    }

    private String getVersion(Component component) {
        final String versionPattern = "@[1-9]\\d*(\\.[1-9]\\d*)*";

        Pattern pattern = Pattern.compile(versionPattern);
        Matcher matcher = pattern.matcher(component.getPurl());

        if (matcher.find()) {
            return matcher.group(0);
        } else {
            throw new RuntimeException(String.format("No version found from component %s", component));
        }
    }

    private String getSeverity(Vulnerability vulnerability) {
        List<Rating> ratings = vulnerability.getRatings();

        for (Rating rating : ratings) {
            String sourceName = rating.getSource().getName();
            String method = rating.getMethod();

            if (sourceName.equals("NVD") && method.startsWith("CVSSv3")) {
                return rating.getSeverity();
            }
        }

        return ratings.get(0).getSeverity();
    }
}
