package io.jenkins.plugins.amazoninspectorbuildstep.csvconversion;

import com.google.common.annotations.VisibleForTesting;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Affect;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Property;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CsvConverter {
    private SbomData sbomData;
    private Map<String, Component> componentMap;
    private PrintStream logger;

    public CsvConverter(PrintStream logger, SbomData sbomData) {
        this.logger = logger;
        this.sbomData = sbomData;
        this.componentMap = populateComponentMap(sbomData);
    }

    public void convert(String outputFileName) {
        List<List<String>> dataLineArray = buildCsvDataLines();
        logger.println("Converting");

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFileName))) {
            for (List<String> lineArray : dataLineArray) {
                String line = String.join(",", lineArray);
                writer.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        logger.println("Conversion done");
    }

    private Map<String, Component> populateComponentMap(SbomData sbomData) {
        Map<String, Component> componentMap = new HashMap<>();

        for (Component component : sbomData.getSbom().getComponents()) {
            componentMap.put(component.getBomRef(), component);
        }

        return componentMap;
    }

    @VisibleForTesting
    protected List<List<String>> buildCsvDataLines() {
        List<List<String>> dataLines = new ArrayList<>();
        logger.println("Getting data lines");
        List<String> headers = List.of("CVE", "Severity", "Description", "Package Name", "Package Installed Version",
                "Package Fixed Version", "Exploit Available");
        dataLines.add(headers);

        List<Vulnerability> vulnerabilities = sbomData.getSbom().getVulnerabilities();

        if (vulnerabilities == null) {
            return dataLines;
        }

        for (Vulnerability vulnerability : vulnerabilities) {
            for (Affect componentRef : vulnerability.getAffects()) {
                CsvData csvData = buildCsvData(vulnerability, componentMap.get(componentRef.getRef()));

                System.out.println(csvData.getDescription());

                List<String> dataLine = List.of(csvData.getCve(), csvData.getSeverity(),
                        csvData.getDescription(), csvData.getPackageName(),
                        csvData.getPackageInstalledVersion(), csvData.getPackageFixedVersion(),
                        csvData.getExploitAvailable());

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
                .cve(vulnerability.getId())
                .severity(getSeverity(vulnerability))
                .description(String.format("\"%s\"", vulnerability.getDescription().replace(",", ".")))
                .packageName(component.getName())
                .packageFixedVersion(fixedVersion)
                .packageInstalledVersion(installedVersion)
                .exploitAvailable(String.format("\"%s\"", exploitAvailable))
                .build();
    }

    @VisibleForTesting
    protected String getExploitAvailable(Vulnerability vulnerability) {
        final String exploitAvailableName = "amazon:inspector:sbom_scanner:exploit_available";
        return vulnerability.getProperties().stream()
                .filter(v -> v.getName().equals(exploitAvailableName))
                .findFirst().orElse(Property.builder().name(exploitAvailableName).value("").build()).getValue();
    }

    @VisibleForTesting
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

    @VisibleForTesting
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

    @VisibleForTesting
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
