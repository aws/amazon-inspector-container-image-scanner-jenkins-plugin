package io.jenkins.plugins.amazoninspectorbuildstep.csvconversion;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class CsvData {
    private String cve;
    private String severity;
    private String description;
    private String packageName;
    private String packageInstalledVersion;
    private String packageFixedVersion;
    private String exploitAvailable;
}
